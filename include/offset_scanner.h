#pragma once

#include "utils.h"

namespace RECLI {

class OffsetScanner {
public:
    explicit OffsetScanner(BinaryData* binary_data);
    int run(const std::map<std::string, std::string>& options);

private:
    std::map<uint64_t, std::string> find_offsets();
    
    BinaryData* m_binary_data;
    Disassembler m_disassembler;
};

} // namespace RECLI

// src/offset_scanner.cpp
#include "offset_scanner.h"
#include <capstone/capstone.h>
#include <LIEF/LIEF.hpp>

namespace RECLI {

OffsetScanner::OffsetScanner(BinaryData* binary_data) 
    : m_binary_data(binary_data) {}

int OffsetScanner::run(const std::map<std::string, std::string>& options) {
    try {
        auto offsets = find_offsets();

        OutputFormat format = OutputFormat::TEXT;
        if (options.find("format") != options.end()) {
            format = parse_format(options.at("format"));
        }

        std::vector<std::string> output_lines;
        for (const auto& [offset, desc] : offsets) {
            std::ostringstream oss;
            oss << "0x" << std::hex << offset << ": " << desc;
            output_lines.push_back(oss.str());
        }

        OutputFormatter formatter(format);
        std::string output = formatter.format(output_lines);

        if (options.find("output") != options.end()) {
            write_file(options.at("output"), output);
        } else {
            std::cout << output;
        }

        return EXIT_SUCCESS;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}

std::map<uint64_t, std::string> OffsetScanner::find_offsets() {
    std::map<uint64_t, std::string> result;
    const auto& binary = m_binary_data->get_binary();

    // Find imports
    for (const auto& import : binary->imported_functions()) {
        result[import.address()] = "Import: " + import.name();
    }

    // Find exports
    for (const auto& export_ : binary->exported_functions()) {
        result[export_.address()] = "Export: " + export_.name();
    }

    // Find sections
    for (const auto& section : binary->sections()) {
        result[section.virtual_address()] = "Section: " + section.name();
    }

    // Find relocations
    for (const auto& relocation : binary->relocations()) {
        result[relocation.address()] = "Relocation";
    }

    // Scan for common patterns in code
    const auto& data = m_binary_data->get_data();
    const uint8_t* code = data.data();
    size_t code_size = data.size();

    // Disassemble and look for interesting instructions
    auto instructions = m_disassembler.disassemble(code, code_size, binary->imagebase());
    for (const auto& insn : instructions) {
        // Look for CALL instructions to fixed addresses
        if (insn.find("call 0x") != std::string::npos) {
            size_t pos = insn.find("0x");
            if (pos != std::string::npos) {
                uint64_t addr = std::stoull(insn.substr(pos + 2), nullptr, 16);
                result[addr] = "Call target: " + insn;
            }
        }
        // Look for MOV instructions with memory operands
        else if (insn.find("mov") != std::string::npos && 
                (insn.find("[0x") != std::string::npos || insn.find("dword ptr") != std::string::npos)) {
            result[0] = "Memory access: " + insn; // Simplified for example
        }
    }

    return result;
}

} // namespace RECLI