#pragma once

#include "utils.h"

namespace RECLI {

class APIScanner {
public:
    explicit APIScanner(BinaryData* binary_data);
    int run(const std::map<std::string, std::string>& options);

private:
    std::map<std::string, std::vector<uint64_t>> find_api_calls();
    
    BinaryData* m_binary_data;
    Disassembler m_disassembler;
};

} 

// src/api_scanner.cpp
#include "api_scanner.h"
#include <LIEF/LIEF.hpp>
#include <set>

namespace RECLI {

APIScanner::APIScanner(BinaryData* binary_data) 
    : m_binary_data(binary_data) {}

int APIScanner::run(const std::map<std::string, std::string>& options) {
    try {
        auto api_calls = find_api_calls();

        OutputFormat format = OutputFormat::TEXT;
        if (options.find("format") != options.end()) {
            format = parse_format(options.at("format"));
        }

        std::map<std::string, std::vector<std::string>> output_data;
        for (const auto& [api, addresses] : api_calls) {
            std::vector<std::string> addr_strs;
            for (auto addr : addresses) {
                std::ostringstream oss;
                oss << "0x" << std::hex << addr;
                addr_strs.push_back(oss.str());
            }
            output_data[api] = addr_strs;
        }

        OutputFormatter formatter(format);
        std::string output = formatter.format(output_data);

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

std::map<std::string, std::vector<uint64_t>> APIScanner::find_api_calls() {
    std::map<std::string, std::vector<uint64_t>> result;
    const auto& binary = m_binary_data->get_binary();

    // Get imports (direct API calls)
    for (const auto& import : binary->imported_functions()) {
        result[import.name()].push_back(import.address());
    }

    // Scan for indirect API calls in code
    const auto& data = m_binary_data->get_data();
    const uint8_t* code = data.data();
    size_t code_size = data.size();

    // Common API call patterns
    static const std::set<std::string> common_apis = {
        "CreateFile", "ReadFile", "WriteFile", "CloseHandle",
        "RegOpenKey", "RegQueryValue", "RegSetValue", "RegCloseKey",
        "socket", "connect", "send", "recv", "bind", "listen",
        "VirtualAlloc", "VirtualFree", "VirtualProtect",
        "LoadLibrary", "GetProcAddress", "FreeLibrary",
        "GetModuleHandle", "GetSystemDirectory", "GetWindowsDirectory"
    };

    auto instructions = m_disassembler.disassemble(code, code_size, binary->imagebase());
    for (const auto& insn : instructions) {
        // Look for CALL instructions to imports
        if (insn.find("call qword ptr [0x") != std::string::npos) {
            size_t pos = insn.find("[0x");
            if (pos != std::string::npos) {
                uint64_t addr = std::stoull(insn.substr(pos + 3), nullptr, 16);
                // Check if this is an import address
                for (const auto& import : binary->imported_functions()) {
                    if (import.address() == addr) {
                        result[import.name()].push_back(addr);
                        break;
                    }
                }
            }
        }
        
        
        for (const auto& api : common_apis) {
            if (insn.find(api) != std::string::npos) {
                size_t addr_pos = insn.find("0x");
                if (addr_pos != std::string::npos) {
                    uint64_t addr = std::stoull(insn.substr(addr_pos + 2), nullptr, 16);
                    result[api].push_back(addr);
                }
            }
        }
    }

    return result;
}

} 