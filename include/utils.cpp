#include "utils.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace RECLI {

BinaryData::BinaryData(const std::string& file_path) : m_file_path(file_path) {
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + file_path);
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    m_data.resize(size);
    if (!file.read(reinterpret_cast<char*>(m_data.data()), size)) {
        throw std::runtime_error("Failed to read file: " + file_path);
    }

    try {
        m_binary = std::unique_ptr<LIEF::Binary>(LIEF::Binary::parse(file_path));
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to parse binary: " + std::string(e.what()));
    }
}

BinaryData::~BinaryData() {
    if (m_binary) {
        delete m_binary.release();
    }
}

Disassembler::Disassembler() {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &m_handle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize Capstone disassembler");
    }
    cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_ON);
}

Disassembler::~Disassembler() {
    cs_close(&m_handle);
}

std::vector<std::string> Disassembler::disassemble(const uint8_t* code, size_t size, uint64_t address, size_t count) {
    std::vector<std::string> result;
    cs_insn* insn;
    
    size_t disassembled = cs_disasm(m_handle, code, size, address, count, &insn);
    if (disassembled > 0) {
        for (size_t i = 0; i < disassembled; i++) {
            std::ostringstream oss;
            oss << "0x" << std::hex << insn[i].address << ": " 
                << insn[i].mnemonic << " " << insn[i].op_str;
            result.push_back(oss.str());
        }
        cs_free(insn, disassembled);
    }
    
    return result;
}

template<typename T>
std::string OutputFormatter::format(const T& data) const {
    switch (m_format) {
        case OutputFormat::JSON: {
            json j = data;
            return j.dump(4);
        }
        case OutputFormat::MARKDOWN: {
            if constexpr (std::is_same_v<T, std::vector<std::string>>) {
                std::string result;
                for (const auto& item : data) {
                    result += "- " + item + "\n";
                }
                return result;
            } else {
                return "```\n" + std::string(data) + "\n```";
            }
        }
        default:
            if constexpr (std::is_same_v<T, std::vector<std::string>>) {
                std::string result;
                for (const auto& item : data) {
                    result += item + "\n";
                }
                return result;
            } else {
                return std::string(data);
            }
    }
}

std::string read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + path);
    }
    std::ostringstream oss;
    oss << file.rdbuf();
    return oss.str();
}

void write_file(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    if (!file) {
        throw std::runtime_error("Failed to open file for writing: " + path);
    }
    file << content;
}

OutputFormat parse_format(const std::string& format_str) {
    auto lower = to_lower(format_str);
    if (lower == "json") return OutputFormat::JSON;
    if (lower == "md" || lower == "markdown") return OutputFormat::MARKDOWN;
    return OutputFormat::TEXT;
}

std::string to_lower(const std::string& str) {
    std::string result;
    result.reserve(str.size());
    for (char c : str) {
        result += tolower(c);
    }
    return result;
}

} // namespace RECLI