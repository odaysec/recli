#pragma once

#include <string>
#include <vector>
#include <map>
#include <stdexcept>
#include <fstream>
#include <memory>
#include <capstone/capstone.h>
#include <LIEF/LIEF.hpp>

namespace RECLI {

class BinaryData {
public:
    explicit BinaryData(const std::string& file_path);
    ~BinaryData();

    const std::vector<uint8_t>& get_data() const { return m_data; }
    std::string get_file_path() const { return m_file_path; }
    LIEF::Binary* get_binary() const { return m_binary.get(); }

private:
    std::string m_file_path;
    std::vector<uint8_t> m_data;
    std::unique_ptr<LIEF::Binary> m_binary;
};

enum class OutputFormat {
    TEXT,
    JSON,
    MARKDOWN
};

class Disassembler {
public:
    Disassembler();
    ~Disassembler();

    std::vector<std::string> disassemble(const uint8_t* code, size_t size, uint64_t address, size_t count = 0);

private:
    csh m_handle;
};

class OutputFormatter {
public:
    explicit OutputFormatter(OutputFormat format) : m_format(format) {}

    template<typename T>
    std::string format(const T& data) const;

private:
    OutputFormat m_format;
};

std::string read_file(const std::string& path);
void write_file(const std::string& path, const std::string& content);
OutputFormat parse_format(const std::string& format_str);
std::string to_lower(const std::string& str);

} // namespace RECLI