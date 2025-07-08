#pragma once

#include "utils.h"

namespace RECLI {

class StringExtractor {
public:
    explicit StringExtractor(BinaryData* binary_data);
    int run(const std::map<std::string, std::string>& options);

private:
    std::vector<std::string> extract_strings(size_t min_length = 4);
    std::vector<std::string> extract_unicode_strings(size_t min_length = 4);
    
    BinaryData* m_binary_data;
};

} // namespace RECLI

// src/string_extractor.cpp
#include "string_extractor.h"
#include <algorithm>
#include <cctype>

namespace RECLI {

StringExtractor::StringExtractor(BinaryData* binary_data) 
    : m_binary_data(binary_data) {}

int StringExtractor::run(const std::map<std::string, std::string>& options) {
    try {
        bool unicode = options.find("unicode") != options.end();
        size_t min_length = 4;
        if (options.find("min-length") != options.end()) {
            min_length = std::stoul(options.at("min-length"));
        }

        std::vector<std::string> strings;
        if (unicode) {
            strings = extract_unicode_strings(min_length);
        } else {
            strings = extract_strings(min_length);
        }

        OutputFormat format = OutputFormat::TEXT;
        if (options.find("format") != options.end()) {
            format = parse_format(options.at("format"));
        }

        OutputFormatter formatter(format);
        std::string output = formatter.format(strings);

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

std::vector<std::string> StringExtractor::extract_strings(size_t min_length) {
    const auto& data = m_binary_data->get_data();
    std::vector<std::string> result;
    std::string current;

    for (uint8_t byte : data) {
        if (isprint(byte) {
            current += static_cast<char>(byte);
        } else {
            if (current.length() >= min_length) {
                result.push_back(current);
            }
            current.clear();
        }
    }

    if (current.length() >= min_length) {
        result.push_back(current);
    }

    return result;
}

std::vector<std::string> StringExtractor::extract_unicode_strings(size_t min_length) {
    const auto& data = m_binary_data->get_data();
    std::vector<std::string> result;
    std::string current;
    bool in_unicode = false;
    size_t unicode_pos = 0;

    for (size_t i = 0; i < data.size(); ++i) {
        if (i + 1 < data.size() && data[i] == 0 && isprint(data[i + 1])) {
            // Potential UTF-16LE
            if (!in_unicode) {
                in_unicode = true;
                unicode_pos = i;
                current.clear();
            }
            
            if (i % 2 == unicode_pos % 2) {
                current += static_cast<char>(data[i + 1]);
            }
            ++i; // Skip next byte
        } else {
            if (in_unicode && current.length() >= min_length) {
                result.push_back(current);
            }
            in_unicode = false;
            current.clear();
        }
    }

    if (in_unicode && current.length() >= min_length) {
        result.push_back(current);
    }

    return result;
}

} // namespace RECLI