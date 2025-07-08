#pragma once

#include "utils.h"
#include <string>
#include <vector>
#include <map>

namespace RECLI {

class YARAScanner {
public:
    explicit YARAScanner(BinaryData* binary_data);
    int run(const std::map<std::string, std::string>& options);

private:
    std::map<std::string, std::vector<std::string>> scan_with_yara(const std::string& rules_path);
    
    BinaryData* m_binary_data;
};

} // namespace RECLI

// src/scanner.cpp
#include "scanner.h"
#include <yara.h>
#include <vector>
#include <stdexcept>

namespace RECLI {

namespace {

int yara_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    auto* results = static_cast<std::map<std::string, std::vector<std::string>>*>(user_data);
    
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = static_cast<YR_RULE*>(message_data);
        std::string rule_name = rule->identifier;
        
        YR_STRING* string = nullptr;
        yr_rule_strings_foreach(rule, string) {
            YR_MATCH* match = nullptr;
            yr_string_matches_foreach(string, match) {
                std::ostringstream oss;
                oss << "0x" << std::hex << match->offset << ":" << string->identifier;
                (*results)[rule_name].push_back(oss.str());
            }
        }
    }
    
    return CALLBACK_CONTINUE;
}

} // anonymous namespace

YARAScanner::YARAScanner(BinaryData* binary_data) 
    : m_binary_data(binary_data) {
    yr_initialize();
}

int YARAScanner::run(const std::map<std::string, std::string>& options) {
    try {
        if (options.find("rules") == options.end()) {
            throw std::runtime_error("No YARA rules file specified");
        }
        
        auto scan_results = scan_with_yara(options.at("rules"));

        OutputFormat format = OutputFormat::TEXT;
        if (options.find("format") != options.end()) {
            format = parse_format(options.at("format"));
        }

        OutputFormatter formatter(format);
        std::string output = formatter.format(scan_results);

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

std::map<std::string, std::vector<std::string>> YARAScanner::scan_with_yara(const std::string& rules_path) {
    YR_COMPILER* compiler = nullptr;
    YR_RULES* rules = nullptr;
    
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        throw std::runtime_error("Failed to create YARA compiler");
    }
    
    FILE* rules_file = fopen(rules_path.c_str(), "r");
    if (!rules_file) {
        yr_compiler_destroy(compiler);
        throw std::runtime_error("Failed to open YARA rules file");
    }
    
    int errors = yr_compiler_add_file(compiler, rules_file, nullptr, rules_path.c_str());
    fclose(rules_file);
    
    if (errors > 0) {
        yr_compiler_destroy(compiler);
        throw std::runtime_error("YARA rules compilation failed");
    }
    
    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
        yr_compiler_destroy(compiler);
        throw std::runtime_error("Failed to get YARA rules");
    }
    
    std::map<std::string, std::vector<std::string>> results;
    const auto& data = m_binary_data->get_data();
    
    if (yr_rules_scan_mem(rules, 
                         data.data(), 
                         data.size(), 
                         0, 
                         yara_callback, 
                         &results, 
                         0) != ERROR_SUCCESS) {
        yr_rules_destroy(rules);
        yr_compiler_destroy(compiler);
        throw std::runtime_error("YARA scan failed");
    }
    
    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    
    return results;
}

} // namespace RECLI