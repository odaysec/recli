#pragma once

#include "utils.h"
#include <string>
#include <vector>

namespace RECLI {

class Decompiler {
public:
    explicit Decompiler(BinaryData* binary_data);
    int run(const std::map<std::string, std::string>& options);

private:
    std::string decompile_with_ghidra();
    
    BinaryData* m_binary_data;
};

} // namespace RECLI

// src/decompiler.cpp
#include "decompiler.h"
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <filesystem>

namespace RECLI {

Decompiler::Decompiler(BinaryData* binary_data) 
    : m_binary_data(binary_data) {}

int Decompiler::run(const std::map<std::string, std::string>& options) {
    try {
        std::string decompiled_code = decompile_with_ghidra();

        OutputFormat format = OutputFormat::TEXT;
        if (options.find("format") != options.end()) {
            format = parse_format(options.at("format"));
        }

        OutputFormatter formatter(format);
        std::string output = formatter.format(decompiled_code);

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

std::string Decompiler::decompile_with_ghidra() {
    namespace fs = std::filesystem;
    
    // Create temp directory
    std::string temp_dir = fs::temp_directory_path().string() + "/recli_ghidra";
    if (!fs::exists(temp_dir)) {
        fs::create_directory(temp_dir);
    }

    std::string input_path = m_binary_data->get_file_path();
    std::string output_path = temp_dir + "/decompiled.c";
    
    // Check if Ghidra is installed
    const char* ghidra_path = std::getenv("GHIDRA_INSTALL_DIR");
    if (!ghidra_path) {
        throw std::runtime_error("GHIDRA_INSTALL_DIR environment variable not set");
    }

    std::string analyzeHeadless = std::string(ghidra_path) + "/support/analyzeHeadless";
    
    // Build command
    std::ostringstream cmd;
    cmd << analyzeHeadless << " " << temp_dir << " TempProject -import " << input_path
        << " -postScript GhidraDecompiler.java " << output_path << " -deleteProject";
    
    // Execute command
    int result = std::system(cmd.str().c_str());
    if (result != 0) {
        throw std::runtime_error("Failed to execute Ghidra decompiler");
    }
    
    // Read output
    if (!fs::exists(output_path)) {
        throw std::runtime_error("Ghidra decompilation failed - no output file");
    }
    
    std::ifstream file(output_path);
    std::stringstream buffer;
    buffer << file.rdbuf();
    
    // Clean up
    fs::remove_all(temp_dir);
    
    return buffer.str();
}

} // namespace RECLI