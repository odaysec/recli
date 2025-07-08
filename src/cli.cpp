#include "cli.h"
#include "string_extractor.h"
#include "offset_scanner.h"
#include "api_scanner.h"
#include "decompiler.h"
#include "memory_mapper.h"
#include "hook_detector.h"
#include "analyzer.h"
#include "patcher.h"
#include "scanner.h"
#include "dumper.h"

namespace RECLI {

CommandLineInterface::CommandLineInterface(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        m_args.emplace_back(argv[i]);
    }
    setup_commands();
}

void CommandLineInterface::setup_commands() {
    m_commands = {
        {"strings", [this]() {
            StringExtractor extractor(m_binary_data.get());
            return extractor.run(m_options);
        }},
        {"offset", [this]() {
            OffsetScanner scanner(m_binary_data.get());
            return scanner.run(m_options);
        }},
        {"api", [this]() {
            APIScanner scanner(m_binary_data.get());
            return scanner.run(m_options);
        }},
        {"decompile", [this]() {
            Decompiler decompiler(m_binary_data.get());
            return decompiler.run(m_options);
        }},
        {"memory", [this]() {
            MemoryMapper mapper(m_binary_data.get());
            return mapper.run(m_options);
        }},
        {"hook", [this]() {
            HookDetector detector(m_binary_data.get());
            return detector.run(m_options);
        }},
        {"analyze", [this]() {
            StaticAnalyzer analyzer(m_binary_data.get());
            return analyzer.run(m_options);
        }},
        {"patch", [this]() {
            Patcher patcher(m_binary_data.get());
            return patcher.run(m_options);
        }},
        {"scan", [this]() {
            YARAScanner scanner(m_binary_data.get());
            return scanner.run(m_options);
        }},
        {"dump", [this]() {
            Dumper dumper(m_binary_data.get());
            return dumper.run(m_options);
        }}
    };
}

int CommandLineInterface::run() {
    if (m_args.empty() || m_args[0] == "--help" || m_args[0] == "-h") {
        show_help();
        return EXIT_SUCCESS;
    }

    if (m_args[0] == "--version" || m_args[0] == "-v") {
        show_version();
        return EXIT_SUCCESS;
    }

    parse_arguments();

    if (m_options.find("input") == m_options.end()) {
        std::cerr << "Error: No input file specified" << std::endl;
        return EXIT_FAILURE;
    }

    try {
        m_binary_data = std::make_unique<BinaryData>(m_options["input"]);
    } catch (const std::exception& e) {
        std::cerr << "Error loading binary: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    auto cmd = m_args[0];
    if (m_commands.find(cmd) != m_commands.end()) {
        return m_commands[cmd]();
    }

    std::cerr << "Error: Unknown command '" << cmd << "'" << std::endl;
    show_help();
    return EXIT_FAILURE;
}

void CommandLineInterface::parse_arguments() {
    for (size_t i = 1; i < m_args.size(); ++i) {
        if (m_args[i].substr(0, 2) == "--") {
            auto eq_pos = m_args[i].find('=');
            if (eq_pos != std::string::npos) {
                auto key = m_args[i].substr(2, eq_pos - 2);
                auto value = m_args[i].substr(eq_pos + 1);
                m_options[key] = value;
            } else {
                m_options[m_args[i].substr(2)] = "";
            }
        } else if (m_args[i][0] == '-') {
            if (i + 1 < m_args.size() && m_args[i + 1][0] != '-') {
                m_options[m_args[i].substr(1)] = m_args[i + 1];
                ++i;
            } else {
                m_options[m_args[i].substr(1)] = "";
            }
        } else if (m_options.find("input") == m_options.end()) {
            m_options["input"] = m_args[i];
        }
    }
}

void CommandLineInterface::show_help() const {
    std::cout << "RECLI - Reverse Engineering Command Line Interface\n\n"
              << "Usage: recli <command> [options] <input_file>\n\n"
              << "Commands:\n"
              << "  strings      Extract strings from binary\n"
              << "  offset       Scan for important offsets\n"
              << "  api          Analyze API calls\n"
              << "  decompile    Decompile binary to pseudo-C\n"
              << "  memory       Map memory sections\n"
              << "  hook         Detect inline hooks\n"
              << "  analyze      Static analysis combining multiple techniques\n"
              << "  patch        Patch binary at specific offsets\n"
              << "  scan         Scan with YARA rules\n"
              << "  dump         Dump memory regions or functions\n\n"
              << "Options:\n"
              << "  -o, --output    Output file\n"
              << "  -f, --format    Output format (json, text, md)\n"
              << "  -v, --verbose   Verbose output\n"
              << "  -h, --help      Show this help message\n";
}

void CommandLineInterface::show_version() const {
    std::cout << "RECLI version 1.0.0\n";
}

} // namespace RECLI