#pragma once

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include "utils.h"

namespace RECLI {

class CommandLineInterface {
public:
    CommandLineInterface(int argc, char* argv[]);
    int run();

private:
    void setup_commands();
    void parse_arguments();
    void show_help() const;
    void show_version() const;

    std::vector<std::string> m_args;
    std::map<std::string, std::function<int()>> m_commands;
    std::map<std::string, std::string> m_options;
    std::unique_ptr<BinaryData> m_binary_data;
};

} // namespace RECLI