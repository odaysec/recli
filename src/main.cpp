#include "cli.h"
#include <iostream>
#include <memory>

int main(int argc, char* argv[]) {
    try {
        RECLI::CommandLineInterface cli(argc, argv);
        return cli.run();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}