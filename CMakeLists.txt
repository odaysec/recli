cmake_minimum_required(VERSION 3.15)
project(recli)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find dependencies
find_package(Capstone REQUIRED)
find_package(LIEF REQUIRED)
find_package(Threads REQUIRED)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/thirdparty
    ${Capstone_INCLUDE_DIRS}
    ${LIEF_INCLUDE_DIRS}
)

# Source files
file(GLOB_RECURSE SOURCES "src/*.cpp")

# Executable
add_executable(recli ${SOURCES})

# Link libraries
target_link_libraries(recli
    PRIVATE
    Capstone::capstone
    LIEF::LIEF
    ${CMAKE_THREAD_LIBS_INIT}
)

# Install target
install(TARGETS recli DESTINATION bin)