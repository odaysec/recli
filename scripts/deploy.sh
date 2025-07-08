#!/bin/bash

# Create build directory
mkdir -p build
cd build

# Run CMake and build
cmake ..
make -j$(nproc)

# Install
sudo make install

echo "RECLI installed successfully"