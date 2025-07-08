#!/bin/bash

# Install system dependencies
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    git \
    pkg-config \
    libcapstone-dev \
    yara \
    python3-pip

# Install LIEF
pip3 install lief

# Clone and build Capstone
git clone https://github.com/aquynh/capstone.git
cd capstone
mkdir build
cd build
cmake ..
make -j$(nproc)
sudo make install
cd ../..

# Clone and build YARA
git clone --recursive https://github.com/VirusTotal/yara.git
cd yara
./bootstrap.sh
./configure --enable-magic --enable-dotnet
make -j$(nproc)
sudo make install
cd ..

# Update linker cache
sudo ldconfig