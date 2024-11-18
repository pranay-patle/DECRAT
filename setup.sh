#!/bin/bash

echo "Setting up the RAT detection framework..."

# Update and install dependencies
echo "Updating package list..."
sudo apt update -y
sudo apt upgrade -y

# Check for Python3 and pip3
echo "Checking for Python3 and pip3..."
sudo apt install -y python3 python3-pip

# Check for TShark (Wireshark CLI)
echo "Checking for TShark..."
sudo apt install -y tshark

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt --user

# Create necessary directories
echo "Creating necessary directories..."
mkdir -p captures
sudo chmod -R 777 captures # Set permissions for the captures folder

# Set capabilities for dumpcap
echo "Setting capabilities for dumpcap..."
sudo setcap cap_net_raw,cap_net_admin=eip $(which dumpcap)

echo "Setup completed successfully!"
