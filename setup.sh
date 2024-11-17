#!/bin/bash

# Update package list
echo "[INFO] Updating package list..."
sudo apt-get update

# Install tshark
echo "[INFO] Installing tshark..."
sudo apt-get install -y tshark

# Install Python packages
echo "[INFO] Installing Python packages..."
pip install -r requirements.txt

echo "[INFO] Setup completed successfully!"
