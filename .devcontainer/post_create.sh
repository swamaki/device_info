#!/usr/bin/env bash
set -e

echo "Installing ZSH Autosuggestions..."
sh .devcontainer/install_autosuggestions.sh

echo "Installing Asyncio netdev..."
sh .devcontainer/install_netdev.sh

echo "Upgrading pip..."
pip install --upgrade pip

echo "Installing other python dependencies..."
pip install -r .devcontainer/requirements.txt 

echo "Setting up environment..."
sudo apt-get update
sudo apt-get install -y git
sudo apt-get install -y curl
sudo apt-get install -y iputils-ping
sudo apt-get install -y fping
# sudo apt-get -y clean && rm -rf /var/lib/apt/lists/*

echo "Loading ENV variables..."
source .devcontainer/.env
echo "✅ loaded .env"

