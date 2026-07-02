#!/bin/bash
# -----------------------------------------------------------------------------
# Automated Setup & Launch Script for Fresh Debian/Ubuntu Linux Systems
# -----------------------------------------------------------------------------

set -e # Exit immediately on error

echo "=== [1/4] Updating Package Index ==="
sudo apt-get update -y

echo "=== [2/4] Installing Node.js and NPM ==="
# Install curl if not present
sudo apt-get install -y curl

# Fetch and configure NodeSource repository for modern Node.js version (LTS)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify installation
echo "Node.js version: $(node -v)"
echo "NPM version: $(npm -v)"

echo "=== [3/4] Installing Node Modules ==="
npm install

echo "=== [4/4] Starting the Server ==="
echo "Launch successful! Connect targets on your LAN."
node server.js
