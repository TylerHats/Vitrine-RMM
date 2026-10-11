#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "==========================================="
echo "       Vitrine RMM Uninstallation Script   "
echo "==========================================="
echo "This script will cleanly remove Vitrine RMM from your system."
echo ""

# 1. Stop and remove systemd service if exists
if [ -f /etc/systemd/system/vitrine-rmm.service ]; then
    echo "--> Detected vitrine-rmm systemd service. Removing (sudo required)..."
    sudo systemctl stop vitrine-rmm.service || true
    sudo systemctl disable vitrine-rmm.service || true
    sudo rm -f /etc/systemd/system/vitrine-rmm.service
    sudo systemctl daemon-reload
    echo "--> Systemd service successfully removed."
fi

# 2. Clean build artifacts and dist bundles
echo "--> Cleaning build artifacts..."
rm -rf frontend/dist || true
rm -rf backend/dist || true

# 3. Optional database wipe
read -p "Would you like to delete the database and persistent vaults? This will ERASE all managed devices, policies, and LAPS credentials! (y/n): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "--> Wiping database and vault data..."
    rm -rf data/ || true
    rm -rf certs/ || true
    echo "--> Database and local vaults deleted."
else
    echo "--> Keeping data/ directory for future upgrades."
fi

echo ""
echo "==========================================="
echo "Vitrine RMM has been cleanly uninstalled."
echo "==========================================="
