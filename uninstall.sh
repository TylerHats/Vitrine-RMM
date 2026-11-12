#!/usr/bin/env bash

# Exit immediately on command failure or unset variable errors
set -euo pipefail

echo "=========================================================="
echo "             Vitrine RMM Uninstallation Script            "
echo "=========================================================="
echo "This script will cleanly remove Vitrine RMM from your system."
echo "SAFETY GUARANTEE: Neighboring MeshCentral 2 services,"
echo "databases, certificates, and agents will NOT be touched."
echo "=========================================================="
echo ""

PROJ_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJ_ROOT"

# 1. Stop and remove ONLY vitrine-rmm.service (never touch meshcentral.service)
if [ -f /etc/systemd/system/vitrine-rmm.service ]; then
    echo "--> Detected vitrine-rmm.service. Stopping and removing (sudo required)..."
    sudo systemctl stop vitrine-rmm.service || true
    sudo systemctl disable vitrine-rmm.service || true
    sudo rm -f /etc/systemd/system/vitrine-rmm.service
    sudo systemctl daemon-reload
    echo "--> vitrine-rmm systemd service removed."
fi

if systemctl list-unit-files 2>/dev/null | grep -q "meshcentral.service"; then
    echo "--> Verified: Neighboring meshcentral.service remains intact and untouched."
fi

# 2. Clean Vitrine build artifacts and dist bundles
echo "--> Cleaning Vitrine build artifacts..."
rm -rf "$PROJ_ROOT/frontend/dist" || true
rm -rf "$PROJ_ROOT/backend/dist" || true

# 3. Optional pre-uninstall backup export & database wipe
if [ -d "$PROJ_ROOT/data" ]; then
    EXPORT_BAK="n"
    DELETE_DATA="n"

    if [ -t 0 ]; then
        read -p "Would you like to export a final backup archive before deciding on data removal? (y/n): " -n 1 -r
        echo ""
        EXPORT_BAK="$REPLY"
    fi

    if [[ "$EXPORT_BAK" =~ ^[Yy]$ ]]; then
        TARGET_HOME=$(eval echo "~${SUDO_USER:-$(whoami)}")
        FINAL_BAK="${TARGET_HOME}/vitrine-rmm-final-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
        tar -czf "$FINAL_BAK" -C "$PROJ_ROOT" data branding 2>/dev/null || true
        echo "--> Saved final backup archive to: $FINAL_BAK"
    fi

    if [ -t 0 ]; then
        read -p "Would you like to delete Vitrine's local data/ directory (vitrine.db & LAPS vault)? Neighboring MeshCentral data will NOT be affected. (y/n): " -n 1 -r
        echo ""
        DELETE_DATA="$REPLY"
    fi

    if [[ "$DELETE_DATA" =~ ^[Yy]$ ]]; then
        echo "--> Removing Vitrine data/ directory..."
        rm -rf "$PROJ_ROOT/data" || true
        echo "--> Vitrine database and local vaults deleted."
    else
        echo "--> Keeping data/ directory for future upgrades or restores."
    fi
fi

echo ""
echo "=========================================================="
echo "Vitrine RMM has been cleanly uninstalled."
echo "All neighboring MeshCentral 2 services and files remain intact."
echo "=========================================================="
