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

# Ensure no standalone Vitrine Node.js backend process is still writing to data/vitrine.db
if command -v pgrep &> /dev/null; then
    RUNNING_PIDS="$(pgrep -f "$PROJ_ROOT/backend/(dist/server\.js|src/server\.ts)" 2>/dev/null || true)"
    if [ -n "$RUNNING_PIDS" ]; then
        echo "--> Stopping active Vitrine RMM Node.js server process(es) ($RUNNING_PIDS) before touching data/..."
        for pid in $RUNNING_PIDS; do
            kill -TERM "$pid" 2>/dev/null || sudo kill -TERM "$pid" 2>/dev/null || true
        done
        sleep 2
    fi
fi

if command -v systemctl &> /dev/null; then
    UNIT_FILES="$(systemctl list-unit-files --no-pager 2>/dev/null || true)"
    if [[ "$UNIT_FILES" == *"meshcentral.service"* ]]; then
        echo "--> Verified: Neighboring meshcentral.service remains intact and untouched."
    fi
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
        TARGET_USER="${SUDO_USER:-$(id -un)}"
        TARGET_HOME="$(getent passwd "$TARGET_USER" 2>/dev/null | cut -d: -f6 || true)"
        if [ -z "$TARGET_HOME" ] || [ ! -d "$TARGET_HOME" ]; then
            TARGET_HOME="${HOME:-/tmp}"
        fi
        if [ "$(id -u)" -ne 0 ] && [ ! -w "$TARGET_HOME" ]; then
            TARGET_HOME="${HOME:-/tmp}"
        fi
        if [ ! -d "$TARGET_HOME" ] || ( [ "$(id -u)" -ne 0 ] && [ ! -w "$TARGET_HOME" ] ); then
            TARGET_HOME="/tmp"
        fi
        FINAL_BAK="${TARGET_HOME}/vitrine-rmm-final-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
        ARCHIVE_ITEMS=("data")
        if [ -d "$PROJ_ROOT/branding" ]; then
            ARCHIVE_ITEMS+=("branding")
        fi
        (umask 077 && tar -czf "$FINAL_BAK" -C "$PROJ_ROOT" "${ARCHIVE_ITEMS[@]}")
        chmod 600 "$FINAL_BAK"
        if [ "$(id -u)" -eq 0 ] && [ "$TARGET_USER" != "root" ]; then
            chown "$TARGET_USER" "$FINAL_BAK" || true
        fi
        echo "--> Saved restricted (0600) final backup archive to: $FINAL_BAK"
    fi

    if [ -t 0 ]; then
        read -p "Would you like to delete Vitrine's local data/ directory (vitrine.db & LAPS vault)? Neighboring MeshCentral data will NOT be affected. (y/n): " -n 1 -r
        echo ""
        DELETE_DATA="$REPLY"
    fi

    if [[ "$DELETE_DATA" =~ ^[Yy]$ ]]; then
        if [[ -n "$PROJ_ROOT" && "$PROJ_ROOT" != "/" && -f "$PROJ_ROOT/uninstall.sh" ]]; then
            echo "--> Removing Vitrine data/ directory..."
            rm -rf "$PROJ_ROOT/data"
            echo "--> Vitrine database and local vaults deleted."
        fi
    else
        echo "--> Keeping data/ directory for future upgrades or restores."
    fi
fi

echo ""
echo "=========================================================="
echo "Vitrine RMM has been cleanly uninstalled."
echo "All neighboring MeshCentral 2 services and files remain intact."
echo "=========================================================="
