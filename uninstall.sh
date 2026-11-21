#!/usr/bin/env bash

# Exit immediately on command failure or unset variable errors
set -euo pipefail

PROJ_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJ_ROOT"

LOCAL_MS2_FOUND=0
LOCAL_MS2_DIR=""
LOCAL_MS2_SERVICE=""

detect_local_meshcentral() {
    LOCAL_MS2_FOUND=0
    LOCAL_MS2_DIR=""
    LOCAL_MS2_SERVICE=""

    local canon_proj
    canon_proj="$(cd "$PROJ_ROOT" 2>/dev/null && pwd -P || printf '%s' "$PROJ_ROOT")"

    if command -v systemctl &> /dev/null; then
        local unit_files line unit_name unit_cfg wd
        unit_files="$(systemctl list-unit-files --no-pager 2>/dev/null || true)"
        while IFS= read -r line; do
            unit_name="${line%%[[:space:]]*}"
            if [[ -n "$unit_name" && "$unit_name" != "vitrine-rmm.service" && "$unit_name" == *meshcentral*.service ]]; then
                LOCAL_MS2_FOUND=1
                LOCAL_MS2_SERVICE="$unit_name"
                unit_cfg="$(systemctl cat "$unit_name" 2>/dev/null || true)"
                wd="$(printf '%s\n' "$unit_cfg" | sed -n 's/^WorkingDirectory=//p' | head -n 1 | sed 's/^"//; s/"$//')"
                if [ -n "$wd" ] && [ -d "$wd" ]; then
                    LOCAL_MS2_DIR="$wd"
                fi
                break
            fi
        done <<< "$unit_files"
    fi

    if [ "$LOCAL_MS2_FOUND" -eq 0 ] && command -v pgrep &> /dev/null; then
        local proc_lines pline
        proc_lines="$(pgrep -af "node.*meshcentral" 2>/dev/null || true)"
        while IFS= read -r pline; do
            if [ -n "$pline" ] && [[ "$pline" != *"$canon_proj"* ]] && [[ "$pline" != *"dev-meshcentral"* ]]; then
                LOCAL_MS2_FOUND=1
                break
            fi
        done <<< "$proc_lines"
    fi

    if [ "$LOCAL_MS2_FOUND" -eq 0 ] || [ -z "$LOCAL_MS2_DIR" ]; then
        local candidates=(
            "/opt/meshcentral"
            "/var/lib/meshcentral"
            "/srv/meshcentral"
            "/usr/local/meshcentral"
            "/root/meshcentral"
            "/root"
        )
        local hdir
        for hdir in /home/*; do
            if [ -d "$hdir" ]; then
                candidates+=("$hdir" "$hdir/meshcentral")
            fi
        done

        local cand resolved_cand
        for cand in "${candidates[@]}"; do
            [ -d "$cand" ] || continue
            resolved_cand="$(cd "$cand" 2>/dev/null && pwd -P || true)"
            [ -n "$resolved_cand" ] || continue
            if [ "$resolved_cand" = "$canon_proj" ] || [[ "$resolved_cand" == "$canon_proj/"* ]]; then
                continue
            fi
            if [ -f "$resolved_cand/node_modules/meshcentral/meshctrl.js" ] || [ -f "$resolved_cand/meshcentral-data/config.json" ]; then
                LOCAL_MS2_FOUND=1
                if [ -z "$LOCAL_MS2_DIR" ]; then
                    LOCAL_MS2_DIR="$resolved_cand"
                fi
                break
            fi
        done
    fi
}

detect_local_meshcentral

echo "=========================================================="
echo "             Vitrine RMM Uninstallation Script            "
echo "=========================================================="
echo "This script will cleanly remove Vitrine RMM from your system."
if [ "$LOCAL_MS2_FOUND" -eq 1 ]; then
    echo "SAFETY GUARANTEE: Local MeshCentral 2 services (${LOCAL_MS2_DIR:-$LOCAL_MS2_SERVICE}),"
    echo "databases, certificates, and agents will NOT be touched."
fi
echo "=========================================================="
echo ""

run_priv() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

# 1. Stop and remove ONLY vitrine-rmm.service (never touch meshcentral.service)
if [ -f /etc/systemd/system/vitrine-rmm.service ]; then
    echo "--> Detected vitrine-rmm.service. Stopping and removing..."
    run_priv systemctl stop vitrine-rmm.service || true
    run_priv systemctl disable vitrine-rmm.service || true
    run_priv rm -f /etc/systemd/system/vitrine-rmm.service
    run_priv systemctl daemon-reload
    echo "--> vitrine-rmm systemd service removed."
fi

# Ensure no standalone Vitrine Node.js backend process is still writing to data/vitrine.db
if command -v pgrep &> /dev/null; then
    RUNNING_PIDS="$(pgrep -f "$PROJ_ROOT/backend/(dist/server\.js|src/server\.ts)" 2>/dev/null || true)"
    if [ -n "$RUNNING_PIDS" ]; then
        echo "--> Stopping active Vitrine RMM Node.js server process(es) ($RUNNING_PIDS) before touching data/..."
        for pid in $RUNNING_PIDS; do
            kill -TERM "$pid" 2>/dev/null || run_priv kill -TERM "$pid" 2>/dev/null || true
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

# 2. Clean Vitrine build artifacts, dist bundles, and workspace node_modules
echo "--> Cleaning Vitrine build artifacts and dependencies..."
rm -rf "$PROJ_ROOT/frontend/dist" "$PROJ_ROOT/backend/dist" || true
rm -rf "$PROJ_ROOT/node_modules" "$PROJ_ROOT/backend/node_modules" "$PROJ_ROOT/frontend/node_modules" || true

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

# 3. Optional pre-uninstall backup export & database/branding wipe
if [ -d "$PROJ_ROOT/data" ] || [ -d "$PROJ_ROOT/branding" ]; then
    EXPORT_BAK="n"
    DELETE_DATA="n"

    if [ -t 0 ]; then
        read -p "Would you like to export a final backup archive before deciding on data removal? (y/n): " -n 1 -r
        echo ""
        EXPORT_BAK="$REPLY"
    fi

    if [[ "$EXPORT_BAK" =~ ^[Yy]$ ]]; then
        FINAL_BAK="${TARGET_HOME}/vitrine-rmm-final-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
        ARCHIVE_ITEMS=()
        if [ -d "$PROJ_ROOT/data" ]; then
            ARCHIVE_ITEMS+=("data")
        fi
        if [ -d "$PROJ_ROOT/branding" ]; then
            ARCHIVE_ITEMS+=("branding")
        fi
        if [ "${#ARCHIVE_ITEMS[@]}" -gt 0 ]; then
            (umask 077 && tar -czf "$FINAL_BAK" -C "$PROJ_ROOT" "${ARCHIVE_ITEMS[@]}")
            chmod 600 "$FINAL_BAK"
            if [ "$(id -u)" -eq 0 ] && [ "$TARGET_USER" != "root" ]; then
                chown "$TARGET_USER" "$FINAL_BAK" || true
            fi
            echo "--> Saved restricted (0600) final backup archive to: $FINAL_BAK"
        fi
    fi

    if [ -t 0 ]; then
        if [ "$LOCAL_MS2_FOUND" -eq 1 ]; then
            read -p "Would you like to delete Vitrine's local data/ and branding/ directories (vitrine.db, LAPS vault & uploaded logos)? Local MeshCentral data will NOT be affected. (y/n): " -n 1 -r
        else
            read -p "Would you like to delete Vitrine's local data/ and branding/ directories (vitrine.db, LAPS vault & uploaded logos)? (y/n): " -n 1 -r
        fi
        echo ""
        DELETE_DATA="$REPLY"
    fi

    if [[ "$DELETE_DATA" =~ ^[Yy]$ ]]; then
        if [[ -n "$PROJ_ROOT" && "$PROJ_ROOT" != "/" && -f "$PROJ_ROOT/uninstall.sh" ]]; then
            echo "--> Removing Vitrine data/ and branding/ directories..."
            rm -rf "$PROJ_ROOT/data" "$PROJ_ROOT/branding" "$PROJ_ROOT/dev-meshcentral" 2>/dev/null || run_priv rm -rf "$PROJ_ROOT/data" "$PROJ_ROOT/branding" "$PROJ_ROOT/dev-meshcentral"
            echo "--> Vitrine database, local vaults, and branding assets deleted."
        fi
    else
        echo "--> Keeping data/ directory for future upgrades or restores."
    fi
fi

# 4. Optional full installation directory removal (only when local data/ has been removed or absent)
REMOVE_DIR="n"
CANON_ROOT=""
SAFE_TO_REMOVE_DIR=0

if [ ! -d "$PROJ_ROOT/data" ]; then
    CANON_ROOT="$(cd "$PROJ_ROOT" 2>/dev/null && pwd -P || true)"
    SAFE_TO_REMOVE_DIR=1

    if [ -z "$CANON_ROOT" ] || [ "$CANON_ROOT" = "/" ]; then
        SAFE_TO_REMOVE_DIR=0
    fi
    if [ -n "${HOME:-}" ] && [ "$CANON_ROOT" = "${HOME%/}" ]; then
        SAFE_TO_REMOVE_DIR=0
    fi
    if [ -n "$TARGET_HOME" ] && [ "$CANON_ROOT" = "${TARGET_HOME%/}" ]; then
        SAFE_TO_REMOVE_DIR=0
    fi
    case "$CANON_ROOT" in
        /root|/home|/opt|/usr|/var|/etc|/tmp|/srv|/opt/meshcentral|/opt/meshcentral/*)
            SAFE_TO_REMOVE_DIR=0
            ;;
    esac
    if [ ! -f "$CANON_ROOT/uninstall.sh" ] || [ ! -f "$CANON_ROOT/package.json" ] || [ ! -d "$CANON_ROOT/backend" ] || [ ! -d "$CANON_ROOT/frontend" ]; then
        SAFE_TO_REMOVE_DIR=0
    elif ! grep -q '"name":[[:space:]]*"vitrine-rmm"' "$CANON_ROOT/package.json" 2>/dev/null; then
        SAFE_TO_REMOVE_DIR=0
    fi

    if [ "$SAFE_TO_REMOVE_DIR" -eq 1 ] && [ -t 0 ]; then
        echo ""
        read -p "Would you like to completely remove the Vitrine RMM installation folder ($CANON_ROOT)? (y/n): " -n 1 -r
        echo ""
        REMOVE_DIR="$REPLY"
    fi
fi

{
    if [[ "$REMOVE_DIR" =~ ^[Yy]$ ]] && [ "$SAFE_TO_REMOVE_DIR" -eq 1 ] && [ -n "$CANON_ROOT" ]; then
        cd /
        echo "--> Removing Vitrine RMM installation folder ($CANON_ROOT)..."
        rm -rf "$CANON_ROOT" 2>/dev/null || run_priv rm -rf "$CANON_ROOT"
        echo "--> Completely removed $CANON_ROOT."
        echo ""
        echo "=========================================================="
        echo "Vitrine RMM has been cleanly uninstalled."
        if [ "$LOCAL_MS2_FOUND" -eq 1 ]; then
            echo "All local MeshCentral 2 services and files remain intact."
        fi
        echo "Note: If your terminal was inside that folder, run 'cd ~' to refresh your working directory."
        echo "=========================================================="
    else
        echo ""
        echo "=========================================================="
        echo "Vitrine RMM has been cleanly uninstalled."
        if [ "$LOCAL_MS2_FOUND" -eq 1 ]; then
            echo "All local MeshCentral 2 services and files remain intact."
        fi
        echo "=========================================================="
    fi
    exit 0
}
