#!/usr/bin/env bash

# Exit immediately on command failure or unset variable errors
set -euo pipefail

PROJ_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJ_ROOT"

run_priv() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

# 1. Check Node.js version (Node.js 20+ required for Fastify 5 & better-sqlite3)
if ! command -v node &> /dev/null; then
    echo "Error: node is not installed. Please install Node.js 20 LTS or higher."
    exit 1
fi

APP_VERSION="$(node -p "try { require('./package.json').version || require('./backend/package.json').version } catch { '2.6.1' }" 2>/dev/null || echo "2.6.1")"

LOCAL_MS2_FOUND=0
LOCAL_MS2_DIR=""
LOCAL_MS2_SERVICE=""

# Strictly read-only detection of any local MeshCentral 2 instance on this host (never touches files outside $PROJ_ROOT)
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
echo "             Vitrine RMM Installation Script              "
echo "=========================================================="
echo "Modern, Glassmorphic Self-Hosted RMM (v${APP_VERSION})"
if [ "$LOCAL_MS2_FOUND" -eq 1 ]; then
    echo "Powered by MeshCentral 2 Remote Engine (Co-Existence Safe)"
else
    echo "Powered by MeshCentral 2 Remote Engine"
fi
echo "=========================================================="

NODE_VER=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VER" -lt 18 ]; then
    echo "Error: Node.js version must be 18+ (20/22 LTS recommended). Detected: $(node -v)"
    exit 1
elif [ "$NODE_VER" -lt 20 ]; then
    echo "    [i] Note: Node.js $(node -v) detected (Node.js 20/22 LTS is recommended for optimal performance)."
fi

echo "--> Node.js $(node -v) and npm $(npm -v) detected."

# 2. Host Environment & Local MeshCentral 2 Check (ZERO writes outside $PROJ_ROOT)
echo "--> Checking host environment for local MeshCentral 2 services (strictly read-only)..."
if [ "$LOCAL_MS2_FOUND" -eq 1 ]; then
    LOCAL_MS2_LOC="${LOCAL_MS2_DIR:-$LOCAL_MS2_SERVICE}"
    echo "    [✓] Detected local MeshCentral 2 installation (${LOCAL_MS2_LOC:-detected}) — running in isolated co-existence mode (never modified or stopped)."
else
    echo "    [i] Standalone host detected (no local MeshCentral 2 instance found on this host)."
fi

# 3. Port Collision Check (scan 8080..8090 SIGPIPE-safely)
is_port_in_use() {
    local check_port="$1"
    if command -v ss &> /dev/null; then
        local ss_out
        ss_out="$(ss -tuln 2>/dev/null || true)"
        if [[ "$ss_out" =~ :${check_port}([[:space:]]|$) ]]; then
            return 0
        fi
        return 1
    fi
    node -e "const net=require('net');const s=net.createServer();s.once('error',()=>process.exit(0));s.once('listening',()=>s.close(()=>process.exit(1)));s.listen(${check_port},'0.0.0.0');" 2>/dev/null
}

DEFAULT_PORT="${PORT:-}"
if [ -n "$DEFAULT_PORT" ]; then
    if is_port_in_use "$DEFAULT_PORT"; then
        echo "    [!] Requested PORT=${DEFAULT_PORT} is currently in use; scanning 8080..8090 for an open port..."
        DEFAULT_PORT=""
    else
        if [ "$LOCAL_MS2_FOUND" -eq 1 ]; then
            echo "    [✓] Port ${DEFAULT_PORT} is available and isolated from local MeshCentral ports."
        else
            echo "    [✓] Port ${DEFAULT_PORT} is available."
        fi
    fi
fi

if [ -z "$DEFAULT_PORT" ]; then
    for candidate_port in $(seq 8080 8090); do
        if ! is_port_in_use "$candidate_port"; then
            DEFAULT_PORT="$candidate_port"
            if [ "$candidate_port" -eq 8080 ]; then
                if [ "$LOCAL_MS2_FOUND" -eq 1 ]; then
                    echo "    [✓] Port ${DEFAULT_PORT} is available and isolated from local MeshCentral ports."
                else
                    echo "    [✓] Port ${DEFAULT_PORT} is available."
                fi
            else
                echo "    [✓] Auto-selected available non-conflicting port: ${DEFAULT_PORT}"
            fi
            break
        else
            echo "    [!] Port ${candidate_port} is currently in use."
        fi
    done
fi

if [ -z "$DEFAULT_PORT" ]; then
    echo "Error: All candidate ports 8080..8090 are currently in use. Set PORT=<free_port> and re-run install.sh."
    exit 1
fi

echo "--> Installing Root & Workspace dependencies..."
npm install --no-audit

echo "--> Installing Backend dependencies..."
cd "$PROJ_ROOT/backend"
npm install --no-audit

echo "--> Installing Frontend dependencies..."
cd "$PROJ_ROOT/frontend"
npm install --no-audit

echo "--> Building Production Frontend Assets (Vite)..."
npm run build

echo "--> Building Production Backend Service (TypeScript)..."
cd "$PROJ_ROOT/backend"
npm run build

cd "$PROJ_ROOT"

# 4. Ensure persistent isolated directories exist with hardened permissions
mkdir -p "$PROJ_ROOT/data"
mkdir -p "$PROJ_ROOT/data/backups"
mkdir -p "$PROJ_ROOT/data/packages"
mkdir -p "$PROJ_ROOT/data/signed-agents"
mkdir -p "$PROJ_ROOT/data/recordings"
mkdir -p "$PROJ_ROOT/branding"
chmod 700 "$PROJ_ROOT/data" "$PROJ_ROOT/data/backups" "$PROJ_ROOT/data/packages" "$PROJ_ROOT/data/recordings"
chmod 755 "$PROJ_ROOT/branding"

CURR_USER="${SUDO_USER:-$(whoami)}"
if [ "$(id -u)" -eq 0 ] && [ "$CURR_USER" != "root" ]; then
    chown -R "$CURR_USER" "$PROJ_ROOT/data" "$PROJ_ROOT/branding"
fi

# Record current git commit SHA and version metadata for the Self-Updater
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "release-build")
node -e "const fs=require('fs');fs.writeFileSync(process.argv[1],JSON.stringify({version:process.argv[2],commit:process.argv[3],installedAt:new Date().toISOString()}));" "$PROJ_ROOT/data/install-meta.json" "$APP_VERSION" "$GIT_COMMIT"

echo "--> Vitrine RMM v${APP_VERSION} compilation completed successfully!"

# 5. Systemd Service Creation Option (Strictly isolated to vitrine-rmm.service)
SETUP_SERVICE="n"
if [ -t 0 ]; then
    echo ""
    read -p "Would you like to configure Vitrine RMM as a systemd background service on port ${DEFAULT_PORT}? (y/n): " -n 1 -r
    echo ""
    SETUP_SERVICE="$REPLY"
fi

if [[ "$SETUP_SERVICE" =~ ^[Yy]$ ]]; then
    NODE_PATH="$(command -v node)"
    SERVER_PATH="$PROJ_ROOT/backend/dist/server.js"
    WORK_DIR="$PROJ_ROOT/backend"
    DATA_PATH="$PROJ_ROOT/data"
    BRAND_PATH="$PROJ_ROOT/branding"
    TMP_UNIT="$PROJ_ROOT/data/vitrine-rmm.service.tmp"

    # Systemd specifier/quoting helpers:
    # - WorkingDirectory= takes an unquoted path (even when containing spaces) with '%' escaped as '%%'.
    # - Environment="K=V" and quoted ExecStart= args escape '\', '"', and '%'.
    esc_systemd_raw() {
        local val="$1"
        printf '%s' "${val//%/%%}"
    }
    esc_systemd_quoted() {
        printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/%/%%/g'
    }
    quote_systemd_arg() {
        local val="$1"
        if [[ "$val" =~ [[:space:]\"\'\\] ]]; then
            printf '"%s"' "$(esc_systemd_quoted "$val")"
        else
            esc_systemd_raw "$val"
        fi
    }

    SERVICE_DESC="Vitrine RMM Fleet Orchestration Engine"
    if [ "$LOCAL_MS2_FOUND" -eq 1 ]; then
        SERVICE_DESC="Vitrine RMM Fleet Orchestration Engine (Isolated from MeshCentral)"
    fi

    echo "--> Generating isolated vitrine-rmm.service unit..."
    cat <<EOF > "$TMP_UNIT"
[Unit]
Description=$SERVICE_DESC
After=network.target

[Service]
Type=simple
User=$CURR_USER
WorkingDirectory=$(esc_systemd_raw "$WORK_DIR")
Environment="NODE_ENV=production"
Environment="PORT=$DEFAULT_PORT"
Environment="DATA_DIR=$(esc_systemd_quoted "$DATA_PATH")"
Environment="BRANDING_DIR=$(esc_systemd_quoted "$BRAND_PATH")"
ExecStart=$(quote_systemd_arg "$NODE_PATH") $(quote_systemd_arg "$SERVER_PATH")
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    echo "--> Installing service unit to systemd..."
    run_priv install -m 0644 "$TMP_UNIT" /etc/systemd/system/vitrine-rmm.service
    rm -f "$TMP_UNIT"
    run_priv systemctl daemon-reload
    run_priv systemctl enable vitrine-rmm.service
    run_priv systemctl restart vitrine-rmm.service

    if ! run_priv systemctl is-active --quiet vitrine-rmm.service; then
        echo "Error: vitrine-rmm.service failed to start. Check logs with: journalctl -u vitrine-rmm.service -n 50 --no-pager"
        exit 1
    fi

    echo "--> Vitrine RMM systemd service is active and enabled on boot!"
else
    echo "--> Skipping systemd service setup."
fi

echo ""
echo "=========================================================="
echo "Vitrine RMM v${APP_VERSION} setup completed successfully!"
if [ "$LOCAL_MS2_FOUND" -eq 1 ]; then
    echo "Local MeshCentral 2 installation was left untouched."
else
    echo "Connect your remote MeshCentral 2 server in Step 2 of the OOBE Wizard."
fi
echo ""
echo "Open http://localhost:${DEFAULT_PORT}/ in your browser to create"
echo "your initial Super Admin account and launch the OOBE Wizard."
echo "=========================================================="
