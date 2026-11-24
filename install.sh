#!/usr/bin/env bash

# Exit immediately on command failure or unset variable errors
set -euo pipefail

PROJ_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJ_ROOT"

TMP_UNIT=""
cleanup_tmp_unit() {
    if [ -n "${TMP_UNIT:-}" ] && [ -f "$TMP_UNIT" ]; then
        rm -f "$TMP_UNIT" || true
    fi
}
trap cleanup_tmp_unit EXIT

run_priv() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

# 1. Check Node.js version (Node.js 20+ required for Fastify 5 & better-sqlite3) and npm
if ! command -v node &> /dev/null; then
    echo "Error: node is not installed. Please install Node.js 20 LTS or higher."
    exit 1
fi
if ! command -v npm &> /dev/null; then
    echo "Error: npm is not installed. Please install npm alongside Node.js 20 LTS or higher."
    exit 1
fi

NODE_VER="$(node -v | sed 's/^v//' | cut -d'.' -f1)"
if ! [[ "$NODE_VER" =~ ^[0-9]+$ ]] || [ "$NODE_VER" -lt 20 ]; then
    echo "Error: Node.js version must be 20+ (20/22 LTS recommended). Detected: $(node -v)"
    exit 1
fi

CURR_USER="${SUDO_USER:-$(id -un)}"
CURR_GROUP="$(id -gn "$CURR_USER" 2>/dev/null || id -gn)"

run_as_owner() {
    if [ "$(id -u)" -eq 0 ] && [ "$CURR_USER" != "root" ]; then
        sudo -u "$CURR_USER" -H env "PATH=$PATH" "$@"
    else
        "$@"
    fi
}

APP_VERSION="$(node -p "try { require('./package.json').version || require('./backend/package.json').version } catch { '2.8.0' }" 2>/dev/null || echo "2.8.0")"

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
echo "--> Node.js $(node -v) and npm $(npm -v) detected."

# 2. Host Environment & Local MeshCentral 2 Check (ZERO writes outside $PROJ_ROOT)
echo "--> Checking host environment for local MeshCentral 2 services (strictly read-only)..."
if [ "$LOCAL_MS2_FOUND" -eq 1 ]; then
    LOCAL_MS2_LOC="${LOCAL_MS2_DIR:-$LOCAL_MS2_SERVICE}"
    echo "    [✓] Detected local MeshCentral 2 installation (${LOCAL_MS2_LOC:-detected}) — running in isolated co-existence mode (never modified or stopped)."
else
    echo "    [i] Standalone host detected (no local MeshCentral 2 instance found on this host)."
fi

# 3. Port Validation & Upgrade-Safe Collision Check (TCP only)
validate_port_int() {
    local p="$1"
    [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ]
}

is_port_in_use() {
    local check_port="$1"
    if command -v ss &> /dev/null; then
        local ss_out
        ss_out="$(ss -tln 2>/dev/null || true)"
        if [[ "$ss_out" =~ :${check_port}([[:space:]]|$) ]]; then
            return 0
        fi
        return 1
    fi
    node -e "const net=require('net');const port=Number(process.argv[1]);const s=net.createServer();s.once('error',()=>process.exit(0));s.once('listening',()=>s.close(()=>process.exit(1)));s.listen(port,'0.0.0.0');" "$check_port" 2>/dev/null
}

is_port_owned_by_vitrine() {
    local check_port="$1"
    local svc_pid=""
    if command -v systemctl &> /dev/null && systemctl is-active --quiet vitrine-rmm.service 2>/dev/null; then
        svc_pid="$(systemctl show -p MainPID --value vitrine-rmm.service 2>/dev/null || true)"
    fi
    if command -v ss &> /dev/null; then
        local ss_proc
        ss_proc="$(ss -tlnp 2>/dev/null | grep -E ":${check_port}([[:space:]]|$)" || true)"
        if [ -n "$svc_pid" ] && [ "$svc_pid" != "0" ] && [[ "$ss_proc" == *"pid=${svc_pid},"* ]]; then
            return 0
        fi
    fi
    if [ -n "$EXISTING_VITRINE_PORT" ] && [ "$check_port" = "$EXISTING_VITRINE_PORT" ] && command -v systemctl &> /dev/null; then
        if systemctl is-active --quiet vitrine-rmm.service 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

EXISTING_VITRINE_PORT=""
if [ -f /etc/systemd/system/vitrine-rmm.service ]; then
    EXISTING_VITRINE_PORT="$(sed -n 's/^Environment="PORT=\([0-9][0-9]*\)"/\1/p' /etc/systemd/system/vitrine-rmm.service | head -n 1 || true)"
fi
if [ -z "$EXISTING_VITRINE_PORT" ] && [ -f "$PROJ_ROOT/.env" ]; then
    EXISTING_VITRINE_PORT="$(sed -n 's/^[[:space:]]*PORT=[[:space:]]*"\{0,1\}\([0-9][0-9]*\)"\{0,1\}[[:space:]]*$/\1/p' "$PROJ_ROOT/.env" | head -n 1 || true)"
fi
if [ -n "$EXISTING_VITRINE_PORT" ] && ! validate_port_int "$EXISTING_VITRINE_PORT"; then
    EXISTING_VITRINE_PORT=""
fi

DEFAULT_PORT=""
if [ -n "${PORT:-}" ]; then
    if ! validate_port_int "$PORT"; then
        echo "Error: Invalid PORT='${PORT}'. PORT must be an integer between 1 and 65535."
        exit 1
    fi
    DEFAULT_PORT="$PORT"
    if is_port_in_use "$DEFAULT_PORT" && ! is_port_owned_by_vitrine "$DEFAULT_PORT"; then
        echo "    [!] Requested PORT=${DEFAULT_PORT} is currently in use by another process; scanning 8080..8090 for an open port..."
        DEFAULT_PORT=""
    else
        echo "    [✓] Using requested PORT=${DEFAULT_PORT}."
    fi
elif [ -n "$EXISTING_VITRINE_PORT" ]; then
    if ! is_port_in_use "$EXISTING_VITRINE_PORT" || is_port_owned_by_vitrine "$EXISTING_VITRINE_PORT"; then
        DEFAULT_PORT="$EXISTING_VITRINE_PORT"
        echo "    [✓] Preserving existing Vitrine RMM service port: ${DEFAULT_PORT}"
    else
        echo "    [!] Previously configured port ${EXISTING_VITRINE_PORT} is occupied by another process; scanning 8080..8090..."
    fi
fi

if [ -z "$DEFAULT_PORT" ]; then
    for candidate_port in $(seq 8080 8090); do
        if ! is_port_in_use "$candidate_port" || is_port_owned_by_vitrine "$candidate_port"; then
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

install_pkg_deps() {
    local pkg_dir="$1"
    cd "$pkg_dir"
    if [ -f package-lock.json ]; then
        run_as_owner npm ci --no-audit --no-fund
    else
        run_as_owner npm install --no-audit --no-fund
    fi
}

if ! command -v x86_64-w64-mingw32-g++ &> /dev/null || ! command -v x86_64-w64-mingw32-windres &> /dev/null || ! command -v clang++ &> /dev/null || ! command -v ld.lld &> /dev/null; then
    if command -v apt-get &> /dev/null; then
        echo "--> Installing Windows PE cross-compiler toolchain (mingw-w64, clang, lld)..."
        run_priv apt-get update -qq
        run_priv apt-get install -y --no-install-recommends g++-mingw-w64-x86-64 binutils-mingw-w64-x86-64
        run_priv apt-get install -y --no-install-recommends clang lld || echo "    [!] Warning: clang/lld unavailable on this apt suite; falling back to g++ PE pipeline."
    else
        echo "    [!] Warning: x86_64-w64-mingw32-g++ / windres / clang++ / ld.lld not found; native Windows PE (.exe) template build requires mingw-w64 (and clang + lld for 6-section UCRT PEs)."
    fi
fi

# Ensure Linux POSIX cross-compiler for companion architecture (amd64 <-> arm64) is present when available
if command -v apt-get &> /dev/null; then
    HOST_MACHINE="$(uname -m 2>/dev/null || echo unknown)"
    if [ "$HOST_MACHINE" = "x86_64" ] && ! command -v aarch64-linux-gnu-g++ &> /dev/null; then
        echo "--> Installing Linux ARM64 POSIX cross-compiler (g++-aarch64-linux-gnu)..."
        run_priv apt-get install -y --no-install-recommends g++-aarch64-linux-gnu || true
    elif [ "$HOST_MACHINE" = "aarch64" ] || [ "$HOST_MACHINE" = "arm64" ]; then
        if ! command -v x86_64-linux-gnu-g++ &> /dev/null; then
            echo "--> Installing Linux x86_64 POSIX cross-compiler (g++-x86-64-linux-gnu)..."
            run_priv apt-get install -y --no-install-recommends g++-x86-64-linux-gnu || true
        fi
    fi
fi

echo "--> Installing Backend dependencies..."
install_pkg_deps "$PROJ_ROOT/backend"

echo "--> Installing Frontend dependencies..."
install_pkg_deps "$PROJ_ROOT/frontend"

echo "--> Building Production Frontend Assets (Vite)..."
cd "$PROJ_ROOT/frontend"
run_as_owner npm run build

echo "--> Building Production Backend Service (TypeScript)..."
cd "$PROJ_ROOT/backend"
run_as_owner npm run build

cd "$PROJ_ROOT"

# 4. Ensure persistent isolated directories exist with hardened permissions
mkdir -p \
    "$PROJ_ROOT/data" \
    "$PROJ_ROOT/data/backups" \
    "$PROJ_ROOT/data/packages" \
    "$PROJ_ROOT/data/signed-agents" \
    "$PROJ_ROOT/data/signing-staging" \
    "$PROJ_ROOT/data/recordings" \
    "$PROJ_ROOT/branding"
chmod 700 \
    "$PROJ_ROOT/data" \
    "$PROJ_ROOT/data/backups" \
    "$PROJ_ROOT/data/packages" \
    "$PROJ_ROOT/data/signed-agents" \
    "$PROJ_ROOT/data/signing-staging" \
    "$PROJ_ROOT/data/recordings"
chmod 755 "$PROJ_ROOT/branding"

# Record current git commit SHA and version metadata for the Self-Updater before final ownership alignment
GIT_COMMIT=$(git -c safe.directory="$PROJ_ROOT" rev-parse --short HEAD 2>/dev/null || echo "release-build")
node -e "const fs=require('fs');fs.writeFileSync(process.argv[1],JSON.stringify({version:process.argv[2],commit:process.argv[3],installedAt:new Date().toISOString()}));" \
    "$PROJ_ROOT/data/install-meta.json" "$APP_VERSION" "$GIT_COMMIT"

if [ "$(id -u)" -eq 0 ] && [ "$CURR_USER" != "root" ]; then
    chown -R "$CURR_USER:$CURR_GROUP" \
        "$PROJ_ROOT/data" \
        "$PROJ_ROOT/branding" \
        "$PROJ_ROOT/backend/dist" \
        "$PROJ_ROOT/backend/node_modules" \
        "$PROJ_ROOT/frontend/dist" \
        "$PROJ_ROOT/frontend/node_modules"
fi

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
    NODE_BIN_DIR="$(dirname "$NODE_PATH")"
    SERVER_PATH="$PROJ_ROOT/backend/dist/server.js"
    WORK_DIR="$PROJ_ROOT/backend"
    DATA_PATH="$PROJ_ROOT/data"
    BRAND_PATH="$PROJ_ROOT/branding"
    ENV_FILE_PATH="$PROJ_ROOT/.env"
    TMP_UNIT="$PROJ_ROOT/data/vitrine-rmm.service.tmp.$$"

    # Systemd specifier/quoting helpers:
    # - WorkingDirectory= and EnvironmentFile= take unquoted paths (with '%' escaped as '%%').
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
Group=$CURR_GROUP
WorkingDirectory=$(esc_systemd_raw "$WORK_DIR")
Environment="NODE_ENV=production"
Environment="PORT=$DEFAULT_PORT"
Environment="DATA_DIR=$(esc_systemd_quoted "$DATA_PATH")"
Environment="BRANDING_DIR=$(esc_systemd_quoted "$BRAND_PATH")"
Environment="PATH=$(esc_systemd_quoted "${NODE_BIN_DIR}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")"
EnvironmentFile=-$(esc_systemd_raw "$ENV_FILE_PATH")
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
    TMP_UNIT=""
    run_priv systemctl daemon-reload
    run_priv systemctl enable vitrine-rmm.service
    run_priv systemctl restart vitrine-rmm.service

    echo "--> Waiting for Vitrine RMM health endpoint on http://127.0.0.1:${DEFAULT_PORT}/api/health ..."
    HEALTH_OK=0
    for _ in $(seq 1 20); do
        if node -e "fetch('http://127.0.0.1:' + process.argv[1] + '/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))" "$DEFAULT_PORT" 2>/dev/null; then
            HEALTH_OK=1
            break
        fi
        sleep 0.5
    done

    if [ "$HEALTH_OK" -ne 1 ] || ! run_priv systemctl is-active --quiet vitrine-rmm.service; then
        echo "Error: vitrine-rmm.service failed health verification on port ${DEFAULT_PORT}. Check logs with: journalctl -u vitrine-rmm.service -n 50 --no-pager"
        exit 1
    fi

    echo "--> Vitrine RMM systemd service is active, healthy, and enabled on boot!"
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
