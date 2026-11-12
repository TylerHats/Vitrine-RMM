#!/usr/bin/env bash

# Exit immediately on command failure or unset variable errors
set -euo pipefail

echo "=========================================================="
echo "             Vitrine RMM Installation Script              "
echo "=========================================================="
echo "Modern, Glassmorphic Self-Hosted RMM (v2.5.1)"
echo "Powered by MeshCentral 2 Remote Engine (Co-Existence Safe)"
echo "=========================================================="

PROJ_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJ_ROOT"

# 1. Check Node.js version (Node.js 20+ required for Fastify 5 & better-sqlite3)
if ! command -v node &> /dev/null; then
    echo "Error: node is not installed. Please install Node.js 20 LTS or higher."
    exit 1
fi

NODE_VER=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VER" -lt 18 ]; then
    echo "Error: Node.js version must be 18+ (20/22 LTS recommended). Detected: $(node -v)"
    exit 1
elif [ "$NODE_VER" -lt 20 ]; then
    echo "    [i] Note: Node.js $(node -v) detected (Node.js 20/22 LTS is recommended for optimal performance)."
fi

echo "--> Node.js $(node -v) and npm $(npm -v) detected."

# 2. Strictly Read-Only MeshCentral 2 Co-Existence Check (ZERO writes outside $PROJ_ROOT)
echo "--> Checking for neighboring MeshCentral 2 services (strictly read-only)..."
if systemctl list-unit-files 2>/dev/null | grep -q "meshcentral.service"; then
    echo "    [✓] Detected neighboring systemd unit: meshcentral.service (Isolated — never modified or restarted)."
fi

# 3. Port Collision Check (Never collide with MeshCentral 443, 80, 4430, 4433)
DEFAULT_PORT=${PORT:-8080}
if command -v ss &> /dev/null; then
    if ss -tuln | grep -q ":${DEFAULT_PORT} "; then
        echo "    [!] Port ${DEFAULT_PORT} is currently in use."
        DEFAULT_PORT=8085
        echo "    [✓] Auto-selected non-conflicting port: ${DEFAULT_PORT}"
    else
        echo "    [✓] Port ${DEFAULT_PORT} is available and isolated from MeshCentral ports."
    fi
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
mkdir -p "$PROJ_ROOT/data/signed-agents"
mkdir -p "$PROJ_ROOT/data/recordings"
mkdir -p "$PROJ_ROOT/branding"
chmod 700 "$PROJ_ROOT/data" "$PROJ_ROOT/data/backups" "$PROJ_ROOT/data/recordings"
chmod 755 "$PROJ_ROOT/branding"

CURR_USER="${SUDO_USER:-$(whoami)}"
if [ "$(id -u)" -eq 0 ] && [ "$CURR_USER" != "root" ]; then
    chown -R "$CURR_USER" "$PROJ_ROOT/data" "$PROJ_ROOT/branding"
fi

# Record current git commit SHA and version metadata for the Self-Updater
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "release-build")
echo "{\"version\":\"2.5.0\",\"commit\":\"$GIT_COMMIT\",\"installedAt\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" > "$PROJ_ROOT/data/install-meta.json"

echo "--> Vitrine RMM v2.5.0 compilation completed successfully!"

# 5. Systemd Service Creation Option (Strictly isolated to vitrine-rmm.service)
SETUP_SERVICE="n"
if [ -t 0 ]; then
    echo ""
    read -p "Would you like to configure Vitrine RMM as a systemd background service on port ${DEFAULT_PORT}? (y/n): " -n 1 -r
    echo ""
    SETUP_SERVICE="$REPLY"
fi

if [[ "$SETUP_SERVICE" =~ ^[Yy]$ ]]; then
    NODE_PATH=$(command -v node)
    SERVER_PATH="$PROJ_ROOT/backend/dist/server.js"
    TMP_UNIT="$PROJ_ROOT/data/vitrine-rmm.service.tmp"

    echo "--> Generating isolated vitrine-rmm.service unit..."
    cat <<EOF > "$TMP_UNIT"
[Unit]
Description=Vitrine RMM Fleet Orchestration Engine (Isolated from MeshCentral)
After=network.target

[Service]
Type=simple
User=$CURR_USER
WorkingDirectory=$PROJ_ROOT/backend
Environment=NODE_ENV=production
Environment=PORT=$DEFAULT_PORT
Environment=DATA_DIR=$PROJ_ROOT/data
Environment=BRANDING_DIR=$PROJ_ROOT/branding
Environment=VITRINE_ENABLE_GIT_SELF_PULL=true
ExecStart=$NODE_PATH $SERVER_PATH
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    echo "--> Installing service unit to systemd (sudo permission required)..."
    sudo cp "$TMP_UNIT" /etc/systemd/system/vitrine-rmm.service
    rm -f "$TMP_UNIT"
    sudo systemctl daemon-reload
    sudo systemctl enable vitrine-rmm.service
    sudo systemctl restart vitrine-rmm.service

    echo "--> Vitrine RMM systemd service is active and enabled on boot!"
else
    echo "--> Skipping systemd service setup."
fi

echo ""
echo "=========================================================="
echo "Vitrine RMM v2.5.1 setup completed successfully!"
echo "Neighboring MeshCentral 2 installations were left untouched."
echo ""
echo "Open http://localhost:${DEFAULT_PORT}/ in your browser to create"
echo "your initial Super Admin account and launch the OOBE Wizard."
echo "=========================================================="
