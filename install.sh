#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "==========================================="
echo "       Vitrine RMM Installation Script     "
echo "==========================================="
echo "Modern, Glassmorphic Self-Hosted RMM"
echo "Powered by MeshCentral 2 Remote Engine"
echo "==========================================="

# Check Node.js version
if ! command -v node &> /dev/null; then
    echo "Error: node is not installed. Please install Node.js 18 or higher."
    exit 1
fi

NODE_VER=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VER" -lt 18 ]; then
    echo "Error: Node.js version must be 18+. Detected: $(node -v)"
    exit 1
fi

echo "--> Node.js $(node -v) and npm $(npm -v) detected."

PROJ_ROOT=$(pwd)

echo "--> Installing Root & Workspace dependencies..."
npm install

echo "--> Installing Backend dependencies..."
cd "$PROJ_ROOT/backend"
npm install --no-audit

echo "--> Installing Frontend dependencies..."
cd "$PROJ_ROOT/frontend"
npm install --no-audit

echo "--> Building Production Frontend Assets (Vite)..."
cd "$PROJ_ROOT/frontend"
npm run build

echo "--> Building Production Backend Service (TypeScript)..."
cd "$PROJ_ROOT/backend"
npm run build

cd "$PROJ_ROOT"

# Ensure data directory exists
mkdir -p "$PROJ_ROOT/data"
chmod 755 "$PROJ_ROOT/data"

echo "--> Vitrine RMM compilation completed successfully!"

# Systemd Service Creation Option
echo ""
read -p "Would you like to configure Vitrine RMM as a systemd background service? (y/n): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    CURR_USER=$(whoami)
    NODE_PATH=$(which node)
    SERVER_PATH="$PROJ_ROOT/backend/dist/server.js"
    
    echo "--> Generating vitrine-rmm.service config..."
    cat <<EOF > vitrine-rmm.service
[Unit]
Description=Vitrine RMM Fleet Orchestration Engine
After=network.target

[Service]
Type=simple
User=$CURR_USER
WorkingDirectory=$PROJ_ROOT/backend
Environment=PORT=8080
Environment=DATA_DIR=$PROJ_ROOT/data
ExecStart=$NODE_PATH $SERVER_PATH
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    echo "--> Installing service unit to systemd (sudo permission required)..."
    sudo cp vitrine-rmm.service /etc/systemd/system/vitrine-rmm.service
    sudo systemctl daemon-reload
    sudo systemctl enable vitrine-rmm.service
    sudo systemctl start vitrine-rmm.service
    rm -f vitrine-rmm.service
    
    echo "--> Vitrine RMM systemd service is active and enabled on boot!"
else
    echo "--> Skipping systemd service setup."
fi

echo ""
echo "==========================================="
echo "Vitrine RMM setup completed successfully!"
echo "If systemd service was installed, the platform is running."
echo "Otherwise, launch it manually with:"
echo "  PORT=8080 node backend/dist/server.js"
echo ""
echo "Open http://localhost:8080/ in your browser to begin."
echo "==========================================="
