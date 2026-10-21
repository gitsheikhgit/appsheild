#!/bin/bash
set -e

# ==============================================================================
# AppShield Central Cloud Server: 1-Click Installer for Ubuntu / Debian LXC
# ==============================================================================

echo "===================================================================="
echo "    Installing AppShield Central Fleet Server on Proxmox LXC        "
echo "===================================================================="

# 1. Install prerequisites
echo "[+] Installing system dependencies..."
apt-get update -y
apt-get install -y python3 python3-pip python3-venv sqlite3 curl

# 2. Setup Server Directory
INSTALL_DIR="/opt/appshield-server"
echo "[+] Setting up installation directory at $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR/static"
mkdir -p "$INSTALL_DIR/data"
cd "$INSTALL_DIR"

# 3. Setup Python Virtual Environment
if [ ! -d "$INSTALL_DIR/.venv" ]; then
    echo "[+] Creating Python virtual environment..."
    python3 -m venv "$INSTALL_DIR/.venv"
fi

echo "[+] Installing FastAPI, Uvicorn, and WebSocket dependencies..."
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip --quiet
"$INSTALL_DIR/.venv/bin/pip" install fastapi uvicorn pydantic websockets --quiet

# 3b. Copy Application Source Code
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/AppShield.CentralServer/server.py" ]; then
    cp "$SCRIPT_DIR/AppShield.CentralServer/server.py" "$INSTALL_DIR/server.py"
    cp -r "$SCRIPT_DIR/AppShield.CentralServer/static/"* "$INSTALL_DIR/static/"
elif [ -f "$SCRIPT_DIR/server.py" ]; then
    cp "$SCRIPT_DIR/server.py" "$INSTALL_DIR/server.py"
    cp -r "$SCRIPT_DIR/static/"* "$INSTALL_DIR/static/"
fi

if [ ! -f "$INSTALL_DIR/server.py" ]; then
    echo "[+] Fetching server code from GitHub..."
    curl -sSL "https://raw.githubusercontent.com/gitsheikhgit/appsheild/main/AppShield.CentralServer/server.py" -o "$INSTALL_DIR/server.py"
    curl -sSL "https://raw.githubusercontent.com/gitsheikhgit/appsheild/main/AppShield.CentralServer/static/index.html" -o "$INSTALL_DIR/static/index.html"
    curl -sSL "https://raw.githubusercontent.com/gitsheikhgit/appsheild/main/AppShield.CentralServer/static/manifest.json" -o "$INSTALL_DIR/static/manifest.json"
fi

# 4. Create systemd service
echo "[+] Configuring systemd background service (appshield-server)..."
cat << 'EOF' > /etc/systemd/system/appshield-server.service
[Unit]
Description=AppShield Central Fleet Management & Parental Shield Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/appshield-server
ExecStart=/opt/appshield-server/.venv/bin/uvicorn server:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now appshield-server

SERVER_IP=$(hostname -I | awk '{print $1}')
echo ""
echo "===================================================================="
echo "    AppShield Central Server Installed & Running!                   "
echo "===================================================================="
echo " Access Dashboard on Phone/Mac:  http://${SERVER_IP}:8000"
echo " Service Status:                systemctl status appshield-server"
echo "===================================================================="
