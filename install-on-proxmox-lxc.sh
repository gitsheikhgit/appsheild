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
if [ -d "$SCRIPT_DIR/AppShield.CentralServer" ]; then
    cp -r "$SCRIPT_DIR/AppShield.CentralServer/"* "$INSTALL_DIR/"
elif [ -f "$SCRIPT_DIR/server.py" ]; then
    cp "$SCRIPT_DIR/"*.py "$INSTALL_DIR/" 2>/dev/null || true
    cp -r "$SCRIPT_DIR/static/"* "$INSTALL_DIR/static/" 2>/dev/null || true
fi

if [ ! -f "$INSTALL_DIR/server.py" ]; then
    echo "[+] Fetching server code from GitHub..."
    for f in server.py core_state.py feature_routes.py settings_routes.py tailscale_manager.py; do
        curl -sSL "https://raw.githubusercontent.com/gitsheikhgit/appsheild/main/AppShield.CentralServer/$f" -o "$INSTALL_DIR/$f"
    done
    for f in index.html manifest.json features.js settings.js; do
        curl -sSL "https://raw.githubusercontent.com/gitsheikhgit/appsheild/main/AppShield.CentralServer/static/$f" -o "$INSTALL_DIR/static/$f"
    done
fi

# Ensure Tailscale runs in unprivileged LXC containers if tun is missing
if [ ! -e /dev/net/tun ] && [ -f /etc/default/tailscaled ]; then
    echo "[+] Configuring Tailscale userspace-networking for Proxmox LXC..."
    sed -i 's|FLAGS=.*|FLAGS="--tun=userspace-networking"|' /etc/default/tailscaled 2>/dev/null || true
    systemctl restart tailscaled 2>/dev/null || true
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
echo ""
echo " Default Security Credentials:"
echo "   Username:         admin"
echo "   Initial Password: changeme"
echo ""
echo " [!] FIRST-TIME SETUP REQUIRED:"
echo "     When opening http://${SERVER_IP}:8000 for the first time, log in"
echo "     with 'changeme' and set your private parental master password."
echo "     The security console will stay locked until password is changed."
echo ""
echo " Service Status:     systemctl status appshield-server"
echo "===================================================================="
