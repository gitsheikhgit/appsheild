#!/usr/bin/env bash
set -e

# ==============================================================================
# AppShield macOS Endpoint Protection: 1-Click Installer
# Deploys the tamper-resistant LaunchDaemon agent for macOS
# ==============================================================================

if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: Please run this installer with sudo: sudo bash install-mac-agent.sh"
    exit 1
fi

SERVER_URL="${1:-http://192.168.0.101:8000}"

echo "===================================================================="
echo "         AppShield macOS Endpoint Protection Installer              "
echo "===================================================================="
echo " Target Central Hub: $SERVER_URL"
echo " Target Directory:   /Library/Application Support/AppShield"
echo "===================================================================="

INSTALL_DIR="/Library/Application Support/AppShield"
AGENT_DIR="$INSTALL_DIR/agent"
PLIST_PATH="/Library/LaunchDaemons/com.appshield.macagent.plist"

mkdir -p "$AGENT_DIR"
chmod 755 "$INSTALL_DIR"
chmod 755 "$AGENT_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Copy agent script
if [ -f "$SCRIPT_DIR/AppShield.MacAgent/agent.py" ]; then
    cp "$SCRIPT_DIR/AppShield.MacAgent/agent.py" "$AGENT_DIR/agent.py"
elif [ -f "$SCRIPT_DIR/agent.py" ]; then
    cp "$SCRIPT_DIR/agent.py" "$AGENT_DIR/agent.py"
else
    echo "[+] Downloading latest Mac agent from GitHub..."
    curl -sSL "https://raw.githubusercontent.com/gitsheikhgit/appsheild/main/AppShield.MacAgent/agent.py" -o "$AGENT_DIR/agent.py"
fi
chmod +x "$AGENT_DIR/agent.py"

# Setup Python environment
echo "[+] Setting up isolated Python runtime environment..."
if [ ! -d "$AGENT_DIR/.venv" ]; then
    python3 -m venv "$AGENT_DIR/.venv"
fi

"$AGENT_DIR/.venv/bin/pip" install --upgrade pip --quiet 2>/dev/null || true
"$AGENT_DIR/.venv/bin/pip" install websockets --quiet 2>/dev/null || true

# Pre-configure server URL
CONFIG_FILE="$INSTALL_DIR/agent_config.json"
if [ ! -f "$CONFIG_FILE" ]; then
    cat << EOF > "$CONFIG_FILE"
{
  "device_id": "mac_$(uuidgen | tr '[:upper:]' '[:lower:]' | cut -d'-' -f1-2)",
  "name": "$(scutil --get ComputerName 2>/dev/null || hostname)",
  "server_url": "$SERVER_URL",
  "rules": [
    {
      "id": "rule_curfew_games",
      "rule_type": "AllowedWindow",
      "target_process": "Roblox",
      "schedule_start": "12:00",
      "schedule_end": "20:00",
      "is_enabled": 1
    },
    {
      "id": "rule_curfew_steam",
      "rule_type": "AllowedWindow",
      "target_process": "steam",
      "schedule_start": "12:00",
      "schedule_end": "20:00",
      "is_enabled": 1
    }
  ],
  "managed_users": [],
  "path_jail_enabled": true
}
EOF
else
    # Update server URL in existing config if changed
    sed -i '' "s|\"server_url\": \".*\"|\"server_url\": \"$SERVER_URL\"|g" "$CONFIG_FILE" 2>/dev/null || true
fi
chmod 644 "$CONFIG_FILE"

# Setup LaunchDaemon for persistent 24/7 background protection
echo "[+] Registering root LaunchDaemon (com.appshield.macagent)..."
cat << EOF > "$PLIST_PATH"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.appshield.macagent</string>
    <key>ProgramArguments</key>
    <array>
        <string>$AGENT_DIR/.venv/bin/python3</string>
        <string>$AGENT_DIR/agent.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/appshield-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/appshield-agent.log</string>
</dict>
</plist>
EOF

chmod 644 "$PLIST_PATH"
chown root:wheel "$PLIST_PATH"

# Reload daemon
launchctl bootout system/com.appshield.macagent 2>/dev/null || launchctl unload "$PLIST_PATH" 2>/dev/null || true
launchctl bootstrap system "$PLIST_PATH" 2>/dev/null || launchctl load -w "$PLIST_PATH" 2>/dev/null || true

echo ""
echo "===================================================================="
echo "    AppShield Mac Agent Installed & Protection Running!             "
echo "===================================================================="
echo " Hub URL:       $SERVER_URL"
echo " Daemon Logs:   tail -f /var/log/appshield-agent.log"
echo " Check Status:  sudo launchctl list | grep appshield"
echo " To Uninstall:  sudo bash uninstall-mac-agent.sh"
echo "===================================================================="
