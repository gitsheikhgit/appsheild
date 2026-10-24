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

SERVER_URL="${1:-standalone}"

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
chmod 775 "$INSTALL_DIR" 2>/dev/null || true
chmod 775 "$AGENT_DIR" 2>/dev/null || true
chown -R root:admin "$INSTALL_DIR" 2>/dev/null || true

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Copy and install GUI AppShield.app to /Applications if running from installer bundle
SOURCE_APP=""
if [ -d "$SCRIPT_DIR/../MacOS" ] && [ -f "$SCRIPT_DIR/../Info.plist" ]; then
    SOURCE_APP="$(cd "$SCRIPT_DIR/../.." && pwd)"
elif [ -d "$SCRIPT_DIR/AppShield.app" ]; then
    SOURCE_APP="$(cd "$SCRIPT_DIR/AppShield.app" && pwd)"
elif [ -d "$SCRIPT_DIR/Installers/macOS/AppShield.app" ]; then
    SOURCE_APP="$(cd "$SCRIPT_DIR/Installers/macOS/AppShield.app" && pwd)"
fi

if [ -n "$SOURCE_APP" ] && [ -d "$SOURCE_APP" ] && [ "$SOURCE_APP" != "/Applications/AppShield.app" ]; then
    echo "[+] Installing AppShield.app into /Applications..."
    rm -rf "/Applications/AppShield.app" 2>/dev/null || true
    cp -R "$SOURCE_APP" "/Applications/AppShield.app"
    chown -R root:admin "/Applications/AppShield.app" 2>/dev/null || true
    chmod -R 755 "/Applications/AppShield.app" 2>/dev/null || true

    # Register with macOS LaunchServices so icon appears immediately in App Drawer / Launchpad
    LS_BIN="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
    if [ -f "$LS_BIN" ]; then
        "$LS_BIN" -f "/Applications/AppShield.app" 2>/dev/null || true
    fi

    LOGGED_IN_USER=$(stat -f "%Su" /dev/console 2>/dev/null || echo "$SUDO_USER")
    if [ -n "$LOGGED_IN_USER" ] && [ "$LOGGED_IN_USER" != "root" ]; then
        sudo -u "$LOGGED_IN_USER" killall Dock 2>/dev/null || true
    fi
    killall Dock 2>/dev/null || true
elif [ -d "/Applications/AppShield.app" ]; then
    if [ -f "$SCRIPT_DIR/static/setup.html" ]; then
        mkdir -p "/Applications/AppShield.app/Contents/Resources/static"
        cp "$SCRIPT_DIR/static/setup.html" "/Applications/AppShield.app/Contents/Resources/static/setup.html" 2>/dev/null || true
    fi
fi

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

# Pre-configure separate settings.json and features.json for easy maintenance
SETTINGS_FILE="$INSTALL_DIR/settings.json"
FEATURES_FILE="$INSTALL_DIR/features.json"
LEGACY_CONFIG="$INSTALL_DIR/agent_config.json"

STANDALONE_VAL="false"
if [ "$SERVER_URL" = "standalone" ] || [ -z "$SERVER_URL" ]; then
    STANDALONE_VAL="true"
fi

HW_UUID=$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'"' '/IOPlatformUUID/{print $4}' | tr -d '-' | tr '[:upper:]' '[:lower:]')
if [ -n "$HW_UUID" ] && [ ${#HW_UUID} -ge 12 ]; then
    MAC_DEVICE_ID="mac_${HW_UUID:0:12}"
else
    MAC_DEVICE_ID="mac_$(uuidgen | tr -d '-' | tr '[:upper:]' '[:lower:]' | cut -c1-12)"
fi
COMPUTER_NAME="$(scutil --get ComputerName 2>/dev/null || hostname)"
PSK_KEY="$(openssl rand -hex 16 2>/dev/null || uuidgen | tr -d '-' | tr '[:upper:]' '[:lower:]')"

if [ -f "$SETTINGS_FILE" ]; then
    sed -i '' "s|\"server_url\": \".*\"|\"server_url\": \"$SERVER_URL\"|g" "$SETTINGS_FILE" 2>/dev/null || true
    sed -i '' "s|\"standalone_mode\": .*|\"standalone_mode\": $STANDALONE_VAL|g" "$SETTINGS_FILE" 2>/dev/null || true
    if ! grep -q "\"psk\"" "$SETTINGS_FILE" 2>/dev/null; then
        sed -i '' "s|\"standalone_mode\": \(.*\)|\"standalone_mode\": \1,\n  \"psk\": \"$PSK_KEY\"|g" "$SETTINGS_FILE" 2>/dev/null || true
    fi
else
    cat << EOF > "$SETTINGS_FILE"
{
  "device_id": "$MAC_DEVICE_ID",
  "name": "$COMPUTER_NAME",
  "server_url": "$SERVER_URL",
  "standalone_mode": $STANDALONE_VAL,
  "psk": "$PSK_KEY"
}
EOF
fi
chmod 666 "$SETTINGS_FILE" 2>/dev/null || true

if [ ! -f "$FEATURES_FILE" ]; then
    cat << EOF > "$FEATURES_FILE"
{
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
fi
chmod 666 "$FEATURES_FILE" 2>/dev/null || true

# Maintain legacy symlink for backwards compatibility
ln -sf "$SETTINGS_FILE" "$LEGACY_CONFIG" 2>/dev/null || true

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
