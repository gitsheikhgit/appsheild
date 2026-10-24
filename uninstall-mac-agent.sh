#!/usr/bin/env bash
set -e

# ==============================================================================
# AppShield macOS Agent Clean Uninstaller
# ==============================================================================

if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: Please run uninstallation with sudo: sudo bash uninstall-mac-agent.sh"
    exit 1
fi

echo "===================================================================="
echo "          Uninstalling AppShield macOS Endpoint Protection          "
echo "===================================================================="

PLIST_PATH="/Library/LaunchDaemons/com.appshield.macagent.plist"

if [ -f "$PLIST_PATH" ]; then
    echo "[+] Unloading LaunchDaemon..."
    launchctl bootout system/com.appshield.macagent 2>/dev/null || launchctl unload "$PLIST_PATH" 2>/dev/null || true
    rm -f "$PLIST_PATH"
fi

# 1. Notify Central Server to deregister device and purge from server database
SETTINGS_FILE="/Library/Application Support/AppShield/settings.json"
CONFIG_FILE="/Library/Application Support/AppShield/config.json"
LEGACY_CONFIG="/Library/Application Support/AppShield/agent_config.json"
ACTIVE_CONFIG=""
if [ -f "$SETTINGS_FILE" ]; then
    ACTIVE_CONFIG="$SETTINGS_FILE"
elif [ -f "$CONFIG_FILE" ]; then
    ACTIVE_CONFIG="$CONFIG_FILE"
elif [ -f "$LEGACY_CONFIG" ]; then
    ACTIVE_CONFIG="$LEGACY_CONFIG"
fi

if [ -n "$ACTIVE_CONFIG" ]; then
    SERVER_URL=$(/usr/bin/python3 -c "import json; print(json.load(open('$ACTIVE_CONFIG')).get('server_url',''))" 2>/dev/null || grep -o '"server_url"[^,]*' "$ACTIVE_CONFIG" 2>/dev/null | cut -d'"' -f4 | tr -d '[:space:]' || true)
    DEVICE_ID=$(/usr/bin/python3 -c "import json; print(json.load(open('$ACTIVE_CONFIG')).get('device_id',''))" 2>/dev/null || grep -o '"device_id"[^,]*' "$ACTIVE_CONFIG" 2>/dev/null | cut -d'"' -f4 | tr -d '[:space:]' || true)

    if [ -z "$DEVICE_ID" ]; then
        DEVICE_ID=$(grep -rho '"device_id"[^,]*' "/Library/Application Support/AppShield" 2>/dev/null | head -n1 | cut -d'"' -f4 | tr -d '[:space:]' || true)
    fi

    TARGET_SERVERS=()
    if [ -n "$SERVER_URL" ] && [ "$SERVER_URL" != "standalone" ]; then
        TARGET_SERVERS+=("$SERVER_URL")
    fi
    TARGET_SERVERS+=("http://192.168.0.101:8000")

    if [ -n "$DEVICE_ID" ]; then
        echo "[+] Sending signal to delete computer '$DEVICE_ID' from Central Server..."
        for srv in "${TARGET_SERVERS[@]}"; do
            srv_clean=$(echo "$srv" | sed 's:/*$::')
            echo "    -> Purging $DEVICE_ID from $srv_clean..."
            curl -s -m 4 -X POST "$srv_clean/api/devices/unregister" \
                 -H "Content-Type: application/json" \
                 -d "{\"device_id\":\"$DEVICE_ID\",\"reason\":\"uninstalled\"}" 2>/dev/null || true
            curl -s -m 4 -X DELETE "$srv_clean/api/fleet/$DEVICE_ID" 2>/dev/null || true
        done
        echo "[+] Central Server delete signal completed."
    fi
fi

# 2. Terminate background daemon and admin processes (DO NOT kill installer wrapper yet)
pkill -9 -f "AppShield/agent/agent.py" 2>/dev/null || true
pkill -9 -f "AppShield Admin.app" 2>/dev/null || true

echo "[+] Removing AppShield system files..."
rm -rf "/Library/Application Support/AppShield"
rm -f "/var/log/appshield-agent.log"
rm -rf "/Applications/AppShield.app" 2>/dev/null || true
rm -rf "/Applications/AppShield Admin.app" 2>/dev/null || true
rm -rf /Users/*/Desktop/AppShield.app 2>/dev/null || true
rm -rf /Users/*/Desktop/AppShield\ Admin.app 2>/dev/null || true
rm -rf /Users/*/Applications/AppShield.app 2>/dev/null || true
rm -rf /Users/*/.appshield 2>/dev/null || true

# Detect logged-in console user
LOGGED_IN_USER=$(stat -f "%Su" /dev/console 2>/dev/null || echo "$SUDO_USER")
if [ -z "$LOGGED_IN_USER" ] || [ "$LOGGED_IN_USER" = "root" ]; then
    LOGGED_IN_USER=$(scutil <<< "show State:/Users/ConsoleUser" 2>/dev/null | awk -F': ' '/Name/ {print $2}' || echo "")
fi

# Purge from Launchpad SQLite database caches across user folders
echo "[+] Purging Launchpad icon cache..."
if [ -n "$LOGGED_IN_USER" ] && [ "$LOGGED_IN_USER" != "root" ]; then
    USER_DARWIN_DIR=$(sudo -u "$LOGGED_IN_USER" getconf DARWIN_USER_DIR 2>/dev/null || echo "")
    if [ -n "$USER_DARWIN_DIR" ] && [ -f "${USER_DARWIN_DIR}com.apple.dock.launchpad/db/db" ]; then
        sqlite3 "${USER_DARWIN_DIR}com.apple.dock.launchpad/db/db" "DELETE FROM apps WHERE bundleid IN ('com.appshield.mac', 'com.appshield.fleetadmin') OR title LIKE '%AppShield%';" 2>/dev/null || true
    fi
fi

# Scan all user Launchpad DBs in /private/var/folders
find /private/var/folders -path "*/com.apple.dock.launchpad/db/db" 2>/dev/null | while read -r db; do
    if [ -f "$db" ]; then
        sqlite3 "$db" "DELETE FROM apps WHERE bundleid IN ('com.appshield.mac', 'com.appshield.fleetadmin') OR title LIKE '%AppShield%';" 2>/dev/null || true
    fi
done

echo "[+] Unregistering AppShield from macOS LaunchServices..."
LS_BIN="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
if [ -f "$LS_BIN" ]; then
    "$LS_BIN" -u "/Applications/AppShield.app" 2>/dev/null || true
    "$LS_BIN" -u "/Applications/AppShield Admin.app" 2>/dev/null || true
    if [ -n "$LOGGED_IN_USER" ] && [ "$LOGGED_IN_USER" != "root" ]; then
        sudo -u "$LOGGED_IN_USER" "$LS_BIN" -u "/Applications/AppShield.app" 2>/dev/null || true
        sudo -u "$LOGGED_IN_USER" "$LS_BIN" -u "/Applications/AppShield Admin.app" 2>/dev/null || true
    fi
fi

# Restart Dock for the logged-in user so the icon immediately vanishes from Launchpad
if [ -n "$LOGGED_IN_USER" ] && [ "$LOGGED_IN_USER" != "root" ]; then
    sudo -u "$LOGGED_IN_USER" killall Dock 2>/dev/null || true
fi
killall Dock 2>/dev/null || true

echo "[+] AppShield macOS agent uninstalled cleanly."
echo "===================================================================="
