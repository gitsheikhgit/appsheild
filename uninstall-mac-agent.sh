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

# Kill any remaining agent processes
pkill -f "AppShield/agent/agent.py" 2>/dev/null || true

echo "[+] Removing AppShield files..."
rm -rf "/Library/Application Support/AppShield"
rm -f "/var/log/appshield-agent.log"

echo "[+] AppShield macOS agent uninstalled cleanly."
echo "===================================================================="
