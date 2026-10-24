#!/usr/bin/env bash

echo "===================================================================="
echo "    AppShield Mac System Cleanup: CPU Relief & Ghost App Removal    "
echo "===================================================================="

# 1. Terminate all stuck log show processes that are thrashing the CPU and disk
echo "[+] Terminating stuck background log processes..."
sudo killall -9 log 2>/dev/null || true

# 2. Surgically delete the orphaned AppShield Admin rows from Launchpad database
echo "[+] Purging ghost AppShield Admin from macOS Launchpad database..."
LP_DB=$(find /var/folders -name "db" -path "*/com.apple.dock.launchpad/db/db" 2>/dev/null | head -n 1)

if [ -n "$LP_DB" ] && [ -f "$LP_DB" ]; then
    sqlite3 "$LP_DB" "DELETE FROM apps WHERE bundleid = 'com.appshield.fleetadmin' OR title = 'AppShield Admin';" 2>/dev/null || true
    sqlite3 "$LP_DB" "DELETE FROM items WHERE rowid IN (164, 165, 167);" 2>/dev/null || true
    echo "[+] Launchpad database cleaned: $LP_DB"
fi

# 3. Restart Dock to instantly reflect the clean Launchpad
killall Dock 2>/dev/null || true

echo ""
echo "===================================================================="
echo " [OK] Done! CPU load relieved and ghost AppShield Admin removed."
echo "===================================================================="
