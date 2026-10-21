#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADMIN_DIR="$SCRIPT_DIR/AppShield.Admin"
PID_FILE="$ADMIN_DIR/.server.pid"

echo "===================================================================="
echo "          Stopping AppShield Admin Background Daemon...             "
echo "===================================================================="

STOPPED=0
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" >/dev/null 2>&1; then
        echo "[+] Terminating AppShield Admin daemon (PID $PID)..."
        kill "$PID" 2>/dev/null || true
        STOPPED=1
    fi
    rm -f "$PID_FILE"
fi

# Fallback check for port 8085 / 8080 uvicorn
for PORT in 8085 8080; do
    PIDS=$(lsof -ti :$PORT 2>/dev/null)
    if [ -n "$PIDS" ]; then
        kill $PIDS 2>/dev/null || true
        STOPPED=1
    fi
done

if [ $STOPPED -eq 1 ]; then
    echo "[+] ✓ AppShield Admin has been stopped successfully."
else
    echo "[+] AppShield Admin is not currently running."
fi
echo ""
