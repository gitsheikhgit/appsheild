#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADMIN_DIR="$SCRIPT_DIR/AppShield.Admin"
cd "$ADMIN_DIR"

echo "===================================================================="
echo "          Starting AppShield Admin Control Dashboard...             "
echo "===================================================================="

# Activate virtual environment if present
if [ -f ".venv/bin/activate" ]; then
    source ".venv/bin/activate"
fi

# Detect available port (defaults to 8080, falls back to 8085 if occupied)
ADMIN_PORT=8080
if lsof -i :8080 >/dev/null 2>&1; then
    ADMIN_PORT=8085
fi

PID_FILE="$ADMIN_DIR/.server.pid"
LOG_FILE="$ADMIN_DIR/admin.log"

# Check if server is already running
RUNNING=0
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if ps -p "$OLD_PID" >/dev/null 2>&1; then
        echo "[+] AppShield Admin background daemon is already running (PID $OLD_PID)."
        RUNNING=1
    fi
fi

if [ $RUNNING -eq 0 ]; then
    echo "[+] Launching AppShield Admin background daemon on port $ADMIN_PORT..."
    nohup python3 -m uvicorn main:app --host 127.0.0.1 --port $ADMIN_PORT > "$LOG_FILE" 2>&1 &
    SERVER_PID=$!
    echo $SERVER_PID > "$PID_FILE"
    echo "[+] Server started successfully with PID $SERVER_PID."
    sleep 1.2
fi

echo "[+] Opening standalone AppShield desktop window..."
if [ -d "/Applications/Google Chrome.app" ]; then
    open -na "Google Chrome" --args "--app=http://127.0.0.1:$ADMIN_PORT" "--window-size=1380,880"
elif [ -d "/Applications/Microsoft Edge.app" ]; then
    open -na "Microsoft Edge" --args "--app=http://127.0.0.1:$ADMIN_PORT" "--window-size=1380,880"
elif [ -d "/Applications/Brave Browser.app" ]; then
    open -na "Brave Browser" --args "--app=http://127.0.0.1:$ADMIN_PORT" "--window-size=1380,880"
else
    open "http://127.0.0.1:$ADMIN_PORT"
fi

echo ""
echo "===================================================================="
echo "  ✓ AppShield Admin is now running independently in the background! "
echo "  ✓ You can SAFELY CLOSE this Terminal window anytime.              "
echo "  ✓ To stop the server later, double-click: stop-admin-mac.command  "
echo "===================================================================="
echo ""
