#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/AppShield.Admin"

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

echo "[+] Starting Admin Dashboard on http://127.0.0.1:$ADMIN_PORT..."

# Open standalone desktop app window (Chrome/Edge App Mode) or fallback to default browser
(sleep 1.5 && {
    if [ -d "/Applications/Google Chrome.app" ]; then
        open -na "Google Chrome" --args "--app=http://127.0.0.1:$ADMIN_PORT" "--window-size=1380,880"
    elif [ -d "/Applications/Microsoft Edge.app" ]; then
        open -na "Microsoft Edge" --args "--app=http://127.0.0.1:$ADMIN_PORT" "--window-size=1380,880"
    elif [ -d "/Applications/Brave Browser.app" ]; then
        open -na "Brave Browser" --args "--app=http://127.0.0.1:$ADMIN_PORT" "--window-size=1380,880"
    else
        open "http://127.0.0.1:$ADMIN_PORT"
    fi
}) &

# Start Uvicorn Server
python3 -m uvicorn main:app --host 127.0.0.1 --port $ADMIN_PORT
