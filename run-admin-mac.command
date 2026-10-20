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

# Open browser after a brief delay in the background
(sleep 1.5 && open "http://127.0.0.1:$ADMIN_PORT") &

# Start Uvicorn Server
python3 -m uvicorn main:app --host 127.0.0.1 --port $ADMIN_PORT
