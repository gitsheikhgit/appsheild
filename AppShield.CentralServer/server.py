import os
import json
import random
import string
import sqlite3
import datetime
import secrets
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from core_state import (
    BASE_DIR,
    STATIC_DIR,
    DATA_DIR,
    DOWNLOADS_DIR,
    DB_PATH,
    manager,
    live_telemetry,
    hash_password,
    verify_password,
    get_session_from_request,
    DeviceRegisterDto,
    TelemetryReportDto,
    LoginDto,
    ChangePasswordDto
)
import feature_routes
import settings_routes

app = FastAPI(
    title="AppShield Central Cloud Server",
    description="Centralized Fleet Management, Telemetry & Real-Time Parental Control Relay",
    version="1.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------------
# Database Initialization
# -------------------------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            os TEXT,
            lan_ip TEXT,
            tailscale_ip TEXT,
            agent_version TEXT,
            status TEXT DEFAULT 'online',
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            pair_code TEXT,
            psk TEXT
        )
    ''')
    try:
        c.execute("ALTER TABLE devices ADD COLUMN tailscale_ip TEXT")
    except Exception:
        pass
    try:
        c.execute("ALTER TABLE devices ADD COLUMN psk TEXT")
    except Exception:
        pass

    c.execute('''
        CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            device_id TEXT,
            rule_type TEXT,
            target_process TEXT,
            target_path TEXT,
            schedule_start TEXT,
            schedule_end TEXT,
            is_enabled INTEGER DEFAULT 1,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            event_type TEXT,
            executable_path TEXT,
            username TEXT,
            action_taken TEXT,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS dns_settings (
            device_id TEXT PRIMARY KEY,
            preset TEXT DEFAULT 'cloudflare_public',
            primary_dns TEXT DEFAULT '1.1.1.1',
            secondary_dns TEXT DEFAULT '1.0.0.1',
            primary_ipv6 TEXT DEFAULT '2606:4700:4700::1111',
            secondary_ipv6 TEXT DEFAULT '2606:4700:4700::1001',
            is_enabled INTEGER DEFAULT 1,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    ''')
    try:
        c.execute("ALTER TABLE dns_settings ADD COLUMN primary_ipv6 TEXT DEFAULT '2606:4700:4700::1111'")
    except Exception:
        pass
    try:
        c.execute("ALTER TABLE dns_settings ADD COLUMN secondary_ipv6 TEXT DEFAULT '2606:4700:4700::1001'")
    except Exception:
        pass
    c.execute('''
        CREATE TABLE IF NOT EXISTS user_policies (
            device_id TEXT,
            sid TEXT,
            is_managed INTEGER DEFAULT 1,
            block_user_writable_directories INTEGER DEFAULT 1,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (device_id, sid)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS global_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin_auth (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            username TEXT NOT NULL DEFAULT 'admin',
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            must_change_password INTEGER DEFAULT 1,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin_sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL
        )
    ''')
    c.execute("SELECT id FROM admin_auth WHERE id = 1")
    if not c.fetchone():
        pw_hash, salt = hash_password("changeme")
        c.execute('''
            INSERT INTO admin_auth (id, username, password_hash, salt, must_change_password)
            VALUES (1, 'admin', ?, ?, 1)
        ''', (pw_hash, salt))
    conn.commit()
    conn.close()

init_db()

# -------------------------------------------------------------------
# Brute-Force Rate Limiter & Auth Middleware
# -------------------------------------------------------------------
LOGIN_ATTEMPTS: Dict[str, List[float]] = {}
MAX_ATTEMPTS_PER_MIN = 8

@app.middleware("http")
async def security_auth_middleware(request: Request, call_next):
    path = request.url.path

    # Public & Agent routes
    if (
        path == "/" or
        path == "/index.html" or
        path.startswith("/static") or
        path.startswith("/downloads") or
        path.startswith("/download") or
        path == "/api/health" or
        path == "/api/auth/login" or
        path == "/api/auth/status" or
        path.startswith("/ws/agent") or
        path == "/api/devices/register" or
        path == "/api/agent/telemetry" or
        path == "/api/pair/new-code" or
        path == "/favicon.ico"
    ):
        return await call_next(request)

    session = get_session_from_request(request)
    if not session:
        return JSONResponse(status_code=401, content={"success": False, "detail": "Authentication required. Please log in."})

    return await call_next(request)

# -------------------------------------------------------------------
# Mount Modular Features & Settings Routers
# -------------------------------------------------------------------
app.include_router(feature_routes.router)
app.include_router(settings_routes.router)

# -------------------------------------------------------------------
# Core Authentication Endpoints
# -------------------------------------------------------------------
@app.get("/api/health")
async def health_check():
    return {"status": "ok", "timestamp": datetime.datetime.utcnow().isoformat()}

@app.post("/api/auth/login")
async def login(dto: LoginDto, request: Request, response: Response):
    client_ip = request.client.host if request.client else "unknown"
    now = datetime.datetime.utcnow().timestamp()

    # Rate limiting
    attempts = LOGIN_ATTEMPTS.get(client_ip, [])
    attempts = [t for t in attempts if now - t < 60.0]
    if len(attempts) >= MAX_ATTEMPTS_PER_MIN:
        LOGIN_ATTEMPTS[client_ip] = attempts
        raise HTTPException(status_code=429, detail="Too many login attempts. Please wait 1 minute.")
    attempts.append(now)
    LOGIN_ATTEMPTS[client_ip] = attempts

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash, salt, must_change_password FROM admin_auth WHERE id = 1")
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=500, detail="Portal authentication not initialized")

    stored_hash, salt, must_change = row
    if not verify_password(dto.password, salt, stored_hash):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid administrator password")

    # Clear failed attempts on success
    LOGIN_ATTEMPTS.pop(client_ip, None)

    token = secrets.token_urlsafe(32)
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=14)
    c.execute('''
        INSERT INTO admin_sessions (token, username, created_at, expires_at)
        VALUES (?, ?, CURRENT_TIMESTAMP, ?)
    ''', (token, dto.username or 'admin', expires_at.strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()

    response.set_cookie(
        key="appshield_session",
        value=token,
        max_age=14 * 86400,
        httponly=True,
        samesite="lax",
        secure=False
    )

    return {
        "success": True,
        "token": token,
        "username": dto.username or 'admin',
        "must_change_password": bool(must_change)
    }

@app.get("/api/auth/status")
async def auth_status(request: Request):
    session = get_session_from_request(request)
    if not session:
        return {
            "authenticated": False,
            "must_change_password": True
        }

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT must_change_password FROM admin_auth WHERE id = 1")
    row = c.fetchone()
    conn.close()
    must_change = bool(row[0]) if row else True

    return {
        "authenticated": True,
        "username": session["username"],
        "must_change_password": must_change
    }

@app.post("/api/auth/change-password")
async def change_password(dto: ChangePasswordDto, request: Request, response: Response):
    session = get_session_from_request(request)
    if not session:
        raise HTTPException(status_code=401, detail="Session expired or invalid. Please log in.")

    if not dto.new_password or len(dto.new_password) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters.")

    if dto.new_password == "changeme":
        raise HTTPException(status_code=400, detail="New password cannot be the default 'changeme'.")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash, salt FROM admin_auth WHERE id = 1")
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=500, detail="Authentication table not found.")

    stored_hash, salt = row
    if not verify_password(dto.current_password, salt, stored_hash):
        conn.close()
        raise HTTPException(status_code=400, detail="Current password is incorrect.")

    new_hash, new_salt = hash_password(dto.new_password)
    c.execute('''
        UPDATE admin_auth 
        SET password_hash = ?, salt = ?, must_change_password = 0, updated_at = CURRENT_TIMESTAMP
        WHERE id = 1
    ''', (new_hash, new_salt))
    conn.commit()
    conn.close()

    return {"success": True, "message": "Master password changed successfully."}

@app.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get("appshield_session")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()

    if token:
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("DELETE FROM admin_sessions WHERE token = ?", (token,))
            conn.commit()
            conn.close()
        except Exception:
            pass

    response.delete_cookie("appshield_session")
    return {"success": True, "message": "Logged out successfully."}

# -------------------------------------------------------------------
# Fleet Registration & Real-Time Telemetry Relay
# -------------------------------------------------------------------
@app.get("/api/fleet")
async def get_fleet():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, name, os, lan_ip, tailscale_ip, agent_version, status, last_seen, pair_code, psk FROM devices")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()

    for r in rows:
        dev_id = r["id"]
        # Merge live status if agent is currently connected via WebSocket
        if dev_id in manager.active_agents:
            r["status"] = "online"
        # Provide active IP: prefer Tailscale IP if reachable, fallback to LAN IP
        t_ip = r.get("tailscale_ip")
        lan_ip = r.get("lan_ip")
        r["active_ip"] = t_ip if (t_ip and str(t_ip).startswith("100.")) else lan_ip

    return {"success": True, "data": rows}

@app.post("/api/devices/register")
async def register_device(dto: DeviceRegisterDto):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO devices (id, name, os, lan_ip, tailscale_ip, agent_version, status, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, 'online', CURRENT_TIMESTAMP)
        ON CONFLICT(id) DO UPDATE SET
            name = excluded.name,
            os = excluded.os,
            lan_ip = excluded.lan_ip,
            tailscale_ip = COALESCE(excluded.tailscale_ip, devices.tailscale_ip),
            agent_version = excluded.agent_version,
            status = 'online',
            last_seen = CURRENT_TIMESTAMP
    ''', (dto.id, dto.name, dto.os, dto.lan_ip, dto.tailscale_ip, dto.agent_version))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Device registered", "device_id": dto.id}

@app.get("/api/pair/new-code")
async def generate_pairing_code():
    code = ''.join(random.choices(string.digits, k=6))
    return {"success": True, "pair_code": code}

@app.websocket("/ws/agent/{device_id}")
async def agent_websocket_endpoint(websocket: WebSocket, device_id: str):
    await manager.connect_agent(device_id, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                action = msg.get("action")
                payload = msg.get("payload", {})
                if action == "telemetry":
                    live_telemetry[device_id] = payload
                    t_ip = payload.get("tailscale_ip")
                    if t_ip:
                        conn = sqlite3.connect(DB_PATH)
                        c = conn.cursor()
                        c.execute("UPDATE devices SET tailscale_ip = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?", (t_ip, device_id))
                        conn.commit()
                        conn.close()
            except Exception as e:
                print(f"Error parsing agent WS message: {e}")
    except WebSocketDisconnect:
        manager.disconnect_agent(device_id)

@app.post("/api/agent/telemetry")
async def report_telemetry(report: TelemetryReportDto):
    dev_id = report.device_id
    live_telemetry[dev_id] = {
        "processes": report.processes,
        "users": report.users,
        "installed_apps": report.installed_apps,
        "tailscale_ip": report.tailscale_ip
    }

    # Persist cache files for users and installed apps
    try:
        if report.users:
            with open(os.path.join(DATA_DIR, f"users_{dev_id}.json"), "w", encoding="utf-8") as f:
                json.dump(report.users, f)
        if report.installed_apps:
            with open(os.path.join(DATA_DIR, f"installed_{dev_id}.json"), "w", encoding="utf-8") as f:
                json.dump(report.installed_apps, f)
    except Exception:
        pass

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if report.tailscale_ip:
        c.execute("UPDATE devices SET tailscale_ip = ?, status = 'online', last_seen = CURRENT_TIMESTAMP WHERE id = ?", (report.tailscale_ip, dev_id))
    else:
        c.execute("UPDATE devices SET status = 'online', last_seen = CURRENT_TIMESTAMP WHERE id = ?", (dev_id,))
    conn.commit()
    conn.close()

    return {"success": True}

# -------------------------------------------------------------------
# Static Web Dashboard, Direct Client Installers & PWA Serving
# -------------------------------------------------------------------
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.mount("/downloads", StaticFiles(directory=DOWNLOADS_DIR), name="downloads")

@app.get("/download/mac")
@app.head("/download/mac")
async def download_mac_client():
    dmg_file = os.path.join(DOWNLOADS_DIR, "AppShield-macOS.dmg")
    if os.path.exists(dmg_file):
        return FileResponse(dmg_file, filename="AppShield-macOS.dmg", media_type="application/x-apple-diskimage")
    zip_file = os.path.join(DOWNLOADS_DIR, "AppShield-macOS.zip")
    if os.path.exists(zip_file):
        return FileResponse(zip_file, filename="AppShield-macOS.zip", media_type="application/zip")
    raise HTTPException(status_code=404, detail="macOS installer not found on server")

@app.get("/download/windows")
@app.head("/download/windows")
async def download_windows_client():
    exe_file = os.path.join(DOWNLOADS_DIR, "AppShield-Setup.exe")
    if os.path.exists(exe_file):
        return FileResponse(exe_file, filename="AppShield-Setup.exe", media_type="application/vnd.microsoft.portable-executable")
    zip_file = os.path.join(DOWNLOADS_DIR, "AppShield-Windows-Install.zip")
    if os.path.exists(zip_file):
        return FileResponse(zip_file, filename="AppShield-Windows-Install.zip", media_type="application/zip")
    raise HTTPException(status_code=404, detail="Windows installer not found on server")

@app.get("/")
async def serve_dashboard():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file, headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        })
    return {"status": "ok", "message": "AppShield Central Cloud Server Running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=False)
