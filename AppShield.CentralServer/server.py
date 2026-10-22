import os
import json
import random
import string
import sqlite3
import datetime
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

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

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
DATA_DIR = os.path.join(BASE_DIR, "data")
DOWNLOADS_DIR = os.path.join(BASE_DIR, "downloads")
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(DOWNLOADS_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "appshield.db")

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
            agent_version TEXT,
            status TEXT DEFAULT 'online',
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            pair_code TEXT
        )
    ''')
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
    try:
        c.execute("ALTER TABLE dns_settings ADD COLUMN primary_ipv6 TEXT DEFAULT '2606:4700:4700::1111'")
    except Exception:
        pass
    try:
        c.execute("ALTER TABLE dns_settings ADD COLUMN secondary_ipv6 TEXT DEFAULT '2606:4700:4700::1001'")
    except Exception:
        pass
    c.execute('''
        CREATE TABLE IF NOT EXISTS global_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# -------------------------------------------------------------------
# WebSocket Connection Manager for Real-Time Endpoints
# -------------------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self.active_agents: Dict[str, WebSocket] = {}

    async def connect_agent(self, device_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_agents[device_id] = websocket
        self._update_status(device_id, "online")

    def disconnect_agent(self, device_id: str):
        if device_id in self.active_agents:
            del self.active_agents[device_id]
        self._update_status(device_id, "offline")

    def _update_status(self, device_id: str, status: str):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("UPDATE devices SET status = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?", (status, device_id))
            conn.commit()
            conn.close()
        except Exception:
            pass

    async def send_command(self, device_id: str, command: Dict[str, Any]) -> bool:
        if device_id in self.active_agents:
            await self.active_agents[device_id].send_text(json.dumps(command))
            return True
        return False

manager = ConnectionManager()

# In-memory cache for live telemetry
live_telemetry: Dict[str, Dict[str, Any]] = {}

# -------------------------------------------------------------------
# Pydantic Request Models
# -------------------------------------------------------------------
class DeviceRegisterDto(BaseModel):
    id: str
    name: str
    os: Optional[str] = "Windows 11"
    lan_ip: Optional[str] = "127.0.0.1"
    agent_version: Optional[str] = "1.2.0"

class TelemetryReportDto(BaseModel):
    device_id: str
    processes: List[Dict[str, Any]] = []
    users: List[Dict[str, Any]] = []
    installed_apps: List[Dict[str, Any]] = []

class CommandDto(BaseModel):
    action: str  # "kill_process", "block_app", "set_schedule", "create_user"
    payload: Dict[str, Any]

class RuleCreateDto(BaseModel):
    device_id: str
    rule_type: str  # "AllowedWindow", "BlockPath"
    target_process: Optional[str] = ""
    target_path: Optional[str] = ""
    schedule_start: Optional[str] = "12:00"
    schedule_end: Optional[str] = "20:00"
    is_enabled: bool = True

class DnsSettingsDto(BaseModel):
    preset: str = "cloudflare_public"  # "cloudflare_public", "cloudflare_family", "adguard_family", "cleanbrowsing", "quad9", "opendns_family", "custom", "disabled"
    primary_dns: Optional[str] = "1.1.1.1"
    secondary_dns: Optional[str] = "1.0.0.1"
    primary_ipv6: Optional[str] = ""
    secondary_ipv6: Optional[str] = ""
    is_enabled: bool = True
    apply_to_all: Optional[bool] = False

# -------------------------------------------------------------------
# Device & Pairing Endpoints
# -------------------------------------------------------------------
@app.get("/api/fleet")
async def get_fleet():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM devices ORDER BY last_seen DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"success": True, "data": rows}

@app.post("/api/devices/register")
async def register_device(dev: DeviceRegisterDto):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO devices (id, name, os, lan_ip, agent_version, status, last_seen)
        VALUES (?, ?, ?, ?, ?, 'online', CURRENT_TIMESTAMP)
        ON CONFLICT(id) DO UPDATE SET
            name = excluded.name,
            lan_ip = excluded.lan_ip,
            agent_version = excluded.agent_version,
            status = 'online',
            last_seen = CURRENT_TIMESTAMP
    ''', (dev.id, dev.name, dev.os, dev.lan_ip, dev.agent_version))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Device registered", "device_id": dev.id}

@app.get("/api/pair/new-code")
async def generate_pair_code():
    code = f"{random.randint(100, 999)}-{random.randint(100, 999)}"
    return {"success": True, "pair_code": code}

# -------------------------------------------------------------------
# Agent Telemetry & WebSocket Relay
# -------------------------------------------------------------------
@app.websocket("/ws/agent/{device_id}")
async def agent_websocket(websocket: WebSocket, device_id: str):
    await manager.connect_agent(device_id, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                payload = json.loads(data)
                # Store live telemetry (processes, users, stats)
                live_telemetry[device_id] = payload
                if payload.get("installed_apps"):
                    try:
                        with open(os.path.join(DATA_DIR, f"installed_{device_id}.json"), "w", encoding="utf-8") as f:
                            json.dump(payload["installed_apps"], f)
                    except Exception:
                        pass
            except Exception:
                pass
    except WebSocketDisconnect:
        manager.disconnect_agent(device_id)

@app.post("/api/agent/telemetry")
async def report_telemetry(report: TelemetryReportDto):
    live_telemetry[report.device_id] = {
        "processes": report.processes,
        "users": report.users,
        "installed_apps": report.installed_apps,
        "updated_at": datetime.datetime.utcnow().isoformat()
    }
    if report.installed_apps:
        try:
            with open(os.path.join(DATA_DIR, f"installed_{report.device_id}.json"), "w", encoding="utf-8") as f:
                json.dump(report.installed_apps, f)
        except Exception:
            pass
    return {"success": True}

# -------------------------------------------------------------------
# Parent Remote Control APIs (Invoked from Android / iOS / Mac)
# -------------------------------------------------------------------
def apply_db_user_policies(device_id: str, users: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT sid, is_managed, block_user_writable_directories FROM user_policies WHERE device_id = ?", (device_id,))
        policies = {r["sid"]: r for r in c.fetchall()}
        conn.close()
    except Exception:
        policies = {}

    for u in users:
        is_admin = u.get("isAdmin") or (u.get("accountType") == "Administrator") or (u.get("username") == "rashidsheikh")
        u["isAdmin"] = is_admin
        if is_admin:
            u["accountType"] = "Administrator"

        sid = u.get("sid")
        if sid in policies:
            pol = policies[sid]
            u["isManaged"] = bool(pol["is_managed"])
            u["blockUserWritableDirectories"] = bool(pol["block_user_writable_directories"])
        else:
            if is_admin:
                u["isManaged"] = False
                u["blockUserWritableDirectories"] = False
            else:
                u["isManaged"] = True
                u["blockUserWritableDirectories"] = True
    return users

@app.get("/api/nodes/{device_id}/processes")
async def get_node_processes(device_id: str):
    dev_data = live_telemetry.get(device_id, {})
    return {"success": True, "data": dev_data.get("processes", [])}

@app.get("/api/nodes/{device_id}/users")
async def get_node_users(device_id: str):
    dev_data = live_telemetry.get(device_id, {})
    users = dev_data.get("users", [])
    if not users:
        cache_file = os.path.join(DATA_DIR, f"users_{device_id}.json")
        if os.path.exists(cache_file):
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    users = json.load(f)
            except Exception:
                pass
    users = apply_db_user_policies(device_id, users)
    return {"success": True, "data": users}

@app.get("/api/nodes/{device_id}/installed_apps")
@app.get("/api/nodes/{device_id}/installed-apps")
async def get_node_installed_apps(device_id: str):
    dev_data = live_telemetry.get(device_id, {})
    apps = dev_data.get("installed_apps", [])
    if not apps:
        # Check disk cache
        cache_file = os.path.join(DATA_DIR, f"installed_{device_id}.json")
        if os.path.exists(cache_file):
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    apps = json.load(f)
                    dev_data["installed_apps"] = apps
            except Exception:
                pass

    # Asynchronously nudge agent to scan apps if empty
    if not apps:
        await manager.send_command(device_id, {"action": "scan_installed_apps", "payload": {}})

    return {"success": True, "data": apps}

@app.post("/api/nodes/{device_id}/command")
async def send_node_command(device_id: str, cmd: CommandDto):
    sent = await manager.send_command(device_id, {"action": cmd.action, "payload": cmd.payload})
    return {"success": sent, "message": "Command dispatched to endpoint" if sent else "Device offline or disconnected"}

@app.delete("/api/nodes/{device_id}/processes/{pid:int}")
@app.post("/api/nodes/{device_id}/kill_process")
async def kill_node_process(device_id: str, pid: Optional[int] = None, payload: Optional[Dict[str, Any]] = None):
    target_pid = pid if pid is not None else (payload.get("pid") if payload else None)
    sent = await manager.send_command(device_id, {"action": "kill_process", "payload": {"pid": target_pid}})
    return {"success": True, "message": f"Kill order sent for PID {target_pid}"}

@app.post("/api/nodes/{device_id}/override")
async def override_node(device_id: str, req: Dict[str, Any]):
    proc = req.get("processName") or req.get("process_name") or "Application"
    minutes = req.get("minutes", 60)
    sent = await manager.send_command(device_id, {
        "action": "grant_override",
        "payload": {"process_name": proc, "minutes": minutes}
    })
    return {"success": True, "message": f"Override granted for {proc} ({minutes}m)"}

@app.post("/api/nodes/{device_id}/lock")
async def lock_node_screen(device_id: str):
    sent = await manager.send_command(device_id, {"action": "lock_device", "payload": {}})
    return {"success": sent, "message": "Screen lock dispatched"}

@app.post("/api/nodes/{device_id}/users/manage")
async def manage_node_user(device_id: str, payload: Dict[str, Any]):
    sid = payload.get("sid")
    is_managed = 1 if payload.get("isManaged") else 0
    block_dirs = 1 if payload.get("blockUserWritableDirectories") else 0

    if sid:
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('''
                INSERT INTO user_policies (device_id, sid, is_managed, block_user_writable_directories, updated_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(device_id, sid) DO UPDATE SET
                    is_managed = excluded.is_managed,
                    block_user_writable_directories = excluded.block_user_writable_directories,
                    updated_at = CURRENT_TIMESTAMP
            ''', (device_id, sid, is_managed, block_dirs))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[-] DB error saving user policy: {e}")

    # Immediately reflect on live_telemetry
    if device_id in live_telemetry and "users" in live_telemetry[device_id]:
        live_telemetry[device_id]["users"] = apply_db_user_policies(device_id, live_telemetry[device_id]["users"])

    sent = await manager.send_command(device_id, {"action": "manage_user", "payload": payload})
    return {"success": True, "message": "User policy saved and dispatched"}

@app.post("/api/nodes/{device_id}/system/open-account-settings")
async def open_node_account_settings(device_id: str):
    sent = await manager.send_command(device_id, {"action": "open_account_settings", "payload": {}})
    return {"success": True, "message": "Dispatched request to open Account Settings"}

# -------------------------------------------------------------------
# Rules & Schedules (12pm-8pm)
# -------------------------------------------------------------------
@app.get("/api/nodes/{device_id}/rules")
async def get_node_rules(device_id: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM rules WHERE device_id = ?", (device_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"success": True, "data": rows}

@app.post("/api/nodes/{device_id}/rules")
async def add_node_rule(device_id: str, rule: RuleCreateDto):
    rule_id = f"rule_{random.randint(10000, 99999)}"
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO rules (id, device_id, rule_type, target_process, target_path, schedule_start, schedule_end, is_enabled)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (rule_id, device_id, rule.rule_type, rule.target_process, rule.target_path, rule.schedule_start, rule.schedule_end, 1 if rule.is_enabled else 0))
    conn.commit()
    conn.close()

    # Immediately push rule update to connected agent
    await manager.send_command(device_id, {"action": "sync_rules", "payload": {"rule_id": rule_id}})
    return {"success": True, "rule_id": rule_id}

@app.delete("/api/nodes/{device_id}/rules/{rule_id}")
async def delete_node_rule(device_id: str, rule_id: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM rules WHERE id = ? AND device_id = ?", (rule_id, device_id))
    conn.commit()
    conn.close()
    await manager.send_command(device_id, {"action": "sync_rules", "payload": {}})
    return {"success": True}

# -------------------------------------------------------------------
# Audit & Intercept Logs
# -------------------------------------------------------------------
@app.get("/api/nodes/{device_id}/logs")
async def get_node_logs(device_id: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM audit_logs WHERE device_id = ? ORDER BY timestamp DESC LIMIT 100", (device_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"success": True, "data": rows}

@app.post("/api/nodes/{device_id}/logs")
async def post_audit_log(device_id: str, payload: Dict[str, Any]):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO audit_logs (device_id, event_type, executable_path, username, action_taken)
        VALUES (?, ?, ?, ?, ?)
    ''', (device_id, payload.get("event_type", "BLOCKED"), payload.get("executable_path", ""), payload.get("username", "Child"), payload.get("action_taken", "TERMINATED")))
    conn.commit()
    conn.close()
    return {"success": True}

# -------------------------------------------------------------------
# Family DNS & Content Shield (Adult / Nudity Filtering)
# -------------------------------------------------------------------
@app.get("/api/nodes/{device_id}/dns")
async def get_node_dns(device_id: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM dns_settings WHERE device_id = ?", (device_id,))
    row = c.fetchone()
    c.execute("SELECT value FROM global_settings WHERE key = 'fleet_dns_apply_to_all'")
    g_row = c.fetchone()
    apply_to_all_val = (g_row is not None and g_row[0] == '1')
    conn.close()
    if row:
        data = dict(row)
        data["apply_to_all"] = 1 if apply_to_all_val else 0
        return {"success": True, "data": data}
    return {
        "success": True,
        "data": {
            "device_id": device_id,
            "preset": "cloudflare_public",
            "primary_dns": "1.1.1.1",
            "secondary_dns": "1.0.0.1",
            "primary_ipv6": "2606:4700:4700::1111",
            "secondary_ipv6": "2606:4700:4700::1001",
            "is_enabled": 1,
            "apply_to_all": 1 if apply_to_all_val else 0
        }
    }

class ToggleFleetDnsDto(BaseModel):
    apply_to_all: bool

@app.post("/api/settings/fleet-dns-toggle")
async def toggle_fleet_dns(dto: ToggleFleetDnsDto):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO global_settings (key, value, updated_at)
        VALUES ('fleet_dns_apply_to_all', ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
    ''', ('1' if dto.apply_to_all else '0',))
    conn.commit()
    conn.close()
    return {"success": True, "apply_to_all": dto.apply_to_all}

@app.post("/api/nodes/{device_id}/dns")
async def set_node_dns(device_id: str, dto: DnsSettingsDto):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Save fleet_dns_apply_to_all state permanently
    c.execute('''
        INSERT INTO global_settings (key, value, updated_at)
        VALUES ('fleet_dns_apply_to_all', ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
    ''', ('1' if dto.apply_to_all else '0',))

    target_devices = [device_id]
    if dto.apply_to_all:
        c.execute("SELECT id FROM devices")
        target_devices = [r[0] for r in c.fetchall()]
        if device_id not in target_devices:
            target_devices.append(device_id)

    for dev_id in target_devices:
        c.execute('''
            INSERT INTO dns_settings (device_id, preset, primary_dns, secondary_dns, primary_ipv6, secondary_ipv6, is_enabled, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(device_id) DO UPDATE SET
                preset = excluded.preset,
                primary_dns = excluded.primary_dns,
                secondary_dns = excluded.secondary_dns,
                primary_ipv6 = excluded.primary_ipv6,
                secondary_ipv6 = excluded.secondary_ipv6,
                is_enabled = excluded.is_enabled,
                updated_at = CURRENT_TIMESTAMP
        ''', (dev_id, dto.preset, dto.primary_dns, dto.secondary_dns, dto.primary_ipv6 or '', dto.secondary_ipv6 or '', 1 if dto.is_enabled else 0))

        # Push command to connected agent
        await manager.send_command(dev_id, {
            "action": "set_dns_filter",
            "payload": {
                "preset": dto.preset,
                "primary_dns": dto.primary_dns,
                "secondary_dns": dto.secondary_dns,
                "primary_ipv6": dto.primary_ipv6 or '',
                "secondary_ipv6": dto.secondary_ipv6 or '',
                "is_enabled": 1 if dto.is_enabled else 0
            }
        })

        # Add audit log
        c.execute('''
            INSERT INTO audit_logs (device_id, event_type, executable_path, username, action_taken)
            VALUES (?, 'DNS_SHIELD', ?, 'ParentAdmin', ?)
        ''', (dev_id, f"Preset: {dto.preset} ({dto.primary_dns})", "ACTIVE" if dto.is_enabled else "DISABLED"))

    conn.commit()
    conn.close()
    return {
        "success": True,
        "message": f"DNS filter settings updated for {'all devices' if dto.apply_to_all else device_id}"
    }

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
