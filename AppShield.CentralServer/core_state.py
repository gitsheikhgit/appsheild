import os
import json
import sqlite3
import hashlib
import secrets
from typing import Dict, Any, List, Optional
from fastapi import WebSocket, Request
from pydantic import BaseModel

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
DATA_DIR = os.path.join(BASE_DIR, "data")
DOWNLOADS_DIR = os.path.join(BASE_DIR, "downloads")

os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(DOWNLOADS_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "appshield.db")

# -------------------------------------------------------------------
# Security & Hash Helpers
# -------------------------------------------------------------------
def hash_password(password: str, salt: Optional[str] = None) -> tuple:
    if not salt:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    ).hex()
    return pw_hash, salt

def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    computed_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(computed_hash, stored_hash)

def get_session_from_request(request: Request) -> Optional[dict]:
    token = request.cookies.get("appshield_session")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
    if not token:
        return None

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('''
            SELECT token, username, expires_at 
            FROM admin_sessions 
            WHERE token = ? AND expires_at > CURRENT_TIMESTAMP
        ''', (token,))
        row = c.fetchone()
        conn.close()
        if row:
            return dict(row)
    except Exception:
        pass
    return None

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
# Shared Policy Helpers
# -------------------------------------------------------------------
def apply_db_user_policies(device_id: str, users: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT sid, is_managed, block_user_writable_directories FROM user_policies WHERE device_id = ?", (device_id,))
    rows = {r["sid"]: r for r in c.fetchall()}
    conn.close()

    for u in users:
        sid = u.get("sid")
        if sid in rows:
            u["isManaged"] = bool(rows[sid]["is_managed"])
            u["blockUserWritableDirectories"] = bool(rows[sid]["block_user_writable_directories"])
        elif not u.get("isAdmin"):
            # By default standard accounts are managed
            if "isManaged" not in u:
                u["isManaged"] = True
                u["blockUserWritableDirectories"] = True
    return users

# -------------------------------------------------------------------
# Pydantic DTOs
# -------------------------------------------------------------------
class DeviceRegisterDto(BaseModel):
    id: str
    name: str
    os: Optional[str] = "Windows 11"
    lan_ip: Optional[str] = "127.0.0.1"
    tailscale_ip: Optional[str] = None
    agent_version: Optional[str] = "1.3.0"
    psk: Optional[str] = None

class DeviceUnregisterDto(BaseModel):
    device_id: str
    reason: Optional[str] = "uninstalled"

class TelemetryReportDto(BaseModel):
    device_id: str
    tailscale_ip: Optional[str] = None
    processes: List[Dict[str, Any]] = []
    users: List[Dict[str, Any]] = []
    installed_apps: List[Dict[str, Any]] = []

class CommandDto(BaseModel):
    action: str
    payload: Dict[str, Any]

class RuleCreateDto(BaseModel):
    device_id: Optional[str] = ""
    rule_type: str = "AllowedWindow"
    target_process: Optional[str] = ""
    target_path: Optional[str] = ""
    schedule_start: Optional[str] = "12:00"
    schedule_end: Optional[str] = "20:00"
    is_enabled: bool = True

class BatchRuleCreateDto(BaseModel):
    apps: List[str]
    rule_type: str = "AllowedWindow"
    schedule_start: Optional[str] = "12:00"
    schedule_end: Optional[str] = "20:00"
    is_enabled: bool = True
    target_path: Optional[str] = ""

class DnsSettingsDto(BaseModel):
    preset: str = "cloudflare_public"
    primary_dns: Optional[str] = "1.1.1.1"
    secondary_dns: Optional[str] = "1.0.0.1"
    primary_ipv6: Optional[str] = ""
    secondary_ipv6: Optional[str] = ""
    is_enabled: bool = True
    apply_to_all: Optional[bool] = False

class ToggleFleetDnsDto(BaseModel):
    apply_to_all: bool

class LoginDto(BaseModel):
    username: str
    password: str

class ChangePasswordDto(BaseModel):
    current_password: str
    new_password: str

class DeviceUpdateDto(BaseModel):
    name: Optional[str] = None
    lan_ip: Optional[str] = None
    tailscale_ip: Optional[str] = None
    psk: Optional[str] = None
