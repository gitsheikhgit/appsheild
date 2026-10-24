import os
import sqlite3
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from tailscale_manager import TailscaleManager
from core_state import (
    DB_PATH,
    DeviceUpdateDto,
    hash_password,
    verify_password,
    get_session_from_request
)

router = APIRouter(prefix="/api", tags=["Settings & Infrastructure"])

# ===================================================================
# 1. Tailscale Remote Mesh Management
# ===================================================================
@router.get("/tailscale/status")
async def get_tailscale_status():
    """Returns current status of Tailscale on the Central Server."""
    data = await TailscaleManager.get_status()
    is_running = (data.get("backend_state") == "Running") or bool(data.get("tailscale_ip"))
    data["running"] = is_running
    data["ip"] = data.get("tailscale_ip") or ""
    return {"success": True, "data": data}

@router.post("/tailscale/install")
async def install_tailscale():
    """Triggers automated 1-click installation of Tailscale on Linux/Ubuntu."""
    res = await TailscaleManager.install()
    return res

@router.post("/tailscale/login")
async def login_tailscale():
    """Generates browser authorization URL for Tailscale sign-in / signup."""
    res = await TailscaleManager.login_or_up()
    return res

@router.get("/nodes/{device_id}/tailscale-probe")
async def probe_node_tailscale(device_id: str):
    """
    Returns the detected Tailscale IP and MagicDNS for a specific connected node
    from the database, active telemetry cache, or Tailscale peer network map.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, name, lan_ip, tailscale_ip FROM devices WHERE id = ?", (device_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Device not found")

    t_ip = row["tailscale_ip"]
    dns_name = ""

    # If missing from DB, query active Tailscale peer list
    if not t_ip or not str(t_ip).startswith("100."):
        import re
        ts_data = await TailscaleManager.get_status()
        peers = ts_data.get("peers", {})
        node_name_clean = re.sub(r"[^a-z0-9]", "", (row["name"] or "").lower())
        for hname, peer in peers.items():
            peer_name_clean = re.sub(r"[^a-z0-9]", "", hname)
            if peer_name_clean in node_name_clean or node_name_clean in peer_name_clean:
                t_ip = peer["ip"]
                dns_name = peer.get("dns_name", "")
                conn2 = sqlite3.connect(DB_PATH)
                c2 = conn2.cursor()
                c2.execute("UPDATE devices SET tailscale_ip = ? WHERE id = ?", (t_ip, device_id))
                conn2.commit()
                conn2.close()
                break

    return {
        "success": True,
        "device_id": device_id,
        "name": row["name"],
        "tailscale_ip": t_ip or "",
        "dns_name": dns_name or "",
        "detected": bool(t_ip and str(t_ip).startswith("100."))
    }

# ===================================================================
# 2. Fleet Node Configuration & Settings
# ===================================================================
@router.put("/fleet/{device_id}")
async def update_device_settings(device_id: str, dto: DeviceUpdateDto):
    """Updates node configuration (name, lan_ip, tailscale_ip, psk) in SQLite."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    try:
        c.execute("ALTER TABLE devices ADD COLUMN tailscale_ip TEXT")
    except Exception:
        pass
    try:
        c.execute("ALTER TABLE devices ADD COLUMN psk TEXT")
    except Exception:
        pass

    updates = []
    params = []
    if dto.name is not None:
        updates.append("name = ?")
        params.append(dto.name)
    if dto.lan_ip is not None:
        updates.append("lan_ip = ?")
        params.append(dto.lan_ip)
    if dto.tailscale_ip is not None:
        updates.append("tailscale_ip = ?")
        params.append(dto.tailscale_ip)
    if dto.psk is not None:
        updates.append("psk = ?")
        params.append(dto.psk)

    if updates:
        params.append(device_id)
        c.execute(f"UPDATE devices SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()

    conn.close()
    return {"success": True, "message": "Device configuration saved successfully."}

@router.delete("/fleet/{device_id}")
@router.post("/fleet/{device_id}/delete")
async def delete_device(device_id: str):
    """Removes a device and all its associated data from fleet management."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM rules WHERE device_id = ?", (device_id,))
    c.execute("DELETE FROM audit_logs WHERE device_id = ?", (device_id,))
    c.execute("DELETE FROM dns_settings WHERE device_id = ?", (device_id,))
    c.execute("DELETE FROM user_policies WHERE device_id = ?", (device_id,))
    c.execute("DELETE FROM devices WHERE id = ?", (device_id,))
    conn.commit()
    conn.close()

    try:
        from core_state import DATA_DIR, live_telemetry, manager
        live_telemetry.pop(device_id, None)
        manager.disconnect_agent(device_id)
        for fname in [f"users_{device_id}.json", f"installed_{device_id}.json"]:
            p = os.path.join(DATA_DIR, fname)
            if os.path.exists(p):
                try: os.remove(p)
                except Exception: pass
    except Exception:
        pass

    return {"success": True, "message": f"Device {device_id} removed from fleet."}

# ===================================================================
# 3. Server Setup & Proxmox LXC Installation Instructions
# ===================================================================
@router.get("/settings/server-setup")
async def get_server_setup_info():
    """
    Returns server deployment details and 1-line script for parents
    who wish to deploy or configure a central server later.
    """
    proxmox_command = "curl -fsSL https://raw.githubusercontent.com/gitsheikhgit/appsheild/main/install-on-proxmox-lxc.sh | bash"
    return {
        "success": True,
        "proxmox_command": proxmox_command,
        "default_port": 8000,
        "supported_os": ["Ubuntu 22.04 LTS", "Ubuntu 24.04 LTS", "Debian 12", "Proxmox LXC", "Docker"],
        "recommended_specs": "1 vCPU, 512 MB RAM, 4 GB Disk"
    }

# ===================================================================
# 4. Master Admin Security Credentials
# ===================================================================
class AdminPasswordUpdateDto(BaseModel):
    current_password: str
    new_password: str

@router.post("/settings/change-password")
async def change_admin_password(dto: AdminPasswordUpdateDto, request: Request):
    """Updates master portal administrative password."""
    session = get_session_from_request(request)
    if not session:
        raise HTTPException(status_code=401, detail="Unauthorized session")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash, salt FROM admin_auth WHERE id = 1")
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=500, detail="Auth not configured")

    stored_hash, salt = row
    if not verify_password(dto.current_password, salt, stored_hash):
        conn.close()
        raise HTTPException(status_code=400, detail="Incorrect current password")

    new_hash, new_salt = hash_password(dto.new_password)
    c.execute('''
        UPDATE admin_auth 
        SET password_hash = ?, salt = ?, must_change_password = 0, updated_at = CURRENT_TIMESTAMP
        WHERE id = 1
    ''', (new_hash, new_salt))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Master password updated successfully"}
