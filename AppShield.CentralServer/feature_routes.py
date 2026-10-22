import os
import json
import random
import sqlite3
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException
from core_state import (
    DB_PATH,
    DATA_DIR,
    manager,
    live_telemetry,
    apply_db_user_policies,
    CommandDto,
    RuleCreateDto,
    BatchRuleCreateDto,
    DnsSettingsDto,
    ToggleFleetDnsDto
)

router = APIRouter(prefix="/api", tags=["Parental Features"])

# ===================================================================
# 1. Active Applications & Process Control
# ===================================================================
@router.get("/nodes/{device_id}/processes")
async def get_node_processes(device_id: str):
    dev_data = live_telemetry.get(device_id, {})
    return {"success": True, "data": dev_data.get("processes", [])}

@router.delete("/nodes/{device_id}/processes/{pid:int}")
@router.post("/nodes/{device_id}/kill_process")
async def kill_node_process(device_id: str, pid: Optional[int] = None, payload: Optional[Dict[str, Any]] = None):
    target_pid = pid if pid is not None else (payload.get("pid") if payload else None)
    sent = await manager.send_command(device_id, {"action": "kill_process", "payload": {"pid": target_pid}})
    return {"success": True, "message": f"Kill order sent for PID {target_pid}"}

@router.post("/nodes/{device_id}/override")
async def override_node(device_id: str, req: Dict[str, Any]):
    proc = req.get("processName") or req.get("process_name") or "Application"
    minutes = req.get("minutes", 60)
    sent = await manager.send_command(device_id, {
        "action": "grant_override",
        "payload": {"process_name": proc, "minutes": minutes}
    })
    return {"success": True, "message": f"Override granted for {proc} ({minutes}m)"}

@router.post("/nodes/{device_id}/lock")
async def lock_node_screen(device_id: str):
    sent = await manager.send_command(device_id, {"action": "lock_device", "payload": {}})
    return {"success": sent, "message": "Screen lock dispatched"}

@router.post("/nodes/{device_id}/command")
async def send_node_command(device_id: str, cmd: CommandDto):
    sent = await manager.send_command(device_id, {"action": cmd.action, "payload": cmd.payload})
    return {"success": sent, "message": "Command dispatched to endpoint" if sent else "Device offline or disconnected"}

# ===================================================================
# 2. Child User Accounts & Path Jail
# ===================================================================
@router.get("/nodes/{device_id}/users")
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

@router.post("/nodes/{device_id}/users/manage")
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

@router.post("/nodes/{device_id}/system/open-account-settings")
async def open_node_account_settings(device_id: str):
    sent = await manager.send_command(device_id, {"action": "open_account_settings", "payload": {}})
    return {"success": True, "message": "Dispatched request to open Account Settings"}

# ===================================================================
# 3. Installed Applications Catalog
# ===================================================================
@router.get("/nodes/{device_id}/installed_apps")
@router.get("/nodes/{device_id}/installed-apps")
async def get_node_installed_apps(device_id: str):
    dev_data = live_telemetry.get(device_id, {})
    apps = dev_data.get("installed_apps", [])
    if not apps:
        cache_file = os.path.join(DATA_DIR, f"installed_{device_id}.json")
        if os.path.exists(cache_file):
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    apps = json.load(f)
                    dev_data["installed_apps"] = apps
            except Exception:
                pass

    if not apps:
        await manager.send_command(device_id, {"action": "scan_installed_apps", "payload": {}})

    return {"success": True, "data": apps}

# ===================================================================
# 4. Rules & Curfew Schedules (Roblox, Steam, Bedtime Windows)
# ===================================================================
@router.get("/nodes/{device_id}/rules")
async def get_node_rules(device_id: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM rules WHERE device_id = ?", (device_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"success": True, "data": rows}

@router.post("/nodes/{device_id}/rules")
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

    await manager.send_command(device_id, {"action": "sync_rules", "payload": {"rule_id": rule_id}})
    return {"success": True, "rule_id": rule_id}

@router.post("/nodes/{device_id}/rules/batch")
async def add_batch_rules(device_id: str, dto: BatchRuleCreateDto):
    created_ids = []
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    for app in dto.apps:
        clean_app = app.strip()
        if not clean_app:
            continue
        c.execute("DELETE FROM rules WHERE device_id = ? AND target_process = ?", (device_id, clean_app))
        rule_id = f"rule_{random.randint(10000, 99999)}"
        c.execute('''
            INSERT INTO rules (id, device_id, rule_type, target_process, target_path, schedule_start, schedule_end, is_enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (rule_id, device_id, dto.rule_type, clean_app, dto.target_path or '', dto.schedule_start, dto.schedule_end, 1 if dto.is_enabled else 0))
        created_ids.append(rule_id)
    conn.commit()
    conn.close()

    await manager.send_command(device_id, {"action": "sync_rules", "payload": {"rule_ids": created_ids}})
    return {"success": True, "created_count": len(created_ids), "rule_ids": created_ids}

@router.delete("/nodes/{device_id}/rules/{rule_id}")
async def delete_node_rule(device_id: str, rule_id: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM rules WHERE id = ? AND device_id = ?", (rule_id, device_id))
    conn.commit()
    conn.close()
    await manager.send_command(device_id, {"action": "sync_rules", "payload": {}})
    return {"success": True}

# ===================================================================
# 5. Audit & Activity Logs
# ===================================================================
@router.get("/nodes/{device_id}/logs")
async def get_node_logs(device_id: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM audit_logs WHERE device_id = ? ORDER BY timestamp DESC LIMIT 100", (device_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"success": True, "data": rows}

@router.post("/nodes/{device_id}/logs")
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

# ===================================================================
# 6. Family Web & DNS Shield (SafeSearch, Nudity & Malware Protection)
# ===================================================================
@router.get("/nodes/{device_id}/dns")
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

@router.post("/settings/fleet-dns-toggle")
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

@router.post("/nodes/{device_id}/dns")
async def set_node_dns(device_id: str, dto: DnsSettingsDto):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
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
        ''', (
            dev_id,
            dto.preset,
            dto.primary_dns or '',
            dto.secondary_dns or '',
            dto.primary_ipv6 or '',
            dto.secondary_ipv6 or '',
            1 if dto.is_enabled else 0
        ))
    conn.commit()
    conn.close()

    dns_payload = {
        "preset": dto.preset,
        "primary_dns": dto.primary_dns,
        "secondary_dns": dto.secondary_dns,
        "primary_ipv6": dto.primary_ipv6,
        "secondary_ipv6": dto.secondary_ipv6,
        "is_enabled": dto.is_enabled
    }
    for dev_id in target_devices:
        await manager.send_command(dev_id, {"action": "apply_dns", "payload": dns_payload})

    return {"success": True, "message": f"DNS settings applied to {len(target_devices)} endpoint(s)"}
