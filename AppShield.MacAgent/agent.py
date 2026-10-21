#!/usr/bin/env python3
"""
AppShield macOS Endpoint Protection & Parental Shield Agent
Version: 1.2.0

Features:
- Outbound encrypted WebSocket & REST telemetry to AppShield Central Server
- Real-time application monitoring & instant SIGKILL enforcement
- Curfew schedule enforcement (e.g. 12:00 PM - 8:00 PM allowed window)
- Standard Child Account detection & "Path Jail" (blocks downloads/desktop/USB exes)
- Remote process termination & instant screen lock from parent mobile app
- Native macOS banner notifications & audit log synchronization
"""

import os
import sys
import time
import json
import socket
import signal
import platform
import subprocess
import threading
import datetime
import urllib.request
import urllib.parse
from typing import Dict, Any, List, Optional

# Optional websockets support; graceful fallback to HTTP polling if unavailable
try:
    import websockets
    import asyncio
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False

# -----------------------------------------------------------------------------
# Configuration & Storage Paths
# -----------------------------------------------------------------------------
DEFAULT_SERVER_URL = "http://192.168.0.101:8000"
SYS_CONFIG_DIR = "/Library/Application Support/AppShield"
LOCAL_CONFIG_DIR = os.path.expanduser("~/.appshield")

def get_config_path() -> str:
    if os.geteuid() == 0:
        os.makedirs(SYS_CONFIG_DIR, exist_ok=True)
        return os.path.join(SYS_CONFIG_DIR, "agent_config.json")
    else:
        os.makedirs(LOCAL_CONFIG_DIR, exist_ok=True)
        return os.path.join(LOCAL_CONFIG_DIR, "agent_config.json")

def load_or_create_config() -> Dict[str, Any]:
    path = get_config_path()
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    # Create new configuration
    import uuid
    mac_id = f"mac_{uuid.uuid4().hex[:12]}"
    try:
        hostname = subprocess.check_output(["scutil", "--get", "ComputerName"], text=True).strip()
    except Exception:
        hostname = socket.gethostname()

    cfg = {
        "device_id": mac_id,
        "name": hostname,
        "server_url": DEFAULT_SERVER_URL,
        "rules": [
            {
                "id": "default_window",
                "rule_type": "AllowedWindow",
                "target_process": "Roblox",
                "schedule_start": "12:00",
                "schedule_end": "20:00",
                "is_enabled": 1
            },
            {
                "id": "default_steam",
                "rule_type": "AllowedWindow",
                "target_process": "steam",
                "schedule_start": "12:00",
                "schedule_end": "20:00",
                "is_enabled": 1
            }
        ],
        "managed_users": [],
        "path_jail_enabled": True
    }
    save_config(cfg)
    return cfg

def save_config(cfg: Dict[str, Any]):
    path = get_config_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        print(f"[!] Warning: Failed to save config to {path}: {e}")

# -----------------------------------------------------------------------------
# System Helpers: macOS User Accounts & Process Inspection
# -----------------------------------------------------------------------------
def get_primary_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def enumerate_macos_users() -> List[Dict[str, Any]]:
    """Enumerate human standard and admin user accounts on macOS (UID >= 501)."""
    users = []
    try:
        out = subprocess.check_output(["dscl", ".", "-list", "/Users", "UniqueID"], text=True)
        for line in out.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                username, uid_str = parts[0], parts[1]
                try:
                    uid = int(uid_str)
                    # Filter out system service accounts (daemon, nobody, _spotlight, etc.)
                    if uid >= 501 and not username.startswith("_"):
                        # Check admin membership
                        is_admin = False
                        try:
                            res = subprocess.run(
                                ["dsmemberutil", "checkmembership", "-U", username, "-G", "admin"],
                                capture_output=True, text=True
                            )
                            if "is a member" in res.stdout:
                                is_admin = True
                        except Exception:
                            pass

                        account_type = "Administrator" if is_admin else "Standard"
                        users.append({
                            "sid": f"uid_{uid}",
                            "username": username,
                            "accountType": account_type,
                            "isManaged": not is_admin,  # Standard child accounts are protected by default
                            "blockUserWritableDirectories": True,
                            "uid": uid
                        })
                except ValueError:
                    continue
    except Exception as e:
        print(f"[-] Error enumerating macOS users: {e}")

    return users

def enumerate_running_processes(managed_user_names: set) -> List[Dict[str, Any]]:
    """
    Scans macOS running processes, captures PIDs, process names, memory in MB,
    and identifies user-space applications.
    """
    processes = []
    try:
        # Run ps to get pid, user, rss (in KB), command path
        cmd = ["ps", "-axo", "pid,user,rss,comm"]
        out = subprocess.check_output(cmd, text=True)
        lines = out.strip().splitlines()
        
        for line in lines[1:]:  # skip header
            parts = line.strip().split(None, 3)
            if len(parts) < 4:
                continue

            pid_str, user, rss_str, path = parts[0], parts[1], parts[2], parts[3]
            try:
                pid = int(pid_str)
                if pid <= 1:
                    continue
                rss_kb = int(rss_str)
                mem_mb = round(rss_kb / 1024.0, 1)
            except ValueError:
                continue

            proc_name = os.path.basename(path)
            # Detect macOS .app bundles (e.g. Roblox.app/Contents/MacOS/RobloxPlayer)
            app_name = proc_name
            if ".app/" in path:
                app_part = path.split(".app/")[0] + ".app"
                app_name = os.path.basename(app_part)

            is_managed = user in managed_user_names

            processes.append({
                "pid": pid,
                "processName": app_name,
                "executablePath": path,
                "username": user,
                "memoryMB": mem_mb,
                "isManagedUser": is_managed,
                "domain": "macOS"
            })
    except Exception as e:
        print(f"[-] Error enumerating processes: {e}")

    return processes

# -----------------------------------------------------------------------------
# Enforcement Engine: Curfews, Blocklists, & Path Jail
# -----------------------------------------------------------------------------
class EnforcementEngine:
    def __init__(self, agent: "AppShieldMacAgent"):
        self.agent = agent
        self.active_overrides: Dict[str, datetime.datetime] = {}
        self.lock = threading.Lock()

    def add_override(self, process_name: str, minutes: int = 60):
        with self.lock:
            expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=minutes)
            self.active_overrides[process_name.lower()] = expiry
            print(f"[+] Override granted for {process_name} until {expiry} UTC")

    def is_override_active(self, process_name: str) -> bool:
        with self.lock:
            key = process_name.lower()
            if key in self.active_overrides:
                if datetime.datetime.utcnow() < self.active_overrides[key]:
                    return True
                else:
                    del self.active_overrides[key]
        return False

    def is_within_schedule(self, start_str: str, end_str: str) -> bool:
        """Checks if current local time is within HH:MM - HH:MM window."""
        try:
            now = datetime.datetime.now().time()
            sh, sm = map(int, start_str.split(":"))
            eh, em = map(int, end_str.split(":"))
            start_time = datetime.time(sh, sm)
            end_time = datetime.time(eh, em)

            if start_time <= end_time:
                return start_time <= now <= end_time
            else:
                # Spans midnight (e.g. 20:00 to 06:00)
                return now >= start_time or now <= end_time
        except Exception:
            return True

    def show_macos_notification(self, title: str, message: str):
        """Displays a native macOS banner alert."""
        try:
            clean_title = title.replace('"', '\\"')
            clean_msg = message.replace('"', '\\"')
            script = f'display notification "{clean_msg}" with title "{clean_title}"'
            subprocess.run(["osascript", "-e", script], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    def lock_mac_screen(self):
        """Locks the macOS display screen immediately."""
        try:
            # Method 1: CGSession suspend
            cgsession = "/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession"
            if os.path.exists(cgsession):
                subprocess.run([cgsession, "-suspend"], check=False)
            else:
                # Method 2: pmset sleepnow
                subprocess.run(["pmset", "displaysleepnow"], check=False)
        except Exception as e:
            print(f"[-] Failed to lock screen: {e}")

    def evaluate_and_enforce(self, processes: List[Dict[str, Any]]):
        """Checks every running process against rules and kills violations."""
        rules = self.agent.config.get("rules", [])
        path_jail = self.agent.config.get("path_jail_enabled", True)
        
        # Blocked directory indicators for path jail (kids downloading portable binaries)
        JAIL_PATHS = ["/Downloads/", "/Desktop/", "/tmp/", "/Volumes/"]

        for proc in processes:
            pid = proc["pid"]
            p_name = proc["processName"]
            p_path = proc["executablePath"]
            user = proc["username"]
            is_managed = proc["isManagedUser"]

            # If user is not managed (e.g. parent/admin), skip enforcement
            if not is_managed and user not in ["root", "system"]:
                continue

            # Check Overrides
            if self.is_override_active(p_name):
                continue

            # 1. Path Jail Check
            if path_jail and is_managed:
                for jail in JAIL_PATHS:
                    if jail.lower() in p_path.lower():
                        # Exclude legitimate OS app launches
                        if not p_path.startswith("/Applications") and not p_path.startswith("/System"):
                            self.kill_process(pid, p_name, user, p_path, "Path Jail: Blocked launch from unapproved location")
                            continue

            # 2. Rules Evaluation
            for rule in rules:
                if not rule.get("is_enabled", True):
                    continue

                target = rule.get("target_process", "").lower()
                if not target:
                    continue

                # Match process name or path
                if target in p_name.lower() or target in p_path.lower():
                    rtype = rule.get("rule_type", "AllowedWindow")

                    if rtype == "AllowedWindow":
                        s_start = rule.get("schedule_start", "12:00")
                        s_end = rule.get("schedule_end", "20:00")
                        if not self.is_within_schedule(s_start, s_end):
                            reason = f"Curfew: Allowed only between {s_start} and {s_end}"
                            self.kill_process(pid, p_name, user, p_path, reason)
                            break
                    elif rtype == "AlwaysBlock":
                        self.kill_process(pid, p_name, user, p_path, "Always Blocked by Parent")
                        break

    def kill_process(self, pid: int, name: str, user: str, path: str, reason: str):
        print(f"[!] ENFORCEMENT: Killing {name} (PID: {pid}, User: {user}) - {reason}")
        try:
            os.kill(pid, signal.SIGKILL)
            self.show_macos_notification("AppShield Parental Shield", f"Blocked {name}: {reason}")
            # Report audit log to central server
            self.agent.report_audit_log({
                "event_type": "BLOCKED",
                "executable_path": path,
                "username": user,
                "action_taken": f"TERMINATED: {reason}"
            })
        except ProcessLookupError:
            pass
        except PermissionError:
            print(f"[-] Permission denied killing PID {pid}. Ensure agent is running with sudo/root.")
        except Exception as e:
            print(f"[-] Error killing PID {pid}: {e}")

# -----------------------------------------------------------------------------
# Main Agent Controller
# -----------------------------------------------------------------------------
class AppShieldMacAgent:
    def __init__(self):
        self.config = load_or_create_config()
        self.device_id = self.config["device_id"]
        self.server_url = self.config.get("server_url", DEFAULT_SERVER_URL).rstrip("/")
        self.enforcer = EnforcementEngine(self)
        self.running = True
        self.managed_usernames = set()

    def update_managed_users_cache(self, users: List[Dict[str, Any]]):
        self.managed_usernames = {u["username"] for u in users if u.get("isManaged", False)}

    def register_with_server(self):
        url = f"{self.server_url}/api/devices/register"
        payload = {
            "id": self.device_id,
            "name": self.config.get("name", socket.gethostname()),
            "os": f"macOS {platform.mac_ver()[0]} ({platform.machine()})",
            "lan_ip": get_primary_ip(),
            "agent_version": "1.2.0"
        }
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5) as res:
                data = json.loads(res.read().decode("utf-8"))
                print(f"[+] Registered with Central Server: {data.get('message', 'OK')}")
        except Exception as e:
            print(f"[-] Could not reach Central Server for registration: {e}")

    def fetch_rules(self):
        url = f"{self.server_url}/api/nodes/{self.device_id}/rules"
        try:
            req = urllib.request.Request(url, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as res:
                data = json.loads(res.read().decode("utf-8"))
                if data.get("success"):
                    rules = data.get("data", [])
                    if rules:
                        self.config["rules"] = rules
                        save_config(self.config)
                        print(f"[+] Synchronized {len(rules)} rules from Central Server")
        except Exception as e:
            pass

    def report_audit_log(self, log_entry: Dict[str, Any]):
        url = f"{self.server_url}/api/nodes/{self.device_id}/logs"
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(log_entry).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=3)
        except Exception:
            pass

    def execute_inbound_command(self, cmd: Dict[str, Any]):
        """Dispatches commands arriving from Central Server / Parent Mobile App."""
        action = cmd.get("action")
        payload = cmd.get("payload", {})
        print(f"[+] Received command from Parent: {action}")

        if action == "kill_process":
            pid = payload.get("pid")
            if pid:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                    print(f"[+] Terminated process PID {pid} per parent request.")
                except Exception as e:
                    print(f"[-] Failed to kill process {pid}: {e}")

        elif action == "sync_rules":
            self.fetch_rules()

        elif action == "lock_device":
            self.enforcer.lock_mac_screen()
            print("[+] Device screen locked per parent request.")

        elif action == "grant_override":
            proc = payload.get("process_name", "")
            minutes = payload.get("minutes", 60)
            if proc:
                self.enforcer.add_override(proc, minutes)

    # -------------------------------------------------------------------------
    # WebSocket Client Loop (Instant real-time connection)
    # -------------------------------------------------------------------------
    async def websocket_loop(self):
        ws_url = self.server_url.replace("http://", "ws://").replace("https://", "wss://")
        endpoint = f"{ws_url}/ws/agent/{self.device_id}"
        print(f"[+] Connecting outbound WebSocket to {endpoint}...")

        while self.running:
            try:
                async with websockets.connect(endpoint, ping_interval=20, ping_timeout=20) as ws:
                    print("[+] WebSocket connected to AppShield Central Relay!")
                    while self.running:
                        # 1. Gather live telemetry
                        users = enumerate_macos_users()
                        self.update_managed_users_cache(users)
                        procs = enumerate_running_processes(self.managed_usernames)

                        # Enforce local rules
                        self.enforcer.evaluate_and_enforce(procs)

                        # Push telemetry
                        telemetry = {
                            "device_id": self.device_id,
                            "timestamp": datetime.datetime.utcnow().isoformat(),
                            "users": users,
                            "processes": procs
                        }
                        await ws.send(json.dumps(telemetry))

                        # Listen for commands with timeout
                        try:
                            msg = await asyncio.wait_for(ws.recv(), timeout=3.0)
                            data = json.loads(msg)
                            self.execute_inbound_command(data)
                        except asyncio.TimeoutError:
                            pass
            except Exception as e:
                print(f"[!] WebSocket disconnected ({e}). Reconnecting in 5s...")
                await asyncio.sleep(5)

    # -------------------------------------------------------------------------
    # HTTP Polling Fallback Loop (If websockets package is not installed)
    # -------------------------------------------------------------------------
    def http_polling_loop(self):
        print("[+] Running in HTTP Polling Mode (5s telemetry intervals)...")
        while self.running:
            try:
                users = enumerate_macos_users()
                self.update_managed_users_cache(users)
                procs = enumerate_running_processes(self.managed_usernames)

                # Local real-time curfew enforcement
                self.enforcer.evaluate_and_enforce(procs)

                # Send telemetry to server
                url = f"{self.server_url}/api/agent/telemetry"
                payload = {
                    "device_id": self.device_id,
                    "processes": procs,
                    "users": users,
                    "installed_apps": []
                }
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"}
                )
                urllib.request.urlopen(req, timeout=4)
            except Exception as e:
                pass

            time.sleep(3.0)

    def start(self):
        print("====================================================================")
        print("          AppShield macOS Endpoint Protection Agent v1.2.0          ")
        print("====================================================================")
        print(f" Device ID:    {self.device_id}")
        print(f" Target Hub:   {self.server_url}")
        print(f" Running As:   UID {os.geteuid()} ({'Root / Daemon' if os.geteuid() == 0 else 'User Session'})")
        print("====================================================================")

        self.register_with_server()
        self.fetch_rules()

        if HAS_WEBSOCKETS:
            try:
                asyncio.run(self.websocket_loop())
            except KeyboardInterrupt:
                print("\n[+] Agent stopped.")
        else:
            self.http_polling_loop()

if __name__ == "__main__":
    agent = AppShieldMacAgent()
    agent.start()
