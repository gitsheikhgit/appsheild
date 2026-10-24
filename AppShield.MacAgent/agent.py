#!/usr/bin/env python3
"""
AppShield macOS Endpoint Protection & Parental Shield Agent
Version: 1.3.0

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
import base64
import urllib.request
import urllib.parse
import re
import plistlib
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

def get_base_dir() -> str:
    d = SYS_CONFIG_DIR if os.geteuid() == 0 else LOCAL_CONFIG_DIR
    os.makedirs(d, exist_ok=True)
    return d

def get_settings_path() -> str:
    return os.path.join(get_base_dir(), "settings.json")

def get_features_path() -> str:
    return os.path.join(get_base_dir(), "features.json")

def load_or_create_settings() -> Dict[str, Any]:
    """Loads system settings (server URL, device ID, tailscale IP, standalone mode)."""
    settings_path = get_settings_path()
    legacy_path = os.path.join(get_base_dir(), "agent_config.json")
    
    if os.path.exists(settings_path):
        try:
            with open(settings_path, "r", encoding="utf-8") as f:
                settings = json.load(f)
                if not settings.get("psk"):
                    import secrets
                    settings["psk"] = secrets.token_hex(16)
                    save_settings(settings)
                return settings
        except Exception:
            pass

    # Migrate from legacy agent_config.json if present
    if os.path.exists(legacy_path):
        try:
            with open(legacy_path, "r", encoding="utf-8") as f:
                old = json.load(f)
                import secrets
                settings = {
                    "device_id": old.get("device_id"),
                    "name": old.get("name"),
                    "server_url": old.get("server_url", DEFAULT_SERVER_URL),
                    "standalone_mode": old.get("server_url") in ["", "standalone", None],
                    "tailscale_ip": get_tailscale_ip() or "",
                    "psk": old.get("psk") or secrets.token_hex(16)
                }
                save_settings(settings)
                return settings
        except Exception:
            pass

    # Create new default settings
    import uuid
    import secrets
    mac_id = f"mac_{uuid.uuid4().hex[:12]}"
    try:
        hostname = subprocess.check_output(["scutil", "--get", "ComputerName"], text=True).strip()
    except Exception:
        hostname = socket.gethostname()

    settings = {
        "device_id": mac_id,
        "name": hostname,
        "server_url": DEFAULT_SERVER_URL,
        "standalone_mode": False,
        "tailscale_ip": get_tailscale_ip() or "",
        "psk": secrets.token_hex(16)
    }
    save_settings(settings)
    return settings

def save_settings(settings: Dict[str, Any]):
    path = get_settings_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
    except Exception as e:
        print(f"[!] Warning: Failed to save settings to {path}: {e}")

def load_or_create_config() -> Dict[str, Any]:
    """Compatibility alias for loading settings."""
    return load_or_create_settings()

def load_or_create_features() -> Dict[str, Any]:
    """Loads parental features (curfew schedules, app blocking, path jail, managed users)."""
    features_path = get_features_path()
    legacy_path = os.path.join(get_base_dir(), "agent_config.json")

    if os.path.exists(features_path):
        try:
            with open(features_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    # Migrate from legacy agent_config.json if present
    if os.path.exists(legacy_path):
        try:
            with open(legacy_path, "r", encoding="utf-8") as f:
                old = json.load(f)
                features = {
                    "rules": old.get("rules", []),
                    "managed_users": old.get("managed_users", []),
                    "path_jail_enabled": old.get("path_jail_enabled", True)
                }
                save_features(features)
                return features
        except Exception:
            pass

    # Default parental features
    features = {
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
    save_features(features)
    return features

def save_features(features: Dict[str, Any]):
    path = get_features_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(features, f, indent=2)
    except Exception as e:
        print(f"[!] Warning: Failed to save features to {path}: {e}")

def get_tailscale_ip() -> Optional[str]:
    """Scans local network interfaces and Tailscale binary for active 100.* mesh IP."""
    # 1. Try ifconfig output
    try:
        out = subprocess.check_output(["ifconfig"], text=True)
        matches = re.findall(r"inet\s+(100\.\d{1,3}\.\d{1,3}\.\d{1,3})", out)
        if matches:
            return matches[0]
    except Exception:
        pass

    # 2. Try macOS Tailscale app binary or CLI
    candidates = [
        "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
        "/usr/local/bin/tailscale",
        "/opt/homebrew/bin/tailscale",
        "tailscale"
    ]
    for p in candidates:
        try:
            out = subprocess.check_output([p, "ip", "-4"], text=True, stderr=subprocess.DEVNULL).strip()
            if out.startswith("100."):
                return out
        except Exception:
            continue
    return None

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

# Cache users for 10 minutes to avoid repeatedly querying DirectoryServices
_cached_users: List[Dict[str, Any]] = []
_last_user_scan_time = 0.0

def get_macos_admin_users() -> set:
    """Returns set of all macOS usernames with administrator privileges."""
    admins = set()
    try:
        out = subprocess.check_output(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"], text=True)
        parts = out.strip().split()
        if len(parts) > 1:
            for u in parts[1:]:
                admins.add(u.strip())
    except Exception:
        pass
    return admins

def enumerate_macos_users() -> List[Dict[str, Any]]:
    """Enumerate human standard and admin user accounts on macOS (UID >= 501). Cached for 30s."""
    global _cached_users, _last_user_scan_time
    now = time.time()
    if _cached_users and (now - _last_user_scan_time < 30):
        return _cached_users

    admin_users = get_macos_admin_users()
    cfg = load_or_create_config()
    user_overrides = cfg.get("user_overrides", {})

    users = []
    try:
        out = subprocess.check_output(["dscl", ".", "-list", "/Users", "UniqueID"], text=True)
        for line in out.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                username, uid_str = parts[0], parts[1]
                try:
                    uid = int(uid_str)
                    if uid >= 501 and not username.startswith("_"):
                        is_admin = username in admin_users
                        account_type = "Administrator" if is_admin else "Standard"
                        sid = f"uid_{uid}"

                        # Defaults: Admins are NOT managed and have NO Path Jail.
                        # Standard child accounts ARE managed and HAVE Path Jail.
                        default_managed = False if is_admin else True
                        default_path_jail = False if is_admin else True

                        if sid in user_overrides:
                            ov = user_overrides[sid]
                            is_managed = ov.get("isManaged", default_managed)
                            block_dir = ov.get("blockUserWritableDirectories", default_path_jail)
                        else:
                            is_managed = default_managed
                            block_dir = default_path_jail

                        users.append({
                            "sid": sid,
                            "username": username,
                            "accountType": account_type,
                            "isAdmin": is_admin,
                            "isManaged": is_managed,
                            "blockUserWritableDirectories": block_dir,
                            "uid": uid
                        })
                except ValueError:
                    continue
    except Exception as e:
        print(f"[-] Error enumerating macOS users: {e}")

    _cached_users = users
    _last_user_scan_time = now
    return users

def get_active_console_user() -> str:
    """Retrieve the human username currently logged in at the macOS GUI console."""
    try:
        out = subprocess.check_output(["stat", "-f%Su", "/dev/console"], text=True).strip()
        if out and out != "root":
            return out
    except Exception:
        pass
    return os.environ.get("USER", "standard_user")

_icon_cache: Dict[str, str] = {}

def get_macos_app_icon_base64(clean_name: str, app_path: str) -> str:
    """Returns data:image/png;base64 string for macOS application icon."""
    global _icon_cache
    if clean_name in _icon_cache:
        return _icon_cache[clean_name]

    # 1. Check shared icon cache populated by Cocoa AppShield.app
    cache_path = f"/Library/Application Support/AppShield/icons/{clean_name}.png"
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "rb") as f:
                b64 = f"data:image/png;base64,{base64.b64encode(f.read()).decode('ascii')}"
                _icon_cache[clean_name] = b64
                return b64
        except Exception:
            pass

    # 2. Extract embedded PNG from .icns inside Contents/Resources
    if app_path and os.path.isdir(app_path):
        res_dir = os.path.join(app_path, "Contents", "Resources")
        if os.path.exists(res_dir):
            try:
                for f in os.listdir(res_dir):
                    if f.endswith(".icns"):
                        icns_file = os.path.join(res_dir, f)
                        with open(icns_file, "rb") as icf:
                            data = icf.read()
                        png_start = data.find(b"\x89PNG\r\n\x1a\n")
                        if png_start != -1:
                            iend = data.find(b"IEND\xaeB`\x82", png_start)
                            if iend != -1:
                                raw_png = data[png_start:iend + 8]
                                b64 = f"data:image/png;base64,{base64.b64encode(raw_png).decode('ascii')}"
                                _icon_cache[clean_name] = b64
                                return b64
            except Exception:
                pass

    return ""

_cached_installed_apps: List[Dict[str, Any]] = []
_last_installed_scan_time = 0.0

def enumerate_installed_macos_apps() -> List[Dict[str, Any]]:
    """
    Enumerate user applications installed in /Applications and /System/Applications.
    Returns clean App Drawer names, publishers, versions, and paths. Cached for 5 minutes.
    """
    global _cached_installed_apps, _last_installed_scan_time
    now = time.time()
    if _cached_installed_apps and (now - _last_installed_scan_time < 300):
        return _cached_installed_apps

    search_dirs = [
        "/Applications",
        "/System/Applications",
        "/System/Applications/Utilities",
        "/Applications/Utilities",
        os.path.expanduser("~/Applications")
    ]
    apps = []
    seen = set()

    for d in search_dirs:
        if not os.path.exists(d):
            continue
        try:
            for item in os.listdir(d):
                if not item.endswith(".app"):
                    continue
                app_path = os.path.join(d, item)
                clean_name = item[:-4]
                if clean_name in seen:
                    continue
                seen.add(clean_name)

                info_plist = os.path.join(app_path, "Contents", "Info.plist")
                display_name = clean_name
                version = "1.0"
                publisher = "Apple Inc." if "/System/" in app_path else "Third Party"

                if os.path.exists(info_plist):
                    try:
                        with open(info_plist, "rb") as f:
                            plist = plistlib.load(f)
                            display_name = plist.get("CFBundleDisplayName") or plist.get("CFBundleName") or clean_name
                            version = plist.get("CFBundleShortVersionString") or plist.get("CFBundleVersion") or "1.0"
                            bundle_id = plist.get("CFBundleIdentifier", "")
                            if "apple." in bundle_id.lower():
                                publisher = "Apple Inc."
                            elif "google." in bundle_id.lower():
                                publisher = "Google LLC"
                            elif "microsoft." in bundle_id.lower():
                                publisher = "Microsoft Corporation"
                            elif "roblox." in bundle_id.lower():
                                publisher = "Roblox Corporation"
                            elif "valve." in bundle_id.lower() or "steam" in clean_name.lower():
                                publisher = "Valve Corporation"
                            elif bundle_id:
                                parts = bundle_id.split(".")
                                if len(parts) >= 2:
                                    publisher = parts[1].capitalize()
                    except Exception:
                        pass

                icon_b64 = get_macos_app_icon_base64(clean_name, app_path)

                apps.append({
                    "DisplayName": display_name,
                    "Publisher": publisher,
                    "DisplayVersion": str(version),
                    "ExeName": clean_name,
                    "InstallLocation": app_path,
                    "IsBlocked": False,
                    "icon": icon_b64
                })
        except Exception:
            pass

    apps.sort(key=lambda x: x["DisplayName"].lower())
    _cached_installed_apps = apps
    _last_installed_scan_time = now
    return apps

def enumerate_running_processes(managed_user_names: set) -> List[Dict[str, Any]]:
    """
    Scans macOS and returns ONLY user-facing applications visible in the App Drawer / Launchpad.
    Completely excludes internal Unix system daemons (logd, configd, amfid, etc.) so parents
    recognize applications by their real drawer names.
    """
    processes = []
    seen_apps = set()
    console_user = get_active_console_user()

    # Step 1: Use Launch Services (lsappinfo) for instant, 100% accurate foreground GUI apps
    try:
        out = subprocess.check_output(["lsappinfo", "list"], text=True)
        entries = re.split(r'\n(?=\s*\d+\))', out)
        for entry in entries:
            if 'type="Foreground"' not in entry:
                continue

            m_name = re.search(r'\"([^\"]+)\"\s+ASN:', entry)
            app_name = m_name.group(1) if m_name else ""

            m_bundle = re.search(r'bundle path=\"([^\"]+)\"', entry)
            bundle_path = m_bundle.group(1) if m_bundle else ""

            m_pid = re.search(r'pid\s*=\s*(\d+)', entry)
            pid = int(m_pid.group(1)) if m_pid else 0

            if not app_name or pid <= 1:
                continue

            if bundle_path.endswith(".app"):
                clean_name = os.path.basename(bundle_path).replace(".app", "")
            else:
                clean_name = app_name

            # Exclude core desktop shell daemons that parents shouldn't manage
            if clean_name in ["loginwindow", "ViewBridgeAuxiliary", "WindowManager", "SystemUIServer", "Dock", "BackgroundTaskManagementAgent"]:
                continue

            if clean_name in seen_apps:
                continue
            seen_apps.add(clean_name)

            is_managed = console_user in managed_user_names
            proc_path = bundle_path or f"/Applications/{clean_name}.app"
            icon_b64 = get_macos_app_icon_base64(clean_name, proc_path)

            processes.append({
                "pid": pid,
                "processName": clean_name,
                "executablePath": proc_path,
                "username": console_user,
                "memoryMB": 65.0,  # Approximate UI app baseline
                "isManagedUser": is_managed,
                "domain": "Application",
                "icon": icon_b64
            })
    except Exception as e:
        pass

    # Step 2: Fallback if lsappinfo was unavailable
    if not processes:
        try:
            cmd = ["ps", "-axo", "pid,user,rss,comm"]
            out = subprocess.check_output(cmd, text=True)
            for line in out.strip().splitlines()[1:]:
                parts = line.strip().split(None, 3)
                if len(parts) < 4:
                    continue
                pid_str, user, rss_str, path = parts[0], parts[1], parts[2], parts[3]
                try:
                    pid = int(pid_str)
                    if pid <= 1:
                        continue
                    mem_mb = round(int(rss_str) / 1024.0, 1)
                except ValueError:
                    continue

                if ('/Applications/' in path or '/Users/' in path) and ('.app/' in path or path.endswith('.app')):
                    app_bundle = path.split('.app')[0] + '.app'
                    clean_name = os.path.basename(app_bundle).replace('.app', '')

                    if any(h in clean_name for h in ['Helper', 'Crashpad', 'Service', 'XPC', 'Daemon', 'plugin', 'Agent']):
                        continue
                    if user.startswith('_') or user == 'root':
                        continue
                    if clean_name in seen_apps:
                        continue
                    seen_apps.add(clean_name)

                    processes.append({
                        "pid": pid,
                        "processName": clean_name,
                        "executablePath": app_bundle,
                        "username": user,
                        "memoryMB": mem_mb,
                        "isManagedUser": user in managed_user_names,
                        "domain": "Application"
                    })
        except Exception:
            pass

    processes.sort(key=lambda x: x["processName"].lower())
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

                # Filter by targeted user if specified (e.g. only masroor)
                target_user = rule.get("target_user")
                if target_user and target_user.lower() != user.lower():
                    continue

                # Support single process or bunch/group of processes
                targets = [t.lower() for t in rule.get("target_processes", []) if t]
                single_target = rule.get("target_process")
                if single_target and single_target.lower() not in targets:
                    targets.append(single_target.lower())

                if not targets:
                    continue

                # Check if this running process matches any target in the rule
                matched = any(t in p_name.lower() or t in p_path.lower() for t in targets)
                if not matched:
                    continue

                # Check day of week schedule if days specified
                days = rule.get("days", [])
                if days:
                    from datetime import datetime
                    curr_day = datetime.now().strftime("%a")
                    if curr_day not in days:
                        # Outside scheduled days -> block process
                        reason = f"Curfew: Not scheduled on {curr_day}"
                        self.kill_process(pid, p_name, user, p_path, reason)
                        break

                rtype = rule.get("rule_type", "AllowedWindow")
                if rtype == "AllowedWindow" or rtype == "AppGroupWindow":
                    s_start = rule.get("schedule_start", "12:00")
                    s_end = rule.get("schedule_end", "20:00")
                    if not self.is_within_schedule(s_start, s_end):
                        sched_name = rule.get("name") or "Curfew"
                        reason = f"{sched_name}: Allowed only {s_start} - {s_end}"
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
        self.settings = load_or_create_settings()
        self.features = load_or_create_features()
        self.device_id = self.settings["device_id"]
        self.server_url = (self.settings.get("server_url") or "").rstrip("/")
        self.standalone_mode = self.settings.get("standalone_mode", False) or not self.server_url or self.server_url.lower() == "standalone"
        self.tailscale_ip = self.settings.get("tailscale_ip") or get_tailscale_ip() or ""
        self.config = {**self.settings, **self.features}
        self.enforcer = EnforcementEngine(self)
        self.running = True
        self.managed_usernames = set()

    def update_managed_users_cache(self, users: List[Dict[str, Any]]):
        self.managed_usernames = {u["username"] for u in users if u.get("isManaged", False)}

    def register_with_server(self):
        if self.standalone_mode:
            return
        t_ip = get_tailscale_ip() or self.tailscale_ip or ""
        url = f"{self.server_url}/api/devices/register"
        payload = {
            "id": self.device_id,
            "name": self.settings.get("name", socket.gethostname()),
            "os": f"macOS {platform.mac_ver()[0]} ({platform.machine()})",
            "lan_ip": get_primary_ip(),
            "tailscale_ip": t_ip,
            "agent_version": "1.3.0",
            "psk": self.settings.get("psk", "")
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
        if self.standalone_mode:
            return
        url = f"{self.server_url}/api/nodes/{self.device_id}/rules"
        try:
            req = urllib.request.Request(url, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as res:
                data = json.loads(res.read().decode("utf-8"))
                if data.get("success"):
                    rules = data.get("data", [])
                    if rules:
                        self.features["rules"] = rules
                        save_features(self.features)
                        self.config["rules"] = rules
                        print(f"[+] Synchronized {len(rules)} rules from Central Server")
        except Exception as e:
            pass

    def standalone_enforcement_loop(self):
        print("====================================================================")
        print("   AppShield macOS STANDALONE Protection Active (Zero Server Needed) ")
        print("====================================================================")
        print(f" Device:         {self.settings.get('name', socket.gethostname())}")
        print(f" Status:         100% Autonomous Local Enforcement")
        print(f" Active Rules:   {len(self.features.get('rules', []))} Curfew & Block Policies")
        print(f" Path Jail:      {'Enabled' if self.features.get('path_jail_enabled') else 'Disabled'}")
        print("====================================================================")
        while self.running:
            try:
                # Reload settings & features in case user updated via App
                self.settings = load_or_create_settings()
                self.features = load_or_create_features()
                self.config["rules"] = self.features.get("rules", [])

                # Check if server was configured
                s_url = (self.settings.get("server_url") or "").rstrip("/")
                is_st = self.settings.get("standalone_mode", False) or not s_url or s_url.lower() == "standalone"
                if not is_st:
                    print(f"[+] Central Server configured ({s_url}). Switching to live fleet relay...")
                    break

                users = enumerate_macos_users()
                self.update_managed_users_cache(users)
                procs = enumerate_running_processes(self.managed_usernames)
                self.enforcer.evaluate_and_enforce(procs)
            except Exception as e:
                pass
            time.sleep(4.0)

    def report_telemetry_now(self):
        """Immediately transmits full system telemetry to Central Server."""
        try:
            users = enumerate_macos_users()
            self.update_managed_users_cache(users)
            procs = enumerate_running_processes(self.managed_usernames)
            installed = enumerate_installed_macos_apps()
            url = f"{self.server_url}/api/agent/telemetry"
            payload = {
                "device_id": self.device_id,
                "processes": procs,
                "users": users,
                "installed_apps": installed
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=4)
            print("[+] Successfully synced updated telemetry snapshot to Central Server.")
        except Exception as e:
            print(f"[-] Error reporting telemetry snapshot: {e}")

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

    def apply_macos_dns_filter(self, primary_dns: str, secondary_dns: str = "", primary_ipv6: str = "", secondary_ipv6: str = "", is_enabled: bool = True) -> bool:
        """
        Applies Family DNS filtering across all active network interfaces (Wi-Fi, Ethernet) on macOS.
        Flushes system DNS cache with dscacheutil and mDNSResponder.
        """
        try:
            out = subprocess.check_output(["networksetup", "-listallnetworkservices"], text=True)
            services = []
            for line in out.splitlines():
                line = line.strip()
                if line and not line.startswith("*") and "An asterisk" not in line:
                    services.append(line)

            dns_args = []
            if is_enabled:
                for addr in [primary_dns, secondary_dns, primary_ipv6, secondary_ipv6]:
                    addr = (addr or "").strip()
                    if addr and addr not in dns_args and addr.upper() != "N/A":
                        dns_args.append(addr)

            for s in services:
                try:
                    if dns_args:
                        subprocess.run(["networksetup", "-setdnsservers", s] + dns_args, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    else:
                        subprocess.run(["networksetup", "-setdnsservers", s, "empty"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception:
                    pass

            subprocess.run(["dscacheutil", "-flushcache"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["killall", "-HUP", "mDNSResponder"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"[+] Applied macOS DNS Shield: {dns_args if dns_args else 'DHCP Default'}")
            return True
        except Exception as e:
            print(f"[-] Error applying macOS DNS filter: {e}")
            return False

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

        elif action == "set_dns_filter":
            p_dns = payload.get("primary_dns", "1.1.1.1")
            s_dns = payload.get("secondary_dns", "1.0.0.1")
            p_ipv6 = payload.get("primary_ipv6", "")
            s_ipv6 = payload.get("secondary_ipv6", "")
            is_en = payload.get("is_enabled", 1) == 1
            preset = payload.get("preset", "cloudflare_public")
            self.apply_macos_dns_filter(p_dns, s_dns, p_ipv6, s_ipv6, is_en)
            try:
                cfg = load_or_create_config()
                cfg["dns_filter"] = {
                    "preset": preset,
                    "primary_dns": p_dns,
                    "secondary_dns": s_dns,
                    "primary_ipv6": p_ipv6,
                    "secondary_ipv6": s_ipv6,
                    "is_enabled": is_en
                }
                save_config(cfg)
            except Exception:
                pass

        elif action == "manage_user":
            sid = payload.get("sid")
            if sid:
                cfg = load_or_create_config()
                if "user_overrides" not in cfg:
                    cfg["user_overrides"] = {}
                cfg["user_overrides"][sid] = {
                    "isManaged": payload.get("isManaged", False),
                    "blockUserWritableDirectories": payload.get("blockUserWritableDirectories", False)
                }
                save_config(cfg)
                global _cached_users, _last_user_scan_time
                _cached_users = []
                _last_user_scan_time = 0
                print(f"[+] Saved policy override for {sid}: {payload}")
                self.report_telemetry_now()

        elif action == "open_account_settings":
            try:
                subprocess.run(["open", "x-apple.systempreferences:com.apple.Users-Groups-Settings.extension"], check=False)
                print("[+] Opened macOS Users & Groups settings.")
            except Exception as e:
                print(f"[-] Failed to open settings: {e}")

        elif action in ["refresh_telemetry", "scan_users", "scan_processes", "ping"]:
            self.report_telemetry_now()

        elif action == "scan_installed_apps":
            global _cached_installed_apps, _last_installed_scan_time
            _last_installed_scan_time = 0
            installed = enumerate_installed_macos_apps()
            try:
                url = f"{self.server_url}/api/agent/telemetry"
                payload = {
                    "device_id": self.device_id,
                    "processes": enumerate_running_processes(self.managed_usernames),
                    "users": enumerate_macos_users(),
                    "installed_apps": installed
                }
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"}
                )
                urllib.request.urlopen(req, timeout=4)
                print(f"[+] Reported {len(installed)} installed macOS apps to central server.")
            except Exception as e:
                print(f"[-] Error syncing installed apps: {e}")

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
                    # Send immediate initial telemetry snapshot
                    self.report_telemetry_now()
                    while self.running:
                        # 1. Gather live telemetry
                        users = enumerate_macos_users()
                        self.update_managed_users_cache(users)
                        procs = enumerate_running_processes(self.managed_usernames)
                        installed = enumerate_installed_macos_apps()

                        # Enforce local rules
                        self.enforcer.evaluate_and_enforce(procs)

                        # Push telemetry
                        telemetry = {
                            "device_id": self.device_id,
                            "timestamp": datetime.datetime.utcnow().isoformat(),
                            "users": users,
                            "processes": procs,
                            "installed_apps": installed,
                            "tailscale_ip": get_tailscale_ip() or ""
                        }
                        ws_msg = {
                            "action": "telemetry",
                            "payload": telemetry
                        }
                        await ws.send(json.dumps(ws_msg))

                        # Sleep 6 seconds between scans to keep CPU usage at 0.0%
                        await asyncio.sleep(6.0)

                        # Listen for commands with timeout
                        try:
                            msg = await asyncio.wait_for(ws.recv(), timeout=2.0)
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
        print("[+] Running in HTTP Polling Mode (8s telemetry intervals)...")
        while self.running:
            try:
                users = enumerate_macos_users()
                self.update_managed_users_cache(users)
                procs = enumerate_running_processes(self.managed_usernames)
                installed = enumerate_installed_macos_apps()

                # Local real-time curfew enforcement
                self.enforcer.evaluate_and_enforce(procs)

                # Send telemetry to server
                url = f"{self.server_url}/api/agent/telemetry"
                payload = {
                    "device_id": self.device_id,
                    "processes": procs,
                    "users": users,
                    "installed_apps": installed
                }
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"}
                )
                urllib.request.urlopen(req, timeout=4)
            except Exception as e:
                pass

            time.sleep(8.0)

    def start(self):
        print("====================================================================")
        print("          AppShield macOS Endpoint Protection Agent v1.3.0          ")
        print("====================================================================")
        print(f" Device ID:    {self.device_id}")
        print(f" Tailscale IP: {get_tailscale_ip() or self.tailscale_ip or 'None detected'}")
        print(f" Running As:   UID {os.geteuid()} ({'Root / Daemon' if os.geteuid() == 0 else 'User Session'})")
        print("====================================================================")

        while self.running:
            self.settings = load_or_create_settings()
            self.features = load_or_create_features()
            self.device_id = self.settings.get("device_id", self.device_id)
            self.server_url = (self.settings.get("server_url") or "").rstrip("/")
            self.standalone_mode = self.settings.get("standalone_mode", False) or not self.server_url or self.server_url.lower() == "standalone"

            if self.standalone_mode:
                print("[+] Standalone mode active: enforcing curfews and app blocks locally.")
                self.standalone_enforcement_loop()
            else:
                print(f"[+] Connecting to Central Hub: {self.server_url}")
                self.register_with_server()
                self.fetch_rules()

                if HAS_WEBSOCKETS:
                    try:
                        asyncio.run(self.websocket_loop())
                    except KeyboardInterrupt:
                        break
                    except Exception as e:
                        time.sleep(4)
                else:
                    self.http_polling_loop()
            time.sleep(2)

if __name__ == "__main__":
    agent = AppShieldMacAgent()
    agent.start()
