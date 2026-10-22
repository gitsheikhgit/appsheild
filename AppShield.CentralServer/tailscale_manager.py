import os
import json
import shutil
import asyncio
import subprocess
import re
from typing import Dict, Any, Optional

class TailscaleManager:
    """
    Manages Tailscale status detection, 1-click installation on Ubuntu/Debian,
    and retrieval of browser authorization URLs for remote access.
    """

    @staticmethod
    def get_binary_path() -> Optional[str]:
        # Check standard PATH
        bin_path = shutil.which("tailscale")
        if bin_path:
            return bin_path
        # Check common system locations
        for p in [
            "/usr/bin/tailscale",
            "/usr/sbin/tailscale",
            "/usr/local/bin/tailscale",
            "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
        ]:
            if os.path.exists(p):
                return p
        return None

    @classmethod
    async def get_status(cls) -> Dict[str, Any]:
        """
        Returns full Tailscale status, IP, backend state, and auth URL if login required.
        """
        result = {
            "installed": False,
            "backend_state": "NotInstalled",
            "tailscale_ip": None,
            "node_name": None,
            "auth_url": None,
            "version": None
        }

        bin_path = cls.get_binary_path()
        if not bin_path:
            # Fallback: check if system interface has an active 100.* IP
            try:
                proc = await asyncio.create_subprocess_shell(
                    "ip -4 addr show || ifconfig",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                out = stdout.decode()
                for line in out.splitlines():
                    if "inet 100." in line:
                        parts = line.strip().split()
                        for p in parts:
                            if p.startswith("100."):
                                result["tailscale_ip"] = p.split("/")[0]
                                result["installed"] = True
                                result["backend_state"] = "Running"
                                break
            except Exception:
                pass
            return result

        result["installed"] = True

        # Check version
        try:
            proc = await asyncio.create_subprocess_exec(
                bin_path, "version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            ver = stdout.decode().strip()
            if ver:
                result["version"] = ver.splitlines()[0]
        except Exception:
            pass

        # Check status --json
        try:
            proc = await asyncio.create_subprocess_exec(
                bin_path, "status", "--json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            raw = stdout.decode().strip()
            if raw.startswith("{"):
                data = json.loads(raw)
                result["backend_state"] = data.get("BackendState", "Unknown")
                self_node = data.get("Self", {})
                addrs = self_node.get("TailscaleIPs", [])
                ipv4_addrs = [a for a in addrs if ":" not in a]
                if ipv4_addrs:
                    result["tailscale_ip"] = ipv4_addrs[0]
                result["node_name"] = self_node.get("HostName")
                result["auth_url"] = data.get("AuthURL")
                return result
        except Exception:
            pass

        # Fallback check via tailscale ip -4
        try:
            proc = await asyncio.create_subprocess_exec(
                bin_path, "ip", "-4",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            ip = stdout.decode().strip()
            if ip.startswith("100."):
                result["tailscale_ip"] = ip.splitlines()[0]
                result["backend_state"] = "Running"
            else:
                result["backend_state"] = "NeedsLogin"
        except Exception:
            result["backend_state"] = "NeedsLogin"

        return result

    @classmethod
    async def install(cls) -> Dict[str, Any]:
        """
        Executes official automated Tailscale installation on Linux/Ubuntu.
        """
        if cls.get_binary_path():
            return {"success": True, "message": "Tailscale is already installed on this server."}

        try:
            proc = await asyncio.create_subprocess_shell(
                "curl -fsSL https://tailscale.com/install.sh | sh",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                # Enable systemd service
                os.system("systemctl enable --now tailscaled 2>/dev/null || true")
                return {"success": True, "message": "Tailscale installed successfully!"}
            else:
                err = stderr.decode().strip() or stdout.decode().strip()
                return {"success": False, "message": f"Installation script failed: {err}"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    @classmethod
    async def login_or_up(cls) -> Dict[str, Any]:
        """
        Runs tailscale up and captures the browser authorization URL.
        """
        bin_path = cls.get_binary_path()
        if not bin_path:
            return {"success": False, "message": "Tailscale is not installed on this server."}

        try:
            # First check if already logged in and has IP
            proc = await asyncio.create_subprocess_exec(
                bin_path, "ip", "-4",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            ip = stdout.decode().strip()
            if ip.startswith("100."):
                return {
                    "success": True,
                    "tailscale_ip": ip.splitlines()[0],
                    "message": "Tailscale is already authenticated and active!"
                }

            # Run tailscale up to get auth URL
            proc = await asyncio.create_subprocess_exec(
                bin_path, "up", "--qr=false", "--timeout=15s",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=20.0)
            output = stdout.decode() + "\n" + stderr.decode()

            # Search for https://login.tailscale.com/a/...
            match = re.search(r"https://login\.tailscale\.com/a/[a-zA-Z0-9_\-]+", output)
            if match:
                return {
                    "success": True,
                    "auth_url": match.group(0),
                    "message": "Authorization URL generated. Please complete signup in your browser."
                }

            return {
                "success": False,
                "message": f"Could not find authorization URL in Tailscale response: {output[:250]}"
            }
        except Exception as e:
            return {"success": False, "message": str(e)}
