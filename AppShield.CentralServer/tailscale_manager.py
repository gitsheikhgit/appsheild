import os
import json
import shutil
import asyncio
import subprocess
import re
from typing import Dict, Any, Optional

class TailscaleManager:
    """
    Manages Tailscale status detection, 1-click installation on Ubuntu/Debian/LXC,
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
    async def ensure_daemon_running(cls) -> bool:
        """
        Verifies that tailscaled is active. In Proxmox LXC containers or systems
        without /dev/net/tun, automatically configures userspace networking mode
        so tailscaled never fails.
        """
        # 1. If socket exists and responsive, daemon is running
        if os.path.exists("/run/tailscale/tailscaled.sock"):
            return True

        # 2. Check if /dev/net/tun exists. If not, enable userspace networking in /etc/default/tailscaled
        if not os.path.exists("/dev/net/tun") and os.path.exists("/etc/default/tailscaled"):
            try:
                with open("/etc/default/tailscaled", "r") as f:
                    content = f.read()
                if "--tun=userspace-networking" not in content:
                    new_content = re.sub(r'FLAGS=".*?"', 'FLAGS="--tun=userspace-networking"', content)
                    if new_content == content:
                        new_content += '\nFLAGS="--tun=userspace-networking"\n'
                    with open("/etc/default/tailscaled", "w") as f:
                        f.write(new_content)
            except Exception:
                pass

        # 3. Attempt to start/restart tailscaled service
        try:
            proc = await asyncio.create_subprocess_shell(
                "systemctl restart tailscaled || systemctl start tailscaled",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
        except Exception:
            pass

        # 4. Wait up to 3 seconds for socket
        for _ in range(6):
            if os.path.exists("/run/tailscale/tailscaled.sock"):
                return True
            await asyncio.sleep(0.5)

        return os.path.exists("/run/tailscale/tailscaled.sock")

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

        # Ensure daemon is running
        await cls.ensure_daemon_running()

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
                    result["ip"] = ipv4_addrs[0]
                result["node_name"] = self_node.get("HostName")
                dns_name = (self_node.get("DNSName") or "").rstrip(".")
                result["dns_name"] = dns_name
                result["magic_link"] = f"http://{dns_name}:8000" if dns_name else ""
                result["ip_link"] = f"http://{result.get('tailscale_ip')}:8000" if result.get("tailscale_ip") else ""
                result["auth_url"] = data.get("AuthURL")
                result["running"] = (result.get("backend_state") == "Running") or bool(result.get("tailscale_ip"))

                # Collect peers map for auto-linking kids' devices
                peers_map = {}
                peer_dict = data.get("Peer", {})
                for pkey, pval in peer_dict.items():
                    hname = pval.get("HostName", "")
                    p_dns = (pval.get("DNSName") or "").rstrip(".")
                    p_ips = [a for a in pval.get("TailscaleIPs", []) if ":" not in a]
                    if p_ips:
                        peers_map[hname.lower()] = {
                            "hostname": hname,
                            "dns_name": p_dns,
                            "ip": p_ips[0],
                            "magic_link": f"http://{p_dns}:54120" if p_dns else "",
                            "os": pval.get("OS", ""),
                            "online": pval.get("Online", False)
                        }
                result["peers"] = peers_map
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
                t_ip = ip.splitlines()[0]
                result["tailscale_ip"] = t_ip
                result["ip"] = t_ip
                result["ip_link"] = f"http://{t_ip}:8000"
                result["backend_state"] = "Running"
                result["running"] = True
            else:
                result["backend_state"] = "NeedsLogin"
        except Exception:
            result["backend_state"] = "NeedsLogin"

        return result

    @classmethod
    async def install(cls) -> Dict[str, Any]:
        """
        Executes official automated Tailscale installation on Linux/Ubuntu/Debian.
        """
        if cls.get_binary_path():
            await cls.ensure_daemon_running()
            return {"success": True, "message": "Tailscale is already installed on this server."}

        try:
            proc = await asyncio.create_subprocess_shell(
                "curl -fsSL https://tailscale.com/install.sh | sh",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                await cls.ensure_daemon_running()
                return {"success": True, "message": "Tailscale installed successfully!"}
            else:
                err = stderr.decode().strip() or stdout.decode().strip()
                return {"success": False, "message": f"Installation script failed: {err}"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    @classmethod
    async def login_or_up(cls) -> Dict[str, Any]:
        """
        Runs tailscale up / login and captures the browser authorization URL.
        """
        bin_path = cls.get_binary_path()
        if not bin_path:
            return {"success": False, "message": "Tailscale is not installed on this server."}

        # Ensure daemon is running and healthy
        await cls.ensure_daemon_running()

        try:
            # 1. Check if already logged in and active with 100.* IP
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
                    "running": True,
                    "tailscale_ip": ip.splitlines()[0],
                    "message": "Tailscale is already authenticated and active!"
                }

            # 2. Check status --json for existing AuthURL
            try:
                proc = await asyncio.create_subprocess_exec(
                    bin_path, "status", "--json",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                raw = stdout.decode().strip()
                if raw.startswith("{"):
                    st = json.loads(raw)
                    auth_url = st.get("AuthURL")
                    if auth_url:
                        return {
                            "success": True,
                            "auth_url": auth_url,
                            "message": "Authorization URL retrieved. Please sign in with your browser."
                        }
            except Exception:
                pass

            # 3. Run tailscale up to generate or request auth URL
            proc = await asyncio.create_subprocess_exec(
                bin_path, "up", "--qr=false", "--timeout=10s",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=12.0)
                output = stdout.decode() + "\n" + stderr.decode()
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                output = ""

            # 4. Search for https://login.tailscale.com/a/... in output
            match = re.search(r"https://login\.tailscale\.com/a/[a-zA-Z0-9_\-]+", output)
            if match:
                return {
                    "success": True,
                    "auth_url": match.group(0),
                    "message": "Authorization URL generated. Please sign in with your browser."
                }

            # 5. Fallback check status --json once more
            try:
                proc2 = await asyncio.create_subprocess_exec(
                    bin_path, "status", "--json",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout2, _ = await proc2.communicate()
                st2 = json.loads(stdout2.decode().strip())
                if st2.get("AuthURL"):
                    return {
                        "success": True,
                        "auth_url": st2["AuthURL"],
                        "message": "Authorization URL retrieved. Please sign in with your browser."
                    }
            except Exception:
                pass

            return {
                "success": False,
                "message": f"Could not find authorization URL: {output.strip() or 'No response from Tailscale'}"
            }
        except Exception as e:
            return {"success": False, "message": str(e)}
