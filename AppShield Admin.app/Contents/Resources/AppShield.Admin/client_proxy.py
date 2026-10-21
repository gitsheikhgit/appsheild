import time
from datetime import datetime
from typing import Any, Dict, Optional, Tuple
import httpx
from fleet_store import FleetNode, fleet_store

class ClientProxy:
    def __init__(self, timeout: float = 3.5):
        self.timeout = timeout

    def _get_headers(self, psk: str) -> Dict[str, str]:
        now_epoch = str(int(time.time()))
        return {
            "X-AppShield-PSK": psk,
            "X-AppShield-Timestamp": now_epoch,
            "Content-Type": "application/json"
        }

    async def _try_request(
        self,
        method: str,
        ip: str,
        port: int,
        path: str,
        headers: Dict[str, str],
        json_data: Optional[Dict] = None,
        params: Optional[Dict] = None
    ) -> httpx.Response:
        url = f"https://{ip}:{port}{path}"
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            return await client.request(
                method=method,
                url=url,
                headers=headers,
                json=json_data,
                params=params
            )

    async def request(
        self,
        node: FleetNode,
        method: str,
        path: str,
        json_data: Optional[Dict] = None,
        params: Optional[Dict] = None
    ) -> Tuple[bool, Any, str]:
        """
        Executes request with automatic LAN -> Tailscale IP failover.
        Returns (success: bool, data: Any, connection_mode: str)
        """
        headers = self._get_headers(node.psk)

        # 1. Try LAN IP first if defined
        if node.lan_ip and node.lan_ip.strip():
            try:
                resp = await self._try_request(method, node.lan_ip.strip(), node.port, path, headers, json_data, params)
                if resp.status_code < 500:
                    # Update active IP and status
                    fleet_store.update(node.id, {
                        "status": "online-lan",
                        "active_ip": node.lan_ip.strip(),
                        "last_seen": datetime.utcnow().isoformat() + "Z"
                    })
                    return True, resp.json(), "online-lan"
            except Exception:
                pass

        # 2. Try Tailscale IP failover if defined
        if node.tailscale_ip and node.tailscale_ip.strip():
            try:
                resp = await self._try_request(method, node.tailscale_ip.strip(), node.port, path, headers, json_data, params)
                if resp.status_code < 500:
                    fleet_store.update(node.id, {
                        "status": "online-tailscale",
                        "active_ip": node.tailscale_ip.strip(),
                        "last_seen": datetime.utcnow().isoformat() + "Z"
                    })
                    return True, resp.json(), "online-tailscale"
            except Exception:
                pass

        # If both fail, mark node offline
        fleet_store.update(node.id, {
            "status": "offline"
        })
        return False, {"error": "Target node unreachable via both LAN and Tailscale."}, "offline"

    async def check_health(self, node: FleetNode) -> Dict[str, Any]:
        """
        Performs health check and updates node telemetry.
        """
        success, data, mode = await self.request(node, "GET", "/api/v1/health")
        if success and isinstance(data, dict) and data.get("success"):
            details = data.get("data", {})
            fleet_store.update(node.id, {
                "hostname": details.get("hostname"),
                "os_version": details.get("osVersion"),
                "agent_version": details.get("agentVersion"),
                "uptime_seconds": details.get("uptimeSeconds"),
                "status": mode,
                "last_seen": datetime.utcnow().isoformat() + "Z"
            })
            return {"online": True, "mode": mode, "details": details}
        else:
            return {"online": False, "mode": "offline", "error": data.get("error", "Offline")}

proxy = ClientProxy()
