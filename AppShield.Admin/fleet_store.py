import json
import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

FLEET_FILE = os.path.join(os.path.dirname(__file__), "fleet.json")

class FleetNode(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    name: str
    lan_ip: Optional[str] = None
    tailscale_ip: Optional[str] = None
    port: int = 54120
    psk: str
    status: str = "unknown" # "online-lan", "online-tailscale", "offline", "unknown"
    active_ip: Optional[str] = None
    last_seen: Optional[str] = None
    hostname: Optional[str] = None
    os_version: Optional[str] = None
    agent_version: Optional[str] = None
    uptime_seconds: Optional[int] = None

class FleetStore:
    def __init__(self, file_path: str = FLEET_FILE):
        self.file_path = file_path
        self._ensure_file()

    def _ensure_file(self):
        if not os.path.exists(self.file_path):
            # Seed default demo node only on Windows; on macOS/Linux start empty so user connects real PC
            initial_data = []
            if os.name == "nt":
                initial_data = [
                    {
                        "id": "node-default",
                        "name": "Local-Test-PC",
                        "lan_ip": "127.0.0.1",
                        "tailscale_ip": "",
                        "port": 54120,
                        "psk": "AppShield-Default-PSK-Key-2026-Secure",
                        "status": "unknown",
                        "active_ip": "127.0.0.1",
                        "last_seen": None
                    }
                ]
            with open(self.file_path, "w", encoding="utf-8") as f:
                json.dump(initial_data, f, indent=2)

    def get_all(self) -> List[FleetNode]:
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return [FleetNode(**item) for item in data]
        except Exception:
            return []

    def get(self, node_id: str) -> Optional[FleetNode]:
        nodes = self.get_all()
        for node in nodes:
            if node.id == node_id:
                return node
        return None

    def add(self, node: FleetNode) -> FleetNode:
        nodes = self.get_all()
        # Avoid duplicate names or IPs
        nodes.append(node)
        self._save(nodes)
        return node

    def update(self, node_id: str, updates: Dict) -> Optional[FleetNode]:
        nodes = self.get_all()
        target = None
        for i, node in enumerate(nodes):
            if node.id == node_id:
                updated_dict = node.model_dump()
                updated_dict.update(updates)
                target = FleetNode(**updated_dict)
                nodes[i] = target
                break
        if target:
            self._save(nodes)
        return target

    def delete(self, node_id: str) -> bool:
        nodes = self.get_all()
        initial_len = len(nodes)
        nodes = [n for n in nodes if n.id != node_id]
        if len(nodes) < initial_len:
            self._save(nodes)
            return True
        return False

    def _save(self, nodes: List[FleetNode]):
        with open(self.file_path, "w", encoding="utf-8") as f:
            json.dump([n.model_dump() for n in nodes], f, indent=2)

fleet_store = FleetStore()
