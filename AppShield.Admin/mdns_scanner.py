import socket
import time
from typing import Dict, List
from zeroconf import ServiceBrowser, ServiceListener, Zeroconf

SERVICE_TYPE = "_appshield._tcp.local."

class AppShieldListener(ServiceListener):
    def __init__(self):
        self.discovered: Dict[str, Dict] = {}

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        self._inspect_service(zc, type_, name)

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        self._inspect_service(zc, type_, name)

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        if name in self.discovered:
            del self.discovered[name]

    def _inspect_service(self, zc: Zeroconf, type_: str, name: str):
        try:
            info = zc.get_service_info(type_, name)
            if info:
                addresses = [socket.inet_ntoa(addr) for addr in info.addresses if len(addr) == 4]
                properties = {k.decode("utf-8"): v.decode("utf-8") for k, v in info.properties.items()}
                
                clean_name = name.replace(f".{SERVICE_TYPE}", "").rstrip(".")
                self.discovered[name] = {
                    "name": clean_name,
                    "server": info.server.rstrip("."),
                    "port": info.port,
                    "addresses": addresses,
                    "primary_ip": addresses[0] if addresses else None,
                    "properties": properties,
                    "discovered_at": time.time()
                }
        except Exception as ex:
            print(f"[mDNS Scanner] Error reading service {name}: {ex}")

def scan_local_network(timeout: float = 2.5) -> List[Dict]:
    """
    Actively queries the local network for _appshield._tcp.local. instances.
    """
    zc = Zeroconf()
    listener = AppShieldListener()
    browser = ServiceBrowser(zc, SERVICE_TYPE, listener)
    try:
        time.sleep(timeout)
        return list(listener.discovered.values())
    finally:
        browser.cancel()
        zc.close()
