import os
import urllib.parse
from typing import Any, Dict, Optional
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from client_proxy import proxy
from fleet_store import FleetNode, fleet_store
from mdns_scanner import scan_local_network

app = FastAPI(
    title="AppShield Fleet Admin",
    description="Centralized Multi-PC Control & Security Dashboard for AppShield Endpoints",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(STATIC_DIR):
    os.makedirs(STATIC_DIR)

# Fleet Management Endpoints

@app.get("/api/fleet")
async def get_fleet():
    nodes = fleet_store.get_all()
    return {"success": True, "data": [n.model_dump() for n in nodes]}

@app.post("/api/fleet")
async def add_fleet_node(node: FleetNode):
    created = fleet_store.add(node)
    return {"success": True, "data": created.model_dump()}

@app.put("/api/fleet/{node_id}")
async def update_fleet_node(node_id: str, updates: Dict[str, Any]):
    updated = fleet_store.update(node_id, updates)
    if not updated:
        raise HTTPException(status_code=404, detail="Node not found")
    return {"success": True, "data": updated.model_dump()}

@app.delete("/api/fleet/{node_id}")
async def delete_fleet_node(node_id: str):
    deleted = fleet_store.delete(node_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Node not found")
    return {"success": True, "message": "Node removed from fleet"}

@app.post("/api/fleet/{node_id}/ping")
async def ping_fleet_node(node_id: str):
    node = fleet_store.get(node_id)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    health = await proxy.check_health(node)
    return {"success": True, "data": health}

@app.get("/api/discovery/scan")
async def scan_mdns():
    results = scan_local_network(timeout=2.0)
    return {"success": True, "data": results}

# Client Proxy Endpoints

def _get_target_node(node_id: str) -> FleetNode:
    node = fleet_store.get(node_id)
    if not node:
        raise HTTPException(status_code=404, detail=f"Fleet node '{node_id}' not found")
    return node

@app.get("/api/nodes/{node_id}/users")
async def proxy_get_users(node_id: str):
    node = _get_target_node(node_id)
    success, data, mode = await proxy.request(node, "GET", "/api/v1/users")
    if not success:
        return JSONResponse(status_code=502, content={"success": False, "error": data})
    return data

@app.post("/api/nodes/{node_id}/users/manage")
async def proxy_manage_user(node_id: str, payload: Dict[str, Any]):
    node = _get_target_node(node_id)
    success, data, mode = await proxy.request(node, "POST", "/api/v1/users/manage", json_data=payload)
    if not success:
        return JSONResponse(status_code=502, content={"success": False, "error": data})
    return data

@app.get("/api/nodes/{node_id}/processes")
async def proxy_get_processes(node_id: str):
    node = _get_target_node(node_id)
    success, data, mode = await proxy.request(node, "GET", "/api/v1/processes")
    if not success:
        return JSONResponse(status_code=502, content={"success": False, "error": data})
    return data

@app.get("/api/nodes/{node_id}/installed-apps")
async def proxy_get_installed_apps(node_id: str):
    node = _get_target_node(node_id)
    success, data, mode = await proxy.request(node, "GET", "/api/v1/installed-apps")
    if not success:
        return JSONResponse(status_code=502, content={"success": False, "error": data})
    return data

@app.get("/api/nodes/{node_id}/rules")
async def proxy_get_rules(node_id: str):
    node = _get_target_node(node_id)
    success, data, mode = await proxy.request(node, "GET", "/api/v1/rules")
    if not success:
        return JSONResponse(status_code=502, content={"success": False, "error": data})
    return data

@app.post("/api/nodes/{node_id}/rules")
async def proxy_create_rule(node_id: str, payload: Dict[str, Any]):
    node = _get_target_node(node_id)
    success, data, mode = await proxy.request(node, "POST", "/api/v1/rules", json_data=payload)
    if not success:
        return JSONResponse(status_code=502, content={"success": False, "error": data})
    return data

@app.delete("/api/nodes/{node_id}/rules/{rule_id}")
async def proxy_delete_rule(node_id: str, rule_id: str):
    node = _get_target_node(node_id)
    success, data, mode = await proxy.request(node, "DELETE", f"/api/v1/rules/{rule_id}")
    if not success:
        return JSONResponse(status_code=502, content={"success": False, "error": data})
    return data

@app.post("/api/nodes/{node_id}/override")
async def proxy_grant_override(node_id: str, payload: Dict[str, Any]):
    node = _get_target_node(node_id)
    success, data, mode = await proxy.request(node, "POST", "/api/v1/override", json_data=payload)
    if not success:
        return JSONResponse(status_code=502, content={"success": False, "error": data})
    return data

@app.get("/api/nodes/{node_id}/logs")
async def proxy_get_logs(node_id: str, limit: int = 100, offset: int = 0):
    node = _get_target_node(node_id)
    params = {"limit": limit, "offset": offset}
    success, data, mode = await proxy.request(node, "GET", "/api/v1/logs", params=params)
    if not success:
        return JSONResponse(status_code=502, content={"success": False, "error": data})
    return data

@app.post("/api/nodes/{node_id}/uninstall")
async def proxy_remote_uninstall(node_id: str, payload: Dict[str, Any]):
    node = _get_target_node(node_id)
    success, data, mode = await proxy.request(node, "POST", "/api/v1/system/uninstall", json_data=payload)
    if not success:
        return JSONResponse(status_code=502, content={"success": False, "error": data})
    return data

# Mount static files and SPA landing
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
async def serve_index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "AppShield Admin API Running. Static Web UI not yet generated."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8080, reload=True)
