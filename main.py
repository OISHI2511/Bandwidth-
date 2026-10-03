import asyncio
import ipaddress
import time
from collections import Counter
from typing import Dict, Any, List

import httpx
import psutil
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

app = FastAPI(title="NetPulse Telemetry Agent")

# In-memory cache so we never look up the same IP twice
GEO_CACHE: Dict[str, Dict[str, Any]] = {}
HOME_COORDS = {"lat": 37.7749, "lon": -122.4194, "city": "Localhost", "country": "Home"}
STANDARD_PORTS = {22, 53, 80, 123, 443, 587, 993, 8000, 8080, 8443}


async def init_home_location():
    """Detect the host machine's public Geo-IP coordinates on startup."""
    global HOME_COORDS
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get("http://ip-api.com/json/")
            data = resp.json()
            if data.get("status") == "success":
                HOME_COORDS = {
                    "lat": data.get("lat", 37.7749),
                    "lon": data.get("lon", -122.4194),
                    "city": data.get("city", "Home"),
                    "country": data.get("country", ""),
                }
    except Exception:
        pass


async def resolve_ips_batch(ips: List[str]):
    """Batch-resolve unknown public IPs via ip-api.com/batch and cache them."""
    unknown_ips = [ip for ip in ips if ip not in GEO_CACHE][:100]
    if not unknown_ips:
        return
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                "http://ip-api.com/batch?fields=status,query,country,city,lat,lon,isp,org",
                json=unknown_ips,
            )
            for item in resp.json():
                ip = item.get("query")
                if item.get("status") == "success" and ip:
                    GEO_CACHE[ip] = {
                        "country": item.get("country", "Unknown"),
                        "city": item.get("city", "Unknown"),
                        "lat": item.get("lat", 0.0),
                        "lon": item.get("lon", 0.0),
                        "org": item.get("org") or item.get("isp") or "Unknown ISP",
                    }
    except Exception:
        pass


def get_process_name(pid: int) -> str:
    if not pid:
        return "system"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return f"pid:{pid}"


def is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global and not ip.is_multicast
    except ValueError:
        return False


async def collect_telemetry_snapshot(prev_io, prev_time):
    """Polls active connections, bandwidth deltas, Geo-IP data, and anomaly rules."""
    now = time.time()
    dt = max(now - prev_time, 0.1)
    curr_io = psutil.net_io_counters()

    up_kbs = round((curr_io.bytes_sent - prev_io.bytes_sent) / 1024.0 / dt, 2)
    down_kbs = round((curr_io.bytes_recv - prev_io.bytes_recv) / 1024.0 / dt, 2)

    raw_conns = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if not conn.raddr:
                continue
            remote_ip = conn.raddr.ip
            if not is_public_ip(remote_ip):
                continue
            proto = "TCP" if conn.type == 1 else "UDP"
            raw_conns.append({
                "local_port": conn.laddr.port if conn.laddr else 0,
                "remote_ip": remote_ip,
                "remote_port": conn.raddr.port,
                "protocol": proto,
                "status": conn.status if proto == "TCP" else "ACTIVE",
                "process": get_process_name(conn.pid),
            })
    except psutil.AccessDenied:
        # On macOS, run with `sudo uvicorn main:app` if global socket inspection is restricted
        pass

    # Resolve any newly seen public IPs
    unique_ips = list({c["remote_ip"] for c in raw_conns})
    await resolve_ips_batch(unique_ips)

    # Enrich connections & evaluate anomaly rules
    connections = []
    anomalies = []
    proc_counts = Counter()
    port_breakdown = Counter({"HTTPS (443)": 0, "HTTP (80)": 0, "DNS (53)": 0, "SSH (22)": 0, "Other": 0})

    for c in raw_conns:
        geo = GEO_CACHE.get(c["remote_ip"])
        if not geo:
            continue
        proc_counts[c["process"]] += 1
        rp = c["remote_port"]

        if rp == 443:
            port_breakdown["HTTPS (443)"] += 1
        elif rp == 80:
            port_breakdown["HTTP (80)"] += 1
        elif rp == 53:
            port_breakdown["DNS (53)"] += 1
        elif rp == 22:
            port_breakdown["SSH (22)"] += 1
        else:
            port_breakdown["Other"] += 1

        if rp not in STANDARD_PORTS:
            anomalies.append(f"Unusual outbound port {rp} ({c['protocol']}) by {c['process']} -> {c['remote_ip']}")

        connections.append({**c, **geo})

    for proc, count in proc_counts.items():
        if count >= 15:
            anomalies.append(f"Connection spike: {proc} holds {count} concurrent external sockets")

    payload = {
        "timestamp": round(now, 1),
        "home": HOME_COORDS,
        "bandwidth": {"upload_kbs": max(up_kbs, 0), "download_kbs": max(down_kbs, 0)},
        "ports": dict(port_breakdown),
        "connections": connections[:60],
        "anomalies": anomalies[:3],
    }
    return payload, curr_io, now


@app.on_event("startup")
async def on_startup():
    await init_home_location()


@app.get("/")
async def serve_dashboard():
    return FileResponse("index.html")


@app.get("/sample_traffic.json")
async def serve_sample():
    return FileResponse("sample_traffic.json")


@app.websocket("/ws/traffic")
async def traffic_stream(ws: WebSocket):
    await ws.accept()
    prev_io = psutil.net_io_counters()
    prev_time = time.time()
    try:
        while True:
            await asyncio.sleep(1.0)
            payload, prev_io, prev_time = await collect_telemetry_snapshot(prev_io, prev_time)
            await ws.send_json(payload)
    except WebSocketDisconnect:
        pass
