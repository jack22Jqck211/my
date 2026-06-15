import asyncio
import json
import os
import hashlib
import secrets
import time
from datetime import datetime
from urllib.parse import quote
from collections import deque, defaultdict

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging
import psutil

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("REN-Gateway")

app = FastAPI(title="REN", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

connections: dict = {}
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

XHTTP_QUEUES: dict = {}
XHTTP_QUEUES_LOCK = asyncio.Lock()

SESSION_COOKIE = "ren_session"
SESSION_TTL = 60 * 60 * 24 * 7

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "admin"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None or exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

async def keep_alive():
    while True:
        await asyncio.sleep(600)
        try:
            domain = get_domain()
            if domain and domain != "localhost":
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.get(f"https://{domain}/health")
                logger.info("Keep-alive ping sent")
        except Exception:
            pass

@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)
    logger.info(f"REN started on port {CONFIG['port']} with XHTTP transport")
    asyncio.create_task(keep_alive())

@app.on_event("shutdown")
async def shutdown():
    if http_client:
        await http_client.aclose()

def get_domain() -> str:
    # Railway uses RAILWAY_PUBLIC_DOMAIN
    railway_domain = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "")
    if railway_domain:
        return railway_domain.replace("https://", "").replace("http://", "")
    # Fallback for other platforms
    render_url = os.environ.get("RENDER_EXTERNAL_URL", "")
    if render_url:
        return render_url.replace("https://", "").replace("http://", "")
    return os.environ.get("CUSTOM_DOMAIN", "localhost")

def generate_uuid(seed: str | None = None) -> str:
    if seed is None:
        return str(secrets.token_hex(16))[:8] + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(6)
    h = hashlib.sha256(f"{seed}{CONFIG['secret']}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def generate_vless_link(uuid: str, remark: str = "REN") -> str:
    domain = get_domain()
    path = f"/xhttp/{uuid}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "xhttp",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "h2",
        "mode": "auto",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{domain}:443?{query}#{quote(remark)}"

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 * 1024 * 1024)
    if unit == "MB": return int(value * 1024 * 1024)
    if unit == "KB": return int(value * 1024)
    return int(value)

async def ensure_default_link():
    async with LINKS_LOCK:
        if not LINKS:
            uid = generate_uuid("default")
            LINKS[uid] = {"label": "Default", "limit_bytes": 0, "used_bytes": 0, "created_at": datetime.now().isoformat(), "active": True}

async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None: return False
        if not link["active"]: return False
        if link["limit_bytes"] == 0: return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]

async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS[uid]["used_bytes"] += n

@app.get("/")
async def root():
    return {"service": "REN", "version": "2.0", "status": "active", "transport": "xhttp", "domain": get_domain(), "platform": "railway"}

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    if hash_password(password) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid password")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    await destroy_session(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    return {"authenticated": await is_valid_session(token)}

@app.post("/api/change-password")
async def api_change_password(request: Request, _=Depends(require_auth)):
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if hash_password(current) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    AUTH["password_hash"] = hash_password(new)
    current_token = request.cookies.get(SESSION_COOKIE)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        if current_token:
            SESSIONS[current_token] = time.time() + SESSION_TTL
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 * 1024), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(LINKS),
        "domain": get_domain(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": psutil.virtual_memory().percent,
        "hourly_traffic": dict(hourly_traffic),
    }

@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    import re as _re
    body = await request.json()
    label = (body.get("label") or "New Link").strip()[:60]
    limit_value = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    custom_uuid = (body.get("custom_uuid") or "").strip()
    uuid_pattern = _re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
    if custom_uuid:
        if not uuid_pattern.match(custom_uuid):
            raise HTTPException(status_code=400, detail="Invalid UUID format. Expected: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
        uid = custom_uuid.lower()
        async with LINKS_LOCK:
            if uid in LINKS:
                raise HTTPException(status_code=409, detail="UUID already exists")
    else:
        uid = generate_uuid(label)
    async with LINKS_LOCK:
        LINKS[uid] = {"label": label, "limit_bytes": limit_bytes, "used_bytes": 0, "created_at": datetime.now().isoformat(), "active": True}
    return {"uuid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0, "active": True, "created_at": LINKS[uid]["created_at"], "vless_link": generate_vless_link(uid, remark=f"REN-{label}")}

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    result = []
    async with LINKS_LOCK:
        for uid, data in LINKS.items():
            result.append({"uuid": uid, "label": data["label"], "limit_bytes": data["limit_bytes"], "used_bytes": data["used_bytes"], "active": data["active"], "created_at": data["created_at"], "vless_link": generate_vless_link(uid, remark=f"REN-{data['label']}")})
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        if "active" in body:
            LINKS[uid]["active"] = bool(body["active"])
        if "limit_value" in body:
            limit_value = float(body.get("limit_value") or 0)
            limit_unit = body.get("limit_unit") or "GB"
            LINKS[uid]["limit_bytes"] = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
        if "reset_usage" in body and body["reset_usage"]:
            LINKS[uid]["used_bytes"] = 0
        if "label" in body:
            LINKS[uid]["label"] = str(body["label"])[:60]
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    async with XHTTP_QUEUES_LOCK:
        queue = XHTTP_QUEUES.pop(uid, None)
        if queue:
            await queue.put(None)
    return {"ok": True}

RELAY_BUF = 64 * 1024

async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("chunk too small")
    pos = 0
    pos += 1; pos += 16
    addon_len = first_chunk[pos]; pos += 1; pos += addon_len
    command = first_chunk[pos]; pos += 1
    port = int.from_bytes(first_chunk[pos:pos + 2], "big"); pos += 2
    addr_type = first_chunk[pos]; pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]; pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]; pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore"); pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]; pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type}")
    return command, address, port, first_chunk[pos:]


class XHTTPSession:
    def __init__(self, uuid: str):
        self.uuid = uuid
        self.conn_id = secrets.token_urlsafe(8)
        self.to_client: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=512)
        self.from_client: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=512)
        self.tcp_reader: asyncio.StreamReader | None = None
        self.tcp_writer: asyncio.StreamWriter | None = None
        self.started = False
        self.closed = False
        self.created_at = datetime.now().isoformat()

XHTTP_SESSIONS: dict[str, XHTTPSession] = {}
XHTTP_SESSIONS_LOCK = asyncio.Lock()


async def xhttp_tcp_relay(session: XHTTPSession):
    uuid = session.uuid
    try:
        first_chunk = await asyncio.wait_for(session.from_client.get(), timeout=15.0)
        if first_chunk is None:
            return

        command, address, port, initial_payload = await parse_vless_header(first_chunk)
        size = len(first_chunk)
        stats["total_bytes"] += size
        stats["total_requests"] += 1
        hourly_traffic[datetime.now().strftime("%H:00")] += size
        await add_usage(uuid, size)

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=10.0
        )
        session.tcp_reader = reader
        session.tcp_writer = writer

        connections[session.conn_id] = {
            "uuid": uuid, "connected_at": session.created_at,
            "bytes": 0, "target": f"{address}:{port}"
        }
        logger.info(f"[XHTTP] {session.conn_id} → {address}:{port}")

        await session.to_client.put(b"\x00\x00")

        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size
            connections[session.conn_id]["bytes"] += p_size
            hourly_traffic[datetime.now().strftime("%H:00")] += p_size
            await add_usage(uuid, p_size)
            writer.write(initial_payload)
            await writer.drain()

        async def client_to_tcp():
            try:
                while not session.closed:
                    try:
                        data = await asyncio.wait_for(session.from_client.get(), timeout=60.0)
                    except asyncio.TimeoutError:
                        continue
                    if data is None:
                        break
                    size = len(data)
                    if not await check_quota(uuid, size):
                        break
                    stats["total_bytes"] += size
                    connections.get(session.conn_id, {})["bytes"] = connections.get(session.conn_id, {}).get("bytes", 0) + size
                    hourly_traffic[datetime.now().strftime("%H:00")] += size
                    await add_usage(uuid, size)
                    writer.write(data)
                    await writer.drain()
            except Exception:
                pass
            finally:
                try:
                    writer.write_eof()
                except Exception:
                    pass

        async def tcp_to_client():
            try:
                while not session.closed:
                    data = await reader.read(RELAY_BUF)
                    if not data:
                        break
                    size = len(data)
                    if not await check_quota(uuid, size):
                        break
                    stats["total_bytes"] += size
                    connections.get(session.conn_id, {})["bytes"] = connections.get(session.conn_id, {}).get("bytes", 0) + size
                    hourly_traffic[datetime.now().strftime("%H:00")] += size
                    await add_usage(uuid, size)
                    await session.to_client.put(data)
            except Exception:
                pass
            finally:
                await session.to_client.put(None)

        task_up = asyncio.create_task(client_to_tcp())
        task_down = asyncio.create_task(tcp_to_client())
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()

    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        logger.error(f"[XHTTP] relay error: {exc}")
    finally:
        session.closed = True
        await session.to_client.put(None)
        if session.tcp_writer:
            try:
                session.tcp_writer.close()
            except Exception:
                pass
        connections.pop(session.conn_id, None)
        async with XHTTP_SESSIONS_LOCK:
            XHTTP_SESSIONS.pop(session.conn_id, None)


async def _get_or_create_session(uuid: str, session_id: str) -> "XHTTPSession":
    async with XHTTP_SESSIONS_LOCK:
        session = XHTTP_SESSIONS.get(session_id)
        if session is None:
            session = XHTTPSession(uuid)
            session.conn_id = session_id
            XHTTP_SESSIONS[session_id] = session
            asyncio.create_task(xhttp_tcp_relay(session))
    return session


@app.get("/xhttp/{uuid}/{session_id}")
async def xhttp_downstream(uuid: str, session_id: str, request: Request):
    await ensure_default_link()
    if not await check_quota(uuid, 0):
        raise HTTPException(status_code=403, detail="quota exceeded or link disabled")
    logger.info(f"[XHTTP] GET session={session_id} uuid={uuid}")
    session = await _get_or_create_session(uuid, session_id)

    async def generate():
        try:
            while True:
                try:
                    chunk = await asyncio.wait_for(session.to_client.get(), timeout=120.0)
                except asyncio.TimeoutError:
                    yield b""
                    continue
                if chunk is None:
                    break
                yield chunk
        except Exception:
            pass

    return StreamingResponse(
        generate(),
        media_type="application/octet-stream",
        headers={
            "Cache-Control": "no-store",
            "X-Accel-Buffering": "no",
            "Transfer-Encoding": "chunked",
        },
    )


@app.post("/xhttp/{uuid}/{session_id}/{seq}")
async def xhttp_upstream(uuid: str, session_id: str, seq: str, request: Request):
    await ensure_default_link()
    if not await check_quota(uuid, 0):
        raise HTTPException(status_code=403, detail="quota exceeded or link disabled")
    logger.info(f"[XHTTP] POST seq={seq} session={session_id} uuid={uuid}")
    session = await _get_or_create_session(uuid, session_id)
    body = await request.body()
    if body:
        try:
            await asyncio.wait_for(session.from_client.put(body), timeout=10.0)
        except asyncio.TimeoutError:
            raise HTTPException(status_code=503, detail="session buffer full")
    return Response(status_code=200, content=b"", media_type="application/octet-stream")


# ─── COMPLETELY NEW UI DESIGN ─────────────────────────────────────────────────
# Design direction: dark glassmorphism / terminal aesthetic
# Palette: deep navy-black (#080c14), electric indigo (#6366f1), cyan (#06b6d4)
# Typography: JetBrains Mono for data, Inter for UI text
# Signature: animated grid background with glowing nodes

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>REN · Gateway</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#080c14;
  --surface:rgba(255,255,255,0.04);
  --surface-hover:rgba(255,255,255,0.07);
  --border:rgba(255,255,255,0.08);
  --border-glow:rgba(99,102,241,0.4);
  --text:#e2e8f0;
  --text-dim:#64748b;
  --text-muted:#334155;
  --indigo:#6366f1;
  --indigo-dim:rgba(99,102,241,0.15);
  --cyan:#06b6d4;
  --cyan-dim:rgba(6,182,212,0.12);
  --green:#10b981;
  --red:#f43f5e;
  --red-dim:rgba(244,63,94,0.12);
  --yellow:#f59e0b;
}
html,body{height:100%;font-family:'Inter',sans-serif;background:var(--bg);color:var(--text)}
canvas#grid{position:fixed;inset:0;z-index:0;opacity:0.4}
.wrap{position:relative;z-index:1;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{
  width:100%;max-width:400px;
  background:rgba(8,12,20,0.85);
  border:1px solid var(--border);
  border-radius:16px;
  padding:40px 36px 32px;
  backdrop-filter:blur(20px);
  box-shadow:0 0 0 1px rgba(99,102,241,0.05),0 20px 60px rgba(0,0,0,0.5),inset 0 1px 0 rgba(255,255,255,0.05);
  position:relative;overflow:hidden;
}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--indigo),transparent)}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:32px}
.logo-icon{
  width:44px;height:44px;border-radius:10px;
  background:linear-gradient(135deg,var(--indigo),#4f46e5);
  display:flex;align-items:center;justify-content:center;
  box-shadow:0 0 20px rgba(99,102,241,0.3);
  font-family:'JetBrains Mono',monospace;font-size:14px;font-weight:700;color:#fff;letter-spacing:-1px
}
.logo-text h1{font-size:18px;font-weight:700;color:var(--text);letter-spacing:-0.02em}
.logo-text p{font-size:11px;color:var(--text-dim);font-family:'JetBrains Mono',monospace;margin-top:2px}
.platform-badge{
  display:inline-flex;align-items:center;gap:5px;padding:4px 10px;
  background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.2);
  border-radius:6px;font-size:10px;color:var(--indigo);font-family:'JetBrains Mono',monospace;
  margin-bottom:24px;
}
.platform-badge::before{content:'';width:6px;height:6px;border-radius:50%;background:var(--cyan);display:inline-block;box-shadow:0 0 6px var(--cyan)}
label{display:block;font-size:11px;font-weight:600;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.08em;margin-bottom:8px;font-family:'JetBrains Mono',monospace}
input{
  width:100%;padding:11px 14px;
  background:rgba(255,255,255,0.03);
  border:1px solid var(--border);
  border-radius:8px;color:var(--text);
  font-size:14px;font-family:'Inter',sans-serif;
  outline:none;transition:all .2s;
}
input:focus{border-color:var(--indigo);box-shadow:0 0 0 3px rgba(99,102,241,0.12),0 0 20px rgba(99,102,241,0.05)}
input::placeholder{color:var(--text-muted)}
.form-group{margin-bottom:20px}
.btn{
  width:100%;padding:12px;margin-top:4px;
  background:linear-gradient(135deg,var(--indigo),#4f46e5);
  border:none;border-radius:8px;
  color:#fff;font-size:14px;font-weight:600;font-family:'Inter',sans-serif;
  cursor:pointer;transition:all .2s;
  box-shadow:0 4px 15px rgba(99,102,241,0.3);
  letter-spacing:0.01em;
}
.btn:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(99,102,241,0.4)}
.btn:active{transform:translateY(0)}
.err{
  background:var(--red-dim);border:1px solid rgba(244,63,94,0.2);
  color:var(--red);padding:10px 14px;border-radius:8px;
  font-size:12px;display:none;margin-bottom:16px;text-align:center;font-weight:500;
}
.err.show{display:block}
.corner{position:absolute;width:16px;height:16px;border-color:var(--indigo);border-style:solid;opacity:0.3}
.corner-tl{top:8px;left:8px;border-width:1px 0 0 1px;border-radius:2px 0 0 0}
.corner-tr{top:8px;right:8px;border-width:1px 1px 0 0;border-radius:0 2px 0 0}
.corner-bl{bottom:8px;left:8px;border-width:0 0 1px 1px;border-radius:0 0 0 2px}
.corner-br{bottom:8px;right:8px;border-width:0 1px 1px 0;border-radius:0 0 2px 0}
</style>
</head>
<body>
<canvas id="grid"></canvas>
<div class="wrap">
  <div class="card">
    <div class="corner corner-tl"></div>
    <div class="corner corner-tr"></div>
    <div class="corner corner-bl"></div>
    <div class="corner corner-br"></div>
    <div class="logo">
      <div class="logo-icon">REN</div>
      <div class="logo-text">
        <h1>REN Gateway</h1>
        <p>VLESS · XHTTP · TLS</p>
      </div>
    </div>
    <div class="platform-badge">railway.app · active</div>
    <div class="err" id="err"></div>
    <form id="form">
      <div class="form-group">
        <label>Admin Password</label>
        <input type="password" id="pw" placeholder="Enter password" autofocus autocomplete="current-password">
      </div>
      <button type="submit" class="btn">Access Panel</button>
    </form>
  </div>
</div>
<script>
// Animated grid background
const canvas = document.getElementById('grid');
const ctx = canvas.getContext('2d');
let W, H, nodes = [], t = 0;

function resize(){W=canvas.width=window.innerWidth;H=canvas.height=window.innerHeight;initNodes()}
function initNodes(){nodes=[];const cols=Math.floor(W/80),rows=Math.floor(H/80);for(let i=0;i<=cols;i++)for(let j=0;j<=rows;j++){if(Math.random()<0.15)nodes.push({x:i*80,y:j*80,phase:Math.random()*Math.PI*2,speed:0.01+Math.random()*0.02})}}

function draw(){
  ctx.clearRect(0,0,W,H);
  // grid lines
  ctx.strokeStyle='rgba(99,102,241,0.06)';ctx.lineWidth=1;
  for(let x=0;x<W;x+=80){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,H);ctx.stroke()}
  for(let y=0;y<H;y+=80){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(W,y);ctx.stroke()}
  // nodes
  t+=0.016;
  nodes.forEach(n=>{
    const pulse=Math.sin(t*n.speed*60+n.phase);
    const a=0.15+0.4*((pulse+1)/2);
    const r=2+2*((pulse+1)/2);
    ctx.beginPath();ctx.arc(n.x,n.y,r,0,Math.PI*2);
    ctx.fillStyle=`rgba(6,182,212,${a})`;ctx.fill();
    // glow
    const grd=ctx.createRadialGradient(n.x,n.y,0,n.x,n.y,12);
    grd.addColorStop(0,`rgba(6,182,212,${a*0.4})`);grd.addColorStop(1,'transparent');
    ctx.beginPath();ctx.arc(n.x,n.y,12,0,Math.PI*2);ctx.fillStyle=grd;ctx.fill();
  });
  requestAnimationFrame(draw);
}
resize();window.addEventListener('resize',resize);draw();

document.getElementById('form').addEventListener('submit',async e=>{
  e.preventDefault();const err=document.getElementById('err');err.classList.remove('show');
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('pw').value})});
    if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'Authentication failed')}
    location.href='/dashboard';
  }catch(e){err.textContent=e.message;err.classList.add('show')}
});
</script>
</body>
</html>"""


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>REN · Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#080c14;
  --sidebar:#060a10;
  --surface:rgba(255,255,255,0.035);
  --surface2:rgba(255,255,255,0.05);
  --surface3:rgba(255,255,255,0.08);
  --border:rgba(255,255,255,0.07);
  --border2:rgba(255,255,255,0.12);
  --text:#e2e8f0;
  --text-dim:#64748b;
  --text-muted:#1e293b;
  --indigo:#6366f1;
  --indigo-bright:#818cf8;
  --indigo-dim:rgba(99,102,241,0.12);
  --indigo-glow:rgba(99,102,241,0.25);
  --cyan:#06b6d4;
  --cyan-dim:rgba(6,182,212,0.1);
  --green:#10b981;
  --green-dim:rgba(16,185,129,0.1);
  --red:#f43f5e;
  --red-dim:rgba(244,63,94,0.1);
  --yellow:#f59e0b;
  --yellow-dim:rgba(245,158,11,0.1);
  --mono:'JetBrains Mono',monospace;
  --sans:'Inter',sans-serif;
}
html,body{height:100%;font-family:var(--sans);background:var(--bg);color:var(--text)}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:rgba(99,102,241,0.2);border-radius:2px}

/* Layout */
.layout{display:flex;min-height:100vh}
.sidebar{
  width:228px;flex-shrink:0;
  background:var(--sidebar);
  border-right:1px solid var(--border);
  display:flex;flex-direction:column;
  position:fixed;left:0;top:0;bottom:0;z-index:100;
}
.main{margin-left:228px;flex:1;min-height:100vh;padding:28px 32px 60px}

/* Sidebar */
.sb-top{padding:20px 16px 16px;border-bottom:1px solid var(--border)}
.sb-logo{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.sb-logo-mark{
  width:32px;height:32px;border-radius:8px;
  background:linear-gradient(135deg,var(--indigo),#4f46e5);
  display:flex;align-items:center;justify-content:center;
  font-family:var(--mono);font-size:10px;font-weight:700;color:#fff;
  box-shadow:0 0 12px rgba(99,102,241,0.35);
}
.sb-logo-name{font-size:15px;font-weight:700;color:var(--text);letter-spacing:-0.02em}
.sb-platform{
  display:flex;align-items:center;gap:6px;
  padding:5px 10px;background:var(--surface);border:1px solid var(--border);
  border-radius:6px;font-size:10px;color:var(--text-dim);font-family:var(--mono);
}
.sb-platform .dot{width:5px;height:5px;border-radius:50%;background:var(--green);box-shadow:0 0 5px var(--green);flex-shrink:0}
.sb-nav{flex:1;padding:12px 8px;overflow-y:auto}
.nav-group{margin-bottom:4px}
.nav-label{font-size:9px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.1em;padding:10px 10px 4px;font-family:var(--mono)}
.nav-btn{
  width:100%;display:flex;align-items:center;gap:9px;
  padding:8px 10px;border-radius:7px;border:none;background:none;
  color:var(--text-dim);font-size:13px;font-weight:500;font-family:var(--sans);
  cursor:pointer;transition:all .15s;text-align:left;
}
.nav-btn:hover{background:var(--surface2);color:var(--text)}
.nav-btn.active{background:var(--indigo-dim);color:var(--indigo-bright)}
.nav-btn.active .ni{color:var(--indigo-bright);opacity:1}
.ni{width:16px;height:16px;flex-shrink:0;opacity:0.5;transition:opacity .15s}
.nav-badge{margin-left:auto;background:var(--indigo-dim);color:var(--indigo);font-size:10px;padding:1px 6px;border-radius:4px;font-weight:700;font-family:var(--mono)}
.sb-bot{padding:12px 8px;border-top:1px solid var(--border)}
.sb-bot-row{display:flex;gap:4px;margin-bottom:6px}
.lang-btn{flex:1;padding:5px;border:1px solid var(--border);border-radius:6px;background:none;color:var(--text-dim);font-family:var(--mono);font-size:10px;font-weight:700;cursor:pointer;transition:all .2s;letter-spacing:0.02em}
.lang-btn.active{background:var(--indigo-dim);border-color:rgba(99,102,241,0.3);color:var(--indigo-bright)}
.logout-btn{
  width:100%;padding:7px 10px;border:1px solid var(--border);border-radius:7px;
  background:none;color:var(--text-dim);font-family:var(--sans);font-size:12px;font-weight:500;
  cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:6px;
}
.logout-btn:hover{background:var(--red-dim);border-color:rgba(244,63,94,0.2);color:var(--red)}
.version{text-align:center;font-size:9px;color:var(--text-muted);margin-top:8px;font-family:var(--mono);letter-spacing:0.04em}

/* Pages */
.page{display:none}.page.active{display:block}
.page-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px}
.page-title{font-size:22px;font-weight:800;color:var(--text);letter-spacing:-0.03em}
.page-sub{font-size:11px;color:var(--text-dim);margin-top:3px;font-family:var(--mono)}

/* Stat cards */
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
.stat-card{
  background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:18px 20px;position:relative;overflow:hidden;transition:border-color .2s;
}
.stat-card:hover{border-color:var(--border2)}
.stat-card::after{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--indigo-dim),transparent)}
.stat-eyebrow{font-size:9px;font-weight:700;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.1em;font-family:var(--mono);margin-bottom:10px}
.stat-value{font-size:26px;font-weight:800;color:var(--text);letter-spacing:-0.04em;line-height:1}
.stat-unit{font-size:13px;font-weight:400;color:var(--text-dim)}
.stat-sub{font-size:10px;color:var(--text-dim);margin-top:6px;font-family:var(--mono)}

/* Cards */
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px;margin-bottom:12px}
.card-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
.card-title{font-size:13px;font-weight:600;color:var(--text);display:flex;align-items:center;gap:8px}
.card-title .ct-dot{width:6px;height:6px;border-radius:50%;background:var(--indigo);box-shadow:0 0 6px var(--indigo)}

/* Sys meters */
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.meter-label{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
.meter-name{font-size:11px;font-weight:600;color:var(--text-dim);font-family:var(--mono);text-transform:uppercase;letter-spacing:0.04em}
.meter-val{font-size:18px;font-weight:800;letter-spacing:-0.03em}
.meter-bar{height:4px;background:rgba(255,255,255,0.06);border-radius:2px;overflow:hidden}
.meter-fill{height:100%;border-radius:2px;transition:width .5s cubic-bezier(.4,0,.2,1)}

/* Buttons */
.btn{font-family:var(--sans);font-size:12px;font-weight:600;border-radius:7px;padding:7px 14px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;border:none;transition:all .15s;letter-spacing:0.01em}
.btn-primary{background:linear-gradient(135deg,var(--indigo),#4f46e5);color:#fff;box-shadow:0 2px 8px rgba(99,102,241,0.3)}
.btn-primary:hover{filter:brightness(1.1);transform:translateY(-1px)}
.btn-ghost{background:var(--surface2);color:var(--text-dim);border:1px solid var(--border)}
.btn-ghost:hover{border-color:var(--border2);color:var(--text)}
.btn-danger{background:var(--red-dim);color:var(--red);border:1px solid rgba(244,63,94,0.15)}
.btn-danger:hover{background:rgba(244,63,94,0.18)}
.btn-sm{padding:5px 9px;font-size:11px}
.btn-xs{padding:3px 7px;font-size:10px;font-family:var(--mono)}

/* Table */
.tbl-wrap{overflow-x:auto}
.tbl{width:100%;border-collapse:collapse}
.tbl th{text-align:left;font-size:10px;font-weight:700;color:var(--text-dim);padding:10px 14px;text-transform:uppercase;letter-spacing:0.06em;border-bottom:1px solid var(--border);font-family:var(--mono);white-space:nowrap}
.tbl td{padding:11px 14px;border-bottom:1px solid rgba(255,255,255,0.03);font-size:12px;vertical-align:middle}
.tbl tr:last-child td{border-bottom:none}
.tbl tbody tr{transition:background .1s}
.tbl tbody tr:hover td{background:rgba(255,255,255,0.02)}

/* Tags / chips */
.tag{display:inline-flex;align-items:center;padding:2px 8px;border-radius:5px;font-size:9px;font-weight:700;letter-spacing:0.05em;text-transform:uppercase;font-family:var(--mono)}
.tag-xhttp{background:rgba(6,182,212,0.12);color:var(--cyan)}
.tag-vless{background:var(--indigo-dim);color:var(--indigo-bright)}
.tag-on{background:var(--green-dim);color:var(--green)}
.tag-off{background:var(--red-dim);color:var(--red)}

/* Usage bar */
.usage{display:flex;align-items:center;gap:8px}
.usage-used{font-size:11px;font-weight:700;color:var(--text);font-family:var(--mono);white-space:nowrap}
.usage-track{flex:1;height:3px;background:rgba(255,255,255,0.05);border-radius:2px;min-width:50px}
.usage-fill{height:100%;border-radius:2px;transition:width .3s}
.usage-lim{font-size:10px;color:var(--text-dim);font-family:var(--mono);white-space:nowrap}

/* Toggle */
.tog{width:32px;height:17px;border-radius:9px;background:rgba(255,255,255,0.08);border:1px solid var(--border);position:relative;cursor:pointer;transition:all .2s;flex-shrink:0}
.tog::after{content:'';position:absolute;width:11px;height:11px;border-radius:50%;background:var(--text-dim);top:2px;left:2px;transition:all .2s}
.tog.on{background:var(--green);border-color:var(--green)}
.tog.on::after{left:17px;background:#fff}

/* Actions row */
.act-row{display:flex;align-items:center;gap:4px}

/* Inbounds toolbar */
.ib-toolbar{display:flex;align-items:center;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.search-wrap{flex:1;min-width:160px;position:relative}
.search-wrap svg{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--text-dim)}
.search-inp{width:100%;padding:8px 12px 8px 32px;background:var(--surface);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;font-family:var(--sans);outline:none;transition:all .2s}
.search-inp:focus{border-color:var(--indigo);box-shadow:0 0 0 3px rgba(99,102,241,0.1)}
.search-inp::placeholder{color:var(--text-dim)}
.filter-row{display:flex;gap:2px;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:3px}
.fchip{padding:4px 12px;border-radius:5px;font-size:10px;font-weight:700;color:var(--text-dim);cursor:pointer;border:none;background:none;font-family:var(--mono);letter-spacing:0.03em;transition:all .15s}
.fchip:hover:not(.active){background:var(--surface2);color:var(--text)}
.fchip.active{background:var(--indigo-dim);color:var(--indigo-bright)}

/* Status items */
.status-row{display:flex;align-items:center;justify-content:space-between;padding:12px 0;border-bottom:1px solid rgba(255,255,255,0.04)}
.status-row:last-child{border-bottom:none}
.sk{color:var(--text-dim);font-size:12px;display:flex;align-items:center;gap:8px}
.sv{color:var(--text);font-weight:600;font-size:12px;font-family:var(--mono)}

/* Forms */
.fg{display:flex;flex-direction:column;gap:5px;margin-bottom:14px}
.fl{font-size:10px;font-weight:700;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.07em;font-family:var(--mono)}
.fi,.fsel{
  padding:9px 12px;border-radius:8px;border:1px solid var(--border);
  font-family:var(--sans);font-size:13px;outline:none;
  color:var(--text);background:var(--surface);transition:all .2s;
}
.fi:focus,.fsel:focus{border-color:var(--indigo);box-shadow:0 0 0 3px rgba(99,102,241,0.1)}
.fi::placeholder{color:var(--text-dim)}
.frow{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
.frow .fg{margin-bottom:0;flex:1;min-width:100px}

/* Modal */
.modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:200;display:none;align-items:center;justify-content:center;backdrop-filter:blur(8px)}
.modal-backdrop.open{display:flex}
.modal{
  background:#0c1018;border:1px solid var(--border);border-radius:14px;
  padding:24px;width:100%;max-width:460px;position:relative;
  box-shadow:0 0 0 1px rgba(99,102,241,0.1),0 24px 60px rgba(0,0,0,0.5);
  transform:scale(0.92) translateY(10px);opacity:0;
  transition:all .25s cubic-bezier(.34,1.56,.64,1);
}
.modal-backdrop.open .modal{transform:scale(1) translateY(0);opacity:1}
.modal::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--indigo),transparent)}
.modal-title{font-size:15px;font-weight:700;margin-bottom:20px;color:var(--text)}
.modal-close{position:absolute;top:14px;right:14px;background:var(--surface2);border:1px solid var(--border);color:var(--text-dim);width:26px;height:26px;border-radius:6px;cursor:pointer;font-size:14px;display:flex;align-items:center;justify-content:center;transition:all .2s;font-family:var(--mono)}
.modal-close:hover{background:var(--red-dim);color:var(--red);border-color:rgba(244,63,94,0.2)}

/* QR */
.qr-box{text-align:center;padding:24px;background:var(--surface);border-radius:10px;border:1px solid var(--border);margin-top:14px}
.qr-box img{max-width:200px;border-radius:8px}

/* Detail */
.detail-pair{margin-bottom:12px}
.dl{font-size:9px;font-weight:700;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.08em;font-family:var(--mono);margin-bottom:5px}
.dv{padding:8px 12px;background:var(--surface);border:1px solid var(--border);border-radius:7px;font-size:11px;color:var(--text-dim);word-break:break-all;font-family:var(--mono);line-height:1.6}
.d-row{display:flex;gap:10px;margin-bottom:12px}
.d-col{flex:1}
.d-actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:14px}

/* Toast */
.toast{
  position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(10px);
  background:#0c1018;color:var(--text);border:1px solid var(--border);
  border-radius:8px;padding:10px 20px;font-size:12px;font-weight:500;
  opacity:0;transition:all .25s;z-index:999;
  display:flex;align-items:center;gap:8px;
  box-shadow:0 8px 30px rgba(0,0,0,0.4),0 0 0 1px rgba(99,102,241,0.1);
  font-family:var(--mono);
}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.err{border-color:rgba(244,63,94,0.3);color:var(--red)}
.toast .ti{width:6px;height:6px;border-radius:50%;background:var(--green);flex-shrink:0}
.toast.err .ti{background:var(--red)}

/* Mobile */
.mob-header{display:none;position:fixed;top:0;left:0;right:0;height:48px;background:var(--sidebar);border-bottom:1px solid var(--border);z-index:90;align-items:center;justify-content:space-between;padding:0 16px}
.mob-header .ml{font-weight:800;font-size:14px;font-family:var(--mono);letter-spacing:-0.02em}
.ham{width:32px;height:32px;border-radius:7px;border:1px solid var(--border);background:var(--surface);color:var(--text-dim);display:flex;align-items:center;justify-content:center;cursor:pointer;font-size:15px}
.sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:99}
.sidebar-overlay.open{display:block}

/* Empty state */
.empty{text-align:center;padding:48px 16px;color:var(--text-dim)}
.empty .ei{font-size:40px;margin-bottom:12px;opacity:0.2}

/* Mobile cards */
.mob-cards{display:none;flex-direction:column;gap:8px}
.mob-card{border:1px solid var(--border);border-radius:10px;padding:14px;background:var(--surface)}
.mob-card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}

@media(max-width:900px){
  .stats-grid{grid-template-columns:1fr 1fr}
  .grid-2{grid-template-columns:1fr}
}
@media(max-width:700px){
  .sidebar{transform:translateX(-100%);transition:transform .25s}
  .sidebar.open{transform:translateX(0);box-shadow:8px 0 30px rgba(0,0,0,0.5)}
  .main{margin-left:0;padding:68px 16px 48px}
  .mob-header{display:flex}
  .tbl-wrap{display:none}
  .mob-cards{display:flex}
  .stats-grid{grid-template-columns:1fr 1fr}
}
@media(max-width:420px){.stats-grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="toast" id="toast"><span class="ti"></span><span id="toast-msg"></span></div>

<div class="mob-header">
  <span class="ml">REN</span>
  <button class="ham" onclick="toggleSidebar()">&#9776;</button>
</div>
<div class="sidebar-overlay" id="sb-overlay" onclick="closeSidebar()"></div>

<aside class="sidebar" id="sidebar">
  <div class="sb-top">
    <div class="sb-logo">
      <div class="sb-logo-mark">REN</div>
      <span class="sb-logo-name">REN Gateway</span>
    </div>
    <div class="sb-platform">
      <span class="dot"></span>
      <span>railway.app · online</span>
    </div>
  </div>
  <nav class="sb-nav">
    <div class="nav-group">
      <div class="nav-label">Overview</div>
      <button class="nav-btn active" data-page="dashboard">
        <svg class="ni" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>
        <span data-en="Dashboard" data-fa="داشبورد">Dashboard</span>
      </button>
      <button class="nav-btn" data-page="inbounds">
        <svg class="ni" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="23" y1="11" x2="17" y2="11"/><line x1="20" y1="8" x2="20" y2="14"/></svg>
        <span data-en="Inbounds" data-fa="کاربران">Inbounds</span>
        <span class="nav-badge" id="links-badge">0</span>
      </button>
      <button class="nav-btn" data-page="traffic">
        <svg class="ni" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        <span data-en="Traffic" data-fa="ترافیک">Traffic</span>
      </button>
    </div>
    <div class="nav-group">
      <div class="nav-label">System</div>
      <button class="nav-btn" data-page="security">
        <svg class="ni" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
        <span data-en="Security" data-fa="امنیت">Security</span>
      </button>
    </div>
  </nav>
  <div class="sb-bot">
    <div class="sb-bot-row">
      <button class="lang-btn active" onclick="setLang('en')" id="l-en">EN</button>
      <button class="lang-btn" onclick="setLang('fa')" id="l-fa">FA</button>
    </div>
    <button class="logout-btn" onclick="doLogout()">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      <span data-en="Sign Out" data-fa="خروج">Sign Out</span>
    </button>
    <div class="version">v2.0 · XHTTP · railway.app</div>
  </div>
</aside>

<main class="main">

  <!-- DASHBOARD PAGE -->
  <section class="page active" id="page-dashboard">
    <div class="page-header">
      <div>
        <div class="page-title" data-en="Dashboard" data-fa="داشبورد">Dashboard</div>
        <div class="page-sub" id="last-update">syncing...</div>
      </div>
      <div style="display:flex;gap:6px">
        <button class="btn btn-ghost btn-sm" onclick="quickCreate(0.5,'GB')">+ 500 MB</button>
        <button class="btn btn-primary btn-sm" onclick="quickCreate(1,'GB')">+ 1 GB</button>
      </div>
    </div>
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-eyebrow" data-en="Total Traffic" data-fa="کل ترافیک">Total Traffic</div>
        <div class="stat-value" id="s-traffic">—<span class="stat-unit"> MB</span></div>
        <div class="stat-sub">since start</div>
      </div>
      <div class="stat-card">
        <div class="stat-eyebrow" data-en="Inbounds" data-fa="کاربران">Inbounds</div>
        <div class="stat-value" id="s-links">—</div>
        <div class="stat-sub">total configs</div>
      </div>
      <div class="stat-card">
        <div class="stat-eyebrow" data-en="Uptime" data-fa="آپتایم">Uptime</div>
        <div class="stat-value" id="s-uptime" style="font-size:18px;padding-top:4px">—</div>
        <div class="stat-sub">hh:mm:ss</div>
      </div>
      <div class="stat-card">
        <div class="stat-eyebrow" data-en="Domain" data-fa="دامنه">Domain</div>
        <div class="stat-value" id="s-domain" style="font-size:10px;font-weight:500;padding-top:6px;word-break:break-all;font-family:var(--mono)">—</div>
      </div>
    </div>

    <div class="grid-2">
      <div class="card">
        <div class="card-head">
          <div class="card-title"><span class="ct-dot"></span>CPU</div>
          <span id="s-cpu-pct" style="font-size:20px;font-weight:800;color:var(--indigo);font-family:var(--mono)">—</span>
        </div>
        <div class="meter-bar"><div class="meter-fill" id="s-cpu-bar" style="width:0%;background:var(--indigo)"></div></div>
      </div>
      <div class="card">
        <div class="card-head">
          <div class="card-title"><span class="ct-dot" style="background:var(--cyan);box-shadow:0 0 6px var(--cyan)"></span>Memory</div>
          <span id="s-mem-pct" style="font-size:20px;font-weight:800;color:var(--cyan);font-family:var(--mono)">—</span>
        </div>
        <div class="meter-bar"><div class="meter-fill" id="s-mem-bar" style="width:0%;background:var(--cyan)"></div></div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <div class="card-title"><span class="ct-dot" style="background:var(--green);box-shadow:0 0 6px var(--green)"></span>Hourly Traffic</div>
      </div>
      <div style="height:160px"><canvas id="tChart"></canvas></div>
    </div>
  </section>

  <!-- INBOUNDS PAGE -->
  <section class="page" id="page-inbounds">
    <div class="page-header">
      <div>
        <div class="page-title" data-en="Inbounds" data-fa="کاربران">Inbounds</div>
        <div class="page-sub">VLESS · XHTTP · TLS</div>
      </div>
      <button class="btn btn-primary" onclick="openAddModal()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
        <span data-en="Add Inbound" data-fa="افزودن">Add Inbound</span>
      </button>
    </div>
    <div class="ib-toolbar">
      <div class="search-wrap">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input class="search-inp" id="ib-search" placeholder="Search name or UUID..." oninput="filterLinks()">
      </div>
      <div class="filter-row">
        <button class="fchip active" onclick="setFilter('all',this)">ALL</button>
        <button class="fchip" onclick="setFilter('active',this)">ON</button>
        <button class="fchip" onclick="setFilter('disabled',this)">OFF</button>
      </div>
    </div>
    <div class="card" style="padding:0;overflow:hidden">
      <div class="tbl-wrap">
        <table class="tbl">
          <thead><tr>
            <th>#</th><th>Remark</th><th>Proto</th><th>Usage</th><th>Status</th><th>Actions</th>
          </tr></thead>
          <tbody id="links-tbody"></tbody>
        </table>
      </div>
      <div class="mob-cards" id="mob-cards"></div>
      <div class="empty" id="links-empty" style="display:none">
        <div class="ei">○</div>
        <div>No inbounds yet</div>
      </div>
    </div>
  </section>

  <!-- TRAFFIC PAGE -->
  <section class="page" id="page-traffic">
    <div class="page-header">
      <div>
        <div class="page-title">Traffic</div>
        <div class="page-sub">Network statistics</div>
      </div>
    </div>
    <div class="card">
      <div class="card-head"><div class="card-title"><span class="ct-dot"></span>Network Stats</div></div>
      <div class="status-row"><span class="sk">Total Traffic</span><span class="sv" id="t-traffic">—</span></div>
      <div class="status-row"><span class="sk">Total Requests</span><span class="sv" id="t-reqs">—</span></div>
      <div class="status-row"><span class="sk">Total Errors</span><span class="sv" id="t-errs">—</span></div>
      <div class="status-row"><span class="sk">Uptime</span><span class="sv" id="t-uptime">—</span></div>
      <div class="status-row"><span class="sk">Platform</span><span class="sv" style="color:var(--indigo)">Railway.app</span></div>
    </div>
  </section>

  <!-- SECURITY PAGE -->
  <section class="page" id="page-security">
    <div class="page-header">
      <div>
        <div class="page-title" data-en="Security" data-fa="امنیت">Security</div>
        <div class="page-sub">Change admin password</div>
      </div>
    </div>
    <div class="card" style="max-width:400px">
      <div class="card-head"><div class="card-title"><span class="ct-dot" style="background:var(--yellow);box-shadow:0 0 6px var(--yellow)"></span>Change Password</div></div>
      <div class="fg">
        <label class="fl">Current Password</label>
        <input class="fi" type="password" id="cur-pw" placeholder="Enter current password">
      </div>
      <div class="fg">
        <label class="fl">New Password</label>
        <input class="fi" type="password" id="new-pw" placeholder="Minimum 4 characters">
      </div>
      <button class="btn btn-primary" onclick="changePassword()" style="margin-top:4px">Update Password</button>
    </div>
  </section>
</main>

<!-- ADD INBOUND MODAL -->
<div class="modal-backdrop" id="add-modal" onclick="if(event.target===this)closeModal('add-modal')">
  <div class="modal">
    <button class="modal-close" onclick="closeModal('add-modal')">✕</button>
    <div class="modal-title" data-en="New Inbound" data-fa="کاربر جدید">New Inbound</div>
    <div class="fg">
      <label class="fl">Remark / Name</label>
      <input class="fi" id="m-label" placeholder="e.g. User 1">
    </div>
    <div class="frow">
      <div class="fg" style="flex:1">
        <label class="fl">Traffic Limit</label>
        <input class="fi" id="m-limit" type="number" min="0" step="0.5" placeholder="0 = Unlimited">
      </div>
      <div class="fg" style="min-width:80px;max-width:100px">
        <label class="fl">Unit</label>
        <select class="fsel" id="m-unit"><option value="GB">GB</option><option value="MB">MB</option></select>
      </div>
    </div>
    <div class="fg">
      <label class="fl" style="display:flex;align-items:center;justify-content:space-between">
        <span>UUID <span style="font-weight:400;opacity:.5;text-transform:none">(optional)</span></span>
        <button type="button" onclick="genUUID()" style="background:none;border:1px solid var(--border);border-radius:5px;color:var(--text-dim);font-size:9px;padding:2px 7px;cursor:pointer;font-family:var(--mono);letter-spacing:.04em">GEN</button>
      </label>
      <input class="fi" id="m-uuid" placeholder="Leave empty to auto-generate" style="font-family:var(--mono);font-size:11px" oninput="validateUUID(this)">
      <div id="uuid-err" style="color:var(--red);font-size:10px;margin-top:3px;display:none;font-family:var(--mono)">Invalid UUID format</div>
    </div>
    <button class="btn btn-primary" onclick="createLink()" style="width:100%;margin-top:6px;justify-content:center">Create Inbound</button>
  </div>
</div>

<!-- DETAIL MODAL -->
<div class="modal-backdrop" id="detail-modal" onclick="if(event.target===this)closeModal('detail-modal')">
  <div class="modal" style="max-width:520px">
    <button class="modal-close" onclick="closeModal('detail-modal')">✕</button>
    <div class="modal-title" id="d-title">Inbound Detail</div>
    <div id="d-content"></div>
  </div>
</div>

<!-- QR MODAL -->
<div class="modal-backdrop" id="qr-modal" onclick="if(event.target===this)closeModal('qr-modal')">
  <div class="modal">
    <button class="modal-close" onclick="closeModal('qr-modal')">✕</button>
    <div class="modal-title">QR Code</div>
    <div class="qr-box"><img id="qr-img" src="" alt="QR Code" style="width:180px;height:180px"></div>
    <div style="display:flex;gap:6px;justify-content:center;margin-top:14px">
      <button class="btn btn-primary btn-sm" onclick="dlQR()">Download</button>
      <button class="btn btn-ghost btn-sm" onclick="closeModal('qr-modal')">Close</button>
    </div>
  </div>
</div>

<script>
let lang = localStorage.getItem('ren_lang') || 'en';
let allLinks = [], curFilter = 'all', statsData = {}, chart = null;

// ── Navigation ──────────────────────────────
document.querySelectorAll('.nav-btn[data-page]').forEach(b => b.addEventListener('click', () => goPage(b.dataset.page)));
function goPage(id){
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById('page-' + id)?.classList.add('active');
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.page === id));
  closeSidebar();
}
function toggleSidebar(){document.getElementById('sidebar').classList.toggle('open');document.getElementById('sb-overlay').classList.toggle('open')}
function closeSidebar(){document.getElementById('sidebar').classList.remove('open');document.getElementById('sb-overlay').classList.remove('open')}

// ── Language ─────────────────────────────────
function setLang(l){
  lang = l;
  document.body.dir = l === 'fa' ? 'rtl' : 'ltr';
  document.querySelectorAll('[data-en]').forEach(el => {const v = el.getAttribute('data-' + l); if(v) el.textContent = v});
  document.getElementById('l-en').classList.toggle('active', l === 'en');
  document.getElementById('l-fa').classList.toggle('active', l === 'fa');
  localStorage.setItem('ren_lang', l);
}

// ── Modals ────────────────────────────────────
function openModal(id){document.getElementById(id).classList.add('open')}
function closeModal(id){document.getElementById(id).classList.remove('open')}
function openAddModal(){document.getElementById('m-label').value='';document.getElementById('m-limit').value='';document.getElementById('m-uuid').value='';document.getElementById('uuid-err').style.display='none';openModal('add-modal')}

// ── Toast ──────────────────────────────────────
function toast(msg, err=false){
  const t = document.getElementById('toast');
  const m = document.getElementById('toast-msg');
  m.textContent = msg; t.className = 'toast' + (err ? ' err' : '') + ' show';
  setTimeout(() => t.classList.remove('show'), 3000);
}

// ── Helpers ────────────────────────────────────
function fmtB(b){return b>1073741824?(b/1073741824).toFixed(2)+' GB':b>1048576?(b/1048576).toFixed(2)+' MB':(b/1024).toFixed(1)+' KB'}
function fmtLim(b){if(!b)return'∞';const gb=b/1073741824;return(gb%1===0?gb.toFixed(0):gb.toFixed(2))+' GB'}
function esc(s){return String(s).replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function genUUIDv4(){return'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,c=>{const r=Math.random()*16|0;return(c==='x'?r:(r&0x3|0x8)).toString(16)})}
function genUUID(){document.getElementById('m-uuid').value=genUUIDv4();document.getElementById('uuid-err').style.display='none'}
function validateUUID(el){const v=el.value.trim();const ok=!v||/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/i.test(v);document.getElementById('uuid-err').style.display=ok?'none':'block'}

// ── Stats ─────────────────────────────────────
async function loadStats(){
  try{
    const r = await fetch('/stats'); if(!r.ok) throw new Error();
    statsData = await r.json();
    document.getElementById('s-traffic').innerHTML = statsData.total_traffic_mb + '<span class="stat-unit"> MB</span>';
    document.getElementById('s-links').textContent = statsData.links_count;
    document.getElementById('s-uptime').textContent = statsData.uptime;
    document.getElementById('s-domain').textContent = statsData.domain;
    document.getElementById('links-badge').textContent = statsData.links_count;
    document.getElementById('last-update').textContent = 'updated ' + new Date().toLocaleTimeString();
    if(document.getElementById('t-traffic')) document.getElementById('t-traffic').textContent = statsData.total_traffic_mb + ' MB';
    if(document.getElementById('t-reqs')) document.getElementById('t-reqs').textContent = statsData.total_requests.toLocaleString();
    if(document.getElementById('t-errs')) document.getElementById('t-errs').textContent = statsData.total_errors;
    if(document.getElementById('t-uptime')) document.getElementById('t-uptime').textContent = statsData.uptime;
    if(statsData.cpu_percent !== undefined){
      const c = statsData.cpu_percent;
      const cc = c > 80 ? 'var(--red)' : c > 50 ? 'var(--yellow)' : 'var(--indigo)';
      document.getElementById('s-cpu-pct').textContent = c.toFixed(1) + '%';
      document.getElementById('s-cpu-pct').style.color = cc;
      document.getElementById('s-cpu-bar').style.width = c + '%';
      document.getElementById('s-cpu-bar').style.background = cc;
    }
    if(statsData.memory_percent !== undefined){
      const m = statsData.memory_percent;
      const mc = m > 80 ? 'var(--red)' : m > 50 ? 'var(--yellow)' : 'var(--cyan)';
      document.getElementById('s-mem-pct').textContent = m.toFixed(1) + '%';
      document.getElementById('s-mem-pct').style.color = mc;
      document.getElementById('s-mem-bar').style.width = m + '%';
      document.getElementById('s-mem-bar').style.background = mc;
    }
    updateChart();
  }catch(e){}
}

// ── Chart ─────────────────────────────────────
function initChart(){
  const ctx = document.getElementById('tChart');
  if(!ctx) return;
  chart = new Chart(ctx, {
    type: 'line',
    data: {labels:[], datasets:[{
      label: 'MB', data: [],
      borderColor: '#6366f1', backgroundColor: 'rgba(99,102,241,0.08)',
      borderWidth: 2, fill: true, tension: 0.4,
      pointRadius: 3, pointBackgroundColor: '#6366f1',
      pointBorderColor: '#080c14', pointBorderWidth: 2,
    }]},
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {legend: {display: false}},
      scales: {
        x: {grid: {color: 'rgba(255,255,255,0.03)'}, ticks: {color: '#334155', font: {size: 9, family: 'JetBrains Mono'}}},
        y: {grid: {color: 'rgba(255,255,255,0.03)'}, ticks: {color: '#334155', font: {size: 9, family: 'JetBrains Mono'}, callback: v => v + ' MB'}, beginAtZero: true}
      }
    }
  });
}
function updateChart(){
  if(!chart || !statsData.hourly_traffic) return;
  const sorted = Object.entries(statsData.hourly_traffic).sort((a,b) => a[0].localeCompare(b[0])).slice(-12);
  chart.data.labels = sorted.map(e => e[0]);
  chart.data.datasets[0].data = sorted.map(e => Math.round(e[1]/1048576));
  chart.update();
}

// ── Links ─────────────────────────────────────
async function loadLinks(){
  try{
    const r = await fetch('/api/links'); if(!r.ok) throw new Error();
    const d = await r.json(); allLinks = d.links || []; filterLinks();
  }catch(e){}
}

function setFilter(f, el){
  curFilter = f;
  document.querySelectorAll('.fchip').forEach(c => c.classList.remove('active'));
  el.classList.add('active');
  filterLinks();
}

function filterLinks(){
  const q = (document.getElementById('ib-search')?.value || '').toLowerCase();
  let fl = allLinks;
  if(curFilter === 'active') fl = fl.filter(l => l.active);
  if(curFilter === 'disabled') fl = fl.filter(l => !l.active);
  if(q) fl = fl.filter(l => l.label.toLowerCase().includes(q) || l.uuid.toLowerCase().includes(q));
  renderLinks(fl);
}

function renderLinks(links){
  const tbody = document.getElementById('links-tbody');
  const cards = document.getElementById('mob-cards');
  const empty = document.getElementById('links-empty');
  if(!links.length){tbody.innerHTML='';cards.innerHTML='';empty.style.display='block';return}
  empty.style.display = 'none';
  let idx = links.length;
  const rows = links.map(l => {
    const u = l.used_bytes, lim = l.limit_bytes;
    const pct = lim > 0 ? Math.min(100, (u/lim)*100) : 0;
    const col = pct > 90 ? 'var(--red)' : pct > 70 ? 'var(--yellow)' : 'var(--indigo)';
    const i = idx--;
    return {l, pct, col, i, uF: fmtB(u), lF: fmtLim(lim)};
  });

  tbody.innerHTML = rows.map(r => `<tr>
    <td style="color:var(--text-dim);font-family:var(--mono);font-size:10px">${r.i}</td>
    <td style="font-weight:600;font-size:13px">${esc(r.l.label)}</td>
    <td><span class="tag tag-vless">VLESS</span> <span class="tag tag-xhttp">XHTTP</span></td>
    <td>
      <div class="usage">
        <span class="usage-used">${r.uF}</span>
        <div class="usage-track"><div class="usage-fill" style="width:${r.pct}%;background:${r.col}"></div></div>
        <span class="usage-lim">${r.lF}</span>
      </div>
    </td>
    <td><span class="tag ${r.l.active?'tag-on':'tag-off'}">${r.l.active?'ON':'OFF'}</span></td>
    <td>
      <div class="act-row">
        <button class="tog ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="toggleLink(this)" title="Toggle"></button>
        <button class="btn btn-ghost btn-xs" onclick="showDetail('${r.l.uuid}')">info</button>
        <button class="btn btn-ghost btn-xs" onclick="copyTxt('${esc(r.l.vless_link)}')">copy</button>
        <button class="btn btn-ghost btn-xs" onclick="showQR('${esc(r.l.vless_link)}')">qr</button>
        <button class="btn btn-danger btn-xs" onclick="delLink('${r.l.uuid}')">del</button>
      </div>
    </td>
  </tr>`).join('');

  cards.innerHTML = rows.map(r => `<div class="mob-card">
    <div class="mob-card-header">
      <div>
        <span style="font-size:10px;color:var(--text-dim);font-family:var(--mono)">#${r.i}</span>
        <span style="font-size:14px;font-weight:700;margin-left:8px">${esc(r.l.label)}</span>
      </div>
      <button class="tog ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="toggleLink(this)"></button>
    </div>
    <div class="usage" style="margin-bottom:10px">
      <span class="usage-used">${r.uF}</span>
      <div class="usage-track"><div class="usage-fill" style="width:${r.pct}%;background:${r.col}"></div></div>
      <span class="usage-lim">${r.lF}</span>
    </div>
    <div class="act-row" style="flex-wrap:wrap">
      <button class="btn btn-ghost btn-xs" onclick="showDetail('${r.l.uuid}')">info</button>
      <button class="btn btn-ghost btn-xs" onclick="copyTxt('${esc(r.l.vless_link)}')">copy</button>
      <button class="btn btn-ghost btn-xs" onclick="showQR('${esc(r.l.vless_link)}')">qr</button>
      <button class="btn btn-ghost btn-xs" onclick="resetUsage('${r.l.uuid}')">reset</button>
      <button class="btn btn-danger btn-xs" onclick="delLink('${r.l.uuid}')">del</button>
    </div>
  </div>`).join('');
}

async function toggleLink(el){
  const uid = el.dataset.uid, link = allLinks.find(l => l.uuid === uid); if(!link) return;
  await fetch(`/api/links/${uid}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:!link.active})});
  link.active = !link.active; filterLinks(); loadStats();
}

async function quickCreate(lim, unit){
  const names = ['Ali','Sara','Reza','Nima','Mina','Arash','Yalda','Cyrus','Shirin','Dariush'];
  const name = names[Math.floor(Math.random()*names.length)] + '-' + Math.floor(Math.random()*100);
  try{
    const r = await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:name,limit_value:lim,limit_unit:unit})});
    if(!r.ok) throw new Error(); toast('Created: ' + name); await loadLinks(); await loadStats();
  }catch(e){toast('Error creating inbound', true)}
}

async function createLink(){
  const label = document.getElementById('m-label').value.trim() || 'New Link';
  const val = parseFloat(document.getElementById('m-limit').value) || 0;
  const unit = document.getElementById('m-unit').value;
  const uuid = document.getElementById('m-uuid').value.trim();
  if(uuid && !/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/i.test(uuid)){
    toast('Invalid UUID format', true); return;
  }
  try{
    const body = {label, limit_value: val, limit_unit: unit};
    if(uuid) body.custom_uuid = uuid;
    const r = await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(!r.ok){const e=await r.json().catch(()=>({}));toast(e.detail||'Error',true);return}
    toast('Inbound created'); closeModal('add-modal'); await loadLinks(); await loadStats();
  }catch(e){toast('Error', true)}
}

async function resetUsage(uid){
  await fetch(`/api/links/${uid}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_usage:true})});
  toast('Usage reset'); await loadLinks();
}

async function delLink(uid){
  if(!confirm('Delete this inbound?')) return;
  await fetch(`/api/links/${uid}`,{method:'DELETE'});
  toast('Deleted'); await loadLinks(); await loadStats();
}

function showDetail(uid){
  const l = allLinks.find(x => x.uuid === uid); if(!l) return;
  const u = l.used_bytes, lim = l.limit_bytes;
  const pct = lim>0 ? Math.min(100,(u/lim)*100) : 0;
  const col = pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--indigo)';
  document.getElementById('d-title').textContent = l.label;
  document.getElementById('d-content').innerHTML = `
    <div class="d-row">
      <div class="d-col"><div class="dl">Protocol</div><div class="dv">${'VLESS'}</div></div>
      <div class="d-col"><div class="dl">Transport</div><div class="dv">${'XHTTP'}</div></div>
      <div class="d-col"><div class="dl">Status</div><div class="dv" style="color:${l.active?'var(--green)':'var(--red)'}">${l.active?'ACTIVE':'DISABLED'}</div></div>
    </div>
    <div class="detail-pair"><div class="dl">UUID</div><div class="dv">${l.uuid}</div></div>
    <div class="d-row">
      <div class="d-col"><div class="dl">Used</div><div class="dv">${fmtB(l.used_bytes)}</div></div>
      <div class="d-col"><div class="dl">Limit</div><div class="dv">${fmtLim(l.limit_bytes)}</div></div>
      <div class="d-col"><div class="dl">Usage</div><div class="dv">${pct.toFixed(1)}%</div></div>
    </div>
    <div class="meter-bar" style="margin-bottom:14px"><div class="meter-fill" style="width:${pct}%;background:${col}"></div></div>
    <div class="detail-pair"><div class="dl">Created</div><div class="dv">${l.created_at?new Date(l.created_at).toLocaleString():'—'}</div></div>
    <div class="detail-pair"><div class="dl">VLESS Link (XHTTP/TLS)</div><div class="dv" style="font-size:10px">${esc(l.vless_link)}</div></div>
    <div class="d-actions">
      <button class="btn btn-primary btn-sm" onclick="copyTxt('${esc(l.vless_link)}');closeModal('detail-modal')">Copy Link</button>
      <button class="btn btn-ghost btn-sm" onclick="showQR('${esc(l.vless_link)}');closeModal('detail-modal')">QR Code</button>
      <button class="btn btn-ghost btn-sm" onclick="resetUsage('${l.uuid}');closeModal('detail-modal')">Reset Traffic</button>
    </div>`;
  openModal('detail-modal');
}

function copyTxt(txt){navigator.clipboard.writeText(txt).then(()=>toast('Copied to clipboard')).catch(()=>toast('Copy failed',true))}
function showQR(txt){if(!txt)return;document.getElementById('qr-img').src='https://api.qrserver.com/v1/create-qr-code/?size=280x280&data='+encodeURIComponent(txt);openModal('qr-modal')}
function dlQR(){const img=document.getElementById('qr-img');if(!img.src)return;const a=document.createElement('a');a.href=img.src;a.download='ren-qr.png';a.click()}

async function changePassword(){
  const cur = document.getElementById('cur-pw').value;
  const nw = document.getElementById('new-pw').value;
  if(!cur||!nw){toast('Please fill all fields',true);return}
  try{
    const r = await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw})});
    if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'Error')}
    toast('Password updated'); document.getElementById('cur-pw').value=''; document.getElementById('new-pw').value='';
  }catch(e){toast(e.message,true)}
}

async function doLogout(){
  await fetch('/api/logout',{method:'POST'});
  location.href='/login';
}

// ── Init ──────────────────────────────────────
setLang(lang);
initChart();
loadStats();
loadLinks();
setInterval(loadStats, 10000);
</script>
</body>
</html>"""


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if await is_valid_session(token):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return HTMLResponse(content=DASHBOARD_HTML)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])