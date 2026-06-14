import asyncio
import json
import os
import hashlib
import secrets
import time
import uuid as uuid_lib
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote
import base64
from collections import deque, defaultdict

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, PlainTextResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("RVG-Gateway")

app = FastAPI(title="tryak Gateway", docs_url=None, redoc_url=None)

def _detect_host() -> str:
    # Railway
    h = os.environ.get("RAILWAY_PUBLIC_DOMAIN")
    if h: return h
    # Render
    h = os.environ.get("RENDER_EXTERNAL_HOSTNAME")
    if h: return h
    # Koyeb
    h = os.environ.get("KOYEB_PUBLIC_DOMAIN")
    if h: return h
    # Fly.io
    h = os.environ.get("FLY_APP_NAME")
    if h: return f"{h}.fly.dev"
    # Heroku
    h = os.environ.get("HEROKU_APP_DEFAULT_DOMAIN_NAME")
    if h: return h
    # متغیر دستی (هر پلتفرمی)
    h = os.environ.get("PUBLIC_DOMAIN")
    if h: return h
    return "localhost"

def _detect_platform() -> str:
    if os.environ.get("RAILWAY_PUBLIC_DOMAIN") or os.environ.get("RAILWAY_ENVIRONMENT"):
        return "Railway"
    if os.environ.get("RENDER_EXTERNAL_HOSTNAME") or os.environ.get("RENDER"):
        return "Render"
    if os.environ.get("KOYEB_PUBLIC_DOMAIN"):
        return "Koyeb"
    if os.environ.get("FLY_APP_NAME"):
        return "Fly.io"
    if os.environ.get("HEROKU_APP_DEFAULT_DOMAIN_NAME"):
        return "Heroku"
    return "Local"

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
    "host": _detect_host(),
}

# ───────── Telegram Bot Config ─────────
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
ADMIN_CHAT_IDS = {c for c in os.environ.get("ADMIN_CHAT_IDS", "").split(",") if c}
BOT_PASSWORD = os.environ.get("BOT_PASSWORD", "admin123")

# ───────── Persistence ─────────
DATA_FILE = Path("/tmp/gateway_data.json")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ───────── State (in-memory) ─────────
connections: dict = {}
stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None

# لینک‌های ساخته‌شده توسط کاربران: uuid -> {label, limit_bytes(0=unlimited), used_bytes, created_at, active}
LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

# ───────── Bot / Block / Tracking State ─────────
BLOCKED_IPS: set = set()
BOT_AUTHED: set = set()

# آمار روزانه و کشورها
stats_daily = {
    "daily_traffic": defaultdict(int),
    "daily_unique_ips": defaultdict(set),
    "daily_countries": defaultdict(lambda: defaultdict(int)),
}

# ip -> {"upload": int, "download": int, "total": int, "country_code": str, "country": str}
ip_traffic: dict = defaultdict(lambda: {"upload": 0, "download": 0, "total": 0, "country_code": "", "country": ""})

# uid -> set اتصالات فعال آن لینک (conn_id ها)
active_link_conns: dict = defaultdict(set)
# uid -> set آی‌پی‌های یکتای متصل به آن لینک
active_link_ips: dict = defaultdict(set)

# جلوگیری از نوتیف تکراری برای reconnect سریع
_notified_connections: dict = {}   # (uid, ip) -> timestamp
_NOTIF_COOLDOWN = 300               # ۵ دقیقه

_ip_cache: dict = {}

# ───────── Auth State ─────────
SESSION_COOKIE = "rvg_session"
SESSION_TTL = 60 * 60 * 24 * 7  # 7 روز

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {}  # رمز هر بار مستقیم از environment خونده می‌شه

SESSIONS: dict = {}  # token -> expiry_timestamp
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
        if exp is None:
            return False
        if exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True


async def destroy_session(token: str | None):
    if not token:
        return
    async with SESSIONS_LOCK:
        SESSIONS.pop(token, None)


async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token


# ───────── Startup / Shutdown ─────────
keepalive_task: asyncio.Task | None = None
bot_task: asyncio.Task | None = None
scheduler_task: asyncio.Task | None = None


async def keepalive_loop():
    """هر ۱۴ دقیقه به آدرس سلامت خودش ریکوئست می‌زند تا روی پلن رایگان Render/Railway به خواب نرود."""
    await asyncio.sleep(60)  # کمی صبر برای آماده شدن کامل سرویس
    while True:
        try:
            host = _detect_host()
            if host and host != "localhost" and http_client:
                url = f"https://{host}/health"
                resp = await http_client.get(url, timeout=20.0)
                logger.info(f"🔁 keepalive ping → {url} [{resp.status_code}]")
            else:
                logger.info("🔁 keepalive: میزبان عمومی شناسایی نشد، پینگ انجام نشد")
        except Exception as exc:
            logger.warning(f"⚠️ keepalive ping failed: {exc}")
        await asyncio.sleep(14 * 60)  # هر ۱۴ دقیقه


@app.on_event("startup")
async def startup():
    global http_client, keepalive_task, bot_task, scheduler_task
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)
    keepalive_task = asyncio.create_task(keepalive_loop())

    load_data()
    await ensure_default_link()

    bot_task = asyncio.create_task(tg_polling_loop())
    scheduler_task = asyncio.create_task(scheduler_loop())
    asyncio.create_task(notify_service_wake())

    logger.info(f"🚀 tryak Gateway started on port {CONFIG['port']}")


@app.on_event("shutdown")
async def shutdown():
    global keepalive_task, bot_task, scheduler_task
    if keepalive_task:
        keepalive_task.cancel()
    if bot_task:
        bot_task.cancel()
    if scheduler_task:
        scheduler_task.cancel()
    if http_client:
        await http_client.aclose()


# ───────── Helpers ─────────
def get_host() -> str:
    return _detect_host()


def generate_uuid(seed: str | None = None) -> str:
    if seed is None:
        return str(secrets.token_hex(16))[:8] + "-" + secrets.token_hex(2) + "-" + \
               secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(6)
    h = hashlib.sha256(f"{seed}{CONFIG['secret']}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def generate_vless_link(uuid: str, host: str, remark: str = "RVG-Railway") -> str:
    path = f"/ws/{uuid}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": host,
        "path": path,
        "sni": host,
        "fp": "chrome",
        "alpn": "http/1.1",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{host}:443?{query}#{quote(remark)}"


def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB":
        return int(value * 1024 * 1024 * 1024)
    if unit == "MB":
        return int(value * 1024 * 1024)
    if unit == "KB":
        return int(value * 1024)
    return int(value)


def fmt_bytes(b: int) -> str:
    if not b:
        return "نامحدود ♾️"
    if b >= 1024 ** 3:
        return f"{b/1024**3:.1f} GB"
    if b >= 1024 ** 2:
        return f"{b/1024**2:.1f} MB"
    return f"{b/1024:.1f} KB"


def flag(code: str) -> str:
    if not code or len(code) != 2:
        return "🌐"
    return chr(0x1F1E6 + ord(code[0].upper()) - 65) + chr(0x1F1E6 + ord(code[1].upper()) - 65)


def today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def now_hour() -> str:
    return datetime.now().strftime("%H:00")


def is_link_expired(link: dict) -> bool:
    exp = link.get("expires_at")
    if not exp:
        return False
    return datetime.fromisoformat(exp) <= datetime.now()


# ───────── Persistence (JSON روی دیسک) ─────────
async def save_data():
    try:
        async with LINKS_LOCK:
            data = {
                "links": LINKS,
                "blocked_ips": list(BLOCKED_IPS),
            }
        DATA_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2))
    except Exception as e:
        logger.error(f"Save error: {e}")


def load_data():
    global LINKS, BLOCKED_IPS
    try:
        if DATA_FILE.exists():
            data = json.loads(DATA_FILE.read_text())
            LINKS.clear()
            LINKS.update(data.get("links", {}))
            BLOCKED_IPS.clear()
            BLOCKED_IPS.update(data.get("blocked_ips", []))
            logger.info(f"✅ Loaded {len(LINKS)} links, {len(BLOCKED_IPS)} blocked IPs")
    except Exception as e:
        logger.error(f"Load error: {e}")


# ───────── IP Geo Info ─────────
async def get_ip_info(ip: str) -> dict:
    if ip in _ip_cache:
        return _ip_cache[ip]
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,proxy,hosting"
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == "success":
                    _ip_cache[ip] = data
                    return data
    except Exception:
        pass
    return {}


# ───────── Default link (auto-created on first request) ─────────
async def ensure_default_link():
    async with LINKS_LOCK:
        if not LINKS:
            uid = generate_uuid("default")
            LINKS[uid] = {
                "label": "لینک پیش‌فرض",
                "limit_bytes": 0,  # unlimited
                "used_bytes": 0,
                "created_at": datetime.now().isoformat(),
                "expires_at": None,  # بدون انقضا
                "max_devices": 0,
                "active": True,
            }
            need_save = True
        else:
            need_save = False
    if need_save:
        await save_data()


# ───────── Basic endpoints ─────────
@app.get("/")
async def root():
    return {
        "service": "tryak Gateway",
        "version": "6.0",
        "status": "active",
        "channel": "",
        "host": get_host(),
    }


@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime(), "platform": _detect_platform()}


# ───────── Auth Endpoints ─────────
@app.post("/api/login")
async def api_login(request: Request):
    _pw = os.environ.get("ADMIN_PASSWORD", "").strip()
    if not _pw:
        raise HTTPException(status_code=503, detail="متغیر ADMIN_PASSWORD در Render/Railway تنظیم نشده. لطفاً آن را اضافه کنید.")
    body = await request.json()
    password = str(body.get("password") or "")
    if hash_password(password) != hash_password(_pw):
        raise HTTPException(status_code=401, detail="رمز عبور اشتباه است")

    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL,
        httponly=True,
        samesite="lax",
        path="/",
    )
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
    valid = await is_valid_session(token)
    return {"authenticated": valid}


@app.post("/api/change-password")
async def api_change_password(request: Request, _=Depends(require_auth)):
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")

    _pw = os.environ.get("ADMIN_PASSWORD", "").strip()
    if hash_password(current) != hash_password(_pw) and hash_password(current) != AUTH.get("password_hash", ""):
        raise HTTPException(status_code=400, detail="رمز فعلی اشتباه است")
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="رمز جدید باید حداقل ۴ کاراکتر باشد")

    AUTH["password_hash"] = hash_password(new)

    # همه سشن‌های دیگر را باطل می‌کنیم، فقط سشن فعلی باقی می‌ماند
    current_token = request.cookies.get(SESSION_COOKIE)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        if current_token:
            SESSIONS[current_token] = time.time() + SESSION_TTL

    return {"ok": True}


# ───────── Stats / Links / Proxy (protected) ─────────
@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    now = datetime.now()
    async with LINKS_LOCK:
        links_count = len(LINKS)
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 * 1024), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": now.isoformat(),
        "hourly": dict(hourly_traffic),
        "recent_errors": list(error_logs)[-10:],
        "links_count": links_count,
        "blocked_ips_count": len(BLOCKED_IPS),
        "bot_enabled": bool(BOT_TOKEN),
        "connections_detail": list(connections.values())[:20],
    }


# ───────── Link Management API ─────────
@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "لینک جدید").strip()[:60]
    limit_value = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"
    expire_days = float(body.get("expire_days") or 0)
    max_devices = int(body.get("max_devices") or 0)

    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    expires_at = (datetime.now() + timedelta(days=expire_days)).isoformat() if expire_days > 0 else None

    uid = generate_uuid()  # کاملا رندوم
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label,
            "limit_bytes": limit_bytes,
            "used_bytes": 0,
            "created_at": datetime.now().isoformat(),
            "expires_at": expires_at,
            "max_devices": max_devices,
            "active": True,
        }
        created_at = LINKS[uid]["created_at"]
    await save_data()

    host = get_host()
    return {
        "uuid": uid,
        "label": label,
        "limit_bytes": limit_bytes,
        "used_bytes": 0,
        "active": True,
        "created_at": created_at,
        "expires_at": expires_at,
        "max_devices": max_devices,
        "vless_link": generate_vless_link(uid, host, remark=f"RVG-{label}"),
    }


@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    host = get_host()
    now = datetime.now()
    result = []
    async with LINKS_LOCK:
        for uid, data in LINKS.items():
            expires_at = data.get("expires_at")
            is_expired = False
            days_left = None
            if expires_at:
                exp_dt = datetime.fromisoformat(expires_at)
                days_left = (exp_dt - now).total_seconds() / 86400
                if days_left <= 0:
                    is_expired = True
                    days_left = 0
            quota_exceeded = data["limit_bytes"] != 0 and data["used_bytes"] >= data["limit_bytes"]
            result.append({
                "uuid": uid,
                "label": data["label"],
                "limit_bytes": data["limit_bytes"],
                "used_bytes": data["used_bytes"],
                "active": data["active"],
                "created_at": data["created_at"],
                "expires_at": expires_at,
                "days_left": None if days_left is None else round(days_left, 1),
                "is_expired": is_expired,
                "quota_exceeded": quota_exceeded,
                "max_devices": data.get("max_devices", 0),
                "active_devices": len(active_link_conns.get(uid, set())),
                "vless_link": generate_vless_link(uid, host, remark=f"RVG-{data['label']}"),
            })
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
        if "label" in body and str(body["label"]).strip():
            LINKS[uid]["label"] = str(body["label"]).strip()[:60]
        if "expire_days" in body:
            expire_days = float(body.get("expire_days") or 0)
            if expire_days > 0:
                LINKS[uid]["expires_at"] = (datetime.now() + timedelta(days=expire_days)).isoformat()
            else:
                LINKS[uid]["expires_at"] = None
        if "max_devices" in body:
            LINKS[uid]["max_devices"] = int(body.get("max_devices") or 0)
    await save_data()
    return {"ok": True}


@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    active_link_conns.pop(uid, None)
    active_link_ips.pop(uid, None)
    await save_data()
    return {"ok": True}


@app.get("/api/blocked")
async def get_blocked(_=Depends(require_auth)):
    return {"blocked_ips": list(BLOCKED_IPS)}


@app.post("/api/blocked")
async def block_ip_api(request: Request, _=Depends(require_auth)):
    body = await request.json()
    ip = str(body.get("ip", "")).strip()
    if not ip:
        raise HTTPException(status_code=400, detail="IP required")
    BLOCKED_IPS.add(ip)
    await save_data()
    return {"ok": True}


@app.delete("/api/blocked/{ip}")
async def unblock_ip_api(ip: str, _=Depends(require_auth)):
    BLOCKED_IPS.discard(ip)
    await save_data()
    return {"ok": True}


# ───────── VLESS Protocol Relay ─────────
RELAY_BUF = 64 * 1024


async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("chunk too small for VLESS header")

    pos = 0
    version = first_chunk[pos]; pos += 1          # noqa: E702
    req_uuid = first_chunk[pos:pos + 16]; pos += 16  # noqa: E702

    addon_len = first_chunk[pos]; pos += 1
    pos += addon_len

    command = first_chunk[pos]; pos += 1  # noqa: E702
    port = int.from_bytes(first_chunk[pos:pos + 2], "big"); pos += 2

    addr_type = first_chunk[pos]; pos += 1

    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]; pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]; pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore")
        pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]; pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type}")

    payload = first_chunk[pos:]
    return req_uuid, command, address, port, payload


def format_link_uuid(raw16: bytes) -> str:
    h = raw16.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


async def check_quota(uid: str, extra_bytes: int, conn_id: str | None = None) -> bool:
    """True اگر اجازه عبور دارد (سهمیه تمام نشده، منقضی نشده و دستگاه‌ها بیش از حد نیست)."""
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            return True  # لینک ناشناس → اجازه (بک‌ورد کامپتیبیلیتی)
        if not link["active"]:
            return False
        expires_at = link.get("expires_at")
        if expires_at and datetime.fromisoformat(expires_at) <= datetime.now():
            return False
        max_devices = link.get("max_devices", 0)
        if max_devices and conn_id is not None:
            current = active_link_conns.get(uid, set())
            if conn_id not in current and len(current) >= max_devices:
                return False
        if link["limit_bytes"] == 0:
            return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]


async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS[uid]["used_bytes"] += n


# ───────── Telegram Bot ─────────
async def tg_send(chat_id, text: str, reply_markup=None):
    if not BOT_TOKEN:
        return
    try:
        payload = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
        if reply_markup:
            payload["reply_markup"] = json.dumps(reply_markup)
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage", json=payload)
    except Exception as e:
        logger.error(f"TG send error: {e}")


async def tg_notify_all(text: str):
    for cid in ADMIN_CHAT_IDS:
        await tg_send(cid, text)


async def notify_new_connection(uid: str, ip: str):
    """ارسال نوتیف اتصال جدید با جلوگیری از ارسال تکراری برای IP یکسان در بازه cooldown."""
    if not BOT_TOKEN or not ADMIN_CHAT_IDS:
        return

    async with LINKS_LOCK:
        link = LINKS.get(uid, {})
        label = link.get("label", "نامشخص")

    info = await get_ip_info(ip)
    country = info.get("country", "نامشخص")
    country_code = info.get("countryCode", "")
    city = info.get("city", "نامشخص")
    isp = info.get("isp", "نامشخص")
    is_proxy = "⚠️ VPN/Proxy" if info.get("proxy") or info.get("hosting") else "✅ مستقیم"

    if country_code:
        ip_traffic[ip]["country_code"] = country_code
        ip_traffic[ip]["country"] = country

    active_unique_ips = len(active_link_ips.get(uid, set()))

    cache_key = (uid, ip)
    now_ts = time.time()
    last_notif = _notified_connections.get(cache_key, 0)
    if now_ts - last_notif < _NOTIF_COOLDOWN:
        logger.info(f"🔁 IP {ip} reconnect (no notification, cooldown active)")
        return
    _notified_connections[cache_key] = now_ts

    ip_data = ip_traffic.get(ip, {})
    up_bytes = ip_data.get("upload", 0)
    down_bytes = ip_data.get("download", 0)
    total_bytes = ip_data.get("total", 0)

    msg = (
        f"🔌 *اتصال جدید!*\n"
        f"{'─' * 28}\n"
        f"🏷 لینک: `{label}`\n"
        f"🌐 IP: `{ip}`\n"
        f"🏳️ کشور: {flag(country_code)} {country}\n"
        f"🏙 شهر: {city}\n"
        f"📡 ISP: {isp}\n"
        f"🔍 نوع: {is_proxy}\n"
        f"\n"
        f"👥 IP فعال این لینک: `{active_unique_ips}`\n"
        f"\n"
        f"📦 مصرف:\n"
        f"  ⬆️ Upload: `{fmt_bytes(up_bytes)}`\n"
        f"  ⬇️ Download: `{fmt_bytes(down_bytes)}`\n"
        f"  📊 مجموع: `{fmt_bytes(total_bytes)}`\n"
        f"\n"
        f"⏰ زمان: `{datetime.now().strftime('%H:%M:%S')}`"
    )
    kb = {"inline_keyboard": [[
        {"text": "🚫 بلاک IP", "callback_data": f"block_ip_{ip}"},
        {"text": "⏸ غیرفعال لینک", "callback_data": f"disable_link_{uid}"},
    ]]}
    for cid in ADMIN_CHAT_IDS:
        await tg_send(cid, msg, kb)


async def notify_service_wake():
    if not ADMIN_CHAT_IDS:
        return
    async with LINKS_LOCK:
        active_links = sum(1 for l in LINKS.values() if l.get("active"))
    msg = (
        f"🟢 *سرویس بیدار شد!*\n"
        f"⏰ زمان: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n"
        f"🔗 لینک‌های فعال: {active_links}"
    )
    await tg_notify_all(msg)


async def send_daily_report():
    """گزارش روزانه با IP های یکتا و ۱۰ IP پرمصرف."""
    if not ADMIN_CHAT_IDS:
        return

    d = today()
    traffic = stats_daily["daily_traffic"].get(d, 0)

    unique_ips_today = stats_daily["daily_unique_ips"].get(d, set())
    unique_ip_count = len(unique_ips_today)

    countries = stats_daily["daily_countries"].get(d, {})
    top_countries = sorted(countries.items(), key=lambda x: x[1], reverse=True)[:5]
    top_str = "\n".join([f"  {flag(c)} {c}: {n} IP" for c, n in top_countries]) or "  هیچ اتصالی"

    today_ips = []
    for ip in unique_ips_today:
        data = ip_traffic.get(ip)
        if data:
            today_ips.append((ip, data))

    top_ips = sorted(today_ips, key=lambda x: x[1].get("total", 0), reverse=True)[:10]
    if top_ips:
        lines = []
        for i, (ip, data) in enumerate(top_ips, 1):
            cc = data.get("country_code", "")
            country_name = data.get("country", "نامشخص")
            total = data.get("total", 0)
            lines.append(f"  {i}) `{ip}` 📦 {fmt_bytes(total)} {flag(cc)} {country_name}")
        top_ips_str = "\n".join(lines)
    else:
        top_ips_str = "  هنوز اطلاعاتی ثبت نشده"

    async with LINKS_LOCK:
        links_count = len(LINKS)

    msg = (
        f"📊 *گزارش روزانه · {d}*\n"
        f"{'─' * 28}\n"
        f"👥 IP های فعال: `{unique_ip_count}`\n"
        f"📦 ترافیک: `{fmt_bytes(traffic)}`\n"
        f"🌍 کشورهای برتر:\n{top_str}\n"
        f"{'─' * 28}\n"
        f"🔥 ۱۰ IP پرمصرف روز:\n{top_ips_str}\n"
        f"{'─' * 28}\n"
        f"🔗 کل لینک‌ها: {links_count}\n"
        f"⏱ آپتایم: `{uptime()}`"
    )
    await tg_notify_all(msg)


async def _track_country(ip: str):
    """ردیابی کشور بر اساس IP یکتا (یک‌بار در روز برای هر IP)."""
    info = await get_ip_info(ip)
    cc = info.get("countryCode", "XX")
    country_name = info.get("country", "نامشخص")
    d = today()

    if cc and cc != "XX":
        ip_traffic[ip]["country_code"] = cc
        ip_traffic[ip]["country"] = country_name

    already_key = f"_country_tracked_{d}_{ip}"
    if not _ip_cache.get(already_key):
        stats_daily["daily_countries"][d][cc] += 1
        _ip_cache[already_key] = True


# ───────── Scheduler ─────────
async def scheduler_loop():
    report_hour = 23  # ساعت گزارش روزانه
    last_report_day = ""

    while True:
        await asyncio.sleep(60)
        now = datetime.now()

        # گزارش روزانه ساعت ۲۳
        if now.hour == report_hour and today() != last_report_day:
            await send_daily_report()
            last_report_day = today()

        # بررسی لینک‌های منقضی شده
        async with LINKS_LOCK:
            expired_now = []
            for uid, link in list(LINKS.items()):
                if is_link_expired(link) and link.get("active"):
                    link["active"] = False
                    expired_now.append(link.get("label", uid[:8]))
        if expired_now:
            await save_data()
            for label in expired_now:
                await tg_notify_all(f"⏰ لینک *{label}* منقضی و غیرفعال شد.")

        # پاکسازی cache نوتیف‌های قدیمی (بیشتر از ۱ ساعت)
        now_ts = time.time()
        expired_keys = [k for k, t in list(_notified_connections.items()) if now_ts - t > 3600]
        for k in expired_keys:
            _notified_connections.pop(k, None)

        # پاکسازی cache ردیابی کشور دیروز
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        stale_keys = [k for k in list(_ip_cache.keys()) if k.startswith(f"_country_tracked_{yesterday}_")]
        for k in stale_keys:
            _ip_cache.pop(k, None)


# ───────── Telegram Commands ─────────
def tg_main_kb():
    return {"keyboard": [
        [{"text": "📋 لینک‌ها"}, {"text": "➕ لینک جدید"}],
        [{"text": "📊 آمار"}, {"text": "🚫 IP های بلاک"}],
        [{"text": "📈 گزارش امروز"}, {"text": "❓ راهنما"}],
        [{"text": "🏠 خانه"}],
    ], "resize_keyboard": True}


async def tg_send_stats(cid):
    active_conns = len(connections)
    async with LINKS_LOCK:
        active_links = sum(1 for l in LINKS.values() if l.get("active") and not is_link_expired(l))
        total_links = len(LINKS)
        total_used = sum(l.get("used_bytes", 0) for l in LINKS.values())
    kb = {"inline_keyboard": [[{"text": "🔄 بروزرسانی", "callback_data": "refresh_stats"}]]}
    msg = (
        f"📊 *آمار سرور*\n"
        f"{'─' * 28}\n"
        f"🔌 اتصالات فعال: `{active_conns}`\n"
        f"🔗 لینک‌های فعال: `{active_links}/{total_links}`\n"
        f"📦 کل ترافیک: `{fmt_bytes(total_used)}`\n"
        f"🚫 IP های بلاک: `{len(BLOCKED_IPS)}`\n"
        f"⏱ آپتایم: `{uptime()}`\n"
        f"🌐 هاست: `{get_host()}`\n"
        f"{'─' * 28}\n"
        f"🕐 `{datetime.now().strftime('%H:%M:%S')}`"
    )
    await tg_send(cid, msg, kb)


async def tg_send_links(cid):
    async with LINKS_LOCK:
        items = list(LINKS.items())
    if not items:
        await tg_send(cid, "هیچ لینکی وجود ندارد. با ➕ لینک جدید بساز.")
        return
    buttons = []
    for uid, d in items:
        exp = " ⏰" if is_link_expired(d) else ""
        status = "✅" if d.get("active") and not is_link_expired(d) else "❌"
        used = fmt_bytes(d.get("used_bytes", 0))
        limit = fmt_bytes(d.get("limit_bytes", 0))
        buttons.append([{"text": f"{status} {d['label']}{exp} | {used}/{limit}",
                          "callback_data": f"show_{uid}"}])
    kb = {"inline_keyboard": buttons}
    await tg_send(cid, f"🔗 *لیست لینک‌ها* ({len(items)} عدد):", kb)


async def tg_show_link(cid, uid):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        link = dict(link) if link else None
    if not link:
        await tg_send(cid, "❌ لینک یافت نشد.")
        return
    host = get_host()
    vl = generate_vless_link(uid, host, remark=f"RVG-{link['label']}")
    exp_str = link.get("expires_at", "")[:10] if link.get("expires_at") else "نامحدود"
    active_dev = len(active_link_conns.get(uid, set()))
    max_dev = link.get("max_devices", 0)
    pct_line = ""
    if link.get("limit_bytes"):
        p = min(100, round(link["used_bytes"] / link["limit_bytes"] * 100))
        bar = "█" * (p // 10) + "░" * (10 - p // 10)
        pct_line = f"\n📊 `[{bar}] {p}%`"

    msg = (
        f"🔗 *{link['label']}*\n"
        f"{'─' * 26}\n"
        f"{'✅ فعال' if link.get('active') and not is_link_expired(link) else '❌ غیرفعال'}\n"
        f"📦 سهمیه: `{fmt_bytes(link.get('limit_bytes', 0))}`\n"
        f"📥 مصرف: `{fmt_bytes(link.get('used_bytes', 0))}`{pct_line}\n"
        f"📅 انقضا: `{exp_str}`\n"
        f"👥 دستگاه: `{active_dev}/{max_dev or '∞'}`\n\n"
        f"🔑 VLESS:\n`{vl}`"
    )
    kb = {"inline_keyboard": [
        [{"text": "⏸/▶️ تغییر وضعیت", "callback_data": f"toggle_{uid}"},
         {"text": "🗑 حذف", "callback_data": f"delete_{uid}"}],
    ]}
    await tg_send(cid, msg, kb)


async def tg_create_link(cid, raw: str):
    """فرمت: عنوان | سهمیه(GB/MB/KB یا 0) | روزهای انقضا | حداکثر دستگاه"""
    parts = [p.strip() for p in raw.split("|")]
    label = (parts[0] if parts and parts[0] else "لینک جدید")[:60]
    limit_bytes = 0
    expires_at = None
    max_devices = 0

    if len(parts) >= 2 and parts[1] not in ("0", ""):
        import re
        m = re.match(r"([\d.]+)\s*(gb|mb|kb)?", parts[1].lower())
        if m:
            v = float(m.group(1))
            u = (m.group(2) or "gb").upper()
            limit_bytes = parse_size_to_bytes(v, u)

    if len(parts) >= 3 and parts[2] not in ("0", ""):
        try:
            days = float(parts[2])
            if days > 0:
                expires_at = (datetime.now() + timedelta(days=days)).isoformat()
        except ValueError:
            pass

    if len(parts) >= 4 and parts[3] not in ("0", ""):
        try:
            max_devices = int(parts[3])
        except ValueError:
            pass

    uid = generate_uuid()
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label,
            "limit_bytes": limit_bytes,
            "used_bytes": 0,
            "created_at": datetime.now().isoformat(),
            "expires_at": expires_at,
            "max_devices": max_devices,
            "active": True,
        }
    await save_data()

    exp_str = expires_at[:10] if expires_at else "نامحدود"
    host = get_host()
    vl = generate_vless_link(uid, host, remark=f"RVG-{label}")
    await tg_send(cid,
        f"✅ *لینک ساخته شد!*\n\n"
        f"🏷 عنوان: `{label}`\n"
        f"📦 سهمیه: `{fmt_bytes(limit_bytes)}`\n"
        f"📅 انقضا: `{exp_str}`\n"
        f"👥 حداکثر دستگاه: `{max_devices or '∞'}`\n\n"
        f"🔑 VLESS:\n`{vl}`"
    )


async def tg_show_blocked(cid):
    if not BLOCKED_IPS:
        await tg_send(cid, "✅ هیچ IP بلاکی وجود ندارد.")
        return
    ips = "\n".join([f"`{ip}`" for ip in list(BLOCKED_IPS)[:20]])
    await tg_send(cid, f"🚫 *IP های بلاک شده:*\n\n{ips}\n\nبرای آنبلاک: `/unblock IP`")


async def tg_process_update(update: dict):
    # ───── Callback queries ─────
    if "callback_query" in update:
        cq = update["callback_query"]
        cid = cq["message"]["chat"]["id"]
        data = cq.get("data", "")

        if str(cid) not in ADMIN_CHAT_IDS and cid not in BOT_AUTHED:
            return

        if data.startswith("block_ip_"):
            ip = data[len("block_ip_"):]
            BLOCKED_IPS.add(ip)
            await save_data()
            await tg_send(cid, f"🚫 IP `{ip}` بلاک شد.")

        elif data.startswith("disable_link_"):
            uid = data[len("disable_link_"):]
            async with LINKS_LOCK:
                if uid in LINKS:
                    LINKS[uid]["active"] = False
                    label = LINKS[uid].get("label", uid[:8])
                else:
                    label = None
            if label is not None:
                await save_data()
                await tg_send(cid, f"⏸ لینک *{label}* غیرفعال شد.")
            else:
                await tg_send(cid, "❌ لینک یافت نشد.")

        elif data.startswith("toggle_"):
            uid = data[len("toggle_"):]
            async with LINKS_LOCK:
                if uid in LINKS:
                    LINKS[uid]["active"] = not LINKS[uid]["active"]
            await save_data()
            await tg_show_link(cid, uid)

        elif data.startswith("delete_"):
            uid = data[len("delete_"):]
            async with LINKS_LOCK:
                LINKS.pop(uid, None)
            active_link_conns.pop(uid, None)
            active_link_ips.pop(uid, None)
            await save_data()
            await tg_send(cid, "🗑 لینک حذف شد.")

        elif data.startswith("show_"):
            uid = data[len("show_"):]
            await tg_show_link(cid, uid)

        elif data == "refresh_stats":
            await tg_send_stats(cid)

        try:
            async with httpx.AsyncClient(timeout=5) as client:
                await client.post(
                    f"https://api.telegram.org/bot{BOT_TOKEN}/answerCallbackQuery",
                    json={"callback_query_id": cq["id"]}
                )
        except Exception:
            pass
        return

    # ───── Messages ─────
    msg = update.get("message", {})
    if not msg:
        return
    cid = msg["chat"]["id"]
    text = (msg.get("text") or "").strip()

    # Auth
    if str(cid) not in ADMIN_CHAT_IDS and cid not in BOT_AUTHED:
        if text == BOT_PASSWORD:
            BOT_AUTHED.add(cid)
            await tg_send(cid, "✅ *ورود موفق!*\nخوش آمدید 👋", tg_main_kb())
        else:
            await tg_send(cid, "🔒 رمز عبور را وارد کنید:")
        return

    if text in ("/start", "🏠 خانه"):
        await tg_send(cid, "👋 سلام!\n🛡 *tryak Gateway*\nاز منو استفاده کن 👇", tg_main_kb())

    elif text in ("/links", "📋 لینک‌ها"):
        await tg_send_links(cid)

    elif text in ("/stats", "📊 آمار"):
        await tg_send_stats(cid)

    elif text in ("/new", "➕ لینک جدید"):
        await tg_send(cid,
            "➕ *ساخت لینک جدید*\n\n"
            "فرمت:\n`/create عنوان | سهمیه | روزهای انقضا | حداکثر دستگاه`\n\n"
            "مثال:\n`/create برای علی | 10 GB | 30 | 2`\n\n"
            "برای نامحدود: `0` بذار\n"
            "`/create برای همه | 0 | 0 | 0`"
        )

    elif text.startswith("/create "):
        await tg_create_link(cid, text[len("/create "):])

    elif text in ("/blocked", "🚫 IP های بلاک"):
        await tg_show_blocked(cid)

    elif text.startswith("/unblock "):
        ip = text[len("/unblock "):].strip()
        BLOCKED_IPS.discard(ip)
        await save_data()
        await tg_send(cid, f"✅ IP `{ip}` آنبلاک شد.")

    elif text.startswith("/block "):
        ip = text[len("/block "):].strip()
        BLOCKED_IPS.add(ip)
        await save_data()
        await tg_send(cid, f"🚫 IP `{ip}` بلاک شد.")

    elif text in ("/report", "📈 گزارش امروز"):
        await send_daily_report()

    elif text in ("/help", "❓ راهنما"):
        await tg_send(cid,
            "❓ *راهنمای دستورات*\n\n"
            "`/create` — ساخت لینک جدید\n"
            "`/links` — لیست لینک‌ها\n"
            "`/stats` — آمار سرور\n"
            "`/block IP` — بلاک کردن IP\n"
            "`/unblock IP` — آنبلاک IP\n"
            "`/blocked` — لیست IP های بلاک\n"
            "`/report` — گزارش امروز\n"
        )
    else:
        await tg_send(cid, "❓ دستور نامشخص. /help بزن.")


async def tg_polling_loop():
    if not BOT_TOKEN:
        logger.warning("BOT_TOKEN تنظیم نشده — ربات تلگرام غیرفعال")
        return
    offset = 0
    logger.info("🤖 Telegram bot polling started")
    while True:
        try:
            async with httpx.AsyncClient(timeout=35) as client:
                r = await client.get(
                    f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates",
                    params={"offset": offset, "timeout": 30, "allowed_updates": ["message", "callback_query"]}
                )
                data = r.json()
                if data.get("ok"):
                    for upd in data.get("result", []):
                        offset = upd["update_id"] + 1
                        asyncio.create_task(tg_process_update(upd))
        except Exception as e:
            logger.error(f"Polling error: {e}")
            await asyncio.sleep(5)


async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, conn_id: str, link_uid: str, client_ip: str):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes")
            if data is None and msg.get("text") is not None:
                data = msg["text"].encode()
            if not data:
                continue

            size = len(data)
            if not await check_quota(link_uid, size, conn_id):
                await websocket.close(code=1008, reason="quota exceeded")
                break

            stats["total_bytes"] += size
            stats["total_requests"] += 1
            connections[conn_id]["bytes"] += size
            connections[conn_id]["upload"] += size
            hourly_traffic[now_hour()] += size
            stats_daily["daily_traffic"][today()] += size
            ip_traffic[client_ip]["upload"] += size
            ip_traffic[client_ip]["total"] += size
            await add_usage(link_uid, size)

            writer.write(data)
            await writer.drain()
    except WebSocketDisconnect:
        pass
    finally:
        try:
            writer.write_eof()
        except Exception:
            pass


async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, conn_id: str, link_uid: str, client_ip: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break

            size = len(data)
            if not await check_quota(link_uid, size, conn_id):
                await websocket.close(code=1008, reason="quota exceeded")
                break

            stats["total_bytes"] += size
            connections[conn_id]["bytes"] += size
            connections[conn_id]["download"] += size
            hourly_traffic[now_hour()] += size
            stats_daily["daily_traffic"][today()] += size
            ip_traffic[client_ip]["download"] += size
            ip_traffic[client_ip]["total"] += size
            await add_usage(link_uid, size)

            if first:
                await websocket.send_bytes(b"\x00\x00" + data)
                first = False
            else:
                await websocket.send_bytes(data)
    except Exception:
        pass


@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await ensure_default_link()
    await websocket.accept()
    conn_id = secrets.token_urlsafe(8)

    # تشخیص IP کلاینت
    client_ip = websocket.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if not client_ip:
        client_ip = websocket.client.host if websocket.client else "unknown"

    # بررسی IP بلاک‌شده
    if client_ip in BLOCKED_IPS:
        await websocket.close(code=1008, reason="blocked")
        return

    connections[conn_id] = {
        "uuid": uuid,
        "ip": client_ip,
        "connected_at": datetime.now().isoformat(),
        "bytes": 0,
        "upload": 0,
        "download": 0,
    }
    active_link_conns[uuid].add(conn_id)
    active_link_ips[uuid].add(client_ip)
    stats_daily["daily_unique_ips"][today()].add(client_ip)

    logger.info(f"✅ WS connected [{conn_id}] uuid={uuid} ip={client_ip} active={len(connections)}")

    # نوتیف تلگرام برای اتصال جدید (بدون بلاک کردن جریان)
    asyncio.create_task(notify_new_connection(uuid, client_ip))
    asyncio.create_task(_track_country(client_ip))

    writer = None
    try:
        # بررسی سهمیه پیش از شروع
        if not await check_quota(uuid, 0, conn_id):
            await websocket.close(code=1008, reason="quota exceeded or link disabled")
            return

        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect":
            return

        first_chunk = first_msg.get("bytes")
        if first_chunk is None and first_msg.get("text") is not None:
            first_chunk = first_msg["text"].encode()
        if not first_chunk:
            return

        req_uuid_raw, command, address, port, initial_payload = await parse_vless_header(first_chunk)

        size = len(first_chunk)
        stats["total_bytes"] += size
        stats["total_requests"] += 1
        connections[conn_id]["bytes"] += size
        connections[conn_id]["upload"] += size
        hourly_traffic[now_hour()] += size
        stats_daily["daily_traffic"][today()] += size
        ip_traffic[client_ip]["upload"] += size
        ip_traffic[client_ip]["total"] += size
        await add_usage(uuid, size)

        logger.info(f"➡️  [{conn_id}] CONNECT {address}:{port} (cmd={command}) link={uuid[:8]}")

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=10.0
        )

        if initial_payload:
            writer.write(initial_payload)
            await writer.drain()

        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid, client_ip))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid, client_ip))

        done, pending = await asyncio.wait(
            {task_up, task_down}, return_when=asyncio.FIRST_COMPLETED
        )
        for t in pending:
            t.cancel()

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        logger.error(f"WS error [{conn_id}]: {exc}")
    finally:
        if writer:
            try:
                writer.close()
            except Exception:
                pass
        connections.pop(conn_id, None)
        active_link_conns[uuid].discard(conn_id)

        # اگر session دیگری از همین IP روی همین لینک باقی نمانده، از active_link_ips حذف کن
        other_same_ip = any(
            info.get("ip") == client_ip and info.get("uuid") == uuid
            for info in connections.values()
        )
        if not other_same_ip:
            active_link_ips[uuid].discard(client_ip)

        asyncio.create_task(save_data())
        logger.info(f"🔌 WS closed [{conn_id}] ip={client_ip} active={len(connections)}")


# ───────── HTTP Proxy ─────────
_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "content-encoding", "content-length",
}


@app.api_route("/proxy/{target_url:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def http_proxy(target_url: str, request: Request):
    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    try:
        body = await request.body()
        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in _HOP_HEADERS and k.lower() != "host"
        }

        resp = await http_client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
        )

        size = len(resp.content)
        stats["total_bytes"] += size
        stats["total_requests"] += 1
        hourly_traffic[datetime.now().strftime("%H:00")] += size

        resp_headers = {
            k: v for k, v in resp.headers.items()
            if k.lower() not in _HOP_HEADERS
        }
        return Response(content=resp.content, status_code=resp.status_code, headers=resp_headers)

    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "url": target_url, "time": datetime.now().isoformat()})
        raise HTTPException(status_code=502, detail=f"Proxy error: {exc}")


# ───────── Login Page ─────────
LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>ورود · tryak Gateway</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.19.0/dist/tabler-icons.min.css">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --accent:#3b82f6;--accent2:#1d4ed8;--accent-glow:rgba(59,130,246,0.35);
  --red-bg:#2a1212;--red-text:#f5a3a3;
  --green-text:#7ee0a8;
  --bg:#0a0e17;--card:#10172a;--card2:#151d33;--border:#1f2940;
  --text-1:#eef2ff;--text-2:#7b8aab;--text-3:#475370;
}
html,body{height:100%}
body{
  font-family:'Vazirmatn',sans-serif;
  background:
    radial-gradient(circle at 18% 18%, rgba(59,130,246,0.16), transparent 42%),
    radial-gradient(circle at 85% 80%, rgba(29,78,216,0.16), transparent 45%),
    var(--bg);
  min-height:100vh;display:flex;align-items:center;justify-content:center;
  padding:20px;color:var(--text-1);
}
.login-card{
  background:var(--card);border-radius:20px;padding:36px 30px;
  width:100%;max-width:380px;box-shadow:0 24px 70px rgba(0,0,0,0.55);
  border:1px solid var(--border);position:relative;overflow:hidden;
}
.login-card::before{
  content:'';position:absolute;top:-60%;right:-40%;width:280px;height:280px;
  background:radial-gradient(circle, var(--accent-glow), transparent 70%);
  pointer-events:none;
}
.login-logo{display:flex;flex-direction:column;align-items:center;gap:13px;margin-bottom:26px;position:relative;z-index:1}
.login-logo-icon{
  width:64px;height:64px;border-radius:16px;
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  display:flex;align-items:center;justify-content:center;
  font-size:28px;color:#fff;
  box-shadow:0 8px 28px var(--accent-glow);
}
.login-logo-name{font-size:21px;font-weight:800;color:var(--text-1);letter-spacing:.01em}
.login-logo-sub{font-size:11.5px;color:var(--accent);margin-top:3px;font-weight:600;letter-spacing:.04em}
.login-title{font-size:15px;font-weight:700;margin-bottom:5px;color:var(--text-1);text-align:center;position:relative;z-index:1}
.login-sub{font-size:12px;color:var(--text-2);margin-bottom:22px;text-align:center;position:relative;z-index:1}
.status-pill{
  display:flex;align-items:center;justify-content:center;gap:7px;
  font-size:11px;color:var(--green-text);background:rgba(76,224,144,0.08);
  border:1px solid rgba(76,224,144,0.18);border-radius:20px;padding:6px 14px;
  margin-bottom:22px;position:relative;z-index:1;font-weight:500;
}
.status-pill .dot{width:6px;height:6px;border-radius:50%;background:#4ce090;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
.form-group{margin-bottom:16px;display:flex;flex-direction:column;gap:7px;position:relative;z-index:1}
.form-label{font-size:12px;font-weight:600;color:var(--text-2)}
.form-input{
  padding:13px 15px;border-radius:11px;border:1px solid var(--border);
  font-family:inherit;font-size:14px;outline:none;background:var(--card2);
  transition:.15s;color:var(--text-1);width:100%;
}
.form-input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow)}
.btn-login{
  width:100%;padding:14px;border-radius:11px;border:none;cursor:pointer;
  background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;font-family:inherit;font-size:14px;
  font-weight:700;display:flex;align-items:center;justify-content:center;gap:8px;
  transition:.15s;box-shadow:0 4px 20px var(--accent-glow);margin-top:4px;position:relative;z-index:1;
}
.btn-login:hover{filter:brightness(1.1)}
.btn-login:disabled{opacity:.6;cursor:not-allowed}
.error-box{
  background:var(--red-bg);color:var(--red-text);font-size:12.5px;
  padding:10px 13px;border-radius:9px;margin-bottom:14px;display:none;
  align-items:center;gap:8px;border:1px solid rgba(240,128,128,0.2);position:relative;z-index:1;
}
.error-box.show{display:flex}
.login-footer{margin-top:20px;text-align:center;font-size:11px;color:var(--text-3);position:relative;z-index:1}
</style>
</head>
<body>
  <div class="login-card">
    <div class="login-logo">
      <div class="login-logo-icon"><svg width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg"><text x="50%" y="50%" dominant-baseline="central" text-anchor="middle" font-family="'Vazirmatn',sans-serif" font-size="24" font-weight="900" fill="#fff">T</text></svg></div>
      <div style="text-align:center">
        <div class="login-logo-name">tryak Gateway</div>
        <div class="login-logo-sub">v6.0</div>
      </div>
    </div>
    <div class="login-title">ورود به پنل مدیریت</div>
    <div class="login-sub">برای دسترسی به داشبورد، رمز عبور را وارد کنید</div>

    <div class="status-pill"><span class="dot"></span> سیستم آنلاین · اتصال امن</div>

    <div class="error-box" id="err-box"><i class="ti ti-alert-circle"></i> <span id="err-text"></span></div>

    <form id="login-form">
      <div class="form-group">
        <label class="form-label">رمز عبور</label>
        <input class="form-input" type="password" id="password" placeholder="••••••••" autofocus required>
      </div>
      <button class="btn-login" type="submit" id="login-btn"><i class="ti ti-login-2"></i> ورود</button>
    </form>

    <div class="login-footer">tryak Gateway &middot; Railway / Render</div>
  </div>

<script>
const form=document.getElementById('login-form');
const errBox=document.getElementById('err-box');
const errText=document.getElementById('err-text');
const btn=document.getElementById('login-btn');

form.addEventListener('submit', async (e)=>{
  e.preventDefault();
  errBox.classList.remove('show');
  btn.disabled=true;
  btn.innerHTML='<i class="ti ti-loader-2"></i> در حال ورود...';
  const password=document.getElementById('password').value;
  try{
    const r=await fetch('/api/login',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({password})
    });
    if(!r.ok){
      const d=await r.json().catch(()=>({}));
      throw new Error(d.detail||'رمز عبور اشتباه است، دوباره تلاش کنید.');
    }
    location.href='/dashboard';
  }catch(err){
    errText.textContent=err.message;
    errBox.classList.add('show');
    btn.disabled=false;
    btn.innerHTML='<i class="ti ti-login-2"></i> ورود';
  }
});
</script>
</body>
</html>"""


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if await is_valid_session(token):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)


# ───────── Dashboard (SPA) ─────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>tryak Gateway · داشبورد</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.19.0/dist/tabler-icons.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --accent:#3b82f6;--accent2:#1d4ed8;--accent-glow:rgba(59,130,246,0.35);
  --green-bg:rgba(76,224,144,0.08);--green-text:#7ee0a8;--green-dot:#4ce090;
  --red-bg:rgba(245,101,101,0.1);--red-text:#f5a3a3;--red-dot:#f56565;
  --amber-bg:rgba(245,191,101,0.1);--amber-text:#f0c878;--amber-dot:#f0b14a;
  --border:#1f2940;--bg:#0a0e17;--white:#10172a;--card2:#151d33;
  --text-1:#eef2ff;--text-2:#7b8aab;--text-3:#475370;
  --blue-50:#151d33;--blue-100:#1f2940;--blue-200:#334163;--blue-300:#5e87d9;
  --blue-400:#7b8aab;--blue-500:#3b82f6;--blue-600:#60a5fa;--blue-700:#93c5fd;
  --blue-800:#cfe0ff;--blue-900:#eef2ff;
  --shadow:0 1px 2px rgba(0,0,0,0.5), 0 1px 16px rgba(0,0,0,0.35);
}
html,body{height:100%}
body{
  font-family:'Vazirmatn',sans-serif;
  background:
    radial-gradient(circle at 15% 10%, rgba(59,130,246,0.10), transparent 40%),
    radial-gradient(circle at 90% 85%, rgba(29,78,216,0.10), transparent 45%),
    var(--bg);
  color:var(--text-1);min-height:100vh;display:flex;font-size:14px
}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-thumb{background:var(--blue-100);border-radius:3px}
a{color:inherit}

/* SIDEBAR */
.sidebar{width:236px;min-height:100vh;background:linear-gradient(180deg,var(--white) 0%,#070c18 100%);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;position:fixed;left:0;top:0;bottom:0;z-index:200;transition:transform .25s ease}
.logo{display:flex;align-items:center;gap:11px;padding:22px 18px 20px;border-bottom:1px solid var(--border)}
.logo img{width:42px;height:42px;border-radius:11px;object-fit:cover;border:1px solid var(--border)}
.logo-name{color:#fff;font-size:15px;font-weight:700;letter-spacing:.01em}
.logo-sub{color:var(--accent);font-size:11px;margin-top:2px}
.sidebar-close{display:none;position:absolute;left:14px;top:24px;background:var(--card2);border:none;color:#fff;width:34px;height:34px;border-radius:9px;font-size:18px;align-items:center;justify-content:center;cursor:pointer}
.nav-scroll{flex:1;overflow-y:auto;padding-bottom:10px}
.nav-group-label{color:var(--text-3);font-size:10px;letter-spacing:.1em;padding:18px 20px 6px;text-transform:uppercase;font-weight:600}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 20px;color:var(--text-2);font-size:13px;cursor:pointer;border-right:3px solid transparent;transition:.15s;user-select:none;position:relative}
.nav-item i{font-size:18px;width:20px;text-align:center}
.nav-item:hover{background:rgba(255,255,255,0.03);color:#fff}
.nav-item.active{background:linear-gradient(90deg,rgba(59,130,246,0.16),rgba(59,130,246,0.02));color:#fff;border-right-color:var(--accent)}
.nav-item .nav-badge{margin-right:auto;background:rgba(59,130,246,0.16);color:var(--blue-600);font-size:10px;padding:2px 7px;border-radius:20px;font-weight:600}
.sidebar-footer{padding:16px 18px;border-top:1px solid var(--border)}
.sidebar-footer-label{color:var(--blue-300);font-size:11px;margin-bottom:9px;display:flex;align-items:center;gap:6px}
.tg-btn{display:flex;align-items:center;justify-content:center;gap:8px;background:linear-gradient(135deg,#0098e6,#0077bb);color:#fff;border-radius:10px;padding:11px;font-size:13px;font-weight:500;font-family:inherit;border:none;cursor:pointer;width:100%;text-decoration:none;transition:.15s;box-shadow:0 4px 14px rgba(0,136,204,0.25)}
.tg-btn:hover{filter:brightness(1.08)}
.tg-btn i{font-size:18px}
.logout-btn{display:flex;align-items:center;justify-content:center;gap:8px;background:rgba(245,101,101,0.1);color:var(--red-text);border-radius:10px;padding:10px;font-size:12.5px;font-weight:500;font-family:inherit;border:1px solid rgba(245,101,101,0.2);cursor:pointer;width:100%;transition:.15s;margin-top:10px}
.logout-btn:hover{background:rgba(245,101,101,0.18);color:#fff}

/* MOBILE TOPBAR + OVERLAY */
.mobile-topbar{display:none;position:fixed;top:0;right:0;left:0;height:56px;background:linear-gradient(180deg,var(--white) 0%,#070c18 100%);border-bottom:1px solid var(--border);z-index:150;align-items:center;justify-content:space-between;padding:0 14px}
.mobile-topbar .mt-left{display:flex;align-items:center;gap:10px}
.mobile-topbar .mt-left img{width:32px;height:32px;border-radius:9px;object-fit:cover}
.mobile-topbar .mt-title{color:#fff;font-size:14px;font-weight:700}
.menu-btn{background:var(--card2);border:none;color:#fff;width:38px;height:38px;border-radius:10px;font-size:19px;display:flex;align-items:center;justify-content:center;cursor:pointer}
.sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.55);z-index:190;backdrop-filter:blur(2px)}
.sidebar-overlay.show{display:block}

/* MAIN */
.main{margin-left:236px;flex:1;padding:26px 28px 50px;max-width:calc(100% - 236px)}
.page{display:none}
.page.active{display:block;animation:fadeIn .25s ease}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}

.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:26px;flex-wrap:wrap;gap:12px}
.topbar-title{font-size:20px;font-weight:700;color:var(--text-1);display:flex;align-items:center;gap:9px}
.topbar-title i{color:var(--accent);font-size:22px}
.topbar-sub{font-size:12px;color:var(--text-2);margin-top:4px}
.topbar-right{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.badge{font-size:11px;padding:5px 12px;border-radius:20px;font-weight:600;display:inline-flex;align-items:center;gap:6px}
.badge-green{background:var(--green-bg);color:var(--green-text)}
.badge-blue{background:rgba(59,130,246,0.1);color:var(--blue-600)}
.badge-amber{background:var(--amber-bg);color:var(--amber-text)}
.badge-red{background:var(--red-bg);color:var(--red-text)}
.dot{width:7px;height:7px;border-radius:50%;display:inline-block}
.dot-green{background:var(--green-dot)}
.dot-red{background:var(--red-dot)}
.dot-amber{background:var(--amber-dot)}
.pulse{animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}

/* METRICS */
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:22px}
.metric{background:var(--white);border-radius:14px;border:1px solid var(--border);padding:18px 18px;box-shadow:var(--shadow);transition:.15s}
.metric:hover{transform:translateY(-2px);border-color:var(--blue-200)}
.metric-label{font-size:11px;color:var(--text-2);margin-bottom:9px;display:flex;align-items:center;gap:6px;font-weight:600}
.metric-label i{font-size:16px;color:var(--accent)}
.metric-val{font-size:28px;font-weight:700;color:var(--text-1);line-height:1}
.metric-unit{font-size:13px;font-weight:500;color:var(--text-2);margin-right:3px}
.metric-sub{font-size:11px;color:var(--text-3);margin-top:6px;display:flex;align-items:center;gap:4px}
.metric-error .metric-label{color:var(--red-text)}
.metric-error .metric-label i{color:var(--red-dot)}
.metric-error .metric-val{color:var(--red-dot)}
.metric-error .metric-sub{color:var(--red-text)}

/* VLESS BOX */
.vless-box{background:linear-gradient(135deg,var(--accent2) 0%,#0a1f4d 100%);border-radius:16px;padding:22px 24px;margin-bottom:22px;box-shadow:0 8px 30px rgba(29,78,216,0.18);border:1px solid rgba(59,130,246,0.25)}
.vless-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:13px;flex-wrap:wrap;gap:10px}
.vless-title{color:var(--blue-700);font-size:12px;display:flex;align-items:center;gap:7px;font-weight:600}
.vless-title i{font-size:17px}
.vless-link-wrap{background:rgba(0,0,0,0.18);border:1px solid rgba(255,255,255,0.1);border-radius:10px;padding:14px 16px}
.vless-link{color:var(--blue-700);font-size:11.5px;font-family:ui-monospace,monospace;word-break:break-all;line-height:1.7;letter-spacing:.01em}
.vless-actions{display:flex;gap:9px;margin-top:14px;flex-wrap:wrap}
.btn{font-family:inherit;font-size:12.5px;font-weight:500;border-radius:9px;padding:9px 15px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;border:none;transition:.15s;white-space:nowrap}
.btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;box-shadow:0 2px 10px var(--accent-glow)}
.btn-primary:hover{filter:brightness(1.1)}
.btn-outline{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.18);color:var(--blue-700)}
.btn-outline:hover{background:rgba(255,255,255,0.08)}
.btn-light-outline{background:var(--card2);border:1px solid var(--border);color:var(--text-2)}
.btn-light-outline:hover{background:var(--blue-100);color:var(--text-1)}
.btn-danger{background:var(--red-bg);color:var(--red-text);border:1px solid rgba(245,101,101,0.3)}
.btn-danger:hover{background:rgba(245,101,101,0.2)}
.btn-sm{padding:6px 11px;font-size:11.5px;border-radius:7px}
.btn i{font-size:14px}
.btn:disabled{opacity:.5;cursor:not-allowed}

/* GRID */
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:22px}
.grid3{display:grid;grid-template-columns:2fr 1fr;gap:14px;margin-bottom:22px}
.card{background:var(--white);border-radius:14px;border:1px solid var(--border);padding:20px 22px;box-shadow:var(--shadow)}
.card-title{font-size:13.5px;font-weight:700;color:var(--text-1);margin-bottom:16px;display:flex;align-items:center;gap:8px}
.card-title i{font-size:18px;color:var(--accent)}
.card-title .ml-auto{margin-right:auto}

/* STATUS TABLE */
.status-row{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border);font-size:12.5px}
.status-row:last-child{border-bottom:none}
.status-key{color:var(--text-1);display:flex;align-items:center;gap:7px}
.status-key i{font-size:15px;color:var(--text-2)}
.status-val{color:var(--blue-600);font-weight:600}
.speed-bar{height:6px;border-radius:4px;background:var(--blue-50);margin-top:6px;overflow:hidden}
.speed-fill{height:100%;border-radius:4px;background:linear-gradient(90deg,var(--accent),var(--accent2));transition:width 1s}

/* ERRORS */
.err-row{padding:10px 0;border-bottom:1px solid var(--border);font-size:11.5px}
.err-row:last-child{border-bottom:none}
.err-time{color:var(--text-2);font-size:10px;margin-bottom:3px;display:flex;align-items:center;gap:5px}
.err-msg{color:var(--red-text);font-family:ui-monospace,monospace;background:var(--red-bg);padding:7px 10px;border-radius:7px;word-break:break-all}

/* CHARTS */
.chart-wrap{position:relative;height:220px;width:100%}
.chart-wrap-sm{position:relative;height:180px;width:100%}

/* FOOTER */
.dash-footer{border-top:1px solid var(--border);margin-top:14px;padding-top:16px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px}
.footer-text{font-size:11px;color:var(--text-2)}
.footer-link{font-size:12.5px;color:var(--blue-600);text-decoration:none;display:flex;align-items:center;gap:6px;font-weight:500}
.footer-link:hover{color:var(--text-1)}

/* TOAST */
.toast{position:fixed;bottom:28px;left:50%;transform:translateX(-50%) translateY(40px);background:var(--white);color:#fff;border:1px solid var(--border);border-radius:10px;padding:11px 22px;font-size:13px;opacity:0;transition:all .3s;z-index:999;pointer-events:none;display:flex;align-items:center;gap:8px;box-shadow:0 6px 24px rgba(0,0,0,.4)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.err{background:var(--red-dot);border-color:var(--red-dot)}

/* FORM ELEMENTS */
.form-row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
.form-group{display:flex;flex-direction:column;gap:6px}
.form-label{font-size:11.5px;color:var(--text-2);font-weight:600}
.form-input,.form-select{padding:10px 13px;border-radius:9px;border:1px solid var(--border);font-family:inherit;font-size:12.5px;outline:none;color:var(--text-1);background:var(--card2);min-width:120px;transition:.15s}
.form-input:focus,.form-select:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow)}
.form-select option{background:var(--card2);color:var(--text-1)}

/* LINKS TABLE */
.links-table{width:100%;border-collapse:collapse}
.links-table th{text-align:right;font-size:11px;color:var(--text-2);font-weight:600;padding:10px 8px;border-bottom:2px solid var(--border);white-space:nowrap}
.links-table td{padding:13px 8px;border-bottom:1px solid var(--border);font-size:12.5px;vertical-align:middle;color:var(--text-1)}
.links-table tr:last-child td{border-bottom:none}
.links-table tr:hover td{background:var(--card2)}
.link-uuid{font-family:ui-monospace,monospace;font-size:10.5px;color:var(--blue-600);background:var(--blue-50);padding:3px 8px;border-radius:6px;display:inline-block}
.usage-bar-wrap{width:140px}
.usage-bar{height:7px;border-radius:4px;background:var(--blue-50);overflow:hidden;margin-bottom:4px}
.usage-bar-fill{height:100%;border-radius:4px;transition:width .3s}
.usage-text{font-size:10.5px;color:var(--text-2)}
.empty-state{text-align:center;padding:50px 20px;color:var(--text-2)}
.empty-state i{font-size:42px;color:var(--blue-200);margin-bottom:12px;display:block}

/* TOGGLE */
.toggle{width:38px;height:21px;border-radius:20px;background:var(--blue-100);position:relative;cursor:pointer;transition:.2s;flex-shrink:0;border:none}
.toggle::after{content:'';position:absolute;width:15px;height:15px;border-radius:50%;background:#fff;top:3px;right:3px;transition:.2s;box-shadow:0 1px 3px rgba(0,0,0,.4)}
.toggle.on{background:var(--green-dot)}
.toggle.on::after{right:20px}

/* INFO CALLOUT */
.callout{background:rgba(59,130,246,0.08);border:1px solid rgba(59,130,246,0.18);border-radius:11px;padding:14px 16px;font-size:12px;color:var(--blue-700);display:flex;gap:10px;align-items:flex-start;line-height:1.8}
.callout i{font-size:18px;color:var(--accent);margin-top:1px}
.callout.amber{background:var(--amber-bg);border-color:rgba(240,193,120,0.25);color:var(--amber-text)}
.callout.amber i{color:var(--amber-dot)}

/* IDEA CARDS */
.idea-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.idea-card{background:var(--white);border:1px solid var(--border);border-radius:14px;padding:18px;box-shadow:var(--shadow)}
.idea-icon{width:38px;height:38px;border-radius:10px;background:rgba(59,130,246,0.1);display:flex;align-items:center;justify-content:center;color:var(--blue-500);font-size:19px;margin-bottom:11px}
.idea-title{font-size:13px;font-weight:700;color:var(--text-1);margin-bottom:6px}
.idea-desc{font-size:11.5px;color:var(--text-2);line-height:1.8}
.idea-badge{display:inline-block;margin-top:10px;font-size:10px;background:rgba(59,130,246,0.1);color:var(--blue-500);padding:3px 9px;border-radius:20px;font-weight:600}

/* FILTER TABS */
.filter-tabs{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}
.filter-tab{background:var(--white);border:1px solid var(--border);color:var(--text-2)}
.filter-tab:hover{background:var(--card2)}
.filter-tab.active{background:var(--accent);color:#fff;border-color:var(--accent)}

/* MODAL */
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:500;align-items:center;justify-content:center;backdrop-filter:blur(2px);padding:16px}
.modal-overlay.show{display:flex}
.modal-box{background:var(--white);border:1px solid var(--border);border-radius:16px;padding:24px;width:100%;max-width:420px;box-shadow:0 20px 60px rgba(0,0,0,0.5)}
.modal-title{font-size:15px;font-weight:700;color:var(--text-1);margin-bottom:18px;display:flex;align-items:center;gap:8px}
.modal-title i{color:var(--accent);font-size:19px}
.modal-actions{display:flex;gap:10px;margin-top:18px;justify-content:flex-end}
.modal-box .form-group{margin-bottom:13px}

/* EXPIRY BADGES */
.expiry-ok{color:var(--blue-600)}
.expiry-warn{color:var(--amber-dot);font-weight:600}
.expiry-danger{color:var(--red-dot);font-weight:600}
.expiry-forever{color:var(--blue-400)}

@media(max-width:1000px){
  .sidebar{transform:translateX(-100%)}
  .sidebar.open{transform:translateX(0);box-shadow:8px 0 30px rgba(0,0,0,0.5)}
  .sidebar-close{display:flex}
  .main{margin-left:0;max-width:100%;padding-top:72px}
  .mobile-topbar{display:flex}
  .metrics{grid-template-columns:1fr 1fr}
  .grid2,.grid3{grid-template-columns:1fr}
  .idea-grid{grid-template-columns:1fr}
}
@media(max-width:480px){
  .metrics{grid-template-columns:1fr}
  .main{padding-left:14px;padding-right:14px}
}
</style>
</head>
<body>

<div class="toast" id="toast"></div>

<!-- MOBILE TOPBAR -->
<div class="mobile-topbar">
  <div class="mt-left">
    <div style="width:32px;height:32px;border-radius:9px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center;color:#fff;font-size:20px;font-weight:900;font-family:'Vazirmatn',sans-serif">T</div>
    <span class="mt-title">tryak Gateway</span>
  </div>
  <button class="menu-btn" id="open-sidebar-btn"><i class="ti ti-menu-2"></i></button>
</div>

<!-- OVERLAY -->
<div class="sidebar-overlay" id="sidebar-overlay"></div>

<!-- SIDEBAR -->
<aside class="sidebar" id="sidebar">
  <button class="sidebar-close" id="close-sidebar-btn"><i class="ti ti-x"></i></button>
  <div class="logo">
    <div style="width:42px;height:42px;border-radius:11px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center;color:#fff;font-size:26px;font-weight:900;font-family:'Vazirmatn',sans-serif;flex-shrink:0;box-shadow:0 4px 16px var(--accent-glow)">T</div>
    <div>
      <div class="logo-name">tryak Gateway</div>
      <div class="logo-sub">v6.0</div>
    </div>
  </div>


  <div class="nav-scroll">
    <div class="nav-group-label">پنل</div>
    <div class="nav-item active" data-page="overview"><i class="ti ti-layout-dashboard"></i> داشبورد کلی</div>
    <div class="nav-item" data-page="links"><i class="ti ti-link-plus"></i> مدیریت لینک‌ها <span class="nav-badge" id="links-count-badge">0</span></div>
    <div class="nav-item" data-page="traffic"><i class="ti ti-chart-area"></i> آمار ترافیک</div>
    <div class="nav-item" data-page="connections"><i class="ti ti-plug-connected"></i> اتصالات فعال <span class="nav-badge" id="conns-count-badge">0</span></div>

    <div class="nav-group-label">سیستم</div>
    <div class="nav-item" data-page="security"><i class="ti ti-shield-lock"></i> امنیت</div>
    <div class="nav-item" data-page="errors"><i class="ti ti-alert-triangle"></i> خطاها</div>
    <div class="nav-item" data-page="testws"><i class="ti ti-wifi"></i> تست WebSocket</div>
    <div class="nav-item" data-page="settings"><i class="ti ti-settings"></i> تنظیمات</div>
  </div>

  <div class="sidebar-footer">
    <button class="logout-btn" id="logout-btn"><i class="ti ti-logout"></i> خروج از حساب</button>
  </div>
</aside>

<!-- MAIN -->
<main class="main">

  <!-- ═══════ OVERVIEW PAGE ═══════ -->
  <section class="page active" id="page-overview">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-layout-dashboard"></i> داشبورد کلی</div>
        <div class="topbar-sub" id="last-update">در حال بارگذاری...</div>
      </div>
      <div class="topbar-right">
        <span class="badge badge-green"><span class="dot dot-green pulse"></span> سرور فعال</span>
        <span class="badge badge-blue" id="uptime-badge">Railway · --</span>
        <button class="btn btn-primary" onclick="refreshAll()"><i class="ti ti-refresh"></i> رفرش</button>
      </div>
    </div>

    <div class="metrics">
      <div class="metric">
        <div class="metric-label"><i class="ti ti-plug-connected"></i> اتصالات فعال</div>
        <div class="metric-val" id="m-conns">—</div>
        <div class="metric-sub" id="m-conns-sub">اتصال WebSocket باز</div>
      </div>
      <div class="metric">
        <div class="metric-label"><i class="ti ti-transfer"></i> کل ترافیک</div>
        <div class="metric-val" id="m-traffic">—<span class="metric-unit">MB</span></div>
        <div class="metric-sub">از ابتدای راه‌اندازی</div>
      </div>
      <div class="metric">
        <div class="metric-label"><i class="ti ti-send"></i> کل درخواست‌ها</div>
        <div class="metric-val" id="m-reqs">—</div>
        <div class="metric-sub">از ابتدای سرویس</div>
      </div>
      <div class="metric metric-error">
        <div class="metric-label"><i class="ti ti-alert-circle"></i> خطاها</div>
        <div class="metric-val" id="m-errors">—</div>
        <div class="metric-sub">ثبت شده</div>
      </div>
    </div>

    <div class="vless-box">
      <div class="vless-header">
        <div class="vless-title"><i class="ti ti-link"></i> لینک پیش‌فرض (بدون محدودیت)</div>
        <span class="badge" style="background:rgba(59,130,246,0.12);color:var(--blue-700)">TLS 443 · WS</span>
      </div>
      <div class="vless-link-wrap">
        <div class="vless-link" id="vless-link-overview">در حال دریافت...</div>
      </div>
      <div class="vless-actions">
        <button class="btn btn-primary" onclick="copyText('vless-link-overview')"><i class="ti ti-copy"></i> کپی لینک</button>
        <button class="btn btn-outline" onclick="qrFor('vless-link-overview')"><i class="ti ti-qrcode"></i> QR کد</button>
        <button class="btn btn-outline" onclick="switchPage('links')"><i class="ti ti-link-plus"></i> ساخت لینک با محدودیت ترافیک</button>
      </div>
    </div>

    <div class="grid3">
      <div class="card">
        <div class="card-title"><i class="ti ti-chart-area"></i> ترافیک ساعتی (MB)</div>
        <div class="chart-wrap"><canvas id="trafficChart" role="img" aria-label="نمودار ترافیک ساعتی"></canvas></div>
      </div>
      <div class="card">
        <div class="card-title"><i class="ti ti-chart-donut"></i> توزیع درخواست‌ها</div>
        <div class="chart-wrap-sm"><canvas id="donutChart" role="img" aria-label="توزیع نوع ترافیک"></canvas></div>
      </div>
    </div>

    <div class="grid2">
      <div class="card">
        <div class="card-title"><i class="ti ti-activity"></i> وضعیت سرویس‌ها</div>
        <div class="status-row"><span class="status-key"><i class="ti ti-circle-check"></i> VLESS / WebSocket Tunnel</span><span class="status-val" style="color:var(--green-text)">● فعال</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-circle-check"></i> HTTP Proxy</span><span class="status-val" style="color:var(--green-text)">● فعال</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-server"></i> Async Connection Pool</span><span class="status-val" style="color:var(--green-text)">● فعال</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-clock"></i> آپتایم</span><span class="status-val" id="uptime-inline">—</span></div>
        <div class="status-row" style="flex-direction:column;align-items:flex-start;gap:6px">
          <div style="width:100%;display:flex;justify-content:space-between"><span class="status-key"><i class="ti ti-gauge"></i> پهنای باند (نسبی)</span><span class="status-val" id="bw-pct">—%</span></div>
          <div class="speed-bar" style="width:100%"><div class="speed-fill" id="bw-bar" style="width:0%"></div></div>
        </div>
      </div>
      <div class="card">
        <div class="card-title"><i class="ti ti-link-plus"></i> خلاصه لینک‌ها <span class="ml-auto badge badge-blue" id="links-summary-badge">۰ لینک</span></div>
        <div id="links-summary-list" style="font-size:12px;color:var(--blue-400)">در حال بارگذاری...</div>
      </div>
    </div>

    <div class="dash-footer">
      <span class="footer-text">tryak Gateway v6.0 · 2025</span>
    </div>
  </section>

  <!-- ═══════ LINKS MANAGEMENT PAGE ═══════ -->
  <section class="page" id="page-links">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-link-plus"></i> مدیریت لینک‌ها</div>
        <div class="topbar-sub">ساخت لینک رندوم با محدودیت ترافیک اختصاصی (MB / GB)</div>
      </div>
      <div class="topbar-right">
        <span class="badge badge-blue" id="links-page-count">۰ لینک ساخته شده</span>
      </div>
    </div>

    <div class="card" style="margin-bottom:18px">
      <div class="card-title"><i class="ti ti-plus"></i> ساخت لینک جدید</div>
      <div class="form-row">
        <div class="form-group" style="flex:1;min-width:180px">
          <label class="form-label">عنوان / یادداشت لینک</label>
          <input class="form-input" id="new-link-label" placeholder="مثلاً: برای علی" style="width:100%">
        </div>
        <div class="form-group">
          <label class="form-label">مقدار سهمیه ترافیک</label>
          <input class="form-input" id="new-link-value" type="number" min="0" step="0.1" placeholder="0 = بی‌نهایت" style="width:130px">
        </div>
        <div class="form-group">
          <label class="form-label">واحد</label>
          <select class="form-select" id="new-link-unit">
            <option value="GB">گیگابایت (GB)</option>
            <option value="MB" selected>مگابایت (MB)</option>
          </select>
        </div>
        <div class="form-group">
          <label class="form-label">اعتبار (روز)</label>
          <input class="form-input" id="new-link-expire" type="number" min="0" step="1" placeholder="0 = همیشگی" style="width:110px">
        </div>
        <div class="form-group">
          <label class="form-label">حداکثر دستگاه</label>
          <input class="form-input" id="new-link-devices" type="number" min="0" step="1" placeholder="0 = بی‌نهایت" style="width:110px">
        </div>
        <button class="btn btn-primary" onclick="createLink()"><i class="ti ti-link-plus"></i> ساخت لینک رندوم</button>
      </div>
      <div class="callout" style="margin-top:14px">
        <i class="ti ti-info-circle"></i>
        <span>هر لینک یک UUID کاملاً رندوم و یکتا دارد. اگر مقدار سهمیه را ۰ یا خالی بگذارید، لینک بدون محدودیت ترافیک خواهد بود. اگر اعتبار روز را ۰ یا خالی بگذارید، لینک هیچ‌وقت منقضی نمی‌شود. به محض رسیدن مصرف به سقف یا گذشتن از تاریخ انقضا، اتصال لینک به‌صورت خودکار قطع و مسدود می‌شود.</span>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><i class="ti ti-list"></i> لینک‌های ساخته‌شده</div>
      <div class="filter-tabs">
        <button class="btn btn-sm filter-tab active" data-filter="all" onclick="setLinksFilter('all')"><i class="ti ti-list"></i> همه</button>
        <button class="btn btn-sm filter-tab" data-filter="active" onclick="setLinksFilter('active')"><i class="ti ti-circle-check"></i> فعال</button>
        <button class="btn btn-sm filter-tab" data-filter="paused" onclick="setLinksFilter('paused')"><i class="ti ti-player-pause"></i> غیرفعال</button>
        <button class="btn btn-sm filter-tab" data-filter="expired" onclick="setLinksFilter('expired')"><i class="ti ti-calendar-x"></i> منقضی‌شده</button>
      </div>
      <div style="overflow-x:auto">
      <table class="links-table">
        <thead>
          <tr>
            <th>عنوان</th>
            <th>UUID</th>
            <th>مصرف / سهمیه</th>
            <th>انقضا</th>
            <th>وضعیت</th>
            <th>عملیات</th>
          </tr>
        </thead>
        <tbody id="links-tbody"></tbody>
      </table>
      </div>
      <div class="empty-state" id="links-empty" style="display:none">
        <i class="ti ti-link-off"></i>
        <span id="links-empty-text">هنوز هیچ لینکی ساخته نشده. از فرم بالا یک لینک جدید بسازید.</span>
      </div>
    </div>
  </section>

  <!-- ═══════ TRAFFIC PAGE ═══════ -->
  <section class="page" id="page-traffic">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-chart-area"></i> آمار ترافیک</div>
        <div class="topbar-sub">نمایش لحظه‌ای ترافیک عبوری از Gateway</div>
      </div>
      <div class="topbar-right">
        <button class="btn btn-primary" onclick="refreshAll()"><i class="ti ti-refresh"></i> رفرش</button>
      </div>
    </div>

    <div class="metrics" style="grid-template-columns:repeat(3,1fr)">
      <div class="metric">
        <div class="metric-label"><i class="ti ti-database"></i> کل ترافیک</div>
        <div class="metric-val" id="t-traffic">—<span class="metric-unit">MB</span></div>
        <div class="metric-sub">جمع آپلود + دانلود</div>
      </div>
      <div class="metric">
        <div class="metric-label"><i class="ti ti-arrow-up"></i> میانگین در ساعت</div>
        <div class="metric-val" id="t-avg">—<span class="metric-unit">MB</span></div>
        <div class="metric-sub">بر اساس داده‌های امروز</div>
      </div>
      <div class="metric">
        <div class="metric-label"><i class="ti ti-chart-bar"></i> پیک ساعتی</div>
        <div class="metric-val" id="t-peak">—<span class="metric-unit">MB</span></div>
        <div class="metric-sub">بالاترین مصرف ساعتی</div>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><i class="ti ti-chart-area"></i> نمودار کامل ترافیک ساعتی</div>
      <div class="chart-wrap" style="height:320px"><canvas id="trafficChartBig"></canvas></div>
    </div>
  </section>

  <!-- ═══════ CONNECTIONS PAGE ═══════ -->
  <section class="page" id="page-connections">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-plug-connected"></i> اتصالات فعال</div>
        <div class="topbar-sub">لیست اتصالات WebSocket باز در همین لحظه</div>
      </div>
      <div class="topbar-right">
        <span class="badge badge-green" id="conns-live-badge"><span class="dot dot-green pulse"></span> ۰ اتصال زنده</span>
        <button class="btn btn-primary" onclick="refreshAll()"><i class="ti ti-refresh"></i> رفرش</button>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><i class="ti ti-list"></i> جزئیات اتصالات</div>
      <div style="overflow-x:auto">
      <table class="links-table">
        <thead><tr><th>شناسه اتصال</th><th>UUID لینک</th><th>زمان اتصال</th><th>حجم انتقال</th></tr></thead>
        <tbody id="conns-tbody"></tbody>
      </table>
      </div>
      <div class="empty-state" id="conns-empty" style="display:none">
        <i class="ti ti-plug-off"></i>
        در حال حاضر هیچ اتصال فعالی وجود ندارد.
      </div>
    </div>
  </section>

  <!-- ═══════ SECURITY PAGE ═══════ -->
  <section class="page" id="page-security">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-shield-lock"></i> امنیت</div>
        <div class="topbar-sub">وضعیت امنیتی Gateway</div>
      </div>
    </div>

    <div class="grid2">
      <div class="card">
        <div class="card-title"><i class="ti ti-lock"></i> رمزنگاری و انتقال</div>
        <div class="status-row"><span class="status-key"><i class="ti ti-certificate"></i> TLS / HTTPS</span><span class="status-val" style="color:var(--green-text)">● فعال (پورت 443)</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-fingerprint"></i> Fingerprint Spoofing</span><span class="status-val" style="color:var(--green-text)">Chrome</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-network"></i> نوع پروتکل</span><span class="status-val">VLESS over WebSocket</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-key"></i> کلید سرویس</span><span class="status-val">رمزنگاری شده (SHA-256)</span></div>
      </div>
      <div class="card">
        <div class="card-title"><i class="ti ti-shield-check"></i> کنترل دسترسی</div>
        <div class="status-row"><span class="status-key"><i class="ti ti-toggle-right"></i> فعال/غیرفعال‌سازی هر لینک</span><span class="status-val" style="color:var(--green-text)">پشتیبانی می‌شود</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-gauge"></i> محدودیت سهمیه ترافیک</span><span class="status-val" style="color:var(--green-text)">پشتیبانی می‌شود</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-ban"></i> قطع خودکار پس از اتمام سهمیه</span><span class="status-val" style="color:var(--green-text)">فعال</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-eye-off"></i> عدم ذخیره محتوای ترافیک</span><span class="status-val" style="color:var(--green-text)">فعال</span></div>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><i class="ti ti-ban"></i> IP های بلاک‌شده</div>
      <div class="form-row" style="margin-bottom:12px">
        <div class="form-group" style="flex:1;min-width:180px">
          <input class="form-input" id="new-block-ip" placeholder="مثلاً 1.2.3.4" style="width:100%">
        </div>
        <button class="btn btn-primary" onclick="blockIPManual()"><i class="ti ti-ban"></i> بلاک کردن</button>
      </div>
      <div id="blocked-ips-list"></div>
      <div class="empty-state" id="blocked-empty" style="display:none">
        <i class="ti ti-shield-check"></i>
        هیچ IP بلاکی وجود ندارد.
      </div>
    </div>

    <div class="callout amber">
      <i class="ti ti-alert-triangle"></i>
      <span>توجه: لینک‌ها و IP های بلاک‌شده روی یک فایل JSON در دیسک ذخیره می‌شوند و بعد از ری‌استارت سرویس باقی می‌مانند (به‌جز سشن‌های ورود و آمار لحظه‌ای که درون‌حافظه هستند). رمز پنل از متغیر محیطی ADMIN_PASSWORD خوانده می‌شود.</span>
    </div>
  </section>

  <!-- ═══════ ERRORS PAGE ═══════ -->
  <section class="page" id="page-errors">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-alert-triangle"></i> خطاها</div>
        <div class="topbar-sub">آخرین خطاهای ثبت‌شده توسط سرویس</div>
      </div>
      <div class="topbar-right">
        <span class="badge badge-red" id="errors-count-badge">۰ خطا</span>
        <button class="btn btn-primary" onclick="refreshAll()"><i class="ti ti-refresh"></i> رفرش</button>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><i class="ti ti-bug"></i> لاگ خطاهای اخیر</div>
      <div id="errors-list-full" style="font-size:12px;color:var(--blue-400)">در حال بارگذاری...</div>
    </div>
  </section>

  <!-- ═══════ TEST WS PAGE ═══════ -->
  <section class="page" id="page-testws">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-wifi"></i> تست WebSocket</div>
        <div class="topbar-sub">بررسی سریع اتصال WebSocket به Gateway</div>
      </div>
    </div>

    <div class="card" style="max-width:680px">
      <div class="form-row" style="margin-bottom:14px">
        <div class="form-group" style="flex:1">
          <label class="form-label">UUID (خالی = تصادفی)</label>
          <input class="form-input" id="ws-uuid" placeholder="UUID لینک" style="width:100%">
        </div>
        <button class="btn btn-primary" onclick="wsConnect()"><i class="ti ti-plug-connected"></i> اتصال</button>
        <button class="btn btn-danger" onclick="wsDisconnect()"><i class="ti ti-plug-x"></i> قطع</button>
      </div>
      <div class="form-row" style="margin-bottom:14px">
        <input class="form-input" id="ws-msg" placeholder="پیام تست..." style="flex:1">
        <button class="btn btn-outline" onclick="wsSend()"><i class="ti ti-send"></i> ارسال</button>
      </div>
      <div style="background:#060a13;border:1px solid var(--border);border-radius:11px;padding:16px;height:260px;overflow-y:auto;font-family:ui-monospace,monospace;font-size:11.5px;line-height:1.9" id="ws-log">
        <p style="color:var(--text-2)">منتظر اتصال...</p>
      </div>
    </div>
  </section>

  <!-- ═══════ SETTINGS PAGE ═══════ -->
  <section class="page" id="page-settings">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-settings"></i> تنظیمات</div>
        <div class="topbar-sub">اطلاعات کلی سرویس tryak Gateway</div>
      </div>
    </div>

    <div class="grid2">
      <div class="card">
        <div class="card-title"><i class="ti ti-server"></i> اطلاعات سرور</div>
        <div class="status-row"><span class="status-key"><i class="ti ti-world"></i> دامنه</span><span class="status-val" id="set-host">—</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-route"></i> پورت اتصال</span><span class="status-val">443 (TLS)</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-versions"></i> نسخه</span><span class="status-val">tryak Gateway v6.0</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-brand-fastapi"></i> فریم‌ورک</span><span class="status-val">FastAPI + Uvicorn</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-cloud"></i> پلتفرم</span><span class="status-val" id="platform-val">—</span></div>
      </div>

      <div class="card">
        <div class="card-title"><i class="ti ti-key"></i> تغییر رمز عبور پنل</div>
        <div class="form-group" style="margin-bottom:14px">
          <label class="form-label">رمز فعلی</label>
          <input class="form-input" type="password" id="cp-current" placeholder="رمز فعلی" style="width:100%">
        </div>
        <div class="form-group" style="margin-bottom:14px">
          <label class="form-label">رمز جدید</label>
          <input class="form-input" type="password" id="cp-new" placeholder="حداقل ۴ کاراکتر" style="width:100%">
        </div>
        <div class="form-group" style="margin-bottom:16px">
          <label class="form-label">تکرار رمز جدید</label>
          <input class="form-input" type="password" id="cp-confirm" placeholder="تکرار رمز جدید" style="width:100%">
        </div>
        <button class="btn btn-primary" onclick="changePassword()" style="width:100%;justify-content:center"><i class="ti ti-key"></i> تغییر رمز عبور</button>
        <div class="callout" style="margin-top:14px">
          <i class="ti ti-info-circle"></i>
          <span>رمز پنل از متغیر محیطی <b>ADMIN_PASSWORD</b> در Render/Railway خوانده می‌شود. پس از تغییر رمز، تمام سشن‌های دیگر باطل می‌شوند و باید مجدداً وارد شوید.</span>
        </div>
      </div>
    </div>
  </section>

</main>

<!-- EDIT LINK MODAL -->
<div class="modal-overlay" id="edit-modal">
  <div class="modal-box">
    <div class="modal-title"><i class="ti ti-edit"></i> ویرایش لینک</div>

    <div class="form-group">
      <label class="form-label">عنوان / یادداشت لینک</label>
      <input class="form-input" id="edit-label" style="width:100%">
    </div>

    <div class="form-row">
      <div class="form-group" style="flex:1">
        <label class="form-label">مقدار سهمیه ترافیک</label>
        <input class="form-input" id="edit-limit-value" type="number" min="0" step="0.1" placeholder="0 = بی‌نهایت" style="width:100%">
      </div>
      <div class="form-group">
        <label class="form-label">واحد</label>
        <select class="form-select" id="edit-limit-unit">
          <option value="GB">GB</option>
          <option value="MB">MB</option>
        </select>
      </div>
    </div>

    <div class="form-group">
      <label class="form-label">اعتبار باقی‌مانده (روز) — ۰ یا خالی = همیشگی</label>
      <input class="form-input" id="edit-expire-days" type="number" min="0" step="1" style="width:100%">
    </div>

    <div class="callout">
      <i class="ti ti-info-circle"></i>
      <span>تغییر «اعتبار» همیشه از <b>همین لحظه</b> محاسبه می‌شود؛ یعنی با ذخیره، شمارش روزها از نو شروع می‌شود.</span>
    </div>

    <div class="modal-actions">
      <button class="btn btn-light-outline" onclick="closeEditModal()">انصراف</button>
      <button class="btn btn-primary" onclick="saveEditLink()"><i class="ti ti-check"></i> ذخیره تغییرات</button>
    </div>
  </div>
</div>

<script>
let trafficChart, donutChart, trafficChartBig;
let prevTraffic = 0;
let vlessLinkText = '';
let ws;

function toast(msg, isErr){
  const t=document.getElementById('toast');
  t.textContent=msg;
  t.className='toast show'+(isErr?' err':'');
  setTimeout(()=>t.classList.remove('show'),2200);
}

function fmt(n){ return n>=1000?`${(n/1000).toFixed(1)}k`:n; }
function fmtBytes(b){
  if(b===0) return '0 B';
  if(b<1024) return b+' B';
  if(b<1024*1024) return (b/1024).toFixed(1)+' KB';
  if(b<1024*1024*1024) return (b/(1024*1024)).toFixed(2)+' MB';
  return (b/(1024*1024*1024)).toFixed(2)+' GB';
}

/* ───────── Auth Guard ───────── */
async function checkAuth(){
  try{
    const r=await fetch('/api/me');
    const d=await r.json();
    if(!d.authenticated){
      location.href='/login';
    }
  }catch(e){
    location.href='/login';
  }
}

async function logout(){
  try{ await fetch('/api/logout',{method:'POST'}); }catch(e){}
  location.href='/login';
}
document.getElementById('logout-btn').addEventListener('click', logout);

/* ───────── Change Password ───────── */
async function changePassword(){
  const cur=document.getElementById('cp-current').value;
  const nw=document.getElementById('cp-new').value;
  const cf=document.getElementById('cp-confirm').value;

  if(!cur || !nw || !cf){ toast('✗ همه فیلدها را پر کنید', true); return; }
  if(nw.length<4){ toast('✗ رمز جدید باید حداقل ۴ کاراکتر باشد', true); return; }
  if(nw!==cf){ toast('✗ رمز جدید و تکرار آن یکسان نیستند', true); return; }

  try{
    const r=await fetch('/api/change-password',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({current_password:cur,new_password:nw})
    });
    const d=await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(d.detail||'خطا در تغییر رمز');
    toast('✓ رمز عبور با موفقیت تغییر کرد');
    document.getElementById('cp-current').value='';
    document.getElementById('cp-new').value='';
    document.getElementById('cp-confirm').value='';
  }catch(e){ toast('✗ '+e.message, true); }
}

/* ───────── Mobile Sidebar ───────── */
const sidebar=document.getElementById('sidebar');
const overlay=document.getElementById('sidebar-overlay');
function openSidebar(){
  sidebar.classList.add('open');
  overlay.classList.add('show');
}
function closeSidebar(){
  sidebar.classList.remove('open');
  overlay.classList.remove('show');
}
document.getElementById('open-sidebar-btn').addEventListener('click', openSidebar);
document.getElementById('close-sidebar-btn').addEventListener('click', closeSidebar);
overlay.addEventListener('click', closeSidebar);

/* ───────── Navigation ───────── */
function switchPage(name){
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('active', n.dataset.page===name));
  document.querySelectorAll('.page').forEach(p=>p.classList.toggle('active', p.id==='page-'+name));
  if(name==='links') loadLinks();
  if(name==='connections') loadConnections();
  if(name==='errors') loadErrorsFull();
  if(name==='security') loadBlockedIPs();
  closeSidebar();
  window.scrollTo({top:0, behavior:'smooth'});
}
document.querySelectorAll('.nav-item').forEach(item=>{
  item.addEventListener('click', ()=>switchPage(item.dataset.page));
});

/* ───────── Fetch wrapper with auth handling ───────── */
async function authFetch(url, opts){
  const r=await fetch(url, opts);
  if(r.status===401){
    location.href='/login';
    throw new Error('unauthorized');
  }
  return r;
}

/* ───────── Stats / Charts ───────── */
async function fetchStats(){
  try{
    const r=await authFetch('/stats');
    const d=await r.json();

    document.getElementById('m-conns').textContent=d.active_connections;
    document.getElementById('conns-count-badge').textContent=d.active_connections;
    document.getElementById('m-traffic').innerHTML=`${d.total_traffic_mb.toFixed(1)}<span class="metric-unit">MB</span>`;
    document.getElementById('m-reqs').textContent=fmt(d.total_requests);
    document.getElementById('m-errors').textContent=d.total_errors;
    document.getElementById('errors-count-badge').textContent=`${d.total_errors} خطا`;
    document.getElementById('uptime-inline').textContent=d.uptime||'—';
    const pv=document.getElementById('platform-val');
    if(pv) pv.textContent=d.platform||'—';
    document.getElementById('uptime-badge').textContent=`${d.platform||'Railway'} · ${d.uptime||'—'}`;
    document.getElementById('last-update').textContent=`آخرین بروزرسانی: ${new Date().toLocaleTimeString('fa-IR')}`;
    document.getElementById('conns-live-badge').innerHTML=`<span class="dot dot-green pulse"></span> ${d.active_connections} اتصال زنده`;

    // traffic page
    document.getElementById('t-traffic').innerHTML=`${d.total_traffic_mb.toFixed(1)}<span class="metric-unit">MB</span>`;

    const delta=d.total_traffic_mb-prevTraffic;
    const pct=Math.min(100,Math.round((delta/50)*100));
    document.getElementById('bw-pct').textContent=`${pct}%`;
    document.getElementById('bw-bar').style.width=pct+'%';
    prevTraffic=d.total_traffic_mb;

    if(d.hourly){
      const labels=Object.keys(d.hourly).sort();
      const vals=labels.map(k=>+(d.hourly[k]/(1024*1024)).toFixed(2));
      [trafficChart, trafficChartBig].forEach(ch=>{
        if(!ch) return;
        ch.data.labels=labels;
        ch.data.datasets[0].data=vals;
        ch.update();
      });
      if(vals.length){
        const avg=vals.reduce((a,b)=>a+b,0)/vals.length;
        const peak=Math.max(...vals);
        document.getElementById('t-avg').innerHTML=`${avg.toFixed(2)}<span class="metric-unit">MB</span>`;
        document.getElementById('t-peak').innerHTML=`${peak.toFixed(2)}<span class="metric-unit">MB</span>`;
      }
    }

    renderErrors(d.recent_errors||[]);
  }catch(e){ console.error(e); }
}

function renderErrors(errors){
  const el=document.getElementById('errors-list');
  const elFull=document.getElementById('errors-list-full');
  if(errors.length){
    const html5=errors.slice(-5).reverse().map(e=>`
      <div class="err-row">
        <div class="err-time"><i class="ti ti-clock" style="font-size:11px"></i> ${new Date(e.time).toLocaleString('fa-IR')}</div>
        <div class="err-msg">${escapeHtml(e.error)}</div>
      </div>`).join('');
    const htmlAll=errors.slice().reverse().map(e=>`
      <div class="err-row">
        <div class="err-time"><i class="ti ti-clock" style="font-size:11px"></i> ${new Date(e.time).toLocaleString('fa-IR')}</div>
        <div class="err-msg">${escapeHtml(e.error)}${e.url?' — '+escapeHtml(e.url):''}</div>
      </div>`).join('');
    if(el) el.innerHTML=html5;
    if(elFull) elFull.innerHTML=htmlAll;
  } else {
    const okHtml='<div style="color:var(--green-text);padding:12px 0;display:flex;align-items:center;gap:6px"><i class="ti ti-circle-check"></i> هیچ خطایی ثبت نشده</div>';
    if(el) el.innerHTML=okHtml;
    if(elFull) elFull.innerHTML=okHtml;
  }
}

function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

/* ───────── Links Management ───────── */
let currentLinks=[];
let linksFilter='all';

function setLinksFilter(f){
  linksFilter=f;
  document.querySelectorAll('.filter-tab').forEach(b=>{
    b.classList.toggle('active', b.dataset.filter===f);
  });
  renderLinksTable();
}

function expiryCell(l){
  if(!l.expires_at) return '<span class="expiry-forever"><i class="ti ti-infinity"></i> همیشگی</span>';
  if(l.is_expired) return '<span class="expiry-danger"><i class="ti ti-calendar-x"></i> منقضی شده</span>';
  const days=Math.ceil(l.days_left);
  const cls = days<=3 ? 'expiry-danger' : days<=7 ? 'expiry-warn' : 'expiry-ok';
  return `<span class="${cls}"><i class="ti ti-calendar-time"></i> ${toFa(days)} روز دیگر</span>`;
}

function statusCell(l){
  if(l.is_expired) return '<span class="badge badge-red">منقضی</span>';
  if(!l.active) return '<span class="badge badge-amber">غیرفعال</span>';
  if(l.quota_exceeded) return '<span class="badge badge-red">اتمام سهمیه</span>';
  return '<span class="badge badge-green">فعال</span>';
}

function renderLinksTable(){
  const tbody=document.getElementById('links-tbody');
  const empty=document.getElementById('links-empty');
  const emptyText=document.getElementById('links-empty-text');

  let filtered=currentLinks;
  if(linksFilter==='active') filtered=currentLinks.filter(l=>l.active && !l.is_expired);
  else if(linksFilter==='paused') filtered=currentLinks.filter(l=>!l.active);
  else if(linksFilter==='expired') filtered=currentLinks.filter(l=>l.is_expired);

  if(!filtered.length){
    tbody.innerHTML='';
    empty.style.display='block';
    emptyText.textContent = currentLinks.length
      ? 'هیچ لینکی با این فیلتر مطابقت ندارد.'
      : 'هنوز هیچ لینکی ساخته نشده. از فرم بالا یک لینک جدید بسازید.';
  } else {
    empty.style.display='none';
    tbody.innerHTML=filtered.map(l=>{
      const limitTxt = l.limit_bytes===0 ? 'بی‌نهایت' : fmtBytes(l.limit_bytes);
      const pct = l.limit_bytes===0 ? 0 : Math.min(100, (l.used_bytes/l.limit_bytes)*100);
      const barColor = pct>90 ? 'var(--red-dot)' : pct>70 ? 'var(--amber-dot)' : 'var(--blue-400)';
      return `
      <tr>
        <td><b>${escapeHtml(l.label)}</b><div style="font-size:10px;color:var(--blue-400);margin-top:2px">${new Date(l.created_at).toLocaleString('fa-IR')}</div></td>
        <td><span class="link-uuid">${l.uuid}</span></td>
        <td>
          <div class="usage-bar-wrap">
            <div class="usage-bar"><div class="usage-bar-fill" style="width:${pct}%;background:${barColor}"></div></div>
            <div class="usage-text">${fmtBytes(l.used_bytes)} / ${limitTxt}</div>
          </div>
        </td>
        <td style="font-size:11.5px;white-space:nowrap">${expiryCell(l)}</td>
        <td style="white-space:nowrap">
          ${statusCell(l)}
          <button class="toggle ${l.active?'on':''}" onclick="toggleLink('${l.uuid}', ${!l.active})" title="فعال/غیرفعال" style="margin-right:8px"></button>
        </td>
        <td style="white-space:nowrap">
          <button class="btn btn-sm btn-light-outline" onclick="openEditModal('${l.uuid}')"><i class="ti ti-edit"></i></button>
          <button class="btn btn-sm btn-light-outline" onclick="copyVless('${l.vless_link.replace(/'/g,"\\'")}')"><i class="ti ti-copy"></i></button>
          <button class="btn btn-sm btn-light-outline" onclick="qrForText('${l.vless_link.replace(/'/g,"\\'")}')"><i class="ti ti-qrcode"></i></button>
          <button class="btn btn-sm btn-light-outline" title="صفحه اشتراک کاربر" onclick="window.open('/sub/${l.uuid}','_blank')"><i class="ti ti-user-circle"></i></button>
          <button class="btn btn-sm btn-light-outline" onclick="resetUsage('${l.uuid}')"><i class="ti ti-rotate"></i></button>
          <button class="btn btn-sm btn-danger" onclick="deleteLink('${l.uuid}')"><i class="ti ti-trash"></i></button>
        </td>
      </tr>`;
    }).join('');
  }
}

async function loadLinks(){
  try{
    const r=await authFetch('/api/links');
    const d=await r.json();
    const links=d.links||[];
    currentLinks=links;

    document.getElementById('links-count-badge').textContent=links.length;
    document.getElementById('links-page-count').textContent=`${toFa(links.length)} لینک ساخته شده`;
    document.getElementById('links-summary-badge').textContent=`${toFa(links.length)} لینک`;

    renderLinksTable();

    // overview summary
    const sumEl=document.getElementById('links-summary-list');
    if(!links.length){
      sumEl.innerHTML='هنوز لینکی ساخته نشده.';
    } else {
      sumEl.innerHTML=links.slice(0,5).map(l=>{
        const limitTxt = l.limit_bytes===0 ? 'بی‌نهایت' : fmtBytes(l.limit_bytes);
        return `<div class="status-row">
          <span class="status-key"><i class="ti ${l.active?'ti-circle-check':'ti-circle-x'}" style="color:${l.active?'var(--green-dot)':'var(--red-dot)'}"></i> ${escapeHtml(l.label)}</span>
          <span class="status-val">${fmtBytes(l.used_bytes)} / ${limitTxt}</span>
        </div>`;
      }).join('');
    }
  }catch(e){ console.error(e); }
}

function toFa(n){ return n.toString().replace(/\d/g, d=>'۰۱۲۳۴۵۶۷۸۹'[d]); }

async function createLink(){
  const label=document.getElementById('new-link-label').value.trim() || 'لینک جدید';
  const value=document.getElementById('new-link-value').value;
  const unit=document.getElementById('new-link-unit').value;
  const expireDays=document.getElementById('new-link-expire').value;
  const devices=document.getElementById('new-link-devices').value;
  try{
    const r=await authFetch('/api/links',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({label, limit_value:value||0, limit_unit:unit, expire_days:expireDays||0, max_devices:devices||0})
    });
    if(!r.ok) throw new Error('failed');
    document.getElementById('new-link-label').value='';
    document.getElementById('new-link-value').value='';
    document.getElementById('new-link-expire').value='';
    document.getElementById('new-link-devices').value='';
    toast('✓ لینک جدید ساخته شد');
    loadLinks();
  }catch(e){ toast('✗ خطا در ساخت لینک', true); }
}

async function toggleLink(uuid, newState){
  try{
    await authFetch(`/api/links/${uuid}`,{
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({active:newState})
    });
    toast(newState?'✓ لینک فعال شد':'✓ لینک غیرفعال شد');
    loadLinks();
  }catch(e){ toast('✗ خطا', true); }
}

async function resetUsage(uuid){
  try{
    await authFetch(`/api/links/${uuid}`,{
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({reset_usage:true})
    });
    toast('✓ مصرف ریست شد');
    loadLinks();
  }catch(e){ toast('✗ خطا', true); }
}

async function deleteLink(uuid){
  if(!confirm('آیا از حذف این لینک مطمئن هستید؟')) return;
  try{
    await authFetch(`/api/links/${uuid}`,{method:'DELETE'});
    toast('✓ لینک حذف شد');
    loadLinks();
  }catch(e){ toast('✗ خطا', true); }
}

async function loadBlockedIPs(){
  try{
    const r=await authFetch('/api/blocked');
    const d=await r.json();
    const el=document.getElementById('blocked-ips-list');
    const empty=document.getElementById('blocked-empty');
    if(!el) return;
    if(!d.blocked_ips || !d.blocked_ips.length){
      el.innerHTML=''; if(empty) empty.style.display='block';
      return;
    }
    if(empty) empty.style.display='none';
    el.innerHTML=d.blocked_ips.map(ip=>`
      <div class="status-row">
        <span class="status-key" style="font-family:monospace">${escapeHtml(ip)}</span>
        <button class="btn btn-sm" onclick="unblockIPManual('${ip}')"><i class="ti ti-x"></i> آنبلاک</button>
      </div>`).join('');
  }catch(e){ console.error(e); }
}

async function blockIPManual(){
  const ip=document.getElementById('new-block-ip').value.trim();
  if(!ip) return;
  try{
    await authFetch('/api/blocked',{
      method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ip})
    });
    document.getElementById('new-block-ip').value='';
    toast('✓ IP بلاک شد');
    loadBlockedIPs();
  }catch(e){ toast('✗ خطا', true); }
}

async function unblockIPManual(ip){
  try{
    await authFetch(`/api/blocked/${ip}`,{method:'DELETE'});
    toast('✓ IP آنبلاک شد');
    loadBlockedIPs();
  }catch(e){ toast('✗ خطا', true); }
}

/* ───────── Edit Link Modal ───────── */
let editingUuid=null;

function openEditModal(uuid){
  const l=currentLinks.find(x=>x.uuid===uuid);
  if(!l) return;
  editingUuid=uuid;
  document.getElementById('edit-label').value=l.label;
  if(l.limit_bytes===0){
    document.getElementById('edit-limit-value').value='';
  } else {
    document.getElementById('edit-limit-value').value=(l.limit_bytes/(1024*1024*1024)).toFixed(3);
  }
  document.getElementById('edit-limit-unit').value='GB';
  document.getElementById('edit-expire-days').value = (l.expires_at && !l.is_expired) ? Math.ceil(l.days_left) : '';
  document.getElementById('edit-modal').classList.add('show');
}

function closeEditModal(){
  document.getElementById('edit-modal').classList.remove('show');
  editingUuid=null;
}

async function saveEditLink(){
  if(!editingUuid) return;
  const label=document.getElementById('edit-label').value.trim();
  const limitVal=document.getElementById('edit-limit-value').value;
  const limitUnit=document.getElementById('edit-limit-unit').value;
  const expireDays=document.getElementById('edit-expire-days').value;
  try{
    const r=await authFetch(`/api/links/${editingUuid}`,{
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        label: label,
        limit_value: limitVal||0,
        limit_unit: limitUnit,
        expire_days: expireDays||0
      })
    });
    if(!r.ok) throw new Error('failed');
    toast('✓ تغییرات ذخیره شد');
    closeEditModal();
    loadLinks();
  }catch(e){ toast('✗ خطا در ذخیره تغییرات', true); }
}

document.getElementById('edit-modal').addEventListener('click', (e)=>{
  if(e.target.id==='edit-modal') closeEditModal();
});

function copyVless(text){
  navigator.clipboard.writeText(text).then(()=>toast('✓ لینک کپی شد'));
}
function qrForText(text){
  window.open(`https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=${encodeURIComponent(text)}`,'_blank');
}

/* ───────── Connections Page ───────── */
async function loadConnections(){
  try{
    const r=await authFetch('/stats');
    const d=await r.json();
    const tbody=document.getElementById('conns-tbody');
    const empty=document.getElementById('conns-empty');
    if(d.active_connections===0){
      tbody.innerHTML='';
      empty.style.display='block';
    } else {
      empty.style.display='none';
      tbody.innerHTML=`<tr><td colspan="4" style="text-align:center;color:var(--blue-400);padding:20px">
        ${d.active_connections} اتصال فعال در حال انتقال داده — برای جزئیات کامل هر اتصال، endpoint <code>/api/connections</code> را اضافه کنید.
      </td></tr>`;
    }
  }catch(e){ console.error(e); }
}

async function loadErrorsFull(){
  try{
    const r=await authFetch('/stats');
    const d=await r.json();
    renderErrors(d.recent_errors||[]);
  }catch(e){}
}

/* ───────── VLESS overview link ───────── */
async function fetchOverviewVless(){
  try{
    const r=await authFetch('/api/links');
    const d=await r.json();
    const links=d.links||[];
    const def = links.find(l=>l.limit_bytes===0) || links[0];
    if(def){
      vlessLinkText=def.vless_link;
      document.getElementById('vless-link-overview').textContent=vlessLinkText;
    } else {
      document.getElementById('vless-link-overview').textContent='در حال ساخت لینک پیش‌فرض... یک‌بار رفرش کنید.';
    }
  }catch(e){ console.error(e); }
}

function copyText(elId){
  const text=document.getElementById(elId).textContent;
  if(!text||text.includes('بارگ')){ toast('لینک هنوز آماده نیست', true); return; }
  navigator.clipboard.writeText(text).then(()=>toast('✓ لینک کپی شد'));
}
function qrFor(elId){
  const text=document.getElementById(elId).textContent;
  if(!text||text.includes('بارگ')){ toast('لینک هنوز آماده نیست', true); return; }
  window.open(`https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=${encodeURIComponent(text)}`,'_blank');
}

function refreshAll(){
  fetchStats();
  fetchOverviewVless();
  loadLinks();
  toast('در حال رفرش...');
}

/* ───────── WebSocket Test ───────── */
function wsLog(cls,msg){
  const log=document.getElementById('ws-log');
  const p=document.createElement('p');
  const colors={ok:'#97C459',err:'#F09595',info:'#85B7EB',sent:'#FAC775'};
  p.style.color=colors[cls]||'#fff';
  p.textContent=`[${new Date().toLocaleTimeString('fa-IR')}] ${msg}`;
  log.appendChild(p); log.scrollTop=log.scrollHeight;
}
function wsConnect(){
  let uuid=document.getElementById('ws-uuid').value.trim()||crypto.randomUUID();
  const url=`${location.protocol==='https:'?'wss':'ws'}://${location.host}/ws/${uuid}`;
  wsLog('info',`در حال اتصال: ${url}`);
  ws=new WebSocket(url);
  ws.onopen=()=>wsLog('ok','✓ اتصال برقرار شد');
  ws.onerror=()=>wsLog('err','✗ خطا در اتصال');
  ws.onmessage=m=>wsLog('info','دریافت داده ('+(m.data.size||m.data.length)+' بایت)');
  ws.onclose=(e)=>wsLog('err',`اتصال قطع شد (code: ${e.code})`);
}
function wsSend(){
  const m=document.getElementById('ws-msg').value;
  if(!m){wsLog('err','پیام خالی است');return}
  if(!ws||ws.readyState!==1){wsLog('err','ابتدا متصل شوید');return}
  ws.send(m); wsLog('sent','ارسال: '+m);
  document.getElementById('ws-msg').value='';
}
function wsDisconnect(){ if(ws) ws.close(); }

/* ───────── Charts init ───────── */
function initCharts(){
  const baseOpts={
    responsive:true,maintainAspectRatio:false,
    plugins:{legend:{display:false},tooltip:{callbacks:{label:v=>`${v.parsed.y.toFixed(2)} MB`}}},
    scales:{
      x:{grid:{color:'rgba(59,130,246,0.08)'},ticks:{color:'#7b8aab',font:{size:10}}},
      y:{grid:{color:'rgba(59,130,246,0.08)'},ticks:{color:'#7b8aab',font:{size:10},callback:v=>`${v}MB`}}
    }
  };
  const lineData={
    label:'MB',data:[],
    borderColor:'#3b82f6',
    backgroundColor:'rgba(59,130,246,0.12)',
    fill:true,tension:0.45,
    pointRadius:4,pointHoverRadius:6,
    pointBackgroundColor:'#1d4ed8',
    pointBorderColor:'#10172a',pointBorderWidth:2,
    borderWidth:2.5
  };

  trafficChart=new Chart(document.getElementById('trafficChart'),{
    type:'line', data:{labels:[],datasets:[{...lineData}]}, options:baseOpts
  });
  trafficChartBig=new Chart(document.getElementById('trafficChartBig'),{
    type:'line', data:{labels:[],datasets:[{...lineData}]}, options:baseOpts
  });

  donutChart=new Chart(document.getElementById('donutChart'),{
    type:'doughnut',
    data:{
      labels:['VLESS / WS','HTTP Proxy','سایر'],
      datasets:[{
        data:[70,25,5],
        backgroundColor:['#1d4ed8','#3b82f6','#93c5fd'],
        borderColor:'#10172a',borderWidth:2,
        hoverOffset:6
      }]
    },
    options:{
      responsive:true,maintainAspectRatio:false,cutout:'68%',
      plugins:{legend:{position:'bottom',labels:{color:'#7b8aab',font:{size:11},padding:10,usePointStyle:true,pointStyleWidth:10}}}
    }
  });
}

document.addEventListener('DOMContentLoaded',async ()=>{
  await checkAuth();
  initCharts();
  document.getElementById('set-host').textContent=location.host;
  fetchStats();
  fetchOverviewVless();
  loadLinks();
  setInterval(fetchStats,4000);
  setInterval(()=>{ if(document.getElementById('page-links').classList.contains('active')) loadLinks(); }, 5000);
});
</script>
</body>
</html>"""


@app.get("/sub/{uid}/config")
async def sub_config(uid: str, request: Request):
    """لینک ساب‌اسکریپشن برای کلاینت‌ها (base64) — بدون نیاز به لاگین"""
    await ensure_default_link()
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        link = dict(link) if link else None

    if not link:
        return PlainTextResponse("link not found", status_code=404)

    if not link.get("active") or is_link_expired(link):
        return PlainTextResponse("link expired or disabled", status_code=403)

    host = get_host()
    label = link.get("label", "tryak")
    vless = generate_vless_link(uid, host, remark=f"tryak-{label}")
    sub_url = f"https://{host}/sub/{uid}/config"

    encoded = base64.b64encode(vless.encode()).decode()
    return PlainTextResponse(
        encoded,
        headers={
            "Content-Type": "text/plain; charset=utf-8",
            "Profile-Title": label,
            "Subscription-Userinfo": (
                f"upload=0; download={link.get('used_bytes', 0)}; "
                f"total={link.get('limit_bytes', 0)}; "
                + (f"expire={int(datetime.fromisoformat(link['expires_at']).timestamp())}" if link.get('expires_at') else "expire=0")
            ),
        }
    )


@app.get("/sub/{uid}")
async def sub_page(uid: str, request: Request):
    """صفحه اطلاعات اشتراک — مرورگر: HTML، کلاینت v2ray: base64"""
    user_agent = request.headers.get("user-agent", "").lower()
    is_client = any(k in user_agent for k in [
        "v2ray", "xray", "clash", "sing-box", "hiddify", "vittoria",
        "shadowrocket", "quantumult", "surge", "stash", "nekoray",
        "matsuri", "v2box", "streisand", "fair", "foxray"
    ])
    if is_client:
        return await sub_config(uid, request)
    await ensure_default_link()
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        link = dict(link) if link else None

    if not link:
        return HTMLResponse("<html><body style='font-family:sans-serif;text-align:center;padding:60px;background:#0a0e17;color:#eef2ff'><h2>❌ لینک یافت نشد</h2></body></html>", status_code=404)

    host = get_host()
    label = link.get("label", "کاربر")
    used_bytes = link.get("used_bytes", 0)
    limit_bytes = link.get("limit_bytes", 0)
    expires_at = link.get("expires_at")
    is_active = link.get("active", True) and not is_link_expired(link)
    vless = generate_vless_link(uid, host, remark=f"tryak-{label}")

    # محاسبه مصرف روزانه تقریبی (۷ روز گذشته)
    created_at = link.get("created_at", datetime.now().isoformat())
    try:
        days_since = max(1, (datetime.now() - datetime.fromisoformat(created_at)).days)
    except Exception:
        days_since = 1
    daily_avg = used_bytes / days_since if days_since > 0 else 0

    # زمان باقی‌مانده
    if expires_at:
        try:
            exp_dt = datetime.fromisoformat(expires_at)
            days_left = max(0, (exp_dt - datetime.now()).days)
            hours_left = max(0, int((exp_dt - datetime.now()).total_seconds() / 3600))
            exp_str = exp_dt.strftime("%Y-%m-%d")
            never_expire = False
        except Exception:
            days_left = 0
            hours_left = 0
            exp_str = "نامشخص"
            never_expire = False
    else:
        days_left = 9999
        hours_left = 0
        exp_str = "بدون انقضا"
        never_expire = True

    # درصد مصرف
    if limit_bytes > 0:
        pct = min(100, round(used_bytes / limit_bytes * 100))
        limit_str = fmt_bytes(limit_bytes)
    else:
        pct = 0
        limit_str = "نامحدود"

    def fmt_usage(b: int) -> str:
        """مثل fmt_bytes ولی صفر رو صفر نشون میده نه نامحدود"""
        if b == 0:
            return "0 B"
        if b >= 1024 ** 3:
            return f"{b/1024**3:.2f} GB"
        if b >= 1024 ** 2:
            return f"{b/1024**2:.1f} MB"
        return f"{b/1024:.1f} KB"

    used_str = fmt_usage(used_bytes)
    daily_avg_str = fmt_usage(int(daily_avg))

    # رنگ progress bar
    if pct >= 90:
        bar_color = "#f56565"
    elif pct >= 70:
        bar_color = "#f0b14a"
    else:
        bar_color = "#3b82f6"

    # رنگ وضعیت
    status_color = "#4ce090" if is_active else "#f56565"
    status_text = "فعال ✓" if is_active else "غیرفعال ✗"
    sub_url = f"https://{host}/sub/{uid}/config"

    sub_html = f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>tryak · {label}</title>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.19.0/dist/tabler-icons.min.css">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
:root{{
  --accent:#3b82f6;--accent2:#1d4ed8;--accent-glow:rgba(59,130,246,0.35);
  --bg:#0a0e17;--card:#10172a;--card2:#151d33;
  --border:#1f2940;--text-1:#eef2ff;--text-2:#7b8aab;--text-3:#475370;
  --green:#4ce090;--red:#f56565;--amber:#f0b14a;
}}
body{{
  font-family:'Vazirmatn',sans-serif;
  background:
    radial-gradient(circle at 20% 20%, rgba(59,130,246,0.12), transparent 40%),
    radial-gradient(circle at 80% 80%, rgba(29,78,216,0.12), transparent 45%),
    var(--bg);
  min-height:100vh;display:flex;align-items:center;justify-content:center;
  padding:20px;color:var(--text-1);
}}
.card{{
  background:var(--card);border-radius:24px;padding:0;
  width:100%;max-width:420px;
  box-shadow:0 24px 70px rgba(0,0,0,0.6);
  border:1px solid var(--border);overflow:hidden;
}}
.card-header{{
  background:linear-gradient(135deg, var(--accent2) 0%, #070e22 100%);
  padding:28px 28px 24px;position:relative;overflow:hidden;
}}
.card-header::before{{
  content:'';position:absolute;top:-40px;left:-40px;
  width:200px;height:200px;
  background:radial-gradient(circle, rgba(59,130,246,0.2), transparent 70%);
  pointer-events:none;
}}
.logo-row{{display:flex;align-items:center;gap:14px;margin-bottom:20px}}
.logo-icon{{
  width:52px;height:52px;border-radius:14px;
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  display:flex;align-items:center;justify-content:center;
  font-size:30px;font-weight:900;color:#fff;
  box-shadow:0 6px 20px var(--accent-glow);flex-shrink:0;
}}
.logo-text .name{{font-size:18px;font-weight:800;color:#fff}}
.logo-text .sub{{font-size:11px;color:rgba(147,197,253,0.8);margin-top:2px}}
.user-section{{display:flex;align-items:center;gap:12px}}
.avatar{{
  width:44px;height:44px;border-radius:50%;
  background:rgba(59,130,246,0.18);border:2px solid rgba(59,130,246,0.3);
  display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0;
}}
.user-name{{font-size:17px;font-weight:700;color:#fff}}
.user-id{{font-size:10px;color:rgba(147,197,253,0.6);font-family:ui-monospace,monospace;margin-top:3px;word-break:break-all}}
.status-pill{{
  display:inline-flex;align-items:center;gap:6px;
  padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600;
  background:rgba(76,224,144,0.1);border:1px solid rgba(76,224,144,0.2);
  color:var(--green);margin-top:10px;
}}
.status-pill.inactive{{background:rgba(245,101,101,0.1);border-color:rgba(245,101,101,0.2);color:var(--red)}}
.status-dot{{width:6px;height:6px;border-radius:50%;background:currentColor;animation:pulse 2s infinite}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.35}}}}

.card-body{{padding:24px 28px 28px}}

.stats-grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:22px}}
.stat-box{{
  background:var(--card2);border-radius:14px;border:1px solid var(--border);
  padding:14px 16px;
}}
.stat-label{{font-size:10px;color:var(--text-2);font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;display:flex;align-items:center;gap:5px}}
.stat-label i{{font-size:13px}}
.stat-val{{font-size:20px;font-weight:700;color:var(--text-1);line-height:1}}
.stat-unit{{font-size:11px;color:var(--text-2);margin-top:3px}}

.usage-section{{margin-bottom:22px}}
.usage-header{{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:10px}}
.usage-title{{font-size:12px;font-weight:600;color:var(--text-2);display:flex;align-items:center;gap:6px}}
.usage-title i{{font-size:14px;color:var(--accent)}}
.usage-numbers{{font-size:12px;color:var(--text-2)}}
.usage-numbers span{{color:var(--text-1);font-weight:700}}
.progress-track{{height:10px;border-radius:6px;background:var(--card2);border:1px solid var(--border);overflow:hidden}}
.progress-fill{{height:100%;border-radius:6px;transition:width .6s ease;background:linear-gradient(90deg, {bar_color}, {bar_color}cc)}}
.progress-pct{{text-align:left;font-size:10.5px;color:var(--text-2);margin-top:5px}}

.info-rows{{margin-bottom:22px}}
.info-row{{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border);font-size:12.5px}}
.info-row:last-child{{border-bottom:none}}
.info-key{{color:var(--text-2);display:flex;align-items:center;gap:7px}}
.info-key i{{font-size:15px}}
.info-val{{color:var(--text-1);font-weight:600}}

.vless-section{{background:var(--card2);border-radius:14px;border:1px solid var(--border);padding:16px}}
.vless-label{{font-size:11px;font-weight:600;color:var(--text-2);margin-bottom:8px;display:flex;align-items:center;gap:6px}}
.vless-label i{{font-size:14px;color:var(--accent)}}
.vless-text{{font-family:ui-monospace,monospace;font-size:10px;color:#93c5fd;word-break:break-all;line-height:1.7;background:rgba(0,0,0,0.2);border-radius:8px;padding:10px 12px;margin-bottom:12px}}
.btn-row{{display:flex;gap:8px;flex-wrap:wrap}}
.btn{{font-family:inherit;font-size:12.5px;font-weight:600;border-radius:9px;padding:10px 16px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;border:none;transition:.15s;flex:1;justify-content:center}}
.btn-primary{{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;box-shadow:0 2px 12px var(--accent-glow)}}
.btn-primary:hover{{filter:brightness(1.1)}}
.btn-outline{{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.12);color:var(--text-1)}}
.btn-outline:hover{{background:rgba(255,255,255,0.08)}}
.btn i{{font-size:14px}}

.footer{{text-align:center;font-size:10.5px;color:var(--text-3);padding-top:18px}}

.days-left-warn{{color:var(--amber);}}
.days-left-danger{{color:var(--red);}}
.days-left-ok{{color:var(--green);}}
</style>
</head>
<body>
<div class="card">
  <div class="card-header">
    <div class="logo-row">
      <div class="logo-icon">T</div>
      <div class="logo-text">
        <div class="name">tryak Gateway</div>
        <div class="sub">پروفایل اشتراک</div>
      </div>
    </div>
    <div class="user-section">
      <div class="avatar"><i class="ti ti-user"></i></div>
      <div>
        <div class="user-name">{label}</div>
        <div class="user-id">{uid}</div>
        <div class="status-pill{'' if is_active else ' inactive'}">
          <span class="status-dot"></span>
          {status_text}
        </div>
      </div>
    </div>
  </div>

  <div class="card-body">

    <div class="stats-grid">
      <div class="stat-box">
        <div class="stat-label"><i class="ti ti-database"></i> کل مصرف</div>
        <div class="stat-val">{used_str.split()[0]}</div>
        <div class="stat-unit">{used_str.split()[-1] if len(used_str.split()) > 1 else ''} / {limit_str}</div>
      </div>
      <div class="stat-box">
        <div class="stat-label"><i class="ti ti-calendar-stats"></i> مصرف روزانه</div>
        <div class="stat-val">{daily_avg_str.split()[0]}</div>
        <div class="stat-unit">{daily_avg_str.split()[-1] if len(daily_avg_str.split()) > 1 else ''} در روز</div>
      </div>
    </div>

    <div class="usage-section">
      <div class="usage-header">
        <div class="usage-title"><i class="ti ti-chart-bar"></i> مصرف ترافیک</div>
        <div class="usage-numbers"><span>{used_str}</span> از {limit_str}</div>
      </div>
      <div class="progress-track">
        <div class="progress-fill" style="width:{pct if limit_bytes > 0 else 0}%"></div>
      </div>
      <div class="progress-pct">{pct}٪ مصرف شده</div>
    </div>

    <div class="info-rows">
      <div class="info-row">
        <span class="info-key"><i class="ti ti-calendar"></i> تاریخ انقضا</span>
        <span class="info-val">{'بدون انقضا ♾️' if never_expire else exp_str}</span>
      </div>
      <div class="info-row">
        <span class="info-key"><i class="ti ti-clock"></i> روزهای باقی‌مانده</span>
        <span class="info-val {'days-left-ok' if days_left > 30 or never_expire else 'days-left-warn' if days_left > 7 else 'days-left-danger'}">
          {'♾️ نامحدود' if never_expire else f'{days_left} روز'}
        </span>
      </div>
      <div class="info-row">
        <span class="info-key"><i class="ti ti-server"></i> سرور</span>
        <span class="info-val">{host}</span>
      </div>
      <div class="info-row">
        <span class="info-key"><i class="ti ti-shield-lock"></i> پروتکل</span>
        <span class="info-val">VLESS · TLS · WS</span>
      </div>
    </div>

    <div class="vless-section">
      <div class="vless-label"><i class="ti ti-link"></i> لینک اتصال (VLESS)</div>
      <div class="vless-text" id="vless-text">{vless}</div>
      <div class="btn-row">
        <button class="btn btn-primary" onclick="copyVless()"><i class="ti ti-copy"></i> کپی لینک</button>
        <button class="btn btn-outline" onclick="showQR()"><i class="ti ti-qrcode"></i> QR کد</button>
      </div>
      <div style="margin-top:14px;padding-top:14px;border-top:1px solid var(--border)">
        <div class="vless-label"><i class="ti ti-rss"></i> لینک اشتراک (Subscription)</div>
        <div class="vless-text" id="sub-url">{sub_url}</div>
        <div class="btn-row">
          <button class="btn btn-primary" onclick="copySub()"><i class="ti ti-copy"></i> کپی لینک ساب</button>
        </div>
      </div>
    </div>

    <div class="footer">tryak Gateway · اطلاعات لحظه‌ای</div>
  </div>
</div>

<script>
function copyVless(){{
  const text=document.getElementById('vless-text').textContent.trim();
  navigator.clipboard.writeText(text).then(()=>{{
    const btn=event.currentTarget;
    const orig=btn.innerHTML;
    btn.innerHTML='<i class="ti ti-check"></i> کپی شد!';
    setTimeout(()=>btn.innerHTML=orig, 2000);
  }});
}}
function copySub(){{
  const text=document.getElementById('sub-url').textContent.trim();
  navigator.clipboard.writeText(text).then(()=>{{
    const btn=event.currentTarget;
    const orig=btn.innerHTML;
    btn.innerHTML='<i class="ti ti-check"></i> کپی شد!';
    setTimeout(()=>btn.innerHTML=orig, 2000);
  }});
}}
function showQR(){{
  const text=document.getElementById('vless-text').textContent.trim();
  window.open('https://api.qrserver.com/v1/create-qr-code/?size=300x300&data='+encodeURIComponent(text),'_blank');
}}
</script>
</body>
</html>"""
    return HTMLResponse(content=sub_html)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    await ensure_default_link()
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return HTMLResponse(content=DASHBOARD_HTML)


@app.get("/test-ws", response_class=HTMLResponse)
async def test_ws_redirect():
    return HTMLResponse(content="<script>location.href='/dashboard';</script>")


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=CONFIG["port"],
        log_level="info",
        workers=1,
    )
