"""
LAN Chat App — Offline WhatsApp-style group & 1-on-1 chat over local Wi-Fi/Hotspot.
Features: PIN + device-IP binding, SQLite WAL mode, chunked 50 MB upload limit, and sent/delivered/read receipts.
Run: python lan_chat_app.py
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sqlite3
import sys
import time
import uuid
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

BASE_DIR = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "lan_chat.db"
UPLOAD_DIR = BASE_DIR / "lan_uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp"}
AUDIO_EXTENSIONS = {".webm", ".ogg", ".mp3", ".wav", ".m4a"}
MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
UPLOAD_RETENTION_DAYS = 7  # Auto-delete uploaded files older than 7 days
UPLOAD_CHUNK_SIZE = 1024 * 1024  # 1 MB
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{2,24}$")
PIN_RE = re.compile(r"^\d{4,8}$")
LOCALHOST_IPS = {"127.0.0.1", "::1"}

@asynccontextmanager
async def lifespan(_app: FastAPI):
    loop = asyncio.get_running_loop()
    prev_handler = loop.get_exception_handler()

    def _ignore_win_reset(cur_loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
        exc = context.get("exception")
        if isinstance(exc, ConnectionResetError) and getattr(exc, "winerror", None) == 10054:
            return
        if prev_handler is not None:
            prev_handler(cur_loop, context)
        else:
            cur_loop.default_exception_handler(context)

    loop.set_exception_handler(_ignore_win_reset)
    yield


app = FastAPI(title="LAN Chat App", lifespan=lifespan)
app.add_middleware(GZipMiddleware, minimum_size=500)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def parse_utc(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn


async def run_db(fn: Any, *args: Any, **kwargs: Any) -> Any:
    return await asyncio.to_thread(fn, *args, **kwargs)


def get_client_ip(conn_obj: Request | WebSocket) -> str:
    return conn_obj.client.host if conn_obj.client and conn_obj.client.host else ""


def hash_pin(pin: str, salt: str | None = None) -> str:
    use_salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), use_salt.encode("utf-8"), 100_000).hex()
    return f"{use_salt}${digest}"


def verify_pin(pin: str, stored: str) -> bool:
    if "$" not in stored:
        return False
    salt, _ = stored.split("$", 1)
    return hmac.compare_digest(hash_pin(pin, salt), stored)


def init_db() -> None:
    with get_db() as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        conn.execute("PRAGMA cache_size=-8000;")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                pin_hash TEXT NOT NULL DEFAULT '',
                token TEXT NOT NULL DEFAULT '',
                device_ip TEXT NOT NULL DEFAULT '',
                public_key TEXT NOT NULL DEFAULT '',
                last_seen TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS rooms (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                is_group INTEGER NOT NULL DEFAULT 1,
                created_by TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                content TEXT NOT NULL DEFAULT '',
                msg_type TEXT NOT NULL DEFAULT 'text',
                file_name TEXT,
                file_url TEXT,
                status TEXT NOT NULL DEFAULT 'sent',
                read_at TEXT,
                edited_at TEXT,
                deleted_for_all INTEGER NOT NULL DEFAULT 0,
                reply_to_id INTEGER,
                reply_sender TEXT,
                reply_preview TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (room_id) REFERENCES rooms(id)
            );

            CREATE TABLE IF NOT EXISTS hidden_messages (
                username TEXT NOT NULL,
                message_id INTEGER NOT NULL,
                PRIMARY KEY (username, message_id)
            );

            CREATE TABLE IF NOT EXISTS cleared_rooms (
                username TEXT NOT NULL,
                room_id TEXT NOT NULL,
                cleared_after_id INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (username, room_id)
            );

            CREATE TABLE IF NOT EXISTS reactions (
                message_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                emoji TEXT NOT NULL,
                PRIMARY KEY (message_id, username)
            );

            CREATE TABLE IF NOT EXISTS group_keys (
                room_id TEXT NOT NULL,
                username TEXT NOT NULL,
                sender TEXT NOT NULL,
                wrapped_key TEXT NOT NULL,
                PRIMARY KEY (room_id, username)
            );
            """
        )
        # Safe migrations for existing databases
        user_cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "pin_hash" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN pin_hash TEXT NOT NULL DEFAULT ''")
        if "token" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN token TEXT NOT NULL DEFAULT ''")
        if "device_ip" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN device_ip TEXT NOT NULL DEFAULT ''")
        if "public_key" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN public_key TEXT NOT NULL DEFAULT ''")

        room_cols = {r["name"] for r in conn.execute("PRAGMA table_info(rooms)").fetchall()}
        if "created_by" not in room_cols:
            conn.execute("ALTER TABLE rooms ADD COLUMN created_by TEXT NOT NULL DEFAULT ''")

        msg_cols = {r["name"] for r in conn.execute("PRAGMA table_info(messages)").fetchall()}
        if "status" not in msg_cols:
            conn.execute("ALTER TABLE messages ADD COLUMN status TEXT NOT NULL DEFAULT 'sent'")
        if "read_at" not in msg_cols:
            conn.execute("ALTER TABLE messages ADD COLUMN read_at TEXT")
        if "edited_at" not in msg_cols:
            conn.execute("ALTER TABLE messages ADD COLUMN edited_at TEXT")
        if "deleted_for_all" not in msg_cols:
            conn.execute("ALTER TABLE messages ADD COLUMN deleted_for_all INTEGER NOT NULL DEFAULT 0")
        if "reply_to_id" not in msg_cols:
            conn.execute("ALTER TABLE messages ADD COLUMN reply_to_id INTEGER")
        if "reply_sender" not in msg_cols:
            conn.execute("ALTER TABLE messages ADD COLUMN reply_sender TEXT")
        if "reply_preview" not in msg_cols:
            conn.execute("ALTER TABLE messages ADD COLUMN reply_preview TEXT")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_room_id ON messages(room_id, id DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_room_sender_status ON messages(room_id, sender, status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_reactions_msg ON reactions(message_id)")

        conn.execute(
            "INSERT OR IGNORE INTO rooms (id, name, is_group, created_at) VALUES (?, ?, 1, ?)",
            ("group:general", "General", utc_now_iso()),
        )
        conn.commit()


init_db()


def cleanup_old_uploads(days: int = UPLOAD_RETENTION_DAYS) -> int:
    if days <= 0 or not UPLOAD_DIR.exists():
        return 0
    cutoff = time.time() - (days * 86400)
    removed = 0
    for f in UPLOAD_DIR.iterdir():
        if f.is_file() and f.stat().st_mtime < cutoff:
            try:
                f.unlink()
                removed += 1
            except OSError:
                pass
    return removed


_pruned = cleanup_old_uploads()
if _pruned:
    print(f"  Cleaned up {_pruned} expired upload(s) older than {UPLOAD_RETENTION_DAYS} days.")


class AuthRequest(BaseModel):
    username: str
    pin: str


class CreateGroupRequest(BaseModel):
    name: str


class PublicKeyRequest(BaseModel):
    public_key: str


class GroupKeyEntry(BaseModel):
    username: str
    wrapped_key: str


class GroupKeysRequest(BaseModel):
    keys: list[GroupKeyEntry]


def verify_token(token: str | None, request_ip: str) -> str:
    if not token:
        raise HTTPException(status_code=401, detail="Missing auth token.")
    with get_db() as conn:
        row = conn.execute(
            "SELECT username, device_ip FROM users WHERE token = ?", (token,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid or expired session.")
    if request_ip not in LOCALHOST_IPS and row["device_ip"] and row["device_ip"] != request_ip:
        raise HTTPException(status_code=401, detail="Device IP changed. Please re-enter your PIN.")
    return row["username"]


class ConnectionManager:
    def __init__(self) -> None:
        self.active: dict[str, set[WebSocket]] = {}

    async def connect(self, username: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active.setdefault(username, set()).add(websocket)
        with get_db() as conn:
            conn.execute("UPDATE users SET last_seen = ? WHERE username = ?", (utc_now_iso(), username))
            pending_rows = conn.execute(
                """
                SELECT DISTINCT room_id, sender FROM messages
                WHERE room_id LIKE 'dm:%'
                  AND (room_id LIKE ? OR room_id LIKE ?)
                  AND sender != ?
                  AND status = 'sent'
                """,
                (f"dm:{username}:%", f"dm:%:{username}", username),
            ).fetchall()
            if pending_rows:
                conn.execute(
                    """
                    UPDATE messages SET status = 'delivered'
                    WHERE room_id LIKE 'dm:%'
                      AND (room_id LIKE ? OR room_id LIKE ?)
                      AND sender != ?
                      AND status = 'sent'
                    """,
                    (f"dm:{username}:%", f"dm:%:{username}", username),
                )
            conn.commit()

        for row in pending_rows:
            await self.send_to_user(
                row["sender"],
                {"type": "receipt", "room_id": row["room_id"], "status": "delivered"},
            )
        await self.broadcast_presence()

    def disconnect(self, username: str, websocket: WebSocket) -> None:
        sockets = self.active.get(username)
        if not sockets:
            return
        sockets.discard(websocket)
        if not sockets:
            self.active.pop(username, None)
            with get_db() as conn:
                conn.execute(
                    "UPDATE users SET last_seen = ? WHERE username = ?",
                    (utc_now_iso(), username),
                )
                conn.commit()

    async def _send_one(self, username: str, ws: WebSocket, payload: dict[str, Any]) -> None:
        try:
            await asyncio.wait_for(ws.send_json(payload), timeout=2.0)
        except Exception:
            self.disconnect(username, ws)

    async def send_to_user(self, username: str, payload: dict[str, Any]) -> None:
        sockets = list(self.active.get(username, set()))
        if not sockets:
            return
        await asyncio.gather(
            *(self._send_one(username, ws, payload) for ws in sockets),
            return_exceptions=True,
        )

    async def broadcast_all(self, payload: dict[str, Any]) -> None:
        tasks = [
            self._send_one(username, ws, payload)
            for username, sockets in list(self.active.items())
            for ws in list(sockets)
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def broadcast_presence(self) -> None:
        def _fetch_users() -> list[sqlite3.Row]:
            with get_db() as conn:
                return conn.execute(
                    "SELECT username, public_key, last_seen FROM users ORDER BY username"
                ).fetchall()

        rows = await run_db(_fetch_users)
        users = [
            {
                "username": row["username"],
                "online": row["username"] in self.active,
                "public_key": row["public_key"],
                "last_seen": row["last_seen"],
            }
            for row in rows
        ]
        await self.broadcast_all({"type": "presence", "users": users})


manager = ConnectionManager()


def dm_room_id(user_a: str, user_b: str) -> str:
    pair = sorted([user_a.strip(), user_b.strip()])
    return f"dm:{pair[0]}:{pair[1]}"


def ensure_dm_room(user_a: str, user_b: str) -> str:
    room_id = dm_room_id(user_a, user_b)
    with get_db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO rooms (id, name, is_group, created_at) VALUES (?, ?, 0, ?)",
            (room_id, f"{user_a} & {user_b}", utc_now_iso()),
        )
        conn.commit()
    return room_id


def room_targets(room_id: str) -> list[str] | None:
    if room_id.startswith("dm:"):
        parts = room_id.split(":", 2)
        if len(parts) == 3:
            return [parts[1], parts[2]]
    return None


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse(OFFLINE_HTML, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})


@app.get("/manifest.json")
async def pwa_manifest() -> JSONResponse:
    return JSONResponse(
        {
            "name": "LAN Chat",
            "short_name": "LAN Chat",
            "description": "Zero-data offline local Wi-Fi chat",
            "start_url": "/",
            "display": "standalone",
            "background_color": "#0b141a",
            "theme_color": "#00a884",
            "icons": [
                {
                    "src": "/icon.svg",
                    "sizes": "any",
                    "type": "image/svg+xml",
                    "purpose": "any maskable",
                }
            ],
        }
    )


@app.get("/icon.svg")
async def pwa_icon() -> Response:
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">'
        '<rect width="128" height="128" rx="28" fill="#00a884"/>'
        '<path d="M32 38h64a10 10 0 0 1 10 10v34a10 10 0 0 1-10 10H54l-18 14v-14h-4a10 10 0 0 1-10-10V48a10 10 0 0 1 10-10z" fill="#0b141a"/>'
        '<circle cx="48" cy="65" r="5" fill="#00a884"/>'
        '<circle cx="64" cy="65" r="5" fill="#00a884"/>'
        '<circle cx="80" cy="65" r="5" fill="#00a884"/>'
        "</svg>"
    )
    return Response(content=svg, media_type="image/svg+xml")


@app.get("/sw.js")
async def pwa_service_worker() -> Response:
    sw_js = '''const CACHE_NAME = "lan-chat-shell-v12";
const MEDIA_CACHE = "lan-chat-media-v1";
const SHELL_URLS = ["/", "/manifest.json", "/icon.svg"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_URLS)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME && k !== MEDIA_CACHE).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== "GET" || url.pathname.startsWith("/api/")) {
    return;
  }
  if (url.pathname.startsWith("/uploads/")) {
    event.respondWith(
      caches.open(MEDIA_CACHE).then(async (cache) => {
        const hit = await cache.match(event.request);
        if (hit) return hit;
        const resp = await fetch(event.request);
        if (resp.ok) cache.put(event.request, resp.clone());
        return resp;
      })
    );
    return;
  }
  // Network-first for HTML shell so updates show immediately on LAN, with full offline fallback
  event.respondWith(
    caches.open(CACHE_NAME).then(async (cache) => {
      try {
        const resp = await fetch(event.request, { cache: "no-store" });
        if (resp.ok) cache.put(event.request, resp.clone());
        return resp;
      } catch {
        return (await cache.match(event.request)) || Response.error();
      }
    })
  );
});
'''
    return Response(
        content=sw_js,
        media_type="application/javascript",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


@app.get("/api/network-info")
async def network_info(request: Request) -> dict[str, Any]:
    scheme = request.url.scheme or "http"
    port = request.url.port or (443 if scheme == "https" else 8000)
    ips = get_all_lan_ips()
    urls = [f"{scheme}://{ip}:{port}" for ip in ips]
    return {"urls": urls, "primary_url": urls[0], "scheme": scheme}


@app.get("/api/qr.svg")
async def qr_svg(url: str = Query(...)) -> Response:
    try:
        import io
        import qrcode  # type: ignore
        import qrcode.image.svg  # type: ignore

        img = qrcode.make(url, image_factory=qrcode.image.svg.SvgPathImage, border=2)
        buf = io.BytesIO()
        img.save(buf)
        return Response(content=buf.getvalue(), media_type="image/svg+xml")
    except Exception:
        raise HTTPException(status_code=501, detail="Install 'qrcode' to render SVG QR codes.")


@app.post("/api/auth")
async def authenticate(req: AuthRequest, request: Request) -> dict[str, Any]:
    username = req.username.strip()
    pin = req.pin.strip()
    if not USERNAME_RE.match(username):
        raise HTTPException(
            status_code=400,
            detail="Username must be 2-24 characters (letters, numbers, _ or -).",
        )
    if not PIN_RE.match(pin):
        raise HTTPException(status_code=400, detail="PIN must be 4-8 digits.")

    ip = get_client_ip(request)
    is_local = ip in LOCALHOST_IPS
    token = secrets.token_urlsafe(24)
    now = utc_now_iso()

    with get_db() as conn:
        existing = conn.execute(
            "SELECT username, pin_hash, device_ip FROM users WHERE username = ?", (username,)
        ).fetchone()

        if not is_local and ip:
            ip_owner = conn.execute(
                "SELECT username FROM users WHERE device_ip = ? AND username != ?",
                (ip, username),
            ).fetchone()
            if ip_owner:
                raise HTTPException(
                    status_code=409,
                    detail=f"This device IP ({ip}) is already registered as '{ip_owner['username']}'.",
                )

        if existing and existing["pin_hash"]:
            if not verify_pin(pin, existing["pin_hash"]):
                raise HTTPException(status_code=401, detail="Incorrect PIN for this username.")
            if is_local:
                conn.execute(
                    "UPDATE users SET token = ?, last_seen = ? WHERE username = ?",
                    (token, now, username),
                )
            else:
                # Correct PIN allows updating device_ip if the user's DHCP IP changed
                conn.execute(
                    "UPDATE users SET token = ?, device_ip = ?, last_seen = ? WHERE username = ?",
                    (token, ip, now, username),
                )
            is_new = False
        else:
            bound_ip = "" if is_local else ip
            conn.execute(
                """
                INSERT INTO users (username, pin_hash, token, device_ip, last_seen)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    pin_hash = excluded.pin_hash,
                    token = excluded.token,
                    device_ip = excluded.device_ip,
                    last_seen = excluded.last_seen
                """,
                (username, hash_pin(pin), token, bound_ip, now),
            )
            is_new = True
        conn.commit()
    return {"username": username, "token": token, "is_new": is_new}


@app.post("/api/keys")
async def publish_public_key(
    req: PublicKeyRequest,
    request: Request,
    x_auth_token: str | None = Header(default=None),
) -> dict[str, Any]:
    username = verify_token(x_auth_token, get_client_ip(request))
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET public_key = ? WHERE username = ?",
            (req.public_key.strip(), username),
        )
        conn.commit()
    await manager.broadcast_presence()
    return {"status": "ok"}


@app.get("/api/rooms")
async def list_rooms(
    request: Request,
    x_auth_token: str | None = Header(default=None),
) -> dict[str, Any]:
    verify_token(x_auth_token, get_client_ip(request))
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, name, is_group, created_by, created_at FROM rooms WHERE is_group = 1 ORDER BY created_at ASC"
        ).fetchall()
    return {"rooms": [dict(r) for r in rows]}


@app.post("/api/rooms")
async def create_group(
    req: CreateGroupRequest,
    request: Request,
    x_auth_token: str | None = Header(default=None),
) -> dict[str, Any]:
    username = verify_token(x_auth_token, get_client_ip(request))
    name = req.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Group name is required.")
    room_id = f"group:{uuid.uuid4().hex[:8]}"
    created_at = utc_now_iso()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO rooms (id, name, is_group, created_by, created_at) VALUES (?, ?, 1, ?, ?)",
            (room_id, name, username, created_at),
        )
        conn.commit()
    room = {"id": room_id, "name": name, "is_group": 1, "created_by": username, "created_at": created_at}
    await manager.broadcast_all({"type": "room_created", "room": room})
    return {"room": room}


@app.get("/api/rooms/{room_id}/keys")
async def get_my_group_key(
    room_id: str,
    request: Request,
    x_auth_token: str | None = Header(default=None),
) -> dict[str, Any]:
    username = verify_token(x_auth_token, get_client_ip(request))
    with get_db() as conn:
        mine = conn.execute(
            "SELECT sender, wrapped_key FROM group_keys WHERE room_id = ? AND username = ?",
            (room_id, username),
        ).fetchone()
        holders = [
            r["username"]
            for r in conn.execute(
                "SELECT username FROM group_keys WHERE room_id = ?", (room_id,)
            ).fetchall()
        ]
    return {
        "my_key": dict(mine) if mine else None,
        "holders": holders,
    }


@app.post("/api/rooms/{room_id}/keys")
async def publish_group_keys(
    room_id: str,
    req: GroupKeysRequest,
    request: Request,
    x_auth_token: str | None = Header(default=None),
) -> dict[str, Any]:
    sender = verify_token(x_auth_token, get_client_ip(request))
    if not room_id.startswith("group:"):
        raise HTTPException(status_code=400, detail="Group keys only apply to group rooms.")
    with get_db() as conn:
        for entry in req.keys:
            conn.execute(
                """
                INSERT INTO group_keys (room_id, username, sender, wrapped_key)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(room_id, username) DO NOTHING
                """,
                (room_id, entry.username, sender, entry.wrapped_key),
            )
        conn.commit()
    await manager.broadcast_all({"type": "group_keys_updated", "room_id": room_id})
    return {"status": "ok"}


@app.delete("/api/rooms/{room_id}")
async def clear_or_delete_room(
    room_id: str,
    request: Request,
    delete_group: bool = Query(default=False),
    x_auth_token: str | None = Header(default=None),
) -> dict[str, Any]:
    username = verify_token(x_auth_token, get_client_ip(request))
    targets = room_targets(room_id)
    if targets is not None and username not in targets:
        raise HTTPException(status_code=403, detail="Access denied to this room.")

    with get_db() as conn:
        room = conn.execute("SELECT id, is_group, created_by FROM rooms WHERE id = ?", (room_id,)).fetchone()
        if delete_group:
            if not room or not room["is_group"] or room_id == "group:general":
                raise HTTPException(status_code=400, detail="Cannot delete this room.")
            if room["created_by"] and room["created_by"] != username:
                raise HTTPException(status_code=403, detail="Only the group creator can delete the group.")
            conn.execute("DELETE FROM messages WHERE room_id = ?", (room_id,))
            conn.execute("DELETE FROM cleared_rooms WHERE room_id = ?", (room_id,))
            conn.execute("DELETE FROM rooms WHERE id = ?", (room_id,))
            conn.commit()
            await manager.broadcast_all({"type": "room_deleted", "room_id": room_id})
            return {"action": "deleted", "room_id": room_id}

        max_row = conn.execute(
            "SELECT COALESCE(MAX(id), 0) AS max_id FROM messages WHERE room_id = ?", (room_id,)
        ).fetchone()
        max_id = int(max_row["max_id"]) if max_row else 0
        conn.execute(
            """
            INSERT INTO cleared_rooms (username, room_id, cleared_after_id)
            VALUES (?, ?, ?)
            ON CONFLICT(username, room_id) DO UPDATE SET cleared_after_id = excluded.cleared_after_id
            """,
            (username, room_id, max_id),
        )
        conn.commit()
    return {"action": "cleared", "room_id": room_id}


@app.get("/api/rooms/{room_id}/messages")
async def get_messages(
    room_id: str,
    request: Request,
    limit: int = 50,
    before_id: int | None = Query(default=None),
    after_id: int | None = Query(default=None),
    x_auth_token: str | None = Header(default=None),
) -> dict[str, Any]:
    username = verify_token(x_auth_token, get_client_ip(request))
    targets = room_targets(room_id)
    if targets is not None and username not in targets:
        raise HTTPException(status_code=403, detail="Access denied to this DM room.")

    with get_db() as conn:
        cleared = conn.execute(
            "SELECT cleared_after_id FROM cleared_rooms WHERE username = ? AND room_id = ?",
            (username, room_id),
        ).fetchone()
        min_id = int(cleared["cleared_after_id"]) if cleared else 0

        effective_min = max(min_id, after_id) if after_id is not None else min_id
        upper_clause = "AND m.id < ?" if before_id is not None else ""
        params: list[Any] = [room_id, effective_min]
        if before_id is not None:
            params.append(before_id)
        params.extend([username, limit])
        rows = conn.execute(
            f"""
            SELECT m.id, m.room_id, m.sender, m.content, m.msg_type, m.file_name, m.file_url,
                   m.status, m.read_at, m.edited_at, m.deleted_for_all,
                   m.reply_to_id, m.reply_sender, m.reply_preview, m.created_at
            FROM messages m
            WHERE m.room_id = ?
              AND m.id > ?
              {upper_clause}
              AND NOT EXISTS (
                  SELECT 1 FROM hidden_messages h
                  WHERE h.username = ? AND h.message_id = m.id
              )
            ORDER BY m.id DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
        messages = [dict(r) for r in reversed(rows)]
        if messages:
            ids = [m["id"] for m in messages]
            placeholders = ",".join("?" for _ in ids)
            r_rows = conn.execute(
                f"SELECT message_id, emoji, COUNT(*) AS cnt FROM reactions WHERE message_id IN ({placeholders}) GROUP BY message_id, emoji",
                ids,
            ).fetchall()
            rx_map: dict[int, dict[str, int]] = {}
            for rr in r_rows:
                rx_map.setdefault(rr["message_id"], {})[rr["emoji"]] = rr["cnt"]
            for m in messages:
                m["reactions"] = rx_map.get(m["id"], {})
    return {"messages": messages}


@app.post("/api/upload")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    e2ee: bool = Form(default=False),
    x_auth_token: str | None = Header(default=None),
) -> dict[str, Any]:
    verify_token(x_auth_token, get_client_ip(request))
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename.")

    original_name = os.path.basename(file.filename)
    ext = Path(original_name).suffix.lower()
    suffix = ".enc" if e2ee else ""
    stored_name = f"{uuid.uuid4().hex[:12]}_{original_name}{suffix}"
    dest = UPLOAD_DIR / stored_name

    total_bytes = 0
    try:
        with dest.open("wb") as out:
            while True:
                chunk = await file.read(UPLOAD_CHUNK_SIZE)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.",
                    )
                out.write(chunk)
    except HTTPException:
        dest.unlink(missing_ok=True)
        raise

    if ext in IMAGE_EXTENSIONS:
        msg_type = "image"
    elif ext in AUDIO_EXTENSIONS:
        msg_type = "audio"
    else:
        msg_type = "file"
    return {
        "file_name": original_name,
        "file_url": f"/uploads/{stored_name}",
        "msg_type": msg_type,
    }


@app.get("/uploads/{stored_name}")
async def download_file(stored_name: str, inline: bool = Query(default=False)) -> FileResponse:
    safe_name = os.path.basename(stored_name)
    path = UPLOAD_DIR / safe_name
    if not path.is_file():
        raise HTTPException(status_code=404, detail="File not found.")
    orig = safe_name.split("_", 1)[-1]
    headers = {"Cache-Control": "public, max-age=604800, immutable"}
    if inline:
        return FileResponse(path, media_type="application/pdf" if orig.lower().endswith(".pdf") else None, headers=headers)
    return FileResponse(path, filename=orig, headers=headers)


@app.websocket("/ws/{username}")
async def websocket_endpoint(
    websocket: WebSocket,
    username: str,
    token: str = Query(default=""),
) -> None:
    clean_user = username.strip()
    if not clean_user or not token:
        await websocket.close(code=1008)
        return

    ip = get_client_ip(websocket)
    is_local = ip in LOCALHOST_IPS
    with get_db() as conn:
        row = conn.execute(
            "SELECT username, device_ip FROM users WHERE username = ? AND token = ?",
            (clean_user, token),
        ).fetchone()
    if not row:
        await websocket.close(code=1008)
        return
    if not is_local and row["device_ip"] and row["device_ip"] != ip:
        await websocket.close(code=1008)
        return

    await manager.connect(clean_user, websocket)
    last_typing_sent: dict[str, float] = {}
    try:
        while True:
            raw = await websocket.receive_text()
            data = json.loads(raw)
            event_type = data.get("type")

            if event_type == "webrtc_signal":
                target = str(data.get("target", "")).strip()
                signal_type = str(data.get("signal_type", ""))
                if not target or not signal_type:
                    continue
                if signal_type == "offer" and target not in manager.active:
                    await manager.send_to_user(
                        clean_user,
                        {"type": "error", "detail": f"{target} is currently offline."},
                    )
                    continue
                await manager.send_to_user(
                    target,
                    {
                        "type": "webrtc_signal",
                        "from": clean_user,
                        "signal_type": signal_type,
                        "video": bool(data.get("video", False)),
                        "payload": data.get("payload"),
                    },
                )

            elif event_type == "typing":
                room_id = data.get("room_id", "group:general")
                is_typing = bool(data.get("is_typing", False))
                now_mono = time.monotonic()
                if is_typing and (now_mono - last_typing_sent.get(room_id, 0.0)) < 0.8:
                    continue
                if is_typing:
                    last_typing_sent[room_id] = now_mono
                payload = {
                    "type": "typing",
                    "room_id": room_id,
                    "sender": clean_user,
                    "is_typing": is_typing,
                }
                targets = room_targets(room_id)
                if targets is None:
                    await manager.broadcast_all(payload)
                elif clean_user in targets:
                    for target in targets:
                        await manager.send_to_user(target, payload)

            elif event_type == "mark_read":
                room_id = str(data.get("room_id", ""))
                if not room_id:
                    continue
                targets = room_targets(room_id)
                if targets is not None and clean_user not in targets:
                    continue

                now_read = utc_now_iso()
                def _do_mark_read() -> int:
                    with get_db() as conn:
                        cur = conn.execute(
                            """
                            UPDATE messages
                            SET status = 'read', read_at = COALESCE(read_at, ?)
                            WHERE room_id = ? AND sender != ? AND status != 'read'
                            """,
                            (now_read, room_id, clean_user),
                        )
                        conn.commit()
                        return cur.rowcount

                changed = await run_db(_do_mark_read)

                if changed > 0:
                    receipt = {"type": "receipt", "room_id": room_id, "status": "read"}
                    if targets is None:
                        await manager.broadcast_all(receipt)
                    else:
                        for target in targets:
                            await manager.send_to_user(target, receipt)

            elif event_type == "edit_message":
                msg_id = int(data.get("id", 0))
                new_content = str(data.get("content", "")).strip()
                if not msg_id or not new_content:
                    continue

                with get_db() as conn:
                    row = conn.execute(
                        "SELECT id, room_id, sender, msg_type, read_at, deleted_for_all, created_at FROM messages WHERE id = ?",
                        (msg_id,),
                    ).fetchone()
                    if not row or row["sender"] != clean_user or row["deleted_for_all"] or row["msg_type"] != "text":
                        await manager.send_to_user(clean_user, {"type": "error", "detail": "Message cannot be edited."})
                        continue

                    now_dt = datetime.now(timezone.utc)
                    created_dt = parse_utc(row["created_at"])
                    read_dt = parse_utc(row["read_at"])
                    if created_dt and (now_dt - created_dt).total_seconds() > 900:
                        await manager.send_to_user(clean_user, {"type": "error", "detail": "Edit window expired (15 min limit)."})
                        continue
                    if read_dt and (now_dt - read_dt).total_seconds() > 60:
                        await manager.send_to_user(clean_user, {"type": "error", "detail": "Cannot edit: message was seen over 1 min ago."})
                        continue

                    edited_at = utc_now_iso()
                    conn.execute(
                        "UPDATE messages SET content = ?, edited_at = ? WHERE id = ?",
                        (new_content, edited_at, msg_id),
                    )
                    conn.commit()

                ev = {"type": "message_edited", "room_id": row["room_id"], "id": msg_id, "content": new_content, "edited_at": edited_at}
                targets = room_targets(row["room_id"])
                if targets is None:
                    await manager.broadcast_all(ev)
                else:
                    for target in targets:
                        await manager.send_to_user(target, ev)

            elif event_type == "delete_message":
                msg_id = int(data.get("id", 0))
                scope = data.get("scope", "me")
                if not msg_id:
                    continue

                with get_db() as conn:
                    row = conn.execute(
                        "SELECT id, room_id, sender, file_url, read_at, deleted_for_all, created_at FROM messages WHERE id = ?",
                        (msg_id,),
                    ).fetchone()
                    if not row:
                        continue
                    targets = room_targets(row["room_id"])
                    if targets is not None and clean_user not in targets:
                        continue

                    if scope == "everyone":
                        if row["sender"] != clean_user or row["deleted_for_all"]:
                            await manager.send_to_user(clean_user, {"type": "error", "detail": "Cannot delete for everyone."})
                            continue
                        now_dt = datetime.now(timezone.utc)
                        created_dt = parse_utc(row["created_at"])
                        read_dt = parse_utc(row["read_at"])
                        if created_dt and (now_dt - created_dt).total_seconds() > 3600:
                            await manager.send_to_user(clean_user, {"type": "error", "detail": "Delete for everyone expired (1 hour limit)."})
                            continue
                        if read_dt and (now_dt - read_dt).total_seconds() > 300:
                            await manager.send_to_user(clean_user, {"type": "error", "detail": "Cannot delete for everyone: seen over 5 min ago."})
                            continue

                        if row["file_url"] and row["file_url"].startswith("/uploads/"):
                            file_path = UPLOAD_DIR / os.path.basename(row["file_url"])
                            file_path.unlink(missing_ok=True)
                        conn.execute(
                            "UPDATE messages SET deleted_for_all = 1, content = '', file_name = NULL, file_url = NULL WHERE id = ?",
                            (msg_id,),
                        )
                        conn.commit()
                        ev = {"type": "message_deleted", "room_id": row["room_id"], "id": msg_id}
                        if targets is None:
                            await manager.broadcast_all(ev)
                        else:
                            for target in targets:
                                await manager.send_to_user(target, ev)
                    else:
                        conn.execute(
                            "INSERT OR IGNORE INTO hidden_messages (username, message_id) VALUES (?, ?)",
                            (clean_user, msg_id),
                        )
                        conn.commit()
                        await manager.send_to_user(
                            clean_user,
                            {"type": "message_hidden", "room_id": row["room_id"], "id": msg_id},
                        )

            elif event_type == "react":
                msg_id = int(data.get("id", 0))
                emoji = str(data.get("emoji", "")).strip()
                if not msg_id or not emoji or len(emoji) > 8:
                    continue
                with get_db() as conn:
                    row = conn.execute(
                        "SELECT id, room_id, deleted_for_all FROM messages WHERE id = ?", (msg_id,)
                    ).fetchone()
                    if not row or row["deleted_for_all"]:
                        continue
                    targets = room_targets(row["room_id"])
                    if targets is not None and clean_user not in targets:
                        continue
                    existing_rx = conn.execute(
                        "SELECT emoji FROM reactions WHERE message_id = ? AND username = ?",
                        (msg_id, clean_user),
                    ).fetchone()
                    if existing_rx and existing_rx["emoji"] == emoji:
                        conn.execute(
                            "DELETE FROM reactions WHERE message_id = ? AND username = ?",
                            (msg_id, clean_user),
                        )
                    else:
                        conn.execute(
                            "INSERT OR REPLACE INTO reactions (message_id, username, emoji) VALUES (?, ?, ?)",
                            (msg_id, clean_user, emoji),
                        )
                    conn.commit()
                    r_rows = conn.execute(
                        "SELECT emoji, COUNT(*) AS cnt FROM reactions WHERE message_id = ? GROUP BY emoji",
                        (msg_id,),
                    ).fetchall()
                    counts = {rr["emoji"]: rr["cnt"] for rr in r_rows}

                ev = {"type": "reaction_updated", "room_id": row["room_id"], "id": msg_id, "reactions": counts}
                if targets is None:
                    await manager.broadcast_all(ev)
                else:
                    for target in targets:
                        await manager.send_to_user(target, ev)

            elif event_type == "message":
                room_id = data.get("room_id", "group:general")
                peer = data.get("peer")
                if peer and room_id.startswith("dm:"):
                    room_id = ensure_dm_room(clean_user, peer)

                targets = room_targets(room_id)
                if targets is not None and clean_user not in targets:
                    continue

                content = str(data.get("content", "")).strip()
                msg_type = str(data.get("msg_type", "text"))
                file_name = data.get("file_name")
                file_url = data.get("file_url")
                reply_to_id = data.get("reply_to_id")
                reply_sender = data.get("reply_sender")
                reply_preview = data.get("reply_preview")
                if not content and not file_url:
                    continue

                if targets is not None:
                    other_online = any(t != clean_user and t in manager.active for t in targets)
                else:
                    other_online = any(u != clean_user for u in manager.active)
                initial_status = "delivered" if other_online else "sent"

                created_at = utc_now_iso()
                def _do_insert_msg() -> int:
                    with get_db() as conn:
                        cur = conn.execute(
                            """
                            INSERT INTO messages (
                                room_id, sender, content, msg_type, file_name, file_url,
                                status, reply_to_id, reply_sender, reply_preview, created_at
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                room_id, clean_user, content, msg_type, file_name, file_url,
                                initial_status, reply_to_id, reply_sender, reply_preview, created_at,
                            ),
                        )
                        conn.commit()
                        return int(cur.lastrowid)

                msg_id = await run_db(_do_insert_msg)

                payload = {
                    "type": "message",
                    "message": {
                        "id": msg_id,
                        "room_id": room_id,
                        "sender": clean_user,
                        "content": content,
                        "msg_type": msg_type,
                        "file_name": file_name,
                        "file_url": file_url,
                        "status": initial_status,
                        "reply_to_id": reply_to_id,
                        "reply_sender": reply_sender,
                        "reply_preview": reply_preview,
                        "reactions": {},
                        "created_at": created_at,
                    },
                }

                if targets is None:
                    await manager.broadcast_all(payload)
                else:
                    for target in targets:
                        await manager.send_to_user(target, payload)
    except WebSocketDisconnect:
        manager.disconnect(clean_user, websocket)
        await manager.broadcast_presence()


def get_all_lan_ips() -> list[str]:
    ips: list[str] = []
    # Probe default outbound route (works on most LANs & hotspots without internet)
    for target in (("10.255.255.255", 1), ("192.168.43.1", 1), ("192.168.1.1", 1)):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(target)
            ip = sock.getsockname()[0]
            sock.close()
            if ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
        except Exception:
            pass
    # Fallback: enumerate hostname addresses
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips or ["127.0.0.1"]


def get_lan_ip() -> str:
    return get_all_lan_ips()[0]


OFFLINE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
  <title>LAN Chat</title>
  <link rel="manifest" href="/manifest.json" />
  <meta name="theme-color" content="#00a884" />
  <meta name="apple-mobile-web-app-capable" content="yes" />
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
  <style>
    :root {
      --bg: #f4f6fb;
      --panel: #ffffff;
      --panel-alt: #f1f3f8;
      --border: #e5e8f0;
      --accent: #7c3aed;
      --accent-dark: #6d28d9;
      --accent-soft: #ede9fe;
      --dark-card: #262938;
      --text: #1e293b;
      --muted: #64748b;
      --read-blue: #38bdf8;
      --error: #ef4444;
      --online: #22c55e;
      --incoming: #eef1f7;
      --outgoing: #7c3aed;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; }
    html, body { width: 100%; height: 100%; background: var(--bg); color: var(--text); overflow: hidden; overscroll-behavior-y: auto; }
    body { display: flex; }
    button { cursor: pointer; border: none; background: none; color: inherit; }

    /* Login Overlay */
    #login-screen {
      position: fixed; inset: 0; background: linear-gradient(135deg, #f4f6fb 0%, #ede9fe 100%);
      display: flex; align-items: center; justify-content: center; z-index: 50; padding: 16px;
    }
    .login-card {
      background: var(--panel); border: 1px solid var(--border); border-radius: 20px;
      padding: 30px; width: 100%; max-width: 390px; display: flex; flex-direction: column; gap: 12px;
      box-shadow: 0 20px 50px rgba(124, 58, 237, 0.12);
    }
    .login-card h1 { font-size: 1.45rem; color: var(--accent); font-weight: 700; }
    .login-card p { font-size: 0.9rem; color: var(--muted); line-height: 1.45; }
    .login-card input {
      padding: 12px 14px; border-radius: 12px; border: 1px solid var(--border);
      background: var(--panel-alt); color: var(--text); font-size: 0.96rem; outline: none;
    }
    .login-card input:focus { border-color: var(--accent); background: #fff; }
    .login-error { color: var(--error); font-size: 0.85rem; min-height: 18px; }
    .primary-btn {
      background: linear-gradient(135deg, #8b5cf6, #7c3aed); color: #ffffff; font-weight: 600;
      padding: 11px 18px; border-radius: 12px; font-size: 0.94rem;
      box-shadow: 0 4px 12px rgba(124, 58, 237, 0.25);
    }

    /* 3-Column App Shell */
    #app { display: none; width: 100%; height: 100%; overflow: hidden; background: var(--panel); }

    /* Left Sidebar */
    .sidebar {
      width: 320px; background: var(--bg); border-right: 1px solid var(--border);
      display: flex; flex-direction: column; flex-shrink: 0;
    }
    .sidebar-top-icons {
      padding: 12px 16px; background: var(--panel); border-bottom: 1px solid var(--border);
      display: flex; align-items: center; justify-content: space-between; gap: 8px;
    }
    .user-badge { font-weight: 700; display: flex; align-items: center; gap: 9px; font-size: 0.95rem; }
    .avatar-circle {
      width: 34px; height: 34px; border-radius: 50%; background: var(--accent-soft); color: var(--accent);
      font-weight: 700; font-size: 0.9rem; display: inline-flex; align-items: center; justify-content: center;
      position: relative; flex-shrink: 0; text-transform: uppercase;
    }
    .avatar-circle .status-dot {
      position: absolute; bottom: 0; right: 0; width: 10px; height: 10px; border-radius: 50%;
      background: var(--online); border: 2px solid #fff;
    }
    .avatar-circle .status-dot.offline { background: #cbd5e1; }
    .top-action-row { display: flex; align-items: center; gap: 6px; }
    .pill-icon-btn {
      padding: 7px 10px; border-radius: 999px; background: var(--panel-alt); color: var(--muted);
      font-size: 0.78rem; font-weight: 600; transition: all 0.15s;
      display: inline-flex; align-items: center; justify-content: center; gap: 5px;
    }
    .pill-icon-btn:hover { background: var(--accent-soft); color: var(--accent); }
    .icon-btn svg, .pill-icon-btn svg, .call-min-top-btn svg, .danger-btn svg, .primary-btn svg {
      width: 18px; height: 18px; stroke: currentColor; fill: none; stroke-width: 2;
      stroke-linecap: round; stroke-linejoin: round; display: block; flex-shrink: 0;
    }

    .chats-title-row {
      padding: 16px 16px 8px; display: flex; align-items: center; justify-content: space-between;
    }
    .chats-title-row h2 { font-size: 1.3rem; font-weight: 700; color: var(--text); }
    .plus-fab {
      width: 32px; height: 32px; border-radius: 50%; background: var(--accent); color: #fff;
      font-size: 1.2rem; font-weight: 700; display: inline-flex; align-items: center; justify-content: center;
      box-shadow: 0 4px 10px rgba(124, 58, 237, 0.3);
    }

    .filter-tabs {
      padding: 4px 16px 10px; display: flex; gap: 14px; font-size: 0.72rem; font-weight: 700;
      letter-spacing: 0.06em; color: var(--muted);
    }
    .filter-tab { padding-bottom: 4px; border-bottom: 2px solid transparent; }
    .filter-tab.active { color: var(--accent); border-bottom-color: var(--accent); }

    .search-wrap { padding: 0 16px 10px; }
    .search-input {
      width: 100%; padding: 9px 14px; border-radius: 999px; border: 1px solid var(--border);
      background: var(--panel); color: var(--text); font-size: 0.88rem; outline: none;
    }
    .search-input:focus { border-color: var(--accent); }

    .list-scroll { overflow-y: auto; flex: 1; padding: 0 12px 14px; display: flex; flex-direction: column; gap: 8px; }
    .section-label {
      padding: 6px 6px 2px; font-size: 0.72rem; font-weight: 700; text-transform: uppercase;
      letter-spacing: 0.06em; color: var(--muted);
    }
    .chat-item {
      padding: 10px 12px; border-radius: 14px; background: var(--panel); border: 1px solid var(--border);
      display: flex; align-items: center; justify-content: space-between; gap: 10px; cursor: pointer;
      transition: transform 0.1s, box-shadow 0.15s;
    }
    .chat-item:hover { box-shadow: 0 4px 12px rgba(15, 23, 42, 0.06); }
    .chat-item.active {
      background: var(--dark-card); color: #ffffff; border-color: var(--dark-card);
      box-shadow: 0 8px 20px rgba(38, 41, 56, 0.22);
    }
    .chat-item.active .chat-sub { color: #94a3b8; }
    .chat-item-left { display: flex; align-items: center; gap: 10px; min-width: 0; }
    .chat-name { font-weight: 600; font-size: 0.92rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .chat-sub { font-size: 0.76rem; color: var(--muted); margin-top: 2px; }
    .unread-pill {
      background: var(--accent); color: #ffffff; font-size: 0.72rem; font-weight: 700;
      min-width: 22px; height: 22px; padding: 0 6px; border-radius: 999px;
      display: inline-flex; align-items: center; justify-content: center;
    }

    /* Center Chat Pane */
    .main { position: relative; flex: 1; display: flex; flex-direction: column; min-width: 0; background: var(--panel); }
    .chat-header {
      padding: 12px 18px; background: var(--panel); border-bottom: 1px solid var(--border);
      display: flex; align-items: center; justify-content: space-between; gap: 12px;
    }
    .chat-title { font-weight: 700; font-size: 1rem; color: var(--text); }
    .chat-status { font-size: 0.78rem; color: var(--muted); margin-top: 2px; }
    .header-actions { display: flex; align-items: center; gap: 6px; position: relative; }
    .icon-btn {
      padding: 8px; border-radius: 999px; background: var(--panel-alt); color: var(--text);
      font-size: 0.84rem; font-weight: 500; transition: background 0.15s, color 0.15s;
      display: inline-flex; align-items: center; justify-content: center; gap: 5px; min-width: 36px; min-height: 36px;
    }
    .icon-btn:hover { background: var(--accent-soft); color: var(--accent); }
    .icon-btn.recording { background: var(--error); color: #fff; font-weight: 600; }

    #pull-refresh-circle {
      position: absolute; top: 68px; left: 50%; z-index: 40;
      width: 38px; height: 38px; border-radius: 50%;
      background: var(--panel); border: 1px solid var(--border);
      box-shadow: 0 4px 14px rgba(15, 23, 42, 0.15);
      display: flex; align-items: center; justify-content: center;
      color: var(--muted); opacity: 0; pointer-events: none;
      transform: translate(-50%, -48px) scale(0.8);
      transition: transform 0.15s ease, opacity 0.15s ease, color 0.15s ease;
    }
    #pull-refresh-circle.ready { color: var(--accent); border-color: var(--accent); }
    #pull-refresh-circle.spinning svg { animation: lan-spin 0.7s linear infinite; }
    @keyframes lan-spin { to { transform: rotate(360deg); } }

    .messages {
      flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 10px;
      background: var(--panel);
    }
    .msg-row {
      position: relative; display: flex; align-items: center; gap: 6px;
      align-self: flex-start; max-width: 78%;
    }
    .msg-row.me { align-self: flex-end; flex-direction: row-reverse; }
    .bubble {
      max-width: 100%; padding: 10px 14px; border-radius: 18px; line-height: 1.42;
      background: var(--incoming); color: var(--text); word-wrap: break-word;
      border-bottom-left-radius: 4px;
    }
    .bubble.me {
      background: linear-gradient(135deg, #8b5cf6, #7c3aed); color: #ffffff;
      border-bottom-left-radius: 18px; border-bottom-right-radius: 4px;
    }
    .bubble-sender { font-size: 0.74rem; font-weight: 700; color: var(--accent); margin-bottom: 3px; }
    .bubble.me .bubble-sender { color: #ede9fe; }
    .bubble-meta {
      display: flex; align-items: center; justify-content: flex-end; gap: 5px;
      font-size: 0.68rem; color: var(--muted); margin-top: 4px;
    }
    .bubble.me .bubble-meta { color: rgba(255,255,255,0.8); }
    .ticks { font-weight: 700; letter-spacing: -1px; }
    .ticks.read { color: var(--read-blue); }
    .bubble img { max-width: 250px; max-height: 250px; border-radius: 12px; display: block; margin-top: 4px; }
    .bubble audio { width: 220px; max-width: 100%; height: 36px; margin-top: 4px; display: block; }
    .file-link {
      display: inline-flex; align-items: center; gap: 6px; padding: 7px 11px; margin-top: 4px;
      background: rgba(15, 23, 42, 0.08); border-radius: 10px; color: inherit; text-decoration: none; font-size: 0.86rem;
    }
    .bubble.me .file-link { background: rgba(255, 255, 255, 0.18); color: #fff; }
    .pdf-actions { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 4px; }

    .menu-trigger {
      opacity: 0; width: 26px; height: 26px; border-radius: 50%;
      display: inline-flex; align-items: center; justify-content: center;
      color: var(--muted); font-size: 1.05rem; flex-shrink: 0; transition: opacity 0.12s, background 0.12s;
    }
    .msg-row:hover .menu-trigger, .msg-row.menu-open .menu-trigger { opacity: 1; }
    .menu-trigger:hover { background: var(--panel-alt); color: var(--text); }
    @media (hover: none) { .menu-trigger { opacity: 0.75; } }
    .msg-menu {
      display: none; position: absolute; top: calc(100% + 4px); left: 0; z-index: 30;
      min-width: 170px; background: var(--panel); border: 1px solid var(--border);
      border-radius: 12px; padding: 5px; box-shadow: 0 10px 30px rgba(15, 23, 42, 0.14);
      flex-direction: column;
    }
    .msg-row.me .msg-menu { left: auto; right: 0; }
    .msg-row.menu-up .msg-menu { top: auto; bottom: calc(100% + 4px); }
    .msg-row.menu-open .msg-menu { display: flex; }
    .msg-menu button {
      text-align: left; padding: 8px 12px; border-radius: 8px; font-size: 0.85rem; color: var(--text);
    }
    .msg-menu button:hover { background: var(--panel-alt); }
    .msg-menu button.danger { color: var(--error); }
    .deleted-msg { font-style: italic; color: var(--muted); font-size: 0.88rem; }
    .bubble.me .deleted-msg { color: rgba(255,255,255,0.75); }
    .reply-quote {
      border-left: 3px solid var(--accent); background: rgba(15, 23, 42, 0.06);
      padding: 5px 8px; border-radius: 8px; margin-bottom: 6px; cursor: pointer; font-size: 0.82rem;
    }
    .bubble.me .reply-quote { border-left-color: #fff; background: rgba(255, 255, 255, 0.16); }
    .reply-quote-sender { font-weight: 700; color: var(--accent); font-size: 0.74rem; }
    .bubble.me .reply-quote-sender { color: #ede9fe; }
    .reply-quote-text { color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 240px; }
    .bubble.me .reply-quote-text { color: rgba(255,255,255,0.85); }
    .reaction-bar { display: flex; gap: 4px; flex-wrap: wrap; margin-top: 4px; }
    .rx-chip {
      background: var(--panel); border: 1px solid var(--border); border-radius: 999px;
      padding: 2px 8px; font-size: 0.76rem; color: var(--text); box-shadow: 0 2px 6px rgba(0,0,0,0.05);
    }
    .menu-emojis {
      display: flex; justify-content: space-between; gap: 2px; padding: 4px 6px;
      border-bottom: 1px solid var(--border); margin-bottom: 2px;
    }
    .menu-emojis button { padding: 4px; font-size: 1rem; border-radius: 6px; text-align: center; }
    .edited-tag { font-style: italic; opacity: 0.75; font-size: 0.68rem; }
    .msg-highlight .bubble { outline: 2px solid var(--accent); }

    #reply-bar {
      display: none; align-items: center; justify-content: space-between; gap: 10px;
      padding: 8px 16px; background: var(--panel-alt); border-top: 1px solid var(--border);
      border-left: 4px solid var(--accent);
    }
    #reply-bar.active { display: flex; }
    #upload-progress-wrap {
      display: none; flex-direction: column; gap: 4px;
      padding: 6px 16px; background: var(--panel-alt); border-top: 1px solid var(--border);
    }
    #upload-progress-wrap.active { display: flex; }
    .progress-label { font-size: 0.78rem; color: var(--muted); display: flex; justify-content: space-between; }
    .progress-track { width: 100%; height: 5px; background: var(--border); border-radius: 999px; overflow: hidden; }
    .progress-fill { width: 0%; height: 100%; background: var(--accent); transition: width 0.1s linear; }

    /* Pill Composer */
    .composer-wrap {
      padding: 10px 16px calc(12px + env(safe-area-inset-bottom, 0px));
      background: var(--panel); border-top: 1px solid var(--border);
    }
    .composer {
      display: flex; align-items: center; gap: 8px; flex-wrap: nowrap;
      background: var(--panel-alt); border: 1px solid var(--border); border-radius: 999px;
      padding: 5px 6px 5px 10px;
    }
    .composer input[type="text"] {
      flex: 1 1 0%; width: 0; min-width: 0; padding: 8px 6px; border: none;
      background: transparent; color: var(--text); font-size: 0.95rem; outline: none;
    }
    .composer button { flex-shrink: 0; }
    .send-circle-btn {
      width: 36px; height: 36px; border-radius: 50%; background: linear-gradient(135deg, #8b5cf6, #7c3aed);
      color: #fff; display: inline-flex; align-items: center; justify-content: center; font-size: 0.95rem;
      box-shadow: 0 3px 10px rgba(124, 58, 237, 0.28);
    }
    .back-btn {
      display: none; padding: 6px 10px; border-radius: 999px; background: var(--panel-alt);
      font-size: 1rem; font-weight: 700; flex-shrink: 0;
    }

    /* Right Panel: Notifications & Quick People */
    .right-panel {
      width: 290px; background: var(--bg); border-left: 1px solid var(--border);
      display: flex; flex-direction: column; padding: 16px; gap: 18px; overflow-y: auto; flex-shrink: 0;
    }
    .right-panel h3 { font-size: 1.05rem; font-weight: 700; color: var(--text); margin-bottom: 8px; }
    .notif-list, .quick-people-list { display: flex; flex-direction: column; gap: 10px; }
    .notif-item {
      display: flex; align-items: flex-start; gap: 10px; font-size: 0.82rem; color: var(--text); line-height: 1.35;
    }
    .notif-time { font-size: 0.72rem; color: var(--muted); }
    .quick-person {
      display: flex; align-items: center; justify-content: space-between; gap: 8px;
      background: var(--panel); padding: 8px 10px; border-radius: 12px; border: 1px solid var(--border);
    }
    .quick-chat-btn {
      background: var(--accent); color: #fff; font-size: 0.75rem; font-weight: 600;
      padding: 5px 12px; border-radius: 999px;
    }

    /* In-Room Message Search Bar */
    #msg-search-bar {
      display: none; align-items: center; gap: 8px; padding: 8px 16px;
      background: var(--panel-alt); border-bottom: 1px solid var(--border);
    }
    #msg-search-bar.active { display: flex; }
    #msg-search-input {
      flex: 1; min-width: 0; padding: 7px 12px; border-radius: 999px;
      border: 1px solid var(--border); background: var(--panel); color: var(--text);
      font-size: 0.88rem; outline: none;
    }
    #msg-search-input:focus { border-color: var(--accent); }
    .search-count { font-size: 0.78rem; color: var(--muted); white-space: nowrap; min-width: 48px; text-align: center; }
    .msg-search-match .bubble { outline: 2px dashed var(--accent); }
    .msg-search-current .bubble { outline: 3px solid var(--accent); box-shadow: 0 0 0 4px var(--accent-soft); }

    /* Vault Modal & Cards */
    #vault-modal {
      display: none; position: fixed; inset: 0; z-index: 66;
      background: rgba(15, 23, 42, 0.72); backdrop-filter: blur(4px);
      align-items: center; justify-content: center; padding: 16px;
    }
    #vault-modal.active { display: flex; }
    .vault-card {
      background: var(--panel); border: 1px solid var(--border); border-radius: 18px;
      padding: 20px; width: 100%; max-width: 640px; max-height: 84vh;
      display: flex; flex-direction: column; gap: 12px; box-shadow: 0 20px 50px rgba(0,0,0,0.22);
    }
    .vault-header { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
    .vault-controls { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
    .vault-tabs { display: flex; gap: 6px; flex-wrap: wrap; }
    .vault-tab {
      padding: 6px 12px; border-radius: 999px; background: var(--panel-alt); color: var(--muted);
      font-size: 0.78rem; font-weight: 600;
    }
    .vault-tab.active { background: var(--accent); color: #fff; }
    .vault-search {
      flex: 1; min-width: 160px; padding: 7px 12px; border-radius: 999px;
      border: 1px solid var(--border); background: var(--panel-alt); color: var(--text);
      font-size: 0.85rem; outline: none;
    }
    .vault-list {
      flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 8px; padding-right: 4px;
    }
    .vault-item {
      display: flex; align-items: center; justify-content: space-between; gap: 12px;
      padding: 10px 12px; border-radius: 12px; background: var(--panel-alt); border: 1px solid var(--border);
    }
    .vault-item-left { display: flex; align-items: center; gap: 10px; min-width: 0; flex: 1; }
    .vault-thumb {
      width: 42px; height: 42px; border-radius: 10px; background: var(--accent-soft); color: var(--accent);
      display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 0.78rem;
      flex-shrink: 0; overflow: hidden;
    }
    .vault-thumb img { width: 100%; height: 100%; object-fit: cover; }
    .vault-meta { min-width: 0; flex: 1; }
    .vault-fname { font-weight: 600; font-size: 0.88rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .vault-sub { font-size: 0.74rem; color: var(--muted); margin-top: 2px; }
    .vault-actions { display: flex; align-items: center; gap: 6px; flex-shrink: 0; flex-wrap: wrap; }

    /* Modals */
    #invite-modal, #call-modal, #pdf-modal {
      display: none; position: fixed; inset: 0; z-index: 65;
      background: rgba(15, 23, 42, 0.72); backdrop-filter: blur(4px);
      align-items: center; justify-content: center; padding: 16px;
    }
    #invite-modal.active, #call-modal.active, #pdf-modal.active { display: flex; }
    #pdf-modal { flex-direction: column; padding: 0; z-index: 70; background: #0f172a; }
    .invite-card, .call-card {
      background: var(--panel); border: 1px solid var(--border); border-radius: 18px;
      padding: 22px; width: 100%; max-width: 400px; display: flex; flex-direction: column;
      gap: 12px; align-items: center; text-align: center; box-shadow: 0 20px 50px rgba(0,0,0,0.2);
    }
    .call-card { position: relative; max-width: 720px; }
    .call-min-top-btn {
      position: absolute; top: 14px; right: 14px; padding: 6px 12px; border-radius: 999px;
      background: var(--panel-alt); color: var(--text); font-size: 0.78rem; font-weight: 600;
    }
    .call-min-top-btn:hover { background: var(--accent-soft); color: var(--accent); }
    #call-modal.minimized {
      inset: auto; top: 68px; right: 16px; width: auto; height: auto;
      background: transparent; backdrop-filter: none; padding: 0; pointer-events: none;
    }
    #call-modal.minimized .call-card {
      pointer-events: auto; width: 270px; max-width: 90vw; padding: 12px; gap: 8px;
      border-radius: 16px; background: var(--dark-card); color: #fff;
      border: 1px solid rgba(255,255,255,0.14); box-shadow: 0 14px 34px rgba(15, 23, 42, 0.38);
    }
    #call-modal.minimized .chat-title { color: #fff; font-size: 0.92rem; }
    #call-modal.minimized .chat-status { color: #cbd5e1; font-size: 0.74rem; }
    #call-modal.minimized .call-min-top-btn { display: none; }
    #call-modal.minimized .call-videos { min-height: 110px; max-height: 130px; border-radius: 10px; }
    #call-modal.minimized #remote-video { max-height: 130px; }
    #call-modal.minimized #local-video { width: 58px; bottom: 6px; right: 6px; border-radius: 6px; }
    #call-modal.minimized .call-controls button { padding: 5px 10px; font-size: 0.75rem; }
    .invite-qr-box {
      background: #ffffff; padding: 10px; border-radius: 12px; border: 1px solid var(--border);
      width: 200px; height: 200px; display: flex; align-items: center; justify-content: center;
    }
    .invite-qr-box img { width: 100%; height: 100%; }
    .invite-url {
      width: 100%; padding: 8px 10px; border-radius: 10px; background: var(--panel-alt);
      font-family: monospace; font-size: 0.84rem; word-break: break-all; color: var(--accent);
    }
    .call-videos {
      position: relative; width: 100%; background: #0f172a; border-radius: 14px; overflow: hidden; min-height: 260px;
      display: flex; align-items: center; justify-content: center;
    }
    #remote-video { width: 100%; max-height: 62vh; object-fit: contain; background: #0f172a; }
    #local-video {
      position: absolute; bottom: 10px; right: 10px; width: 120px; border-radius: 10px;
      border: 2px solid var(--accent); background: #111;
    }
    .call-controls { display: flex; gap: 10px; flex-wrap: wrap; justify-content: center; }
    .danger-btn {
      background: var(--error); color: #fff; font-weight: 600; padding: 10px 18px; border-radius: 10px;
    }
    .pdf-toolbar {
      width: 100%; display: flex; align-items: center; justify-content: space-between; gap: 10px;
      padding: 10px 14px; background: var(--panel); border-bottom: 1px solid var(--border);
    }
    .pdf-title { font-weight: 600; font-size: 0.95rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    #pdf-frame { flex: 1; width: 100%; border: none; background: #1e293b; }

    @media (max-width: 1080px) {
      .right-panel { display: none; }
    }
    @media (max-width: 768px) {
      .sidebar { width: 100%; border-right: none; }
      .main { display: none; width: 100%; }
      #app.chat-open .sidebar { display: none; }
      #app.chat-open .main { display: flex; }
      .back-btn { display: inline-flex; align-items: center; justify-content: center; }
      .chat-header { padding: 10px 12px; flex-wrap: wrap; gap: 8px; }
      .header-actions { flex-wrap: wrap; gap: 6px; }
      .header-actions .icon-btn { padding: 6px 9px; font-size: 0.78rem; }
      .msg-row { max-width: 90%; }
      .bubble img { max-width: 210px; max-height: 210px; }
      .composer-wrap { padding: 8px 10px calc(8px + env(safe-area-inset-bottom, 0px)); }
      .composer .icon-btn { padding: 6px 8px; font-size: 0.8rem; }
    }
  </style>
</head>
<body>
  <div id="login-screen">
    <form class="login-card" id="login-form">
      <h1>LAN Chat</h1>
      <p>Zero-data local Wi-Fi chat. Each device IP gets one account; enter your PIN if your IP changes.</p>
      <input id="username-input" type="text" placeholder="Username (letters, numbers, _ or -)" required maxlength="24" />
      <input id="pin-input" type="password" inputmode="numeric" placeholder="4-8 digit PIN" required minlength="4" maxlength="8" />
      <div class="login-error" id="login-error"></div>
      <button class="primary-btn" type="submit">Join Network Chat</button>
    </form>
  </div>

  <div id="app">
    <aside class="sidebar">
      <div class="sidebar-top-icons">
        <div class="user-badge">
          <div class="avatar-circle" id="me-avatar">U<span class="status-dot"></span></div>
          <span id="me-label"></span>
        </div>
        <div class="top-action-row">
          <button class="pill-icon-btn" id="invite-btn" title="Invite via Hotspot / Wi-Fi (QR)">
            <svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h3v3h-3zM18 18h3v3h-3zM18 14h3M14 18v3"/></svg>
          </button>
          <button class="pill-icon-btn" id="logout-btn" title="Logout">
            <svg viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
          </button>
        </div>
      </div>

      <div class="chats-title-row">
        <h2>Chats</h2>
        <button class="plus-fab" id="new-group-btn" title="Create new group">+</button>
      </div>

      <div class="filter-tabs" id="filter-tabs">
        <button type="button" class="filter-tab active" data-filter="all">ALL</button>
        <button type="button" class="filter-tab" data-filter="direct">DIRECT</button>
        <button type="button" class="filter-tab" data-filter="groups">GROUPS</button>
      </div>

      <div class="search-wrap">
        <input type="text" class="search-input" id="sidebar-search" placeholder="Search chats or people..." />
      </div>

      <div class="list-scroll">
        <div class="section-label" id="groups-label">Groups</div>
        <div id="groups-list" style="display:flex;flex-direction:column;gap:8px;"></div>

        <div class="section-label" id="users-label" style="margin-top:6px;">People (1-on-1)</div>
        <div id="users-list" style="display:flex;flex-direction:column;gap:8px;"></div>
      </div>
    </aside>

    <main class="main">
      <div class="chat-header">
        <div style="display:flex;align-items:center;gap:10px;min-width:0;">
          <button type="button" class="back-btn" id="back-to-chats-btn" title="Back to chats">←</button>
          <div class="avatar-circle" id="header-avatar">G</div>
          <div style="min-width:0;">
            <div class="chat-title" id="active-room-title" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">General</div>
            <div class="chat-status" id="active-room-status">Group chat</div>
          </div>
        </div>
        <div class="header-actions">
          <button type="button" class="icon-btn" id="msg-search-btn" title="Search messages in this chat (Ctrl+F)">
            <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          </button>
          <button type="button" class="icon-btn" id="vault-btn" title="Shared Files, PDFs & Media Vault">
            <svg viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
          </button>
          <button type="button" class="icon-btn" id="group-invite-btn" title="Invite others to this group">
            <svg viewBox="0 0 24 24"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="23" y1="11" x2="17" y2="11"/></svg>
          </button>
          <button type="button" class="icon-btn" id="voice-call-btn" style="display:none;" title="Voice call">
            <svg viewBox="0 0 24 24"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/></svg>
          </button>
          <button type="button" class="icon-btn" id="video-call-btn" style="display:none;" title="Video call">
            <svg viewBox="0 0 24 24"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg>
          </button>
          <button type="button" class="icon-btn" id="clear-chat-btn" title="Clear Chat">
            <svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
          </button>
          <button type="button" class="icon-btn" id="sound-toggle-btn" title="Sound: On"></button>
        </div>
      </div>

      <div id="msg-search-bar">
        <input type="text" id="msg-search-input" placeholder="Search messages, sender, or filenames in this room..." autocomplete="off" />
        <span class="search-count" id="msg-search-count">0 / 0</span>
        <button type="button" class="icon-btn" id="msg-search-prev" title="Previous match">↑</button>
        <button type="button" class="icon-btn" id="msg-search-next" title="Next match">↓</button>
        <button type="button" class="icon-btn" id="msg-search-close" title="Close search">×</button>
      </div>

      <div id="pull-refresh-circle" aria-hidden="true">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 12a9 9 0 1 1-2.64-6.36"/>
          <polyline points="21 3 21 9 15 9"/>
        </svg>
      </div>
      <div class="messages" id="messages"></div>

      <div id="reply-bar">
        <div style="min-width:0;">
          <div class="reply-quote-sender" id="reply-bar-sender"></div>
          <div class="reply-quote-text" id="reply-bar-text" style="max-width:none;"></div>
        </div>
        <button type="button" class="icon-btn" id="cancel-reply-btn" title="Cancel reply">×</button>
      </div>

      <div id="upload-progress-wrap">
        <div class="progress-label">
          <span id="upload-progress-text">Uploading...</span>
          <span id="upload-progress-pct">0%</span>
        </div>
        <div class="progress-track"><div class="progress-fill" id="upload-progress-fill"></div></div>
      </div>

      <div class="composer-wrap">
        <form class="composer" id="composer">
          <input type="file" id="file-input" hidden />
          <button type="button" class="icon-btn" id="attach-btn" title="Attach file or image (max 50 MB)">
            <svg viewBox="0 0 24 24"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>
          </button>
          <button type="button" class="icon-btn" id="record-btn" title="Record voice note">
            <svg viewBox="0 0 24 24"><path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="23"/><line x1="8" y1="23" x2="16" y2="23"/></svg>
          </button>
          <input type="text" id="msg-input" placeholder="Type a message here..." autocomplete="off" />
          <button type="submit" class="send-circle-btn" title="Send">
            <svg viewBox="0 0 24 24" width="17" height="17" stroke="currentColor" fill="none" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
          </button>
        </form>
      </div>
    </main>

    <aside class="right-panel">
      <div>
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
          <h3 style="margin-bottom:0;">Shared Files & PDFs</h3>
          <button type="button" class="pill-icon-btn" id="right-vault-btn">View All</button>
        </div>
        <div class="quick-people-list" id="quick-files-list">
          <div class="notif-item" style="color:var(--muted);">No files shared in this room yet.</div>
        </div>
      </div>
      <div>
        <h3>Notifications</h3>
        <div class="notif-list" id="notif-feed">
          <div class="notif-item" style="color:var(--muted);">Activity on your LAN will appear here.</div>
        </div>
      </div>
      <div>
        <h3>People on LAN</h3>
        <div class="quick-people-list" id="quick-people-list"></div>
      </div>
    </aside>
  </div>

  <div id="vault-modal">
    <div class="vault-card">
      <div class="vault-header">
        <div>
          <div class="chat-title" id="vault-room-title">Shared Files & PDF Vault</div>
          <div class="chat-status" id="vault-room-sub">Decrypted locally in your browser</div>
        </div>
        <button type="button" class="icon-btn" id="vault-close-btn" title="Close">✕</button>
      </div>
      <div class="vault-controls">
        <div class="vault-tabs" id="vault-tabs">
          <button type="button" class="vault-tab active" data-vtab="all">All</button>
          <button type="button" class="vault-tab" data-vtab="docs">PDFs & Docs</button>
          <button type="button" class="vault-tab" data-vtab="images">Images</button>
          <button type="button" class="vault-tab" data-vtab="audio">Voice / Audio</button>
        </div>
        <input type="text" class="vault-search" id="vault-search-input" placeholder="Filter by filename or sender..." />
      </div>
      <div class="vault-list" id="vault-list"></div>
    </div>
  </div>

  <div id="invite-modal">
    <div class="invite-card">
      <div class="chat-title" id="invite-modal-title">Invite via Hotspot / Wi-Fi</div>
      <div class="chat-status">Turn off mobile data, connect to the same hotspot/Wi-Fi, and scan:</div>
      <div class="invite-qr-box"><img id="invite-qr-img" alt="Join QR Code" /></div>
      <div class="invite-url" id="invite-url-text">Loading...</div>
      <div class="call-controls">
        <button type="button" class="primary-btn" id="copy-invite-btn" title="Copy URL">Copy URL</button>
        <button type="button" class="icon-btn" id="close-invite-btn" title="Close">✕</button>
      </div>
    </div>
  </div>

  <div id="pdf-modal">
    <div class="pdf-toolbar">
      <div class="pdf-title" id="pdf-title">Document.pdf</div>
      <div class="header-actions">
        <a class="icon-btn" id="pdf-download-link" href="#" download style="text-decoration:none;" title="Download PDF">
          <svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        </a>
        <a class="icon-btn" id="pdf-newtab-link" href="#" target="_blank" style="text-decoration:none;" title="Open in new tab">
          <svg viewBox="0 0 24 24"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
        </a>
        <button type="button" class="danger-btn" id="pdf-close-btn" style="padding:7px 11px;" title="Close">✕</button>
      </div>
    </div>
    <iframe id="pdf-frame" title="In-app PDF viewer"></iframe>
  </div>

  <div id="call-modal">
    <div class="call-card">
      <button type="button" class="call-min-top-btn" id="call-min-toggle-btn" title="Minimize / Expand call">
        <svg viewBox="0 0 24 24"><polyline points="4 14 10 14 10 20"/><polyline points="20 10 14 10 14 4"/><line x1="14" y1="10" x2="21" y2="3"/><line x1="3" y1="21" x2="10" y2="14"/></svg>
      </button>
      <div style="text-align:center;">
        <div class="chat-title" id="call-peer-name">Call</div>
        <div class="chat-status" id="call-status">Connecting...</div>
      </div>
      <div class="call-videos" id="call-videos">
        <video id="remote-video" autoplay playsinline></video>
        <video id="local-video" autoplay muted playsinline></video>
      </div>
      <div class="call-controls" id="call-controls"></div>
    </div>
  </div>

  <script>
    let me = "";
    let authToken = "";
    let ws = null;
    let activeRoom = { id: "group:general", name: "General", isGroup: true, peer: null };
    let rooms = [];
    let users = [];
    let roomMessages = [];
    const roomCache = {};

    function saveRoomCache(roomId, msgs) {
      roomCache[roomId] = msgs.slice(-100);
      try {
        // Persist decrypted text/metadata (strip transient blob: URLs so they re-resolve cleanly)
        const serializable = roomCache[roomId].map(m => ({
          ...m,
          file_url: m.orig_file_url || m.file_url,
        }));
        localStorage.setItem(`lan_chat_cache_${me}_${roomId}`, JSON.stringify(serializable));
      } catch {}
    }

    function loadRoomCache(roomId) {
      if (roomCache[roomId]) return roomCache[roomId];
      try {
        const raw = localStorage.getItem(`lan_chat_cache_${me}_${roomId}`);
        if (raw) {
          roomCache[roomId] = JSON.parse(raw);
          return roomCache[roomId];
        }
      } catch {}
      return null;
    }
    let unread = {};
    let replyTo = null;
    let typingTimer = null;
    let myPrivateKey = null;
    const sharedKeyCache = {};

    function b64Encode(buf) {
      const bytes = new Uint8Array(buf);
      let bin = "";
      bytes.forEach(b => { bin += String.fromCharCode(b); });
      return btoa(bin);
    }

    function b64Decode(str) {
      const bin = atob(str);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return bytes;
    }

    async function ensureE2EEKeys() {
      if (!window.crypto || !window.crypto.subtle) return;
      const storageKey = `lan_chat_e2ee_${me}`;
      let saved = null;
      try { saved = JSON.parse(localStorage.getItem(storageKey) || "null"); } catch {}

      let pubJwk, privJwk;
      if (saved && saved.pub && saved.priv) {
        pubJwk = saved.pub;
        privJwk = saved.priv;
      } else {
        const kp = await crypto.subtle.generateKey(
          { name: "ECDH", namedCurve: "P-256" },
          true,
          ["deriveKey"]
        );
        pubJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
        privJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
        localStorage.setItem(storageKey, JSON.stringify({ pub: pubJwk, priv: privJwk }));
      }
      myPrivateKey = await crypto.subtle.importKey(
        "jwk",
        privJwk,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveKey"]
      );
      await fetch("/api/keys", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ public_key: JSON.stringify(pubJwk) }),
      });
    }

    async function getPeerAesKey(peerUsername) {
      if (!myPrivateKey || !window.crypto || !window.crypto.subtle) return null;
      const peerObj = users.find(u => u.username === peerUsername);
      if (!peerObj || !peerObj.public_key) return null;
      const cacheKey = `${peerUsername}:${peerObj.public_key}`;
      if (sharedKeyCache[cacheKey]) return sharedKeyCache[cacheKey];
      const peerPub = await crypto.subtle.importKey(
        "jwk",
        JSON.parse(peerObj.public_key),
        { name: "ECDH", namedCurve: "P-256" },
        false,
        []
      );
      const aesKey = await crypto.subtle.deriveKey(
        { name: "ECDH", public: peerPub },
        myPrivateKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      );
      sharedKeyCache[cacheKey] = aesKey;
      return aesKey;
    }

    async function encryptForPeer(peerUsername, plaintext) {
      const key = await getPeerAesKey(peerUsername);
      if (!key) return plaintext;
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(plaintext);
      const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
      return `E2EE:${b64Encode(iv)}:${b64Encode(cipher)}`;
    }

    const groupKeyCache = {};

    async function ensureGroupAesKey(roomId) {
      if (!myPrivateKey || !window.crypto || !window.crypto.subtle) return null;
      if (groupKeyCache[roomId]) return groupKeyCache[roomId];

      const res = await fetch(`/api/rooms/${encodeURIComponent(roomId)}/keys`, { headers: authHeaders() });
      const data = await res.json();

      let rawKeyBytes = null;
      if (data.my_key && data.my_key.wrapped_key) {
        const unwrapped = await decryptWithPeer(data.my_key.sender, data.my_key.wrapped_key);
        if (unwrapped && !unwrapped.startsWith("[")) {
          rawKeyBytes = b64Decode(unwrapped);
        }
      } else if (!data.holders || data.holders.length === 0) {
        const gen = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
        rawKeyBytes = new Uint8Array(await crypto.subtle.exportKey("raw", gen));
        const b64Key = b64Encode(rawKeyBytes);
        const entries = [];
        for (const u of users) {
          if (u.public_key) {
            const wrapped = await encryptForPeer(u.username, b64Key);
            entries.push({ username: u.username, wrapped_key: wrapped });
          }
        }
        if (entries.length > 0) {
          await fetch(`/api/rooms/${encodeURIComponent(roomId)}/keys`, {
            method: "POST",
            headers: authHeaders({ "Content-Type": "application/json" }),
            body: JSON.stringify({ keys: entries }),
          });
        }
      }

      if (!rawKeyBytes) return null;
      const aesKey = await crypto.subtle.importKey(
        "raw",
        rawKeyBytes,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
      groupKeyCache[roomId] = aesKey;
      await shareGroupKeyWithNewMembers(roomId, data.holders || []);
      return aesKey;
    }

    async function shareGroupKeyWithNewMembers(roomId, existingHolders) {
      const aesKey = groupKeyCache[roomId];
      if (!aesKey) return;
      const holderSet = new Set(existingHolders);
      const missing = users.filter(u => u.public_key && !holderSet.has(u.username));
      if (missing.length === 0) return;

      const rawKeyBytes = new Uint8Array(await crypto.subtle.exportKey("raw", aesKey));
      const b64Key = b64Encode(rawKeyBytes);
      const entries = [];
      for (const u of missing) {
        const wrapped = await encryptForPeer(u.username, b64Key);
        entries.push({ username: u.username, wrapped_key: wrapped });
      }
      if (entries.length > 0) {
        await fetch(`/api/rooms/${encodeURIComponent(roomId)}/keys`, {
          method: "POST",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({ keys: entries }),
        });
      }
    }

    async function getRoomAesKey(roomId) {
      if (roomId.startsWith("dm:")) {
        const parts = roomId.split(":");
        const peer = parts[1] === me ? parts[2] : parts[1];
        return getPeerAesKey(peer);
      }
      if (roomId.startsWith("group:")) {
        return ensureGroupAesKey(roomId);
      }
      return null;
    }

    async function encryptForRoom(roomId, plaintext) {
      const key = await getRoomAesKey(roomId);
      if (!key) return plaintext;
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(plaintext);
      const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
      return `E2EE:${b64Encode(iv)}:${b64Encode(cipher)}`;
    }

    async function decryptWithPeer(peer, content) {
      if (!content || !content.startsWith("E2EE:")) return content;
      try {
        const key = await getPeerAesKey(peer);
        if (!key) return "[Encrypted message — key unavailable]";
        const [, ivB64, cipherB64] = content.split(":", 3);
        const plain = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: b64Decode(ivB64) },
          key,
          b64Decode(cipherB64)
        );
        return new TextDecoder().decode(plain);
      } catch {
        return "[Unable to decrypt message]";
      }
    }

    async function decryptContent(roomId, content) {
      if (!content || !content.startsWith("E2EE:")) return content;
      try {
        const key = await getRoomAesKey(roomId);
        if (!key) return "[Encrypted message — key unavailable]";
        const [, ivB64, cipherB64] = content.split(":", 3);
        const plain = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: b64Decode(ivB64) },
          key,
          b64Decode(cipherB64)
        );
        return new TextDecoder().decode(plain);
      } catch {
        return "[Unable to decrypt message]";
      }
    }

    function guessMimeType(filename) {
      const ext = (filename || "").split(".").pop().toLowerCase();
      const map = {
        png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp",
        webm: "audio/webm", ogg: "audio/ogg", mp3: "audio/mpeg", wav: "audio/wav", m4a: "audio/mp4",
        pdf: "application/pdf", txt: "text/plain"
      };
      return map[ext] || "application/octet-stream";
    }

    const decryptedBlobCache = {};

    async function decryptMediaUrl(roomId, fileUrl, fileName) {
      if (!fileUrl || !fileUrl.endsWith(".enc")) return fileUrl;
      if (decryptedBlobCache[fileUrl]) return decryptedBlobCache[fileUrl];
      try {
        const key = await getRoomAesKey(roomId);
        if (!key) return fileUrl;
        const res = await fetch(fileUrl);
        const buf = await res.arrayBuffer();
        const iv = new Uint8Array(buf, 0, 12);
        const cipher = new Uint8Array(buf, 12);
        const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
        const blob = new Blob([plain], { type: guessMimeType(fileName) });
        const blobUrl = URL.createObjectURL(blob);
        decryptedBlobCache[fileUrl] = blobUrl;
        return blobUrl;
      } catch {
        return fileUrl;
      }
    }

    const loginScreen = document.getElementById("login-screen");
    const loginError = document.getElementById("login-error");
    const appEl = document.getElementById("app");
    const groupsList = document.getElementById("groups-list");
    const usersList = document.getElementById("users-list");
    const messagesEl = document.getElementById("messages");
    const msgInput = document.getElementById("msg-input");
    const fileInput = document.getElementById("file-input");

    function dmRoomId(a, b) {
      const pair = [a, b].sort();
      return `dm:${pair[0]}:${pair[1]}`;
    }

    function escapeHtml(str) {
      return str.replace(/[&<>"']/g, c => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c]));
    }

    function authHeaders(extra = {}) {
      return { ...extra, "X-Auth-Token": authToken };
    }

    function ticksHtml(status) {
      if (status === "queued") return `<span class="ticks" title="Queued offline">⏳</span>`;
      if (status === "read") return `<span class="ticks read">✓✓</span>`;
      if (status === "delivered") return `<span class="ticks">✓✓</span>`;
      return `<span class="ticks">✓</span>`;
    }

    function sendMarkRead(roomId) {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "mark_read", room_id: roomId }));
      }
    }

    async function loadRooms() {
      const res = await fetch("/api/rooms", { headers: authHeaders() });
      const data = await res.json();
      rooms = data.rooms || [];
      renderSidebar();
    }

    async function selectRoom(room, openMobileChat = true) {
      activeRoom = room;
      if (openMobileChat) appEl.classList.add("chat-open");
      unread[room.id] = 0;
      document.getElementById("active-room-title").textContent = room.name;
      document.getElementById("header-avatar").textContent = (room.name[0] || "C").toUpperCase();
      const roomKey = await getRoomAesKey(room.id);
      const hasE2EE = roomKey !== null;
      document.getElementById("active-room-status").textContent = room.isGroup
        ? (hasE2EE ? "Group chat • E2EE 🔒" : "Group chat")
        : (hasE2EE ? "Direct message • E2EE 🔒" : "Direct message");
      const clearBtn = document.getElementById("clear-chat-btn");
      clearBtn.title = (room.isGroup && room.createdBy === me && room.id !== "group:general")
        ? "Delete Group"
        : "Clear Chat";
      const showCallBtns = !room.isGroup && Boolean(room.peer);
      document.getElementById("group-invite-btn").style.display = room.isGroup ? "inline-flex" : "none";
      document.getElementById("voice-call-btn").style.display = showCallBtns ? "inline-flex" : "none";
      document.getElementById("video-call-btn").style.display = showCallBtns ? "inline-flex" : "none";
      renderSidebar();

      const cached = loadRoomCache(room.id);
      if (cached && cached.length > 0) {
        await Promise.all(cached.map(async (m) => {
          if (m.file_url && m.file_url.endsWith(".enc") && (m.msg_type === "image" || m.msg_type === "audio")) {
            m.orig_file_url = m.file_url;
            m.file_url = await decryptMediaUrl(m.room_id, m.file_url, m.file_name);
          }
        }));
        messagesEl.innerHTML = "";
        roomMessages = [];
        const loadBtn = document.createElement("button");
        loadBtn.type = "button";
        loadBtn.className = "icon-btn";
        loadBtn.style.alignSelf = "center";
        loadBtn.textContent = "Load older messages";
        loadBtn.onclick = () => loadOlderMessages(loadBtn);
        messagesEl.appendChild(loadBtn);
        cached.forEach(m => appendMessage(m, true));
        messagesEl.scrollTop = messagesEl.scrollHeight;
        renderQuickFiles();
      } else {
        messagesEl.innerHTML = "";
        roomMessages = [];
      }

      const lastId = roomMessages.length > 0 ? roomMessages[roomMessages.length - 1].id : null;
      const query = lastId ? `limit=50&after_id=${lastId}` : "limit=50";
      try {
        const res = await fetch(`/api/rooms/${encodeURIComponent(room.id)}/messages?${query}`, { headers: authHeaders() });
        const data = await res.json();
        const fresh = data.messages || [];
        await Promise.all(fresh.map(async (m) => {
          m.content = await decryptContent(m.room_id, m.content);
          if (m.reply_preview) m.reply_preview = await decryptContent(m.room_id, m.reply_preview);
          if (m.file_url && m.file_url.endsWith(".enc") && (m.msg_type === "image" || m.msg_type === "audio")) {
            m.orig_file_url = m.file_url;
            m.file_url = await decryptMediaUrl(m.room_id, m.file_url, m.file_name);
          }
        }));
        if (!lastId && fresh.length >= 50) {
          const loadBtn = document.createElement("button");
          loadBtn.type = "button";
          loadBtn.className = "icon-btn";
          loadBtn.style.alignSelf = "center";
          loadBtn.textContent = "Load older messages";
          loadBtn.onclick = () => loadOlderMessages(loadBtn);
          messagesEl.prepend(loadBtn);
        }
        fresh.forEach(m => {
          if (!roomMessages.some(x => x.id === m.id)) appendMessage(m, true);
        });
        if (fresh.length > 0 || !cached) {
          messagesEl.scrollTop = messagesEl.scrollHeight;
          renderQuickFiles();
        }
        saveRoomCache(room.id, roomMessages);
      } catch {}

      if (document.getElementById("msg-search-bar").classList.contains("active")) {
        runRoomSearch();
      }
      sendMarkRead(room.id);
    }

    function renderBubbleInner(m) {
      const isMe = m.sender === me;
      let body = "";
      if (!isMe && activeRoom.isGroup) {
        body += `<div class="bubble-sender">${escapeHtml(m.sender)}</div>`;
      }
      if (m.deleted_for_all) {
        body += `<div class="deleted-msg">This message was deleted</div>`;
      } else {
        if (m.reply_to_id && m.reply_sender) {
          body += `<div class="reply-quote" onclick="scrollToMsg(${m.reply_to_id})">` +
            `<div class="reply-quote-sender">${escapeHtml(m.reply_sender)}</div>` +
            `<div class="reply-quote-text">${escapeHtml(m.reply_preview || "Attachment")}</div>` +
            `</div>`;
        }
        if (m.msg_type === "image" && m.file_url) {
          body += `<a href="${m.file_url}" target="_blank"><img src="${m.file_url}" alt="${escapeHtml(m.file_name || "image")}" /></a>`;
        } else if (m.msg_type === "audio" && m.file_url) {
          body += `<audio controls preload="metadata" src="${m.file_url}"></audio>`;
        } else if (m.msg_type === "file" && m.file_url) {
          const fname = m.file_name || "Download file";
          if (fname.toLowerCase().endsWith(".pdf")) {
            body += `<div class="pdf-actions">` +
              `<button type="button" class="file-link" onclick="openLazyPdf('${m.room_id}', '${m.file_url}', '${escapeHtml(fname)}')">📄 View ${escapeHtml(fname)}</button>` +
              `<button type="button" class="file-link" onclick="downloadLazyFile('${m.room_id}', '${m.file_url}', '${escapeHtml(fname)}')">Download</button>` +
              `</div>`;
          } else if (m.file_url.endsWith(".enc")) {
            body += `<button type="button" class="file-link" onclick="downloadLazyFile('${m.room_id}', '${m.file_url}', '${escapeHtml(fname)}')">📎 Download ${escapeHtml(fname)}</button>`;
          } else {
            body += `<a class="file-link" href="${m.file_url}" download="${escapeHtml(fname)}">${escapeHtml(fname)}</a>`;
          }
        }
        if (m.content) {
          body += `<div class="bubble-text">${escapeHtml(m.content)}</div>`;
        }
      }
      const editedTag = m.edited_at && !m.deleted_for_all ? `<span class="edited-tag">(edited)</span>` : "";
      body += `<div class="bubble-meta">${editedTag}<span>${escapeHtml((m.created_at || "").slice(11, 16))}</span>${isMe && !m.deleted_for_all ? ticksHtml(m.status) : ""}</div>`;
      return body;
    }

    function closeAllMenus() {
      document.querySelectorAll(".msg-row.menu-open").forEach(el => {
        el.classList.remove("menu-open", "menu-up");
      });
    }
    document.addEventListener("click", closeAllMenus);

    function appendMessage(m, skipExtras = false) {
      const isMe = m.sender === me;
      const row = document.createElement("div");
      row.className = "msg-row" + (isMe ? " me" : "");
      row.dataset.msgId = String(m.id);

      const bubbleWrap = document.createElement("div");
      bubbleWrap.style.display = "flex";
      bubbleWrap.style.flexDirection = "column";
      bubbleWrap.style.alignItems = isMe ? "flex-end" : "flex-start";

      const bubble = document.createElement("div");
      bubble.className = "bubble" + (isMe ? " me" : "");
      bubble.dataset.msgId = String(m.id);
      bubble.dataset.status = m.status || "sent";
      bubble.dataset.sender = m.sender;
      bubble.dataset.preview = m.content || (m.msg_type === "audio" ? "Voice note" : m.file_name || "Attachment");
      bubble.innerHTML = renderBubbleInner(m);
      bubbleWrap.appendChild(bubble);

      const rxBar = document.createElement("div");
      rxBar.className = "reaction-bar";
      rxBar.dataset.rxMsgId = String(m.id);
      renderReactionsInto(rxBar, m.id, m.reactions || {});
      bubbleWrap.appendChild(rxBar);

      row.appendChild(bubbleWrap);

      if (!m.deleted_for_all) {
        const trigger = document.createElement("button");
        trigger.type = "button";
        trigger.className = "menu-trigger";
        trigger.title = "Message options";
        trigger.textContent = "⋮";

        const menu = document.createElement("div");
        menu.className = "msg-menu";
        const emojis = ["👍", "❤️", "😂", "😮", "😢", "🙏"];
        let menuHtml = `<div class="menu-emojis">` +
          emojis.map(em => `<button type="button" onclick="reactMsg(${m.id}, '${em}')">${em}</button>`).join("") +
          `</div>`;
        menuHtml += `<button type="button" onclick="replyMsg(${m.id})">Reply</button>`;
        if (isMe && m.msg_type === "text") {
          menuHtml += `<button type="button" onclick="editMsg(${m.id})">Edit</button>`;
        }
        menuHtml += `<button type="button" onclick="deleteMsg(${m.id}, 'me')">Delete for me</button>`;
        if (isMe) {
          menuHtml += `<button type="button" class="danger" onclick="deleteMsg(${m.id}, 'everyone')">Delete for everyone</button>`;
        }
        menu.innerHTML = menuHtml;

        trigger.onclick = (e) => {
          e.stopPropagation();
          const wasOpen = row.classList.contains("menu-open");
          closeAllMenus();
          if (!wasOpen) {
            const rect = row.getBoundingClientRect();
            const spaceBelow = messagesEl.getBoundingClientRect().bottom - rect.bottom;
            if (spaceBelow < 130) row.classList.add("menu-up");
            row.classList.add("menu-open");
          }
        };

        row.appendChild(trigger);
        row.appendChild(menu);
      }

      messagesEl.appendChild(row);
      const existingIdx = roomMessages.findIndex(x => x.id === m.id);
      if (existingIdx >= 0) roomMessages[existingIdx] = m;
      else roomMessages.push(m);
      if (!skipExtras) {
        messagesEl.scrollTop = messagesEl.scrollHeight;
        renderQuickFiles();
        saveRoomCache(m.room_id || activeRoom.id, roomMessages);
      }
    }

    async function loadOlderMessages(btn) {
      if (roomMessages.length === 0) return;
      btn.disabled = true;
      btn.textContent = "Loading...";
      const oldestId = roomMessages[0].id;
      const res = await fetch(
        `/api/rooms/${encodeURIComponent(activeRoom.id)}/messages?limit=50&before_id=${oldestId}`,
        { headers: authHeaders() }
      );
      const data = await res.json();
      const older = data.messages || [];
      await Promise.all(older.map(async (m) => {
        m.content = await decryptContent(m.room_id, m.content);
        if (m.reply_preview) m.reply_preview = await decryptContent(m.room_id, m.reply_preview);
        if (m.file_url && m.file_url.endsWith(".enc") && (m.msg_type === "image" || m.msg_type === "audio")) {
          m.file_url = await decryptMediaUrl(m.room_id, m.file_url, m.file_name);
        }
      }));
      btn.remove();
      if (older.length > 0) {
        const prevHeight = messagesEl.scrollHeight;
        const saved = [...roomMessages];
        messagesEl.innerHTML = "";
        roomMessages = [];
        if (older.length >= 50) {
          const nextBtn = document.createElement("button");
          nextBtn.type = "button";
          nextBtn.className = "icon-btn";
          nextBtn.style.alignSelf = "center";
          nextBtn.textContent = "Load older messages";
          nextBtn.onclick = () => loadOlderMessages(nextBtn);
          messagesEl.appendChild(nextBtn);
        }
        [...older, ...saved].forEach(m => appendMessage(m, true));
        messagesEl.scrollTop = messagesEl.scrollHeight - prevHeight;
        renderQuickFiles();
      }
    }

    window.openLazyPdf = async (roomId, fileUrl, fname) => {
      const resolved = fileUrl.endsWith(".enc") ? await decryptMediaUrl(roomId, fileUrl, fname) : fileUrl;
      const viewUrl = resolved.startsWith("blob:") ? resolved : `${resolved}?inline=true`;
      openPdfViewer(viewUrl, fname, resolved);
    };

    window.downloadLazyFile = async (roomId, fileUrl, fname) => {
      const resolved = fileUrl.endsWith(".enc") ? await decryptMediaUrl(roomId, fileUrl, fname) : fileUrl;
      const a = document.createElement("a");
      a.href = resolved;
      a.download = fname || "download";
      document.body.appendChild(a);
      a.click();
      a.remove();
    };

    function renderReactionsInto(bar, msgId, reactions) {
      bar.innerHTML = "";
      Object.entries(reactions || {}).forEach(([emoji, count]) => {
        if (!count) return;
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "rx-chip";
        btn.textContent = `${emoji} ${count}`;
        btn.onclick = () => reactMsg(msgId, emoji);
        bar.appendChild(btn);
      });
    }

    const pdfModal = document.getElementById("pdf-modal");
    const pdfFrame = document.getElementById("pdf-frame");
    const pdfTitle = document.getElementById("pdf-title");
    const pdfDlLink = document.getElementById("pdf-download-link");
    const pdfTabLink = document.getElementById("pdf-newtab-link");

    window.openPdfViewer = (viewUrl, name, downloadUrl) => {
      pdfTitle.textContent = name || "Document.pdf";
      pdfFrame.src = viewUrl;
      pdfDlLink.href = downloadUrl || viewUrl;
      pdfDlLink.download = name || "document.pdf";
      pdfTabLink.href = viewUrl;
      pdfModal.classList.add("active");
    };

    document.getElementById("pdf-close-btn").onclick = () => {
      pdfModal.classList.remove("active");
      pdfFrame.src = "about:blank";
    };

    window.scrollToMsg = (id) => {
      const target = document.querySelector(`.msg-row[data-msg-id="${id}"]`);
      if (!target) return;
      target.scrollIntoView({ behavior: "smooth", block: "center" });
      target.classList.add("msg-highlight");
      setTimeout(() => target.classList.remove("msg-highlight"), 1200);
    };

    window.reactMsg = (id, emoji) => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "react", id, emoji }));
      }
    };

    window.replyMsg = (id) => {
      const bubble = document.querySelector(`.bubble[data-msg-id="${id}"]`);
      if (!bubble) return;
      const preview = (bubble.dataset.preview || "").slice(0, 90);
      replyTo = { id, sender: bubble.dataset.sender || "", preview };
      document.getElementById("reply-bar-sender").textContent = `Replying to ${replyTo.sender}`;
      document.getElementById("reply-bar-text").textContent = replyTo.preview;
      document.getElementById("reply-bar").classList.add("active");
      msgInput.focus();
    };

    document.getElementById("cancel-reply-btn").onclick = () => {
      replyTo = null;
      document.getElementById("reply-bar").classList.remove("active");
    };

    window.editMsg = async (id) => {
      const el = document.querySelector(`.bubble[data-msg-id="${id}"] .bubble-text`);
      const current = el ? el.textContent : "";
      const next = prompt("Edit message:", current);
      if (!next || !next.trim() || next.trim() === current) return;
      const payloadText = await encryptForRoom(activeRoom.id, next.trim());
      ws.send(JSON.stringify({ type: "edit_message", id, content: payloadText }));
    };

    window.deleteMsg = (id, scope) => {
      ws.send(JSON.stringify({ type: "delete_message", id, scope }));
    };

    function updateVisibleReceipts(status) {
      document.querySelectorAll(".bubble.me").forEach(el => {
        const cur = el.dataset.status || "sent";
        if (status === "read" || (status === "delivered" && cur === "sent")) {
          el.dataset.status = status;
          const meta = el.querySelector(".bubble-meta");
          const oldTicks = meta && meta.querySelector(".ticks");
          if (oldTicks) oldTicks.outerHTML = ticksHtml(status);
        }
      });
    }

    let sidebarFilter = "all";
    let sidebarQuery = "";
    const notifItems = [];

    function pushNotif(text) {
      const timeStr = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      notifItems.unshift({ text, timeStr });
      if (notifItems.length > 8) notifItems.pop();
      const feed = document.getElementById("notif-feed");
      if (!feed) return;
      feed.innerHTML = notifItems.map(n =>
        `<div class="notif-item"><div class="avatar-circle" style="width:28px;height:28px;font-size:0.75rem;">•</div>` +
        `<div><div>${escapeHtml(n.text)}</div><div class="notif-time">${n.timeStr}</div></div></div>`
      ).join("");
    }

    function renderSidebar() {
      const q = sidebarQuery.toLowerCase();
      const showGroups = sidebarFilter === "all" || sidebarFilter === "groups";
      const showDirect = sidebarFilter === "all" || sidebarFilter === "direct";

      document.getElementById("groups-label").style.display = showGroups ? "block" : "none";
      groupsList.style.display = showGroups ? "flex" : "none";
      document.getElementById("users-label").style.display = showDirect ? "block" : "none";
      usersList.style.display = showDirect ? "flex" : "none";

      groupsList.innerHTML = "";
      rooms.filter(r => !q || r.name.toLowerCase().includes(q)).forEach(r => {
        const el = document.createElement("div");
        el.className = "chat-item" + (activeRoom.id === r.id ? " active" : "");
        const count = unread[r.id] || 0;
        const init = (r.name[0] || "#").toUpperCase();
        el.innerHTML = `
          <div class="chat-item-left">
            <div class="avatar-circle">${escapeHtml(init)}</div>
            <div style="min-width:0;">
              <div class="chat-name"># ${escapeHtml(r.name)}</div>
              <div class="chat-sub">Group room</div>
            </div>
          </div>
          ${count ? `<span class="unread-pill">${count}</span>` : ""}
        `;
        el.onclick = () => selectRoom({ id: r.id, name: r.name, isGroup: true, createdBy: r.created_by || '', peer: null });
        groupsList.appendChild(el);
      });

      const others = users.filter(u => u.username !== me);
      usersList.innerHTML = "";
      others.filter(u => !q || u.username.toLowerCase().includes(q)).forEach(u => {
        const rid = dmRoomId(me, u.username);
        const el = document.createElement("div");
        el.className = "chat-item" + (activeRoom.id === rid ? " active" : "");
        const count = unread[rid] || 0;
        const init = (u.username[0] || "U").toUpperCase();
        el.innerHTML = `
          <div class="chat-item-left">
            <div class="avatar-circle">${escapeHtml(init)}<span class="status-dot ${u.online ? "" : "offline"}"></span></div>
            <div style="min-width:0;">
              <div class="chat-name">${escapeHtml(u.username)}</div>
              <div class="chat-sub">${u.online ? "Online" : "Offline"}</div>
            </div>
          </div>
          ${count ? `<span class="unread-pill">${count}</span>` : ""}
        `;
        el.onclick = () => selectRoom({ id: rid, name: u.username, isGroup: false, peer: u.username });
        usersList.appendChild(el);
      });

      const qp = document.getElementById("quick-people-list");
      if (qp) {
        qp.innerHTML = "";
        others.slice(0, 6).forEach(u => {
          const rid = dmRoomId(me, u.username);
          const row = document.createElement("div");
          row.className = "quick-person";
          const init = (u.username[0] || "U").toUpperCase();
          row.innerHTML = `
            <div class="chat-item-left">
              <div class="avatar-circle" style="width:30px;height:30px;font-size:0.78rem;">${escapeHtml(init)}<span class="status-dot ${u.online ? "" : "offline"}"></span></div>
              <div>
                <div class="chat-name" style="font-size:0.84rem;">${escapeHtml(u.username)}</div>
                <div class="chat-sub" style="font-size:0.7rem;">${u.online ? "Online" : "Offline"}</div>
              </div>
            </div>
          `;
          const btn = document.createElement("button");
          btn.type = "button";
          btn.className = "quick-chat-btn";
          btn.textContent = "Chat";
          btn.onclick = () => selectRoom({ id: rid, name: u.username, isGroup: false, peer: u.username });
          row.appendChild(btn);
          qp.appendChild(row);
        });
      }
    }

    document.querySelectorAll("#filter-tabs .filter-tab").forEach(btn => {
      btn.onclick = () => {
        document.querySelectorAll("#filter-tabs .filter-tab").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        sidebarFilter = btn.dataset.filter || "all";
        renderSidebar();
      };
    });
    document.getElementById("sidebar-search").addEventListener("input", (e) => {
      sidebarQuery = e.target.value.trim();
      renderSidebar();
    });

    function outboxKey() {
      return `lan_chat_outbox_${me}`;
    }

    function loadOutbox() {
      try { return JSON.parse(localStorage.getItem(outboxKey()) || "[]"); } catch { return []; }
    }

    function saveOutbox(items) {
      localStorage.setItem(outboxKey(), JSON.stringify(items));
    }

    function flushOutbox() {
      if (!ws || ws.readyState !== WebSocket.OPEN) return;
      const items = loadOutbox();
      if (items.length === 0) return;
      saveOutbox([]);
      document.querySelectorAll(".msg-row[data-queued='1']").forEach(el => el.remove());
      items.forEach(item => ws.send(JSON.stringify(item)));
    }

    function connectWS() {
      if (ws) ws.close();
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/ws/${encodeURIComponent(me)}?token=${encodeURIComponent(authToken)}`);
      ws.onopen = () => {
        flushOutbox();
        sendMarkRead(activeRoom.id);
      };
      ws.onmessage = async (evt) => {
        const data = JSON.parse(evt.data);
        if (data.type === "presence") {
          users = data.users;
          renderSidebar();
          if (activeRoom.isGroup && groupKeyCache[activeRoom.id]) {
            const kRes = await fetch(`/api/rooms/${encodeURIComponent(activeRoom.id)}/keys`, { headers: authHeaders() });
            const kData = await kRes.json();
            await shareGroupKeyWithNewMembers(activeRoom.id, kData.holders || []);
          }
        } else if (data.type === "group_keys_updated") {
          if (data.room_id === activeRoom.id && !groupKeyCache[data.room_id]) {
            await selectRoom(activeRoom, false);
          }
        } else if (data.type === "room_created") {
          if (!rooms.some(r => r.id === data.room.id)) {
            rooms.push(data.room);
            renderSidebar();
          }
        } else if (data.type === "typing") {
          if (data.room_id === activeRoom.id && data.sender !== me) {
            document.getElementById("active-room-status").textContent =
              data.is_typing ? `${data.sender} is typing...` : (activeRoom.isGroup ? "Group chat" : "Direct message");
          }
        } else if (data.type === "receipt") {
          if (data.room_id === activeRoom.id) {
            updateVisibleReceipts(data.status);
          }
        } else if (data.type === "message") {
          const msg = data.message;
          msg.content = await decryptContent(msg.room_id, msg.content);
          if (msg.reply_preview) msg.reply_preview = await decryptContent(msg.room_id, msg.reply_preview);
          if (msg.file_url && msg.file_url.endsWith(".enc") && (msg.msg_type === "image" || msg.msg_type === "audio")) {
            msg.file_url = await decryptMediaUrl(msg.room_id, msg.file_url, msg.file_name);
          }
          if (msg.room_id === activeRoom.id) {
            appendMessage(msg);
            if (msg.sender !== me) sendMarkRead(activeRoom.id);
          } else {
            unread[msg.room_id] = (unread[msg.room_id] || 0) + 1;
            renderSidebar();
          }
          if (msg.sender !== me) {
            notifyIncoming(msg);
          }
        } else if (data.type === "reaction_updated") {
          const bar = document.querySelector(`.reaction-bar[data-rx-msg-id="${data.id}"]`);
          if (bar) renderReactionsInto(bar, data.id, data.reactions || {});
        } else if (data.type === "message_edited") {
          const el = document.querySelector(`.bubble[data-msg-id="${data.id}"]`);
          if (el) {
            const textEl = el.querySelector(".bubble-text");
            if (textEl) textEl.textContent = await decryptContent(data.room_id, data.content);
            const meta = el.querySelector(".bubble-meta");
            if (meta && !meta.querySelector(".edited-tag")) {
              meta.insertAdjacentHTML("afterbegin", `<span class="edited-tag">(edited)</span>`);
            }
          }
        } else if (data.type === "message_deleted") {
          const row = document.querySelector(`.msg-row[data-msg-id="${data.id}"]`);
          if (row) {
            const bubble = row.querySelector(".bubble");
            if (bubble) bubble.innerHTML = `<div class="deleted-msg">This message was deleted</div>`;
            row.querySelectorAll(".menu-trigger, .msg-menu").forEach(n => n.remove());
          }
          const targetMsg = roomMessages.find(x => x.id === data.id);
          if (targetMsg) {
            targetMsg.deleted_for_all = 1;
            targetMsg.content = "";
            targetMsg.file_url = null;
            targetMsg.file_name = null;
          }
          renderQuickFiles();
        } else if (data.type === "message_hidden") {
          const row = document.querySelector(`.msg-row[data-msg-id="${data.id}"]`);
          if (row) row.remove();
          roomMessages = roomMessages.filter(x => x.id !== data.id);
          renderQuickFiles();
        } else if (data.type === "room_deleted") {
          rooms = rooms.filter(r => r.id !== data.room_id);
          renderSidebar();
          if (activeRoom.id === data.room_id) {
            selectRoom({ id: "group:general", name: "General", isGroup: true, createdBy: "", peer: null });
          }
        } else if (data.type === "webrtc_signal") {
          await handleWebRTCSignal(data);
        } else if (data.type === "error") {
          alert(data.detail || "Action not allowed.");
        }
      };
      ws.onclose = (evt) => {
        document.getElementById("active-room-status").textContent = "Reconnecting (messages will queue)...";
        if (evt.code !== 1008 && authToken) setTimeout(connectWS, 2000);
      };
    }

    async function enterApp(username, token) {
      me = username;
      authToken = token;
      localStorage.setItem("lan_chat_auth", JSON.stringify({ username, token }));
      document.getElementById("me-label").textContent = me;
      document.getElementById("me-avatar").firstChild.textContent = (me[0] || "U").toUpperCase();
      loginScreen.style.display = "none";
      appEl.style.display = "flex";
      if ("Notification" in window && Notification.permission === "default") {
        Notification.requestPermission().catch(() => {});
      }
      await ensureE2EEKeys();
      await loadRooms();
      const joinId = new URLSearchParams(location.search).get("join");
      if (joinId) {
        const targetRoom = rooms.find(r => r.id === joinId);
        if (targetRoom) {
          activeRoom = {
            id: targetRoom.id,
            name: targetRoom.name,
            isGroup: true,
            createdBy: targetRoom.created_by || "",
            peer: null,
          };
          history.replaceState(null, "", "/");
          await selectRoom(activeRoom, true);
        } else {
          await selectRoom(activeRoom, false);
        }
      } else {
        await selectRoom(activeRoom, false);
      }
      connectWS();
    }

    document.getElementById("login-form").onsubmit = async (e) => {
      e.preventDefault();
      loginError.textContent = "";
      const username = document.getElementById("username-input").value.trim();
      const pin = document.getElementById("pin-input").value.trim();
      const res = await fetch("/api/auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, pin }),
      });
      const data = await res.json();
      if (!res.ok) {
        loginError.textContent = data.detail || "Login failed.";
        return;
      }
      await enterApp(data.username, data.token);
    };

    document.getElementById("clear-chat-btn").onclick = async () => {
      const isOwnerGroup = activeRoom.isGroup && activeRoom.createdBy === me && activeRoom.id !== "group:general";
      const msg = isOwnerGroup
        ? `Delete group "${activeRoom.name}" for everyone?`
        : `Clear chat history in "${activeRoom.name}" for you?`;
      if (!confirm(msg)) return;
      const res = await fetch(
        `/api/rooms/${encodeURIComponent(activeRoom.id)}?delete_group=${isOwnerGroup}`,
        { method: "DELETE", headers: authHeaders() }
      );
      if (res.ok && !isOwnerGroup) {
        messagesEl.innerHTML = "";
      }
    };

    // In-Room Message Search
    const msgSearchBar = document.getElementById("msg-search-bar");
    const msgSearchInput = document.getElementById("msg-search-input");
    const msgSearchCount = document.getElementById("msg-search-count");
    let searchMatches = [];
    let searchIdx = -1;

    function clearSearchHighlights() {
      document.querySelectorAll(".msg-search-match, .msg-search-current").forEach(el => {
        el.classList.remove("msg-search-match", "msg-search-current");
      });
    }

    function runRoomSearch() {
      clearSearchHighlights();
      const q = msgSearchInput.value.trim().toLowerCase();
      searchMatches = [];
      searchIdx = -1;
      if (!q) {
        msgSearchCount.textContent = "0 / 0";
        return;
      }
      roomMessages.forEach(m => {
        if (m.deleted_for_all) return;
        const hay = `${m.content || ""} ${m.file_name || ""} ${m.sender || ""}`.toLowerCase();
        if (hay.includes(q)) {
          const row = document.querySelector(`.msg-row[data-msg-id="${m.id}"]`);
          if (row) {
            row.classList.add("msg-search-match");
            searchMatches.push(row);
          }
        }
      });
      if (searchMatches.length > 0) {
        searchIdx = searchMatches.length - 1;
        focusSearchMatch();
      } else {
        msgSearchCount.textContent = "0 / 0";
      }
    }

    function focusSearchMatch() {
      if (searchMatches.length === 0 || searchIdx < 0) return;
      searchMatches.forEach(el => el.classList.remove("msg-search-current"));
      const cur = searchMatches[searchIdx];
      cur.classList.add("msg-search-current");
      cur.scrollIntoView({ behavior: "smooth", block: "center" });
      msgSearchCount.textContent = `${searchIdx + 1} / ${searchMatches.length}`;
    }

    function toggleRoomSearch(forceOpen = null) {
      const open = forceOpen !== null ? forceOpen : !msgSearchBar.classList.contains("active");
      msgSearchBar.classList.toggle("active", open);
      if (open) {
        msgSearchInput.focus();
        runRoomSearch();
      } else {
        msgSearchInput.value = "";
        clearSearchHighlights();
        msgSearchCount.textContent = "0 / 0";
      }
    }

    document.getElementById("msg-search-btn").onclick = () => toggleRoomSearch();
    document.getElementById("msg-search-close").onclick = () => toggleRoomSearch(false);
    msgSearchInput.addEventListener("input", runRoomSearch);
    msgSearchInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && searchMatches.length > 0) {
        e.preventDefault();
        searchIdx = (searchIdx - 1 + searchMatches.length) % searchMatches.length;
        focusSearchMatch();
      } else if (e.key === "Escape") {
        toggleRoomSearch(false);
      }
    });
    document.getElementById("msg-search-prev").onclick = () => {
      if (searchMatches.length === 0) return;
      searchIdx = (searchIdx - 1 + searchMatches.length) % searchMatches.length;
      focusSearchMatch();
    };
    document.getElementById("msg-search-next").onclick = () => {
      if (searchMatches.length === 0) return;
      searchIdx = (searchIdx + 1) % searchMatches.length;
      focusSearchMatch();
    };
    document.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "f" && appEl.style.display === "flex") {
        e.preventDefault();
        toggleRoomSearch(true);
      }
    });

    // Shared Files / PDF & Media Vault
    const vaultModal = document.getElementById("vault-modal");
    const vaultListEl = document.getElementById("vault-list");
    const vaultSearchInput = document.getElementById("vault-search-input");
    let vaultTab = "all";

    function getRoomAttachments() {
      return roomMessages.filter(m => !m.deleted_for_all && m.file_url).slice().reverse();
    }

    function renderQuickFiles() {
      const qf = document.getElementById("quick-files-list");
      if (!qf) return;
      const files = getRoomAttachments();
      if (files.length === 0) {
        qf.innerHTML = `<div class="notif-item" style="color:var(--muted);">No files shared in this room yet.</div>`;
        return;
      }
      qf.innerHTML = "";
      files.slice(0, 4).forEach(m => {
        const fname = m.file_name || (m.msg_type === "audio" ? "Voice note" : "Attachment");
        const isPdf = fname.toLowerCase().endsWith(".pdf");
        const badge = isPdf ? "PDF" : (m.msg_type === "image" ? "IMG" : (m.msg_type === "audio" ? "MIC" : "DOC"));
        const item = document.createElement("div");
        item.className = "quick-person";
        item.innerHTML = `
          <div class="chat-item-left" style="min-width:0;flex:1;">
            <div class="vault-thumb" style="width:32px;height:32px;font-size:0.7rem;">${badge}</div>
            <div style="min-width:0;">
              <div class="chat-name" style="font-size:0.82rem;">${escapeHtml(fname)}</div>
              <div class="chat-sub" style="font-size:0.7rem;">by ${escapeHtml(m.sender)}</div>
            </div>
          </div>
        `;
        const actBtn = document.createElement("button");
        actBtn.type = "button";
        actBtn.className = "quick-chat-btn";
        if (isPdf) {
          actBtn.textContent = "View";
          actBtn.onclick = () => openLazyPdf(m.room_id, m.file_url, fname);
        } else {
          actBtn.textContent = "Open";
          actBtn.onclick = () => openVaultModal();
        }
        item.appendChild(actBtn);
        qf.appendChild(item);
      });
    }

    function renderVaultList() {
      const q = vaultSearchInput.value.trim().toLowerCase();
      const all = getRoomAttachments().filter(m => {
        const fname = (m.file_name || (m.msg_type === "audio" ? "Voice note" : "Attachment")).toLowerCase();
        if (q && !fname.includes(q) && !(m.sender || "").toLowerCase().includes(q)) return false;
        if (vaultTab === "docs") return m.msg_type === "file";
        if (vaultTab === "images") return m.msg_type === "image";
        if (vaultTab === "audio") return m.msg_type === "audio";
        return true;
      });

      if (all.length === 0) {
        vaultListEl.innerHTML = `<div style="padding:28px;text-align:center;color:var(--muted);font-size:0.9rem;">No matching files or media found in this room.</div>`;
        return;
      }

      vaultListEl.innerHTML = "";
      all.forEach(m => {
        const fname = m.file_name || (m.msg_type === "audio" ? "Voice note.webm" : "Attachment");
        const isPdf = fname.toLowerCase().endsWith(".pdf");
        const row = document.createElement("div");
        row.className = "vault-item";

        let thumbHtml = `<div class="vault-thumb">${isPdf ? "PDF" : (m.msg_type === "audio" ? "MIC" : "DOC")}</div>`;
        if (m.msg_type === "image") {
          thumbHtml = `<div class="vault-thumb"><img src="${m.file_url}" alt="${escapeHtml(fname)}" /></div>`;
        }

        let actionsHtml = "";
        if (isPdf) {
          actionsHtml += `<button type="button" class="primary-btn" style="padding:6px 12px;font-size:0.8rem;" onclick="openLazyPdf('${m.room_id}', '${m.file_url}', '${escapeHtml(fname)}')">View PDF</button>`;
        } else if (m.msg_type === "image") {
          actionsHtml += `<a class="icon-btn" href="${m.file_url}" target="_blank" style="text-decoration:none;">Open</a>`;
        }
        actionsHtml += `<button type="button" class="icon-btn" onclick="downloadLazyFile('${m.room_id}', '${m.file_url}', '${escapeHtml(fname)}')">Download</button>`;
        actionsHtml += `<button type="button" class="icon-btn" onclick="jumpFromVault(${m.id})">Jump</button>`;

        row.innerHTML = `
          <div class="vault-item-left">
            ${thumbHtml}
            <div class="vault-meta">
              <div class="vault-fname">${escapeHtml(fname)}</div>
              <div class="vault-sub">Shared by ${escapeHtml(m.sender)} • ${escapeHtml((m.created_at || "").slice(0, 16))}</div>
              ${m.msg_type === "audio" ? `<audio controls preload="metadata" src="${m.file_url}" style="height:30px;margin-top:4px;max-width:220px;"></audio>` : ""}
            </div>
          </div>
          <div class="vault-actions">${actionsHtml}</div>
        `;
        vaultListEl.appendChild(row);
      });
    }

    function openVaultModal() {
      document.getElementById("vault-room-title").textContent = `Shared Files — ${activeRoom.name}`;
      renderVaultList();
      vaultModal.classList.add("active");
    }

    window.jumpFromVault = (msgId) => {
      vaultModal.classList.remove("active");
      scrollToMsg(msgId);
    };

    document.getElementById("vault-btn").onclick = openVaultModal;
    document.getElementById("right-vault-btn").onclick = openVaultModal;
    document.getElementById("vault-close-btn").onclick = () => vaultModal.classList.remove("active");
    vaultSearchInput.addEventListener("input", renderVaultList);
    document.querySelectorAll("#vault-tabs .vault-tab").forEach(btn => {
      btn.onclick = () => {
        document.querySelectorAll("#vault-tabs .vault-tab").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        vaultTab = btn.dataset.vtab || "all";
        renderVaultList();
      };
    });

    const inviteModal = document.getElementById("invite-modal");
    const inviteUrlText = document.getElementById("invite-url-text");
    const inviteQrImg = document.getElementById("invite-qr-img");

    async function openInviteModal(title, joinRoomId = "") {
      document.getElementById("invite-modal-title").textContent = title;
      let baseUrl = location.origin;
      try {
        const res = await fetch("/api/network-info");
        const info = await res.json();
        if (info.primary_url) baseUrl = info.primary_url;
      } catch {}
      const url = joinRoomId ? `${baseUrl}/?join=${encodeURIComponent(joinRoomId)}` : baseUrl;
      inviteUrlText.textContent = url;
      inviteQrImg.src = `/api/qr.svg?url=${encodeURIComponent(url)}`;
      inviteModal.classList.add("active");
    }

    document.getElementById("invite-btn").onclick = () => openInviteModal("Invite via Hotspot / Wi-Fi");
    document.getElementById("group-invite-btn").onclick = () => {
      if (activeRoom && activeRoom.isGroup) {
        openInviteModal(`Invite to # ${activeRoom.name}`, activeRoom.id);
      }
    };
    document.getElementById("close-invite-btn").onclick = () => inviteModal.classList.remove("active");
    document.getElementById("copy-invite-btn").onclick = async () => {
      try {
        await navigator.clipboard.writeText(inviteUrlText.textContent);
        document.getElementById("copy-invite-btn").textContent = "Copied!";
        setTimeout(() => { document.getElementById("copy-invite-btn").textContent = "Copy URL"; }, 1500);
      } catch {}
    };

    document.getElementById("back-to-chats-btn").onclick = () => {
      appEl.classList.remove("chat-open");
    };

    document.getElementById("logout-btn").onclick = () => {
      localStorage.removeItem("lan_chat_auth");
      authToken = "";
      if (ws) ws.close();
      appEl.style.display = "none";
      loginScreen.style.display = "flex";
    };

    document.getElementById("new-group-btn").onclick = async () => {
      const name = prompt("New group name:");
      if (!name || !name.trim()) return;
      await fetch("/api/rooms", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ name: name.trim() }),
      });
    };

    msgInput.addEventListener("input", () => {
      if (!ws || ws.readyState !== WebSocket.OPEN) return;
      ws.send(JSON.stringify({ type: "typing", room_id: activeRoom.id, is_typing: true }));
      clearTimeout(typingTimer);
      typingTimer = setTimeout(() => {
        ws.send(JSON.stringify({ type: "typing", room_id: activeRoom.id, is_typing: false }));
      }, 1200);
    });

    document.getElementById("composer").onsubmit = async (e) => {
      e.preventDefault();
      const text = msgInput.value.trim();
      if (!text) return;
      const payloadText = await encryptForRoom(activeRoom.id, text);
      let replyPreviewPayload = replyTo ? replyTo.preview : null;
      if (replyTo) {
        replyPreviewPayload = await encryptForRoom(activeRoom.id, replyTo.preview);
      }
      const msgPayload = {
        type: "message",
        room_id: activeRoom.id,
        peer: activeRoom.peer,
        content: payloadText,
        msg_type: "text",
        reply_to_id: replyTo ? replyTo.id : null,
        reply_sender: replyTo ? replyTo.sender : null,
        reply_preview: replyPreviewPayload
      };
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(msgPayload));
      } else {
        const items = loadOutbox();
        items.push(msgPayload);
        saveOutbox(items);
        appendMessage({
          id: Date.now(),
          room_id: activeRoom.id,
          sender: me,
          content: text,
          msg_type: "text",
          status: "queued",
          created_at: new Date().toISOString().replace("T", " ").slice(0, 19),
        });
        const lastRow = messagesEl.lastElementChild;
        if (lastRow) lastRow.dataset.queued = "1";
      }
      msgInput.value = "";
      replyTo = null;
      document.getElementById("reply-bar").classList.remove("active");
    };

    const progressWrap = document.getElementById("upload-progress-wrap");
    const progressText = document.getElementById("upload-progress-text");
    const progressPct = document.getElementById("upload-progress-pct");
    const progressFill = document.getElementById("upload-progress-fill");

    function setUploadProgress(visible, label = "Uploading...", pct = 0) {
      progressWrap.classList.toggle("active", visible);
      progressText.textContent = label;
      progressPct.textContent = `${pct}%`;
      progressFill.style.width = `${pct}%`;
    }

    async function uploadEncryptedOrPlain(blobOrFile, filename) {
      const form = new FormData();
      const key = await getRoomAesKey(activeRoom.id);
      if (key) {
        setUploadProgress(true, `Encrypting ${filename}...`, 0);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const raw = await blobOrFile.arrayBuffer();
        const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, raw));
        const packed = new Uint8Array(12 + cipher.byteLength);
        packed.set(iv, 0);
        packed.set(cipher, 12);
        form.append("file", new Blob([packed], { type: "application/octet-stream" }), filename);
        form.append("e2ee", "true");
      } else {
        form.append("file", blobOrFile, filename);
        form.append("e2ee", "false");
      }

      setUploadProgress(true, `Uploading ${filename}...`, 0);
      return new Promise((resolve) => {
        const xhr = new XMLHttpRequest();
        xhr.open("POST", "/api/upload");
        xhr.setRequestHeader("X-Auth-Token", authToken);
        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable) {
            const pct = Math.round((e.loaded / e.total) * 100);
            setUploadProgress(true, `Uploading ${filename}...`, pct);
          }
        };
        xhr.onload = () => {
          setUploadProgress(false);
          let body = {};
          try { body = JSON.parse(xhr.responseText || "{}"); } catch {}
          resolve({ ok: xhr.status >= 200 && xhr.status < 300, status: xhr.status, data: body });
        };
        xhr.onerror = () => {
          setUploadProgress(false);
          resolve({ ok: false, status: 0, data: { detail: "Network error during upload." } });
        };
        xhr.send(form);
      });
    }

    async function uploadAndSendFile(file) {
      if (!file) return;
      const res = await uploadEncryptedOrPlain(file, file.name || "attachment");
      const uploaded = res.data;
      if (!res.ok) {
        alert(uploaded.detail || "Upload failed.");
        return;
      }
      ws.send(JSON.stringify({
        type: "message",
        room_id: activeRoom.id,
        peer: activeRoom.peer,
        content: "",
        msg_type: uploaded.msg_type,
        file_name: uploaded.file_name,
        file_url: uploaded.file_url,
        reply_to_id: replyTo ? replyTo.id : null,
        reply_sender: replyTo ? replyTo.sender : null,
        reply_preview: replyTo ? replyTo.preview : null
      }));
      replyTo = null;
      document.getElementById("reply-bar").classList.remove("active");
    }

    document.getElementById("attach-btn").onclick = () => fileInput.click();
    fileInput.onchange = async () => {
      await uploadAndSendFile(fileInput.files[0]);
      fileInput.value = "";
    };

    msgInput.addEventListener("paste", async (e) => {
      const items = (e.clipboardData && e.clipboardData.items) || [];
      for (const item of items) {
        if (item.type && item.type.startsWith("image/")) {
          e.preventDefault();
          const blob = item.getAsFile();
          if (blob) {
            const ext = (item.type.split("/")[1] || "png").split(";")[0];
            const named = new File([blob], `pasted_${Date.now()}.${ext}`, { type: item.type });
            await uploadAndSendFile(named);
          }
          break;
        }
      }
    });

    let soundEnabled = localStorage.getItem("lan_chat_sound") !== "off";
    const soundBtn = document.getElementById("sound-toggle-btn");
    const SVG_ICONS = {
      volOn: '<svg viewBox="0 0 24 24"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14"/><path d="M15.54 8.46a5 5 0 0 1 0 7.07"/></svg>',
      volOff: '<svg viewBox="0 0 24 24"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><line x1="23" y1="9" x2="17" y2="15"/><line x1="17" y1="9" x2="23" y2="15"/></svg>',
      micOn: '<svg viewBox="0 0 24 24"><path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="23"/><line x1="8" y1="23" x2="16" y2="23"/></svg>',
      micOff: '<svg viewBox="0 0 24 24"><line x1="1" y1="1" x2="23" y2="23"/><path d="M9 9v3a3 3 0 0 0 5.12 2.12M15 9.34V4a3 3 0 0 0-5.94-.6"/><path d="M17 16.95A7 7 0 0 1 5 12v-2m14 0v2a7 7 0 0 1-.11 1.23"/><line x1="12" y1="19" x2="12" y2="23"/><line x1="8" y1="23" x2="16" y2="23"/></svg>',
      screenShare: '<svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/><polyline points="9 10 12 7 15 10"/><line x1="12" y1="7" x2="12" y2="13"/></svg>',
      screenStop: '<svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/><line x1="9" y1="7" x2="15" y2="13"/><line x1="15" y1="7" x2="9" y2="13"/></svg>',
      fullscreen: '<svg viewBox="0 0 24 24"><path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"/></svg>',
      minimize: '<svg viewBox="0 0 24 24"><polyline points="4 14 10 14 10 20"/><polyline points="20 10 14 10 14 4"/><line x1="14" y1="10" x2="21" y2="3"/><line x1="3" y1="21" x2="10" y2="14"/></svg>',
      expand: '<svg viewBox="0 0 24 24"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>',
      hangup: '<svg viewBox="0 0 24 24"><path d="M10.68 13.31a16 16 0 0 0 3.41 2.6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7 2 2 0 0 1 1.72 2v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.42 19.42 0 0 1-3.33-2.67m-2.67-3.34a19.79 19.79 0 0 1-3.07-8.63A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91"/><line x1="23" y1="1" x2="1" y2="23"/></svg>',
      callAccept: '<svg viewBox="0 0 24 24"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/></svg>'
    };

    function updateSoundBtn() {
      soundBtn.innerHTML = soundEnabled ? SVG_ICONS.volOn : SVG_ICONS.volOff;
      soundBtn.title = soundEnabled ? "Sound: On (click to mute)" : "Muted (click to unmute)";
    }
    updateSoundBtn();
    soundBtn.onclick = () => {
      soundEnabled = !soundEnabled;
      localStorage.setItem("lan_chat_sound", soundEnabled ? "on" : "off");
      updateSoundBtn();
    };

    let sharedAudioCtx = null;
    function unlockAudio() {
      try {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (!AudioCtx) return;
        if (!sharedAudioCtx) sharedAudioCtx = new AudioCtx();
        if (sharedAudioCtx.state === "suspended") sharedAudioCtx.resume().catch(() => {});
      } catch {}
    }
    document.addEventListener("pointerdown", unlockAudio, { passive: true });
    document.addEventListener("keydown", unlockAudio, { passive: true });

    function playChime() {
      if (!soundEnabled) return;
      try {
        unlockAudio();
        if (!sharedAudioCtx) return;
        const ctx = sharedAudioCtx;
        if (ctx.state === "suspended") ctx.resume().catch(() => {});
        const now = ctx.currentTime;
        [587.33, 880].forEach((freq, idx) => {
          const osc = ctx.createOscillator();
          const gain = ctx.createGain();
          osc.type = "sine";
          osc.frequency.setValueAtTime(freq, now + idx * 0.09);
          gain.gain.setValueAtTime(0.14, now + idx * 0.09);
          gain.gain.exponentialRampToValueAtTime(0.001, now + idx * 0.09 + 0.18);
          osc.connect(gain);
          gain.connect(ctx.destination);
          osc.start(now + idx * 0.09);
          osc.stop(now + idx * 0.09 + 0.19);
        });
      } catch {}
    }

    function notifyIncoming(msg) {
      pushNotif(`${msg.sender} sent a message`);
      playChime();
      if (document.hidden && "Notification" in window && Notification.permission === "granted") {
        const preview = msg.content || (msg.msg_type === "audio" ? "Voice note" : msg.file_name || "Attachment");
        new Notification(`New message from ${msg.sender}`, { body: preview });
      }
    }

    let mediaRecorder = null;
    let audioChunks = [];
    let recStream = null;
    let recInterval = null;
    const recordBtn = document.getElementById("record-btn");

    recordBtn.onclick = async () => {
      if (mediaRecorder && mediaRecorder.state === "recording") {
        mediaRecorder.stop();
        return;
      }
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        alert("Microphone recording requires localhost or HTTPS in this browser.");
        return;
      }
      try {
        recStream = await navigator.mediaDevices.getUserMedia({ audio: true });
        audioChunks = [];
        mediaRecorder = new MediaRecorder(recStream);
        let seconds = 0;
        recordBtn.classList.add("recording");
        recordBtn.textContent = "⏹ 0s";
        recInterval = setInterval(() => {
          seconds += 1;
          recordBtn.textContent = `⏹ ${seconds}s`;
        }, 1000);

        mediaRecorder.ondataavailable = (e) => {
          if (e.data && e.data.size > 0) audioChunks.push(e.data);
        };
        mediaRecorder.onstop = async () => {
          clearInterval(recInterval);
          recordBtn.classList.remove("recording");
          recordBtn.innerHTML = SVG_ICONS.micOn;
          if (recStream) recStream.getTracks().forEach(t => t.stop());

          const blob = new Blob(audioChunks, { type: mediaRecorder.mimeType || "audio/webm" });
          if (blob.size === 0) return;
          const ext = (mediaRecorder.mimeType || "").includes("ogg") ? "ogg" : "webm";
          const res = await uploadEncryptedOrPlain(blob, `voice_${Date.now()}.${ext}`);
          const uploaded = res.data;
          if (!res.ok) {
            alert(uploaded.detail || "Voice upload failed.");
            return;
          }
          ws.send(JSON.stringify({
            type: "message",
            room_id: activeRoom.id,
            peer: activeRoom.peer,
            content: "",
            msg_type: uploaded.msg_type,
            file_name: uploaded.file_name,
            file_url: uploaded.file_url
          }));
        };
        mediaRecorder.start();
      } catch (err) {
        alert("Could not access microphone: " + (err.message || err));
      }
    };

    let pc = null;
    let callStream = null;
    let screenStream = null;
    let callPeer = null;
    let callIsVideo = false;
    let isSharingScreen = false;
    let pendingOffer = null;
    let pendingCandidates = [];
    let micMuted = false;

    async function flushPendingCandidates() {
      if (!pc || !pc.remoteDescription) return;
      while (pendingCandidates.length > 0) {
        const cand = pendingCandidates.shift();
        try { await pc.addIceCandidate(new RTCIceCandidate(cand)); } catch {}
      }
    }

    const callModal = document.getElementById("call-modal");
    const callPeerEl = document.getElementById("call-peer-name");
    const callStatusEl = document.getElementById("call-status");
    const callControlsEl = document.getElementById("call-controls");
    const callVideosEl = document.getElementById("call-videos");
    const remoteVideo = document.getElementById("remote-video");
    const localVideo = document.getElementById("local-video");

    function sendSignal(target, signal_type, payload = null, video = callIsVideo) {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "webrtc_signal", target, signal_type, payload, video }));
      }
    }

    let mobileShareInterval = null;

    function stopScreenShareTrackOnly() {
      if (mobileShareInterval) {
        clearInterval(mobileShareInterval);
        mobileShareInterval = null;
      }
      if (screenStream) {
        screenStream.getTracks().forEach(t => t.stop());
        screenStream = null;
      }
      isSharingScreen = false;
    }

    function startMobileImageShareStream() {
      return new Promise((resolve, reject) => {
        const picker = document.createElement("input");
        picker.type = "file";
        picker.accept = "image/*";
        picker.onchange = () => {
          const file = picker.files && picker.files[0];
          if (!file) { reject(new Error("No image selected")); return; }
          const img = new Image();
          img.onload = () => {
            const canvas = document.createElement("canvas");
            const maxDim = 1280;
            const scale = Math.min(1, maxDim / Math.max(img.width || 1, img.height || 1));
            canvas.width = Math.max(320, Math.round((img.width || 640) * scale));
            canvas.height = Math.max(240, Math.round((img.height || 480) * scale));
            const ctx = canvas.getContext("2d");
            const draw = () => {
              ctx.fillStyle = "#0f172a";
              ctx.fillRect(0, 0, canvas.width, canvas.height);
              ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
            };
            draw();
            mobileShareInterval = setInterval(draw, 250);
            const stream = canvas.captureStream ? canvas.captureStream(15) : null;
            if (!stream) { reject(new Error("Canvas stream not supported")); return; }
            resolve(stream);
          };
          img.onerror = () => reject(new Error("Could not load image"));
          img.src = URL.createObjectURL(file);
        };
        picker.click();
      });
    }

    function endCall(notifyPeer = true) {
      if (notifyPeer && callPeer) sendSignal(callPeer, "hangup");
      stopScreenShareTrackOnly();
      if (pc) { pc.close(); pc = null; }
      if (callStream) { callStream.getTracks().forEach(t => t.stop()); callStream = null; }
      remoteVideo.srcObject = null;
      localVideo.srcObject = null;
      callPeer = null;
      pendingOffer = null;
      pendingCandidates = [];
      micMuted = false;
      callModal.classList.remove("active", "minimized");
      const topMinBtn = document.getElementById("call-min-toggle-btn");
      topMinBtn.innerHTML = SVG_ICONS.minimize;
      topMinBtn.title = "Minimize call to view chats";
    }

    function toggleCallMinimized(forceMin = null) {
      const nextMin = forceMin !== null ? forceMin : !callModal.classList.contains("minimized");
      callModal.classList.toggle("minimized", nextMin);
      const topMinBtn = document.getElementById("call-min-toggle-btn");
      topMinBtn.innerHTML = nextMin ? SVG_ICONS.expand : SVG_ICONS.minimize;
      topMinBtn.title = nextMin ? "Expand Call" : "Minimize call to view chats";
      renderActiveCallControls();
    }
    document.getElementById("call-min-toggle-btn").onclick = () => toggleCallMinimized();

    async function toggleScreenShare() {
      if (!pc || !callPeer) return;
      if (isSharingScreen) {
        stopScreenShareTrackOnly();
        const camTrack = callStream ? callStream.getVideoTracks()[0] : null;
        const vSender = pc.getSenders().find(s => s.track && s.track.kind === "video");
        if (vSender && camTrack) {
          await vSender.replaceTrack(camTrack);
          localVideo.srcObject = callStream;
        } else {
          localVideo.srcObject = null;
          sendSignal(callPeer, "screen_stopped");
        }
        renderActiveCallControls();
        return;
      }
      try {
        const displayFn = (navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia)
          ? navigator.mediaDevices.getDisplayMedia.bind(navigator.mediaDevices)
          : (navigator.getDisplayMedia ? navigator.getDisplayMedia.bind(navigator) : null);

        if (displayFn) {
          screenStream = await displayFn({ video: true, audio: false });
        } else {
          // Mobile browser fallback (Android Chrome / iOS Safari do not expose OS getDisplayMedia to web pages):
          const useImage = confirm(
            "Mobile browsers block full OS screen capture. " +
            "Press OK to share a Screenshot / Image live on screen, or Cancel to switch to your Back Camera."
          );
          if (useImage) {
            screenStream = await startMobileImageShareStream();
          } else {
            screenStream = await navigator.mediaDevices.getUserMedia({
              video: { facingMode: { ideal: "environment" } },
              audio: false,
            });
          }
        }
        const screenTrack = screenStream.getVideoTracks()[0];
        if (!screenTrack) return;
        isSharingScreen = true;
        callIsVideo = true;
        callVideosEl.style.display = "flex";
        localVideo.srcObject = screenStream;

        screenTrack.onended = () => {
          if (isSharingScreen) toggleScreenShare();
        };

        const vSender = pc.getSenders().find(s => s.track && s.track.kind === "video");
        if (vSender) {
          await vSender.replaceTrack(screenTrack);
        } else {
          pc.addTrack(screenTrack, screenStream);
          const offer = await pc.createOffer();
          await pc.setLocalDescription(offer);
          sendSignal(callPeer, "renegotiate", offer, true);
        }
        renderActiveCallControls();
      } catch (err) {
        stopScreenShareTrackOnly();
        renderActiveCallControls();
      }
    }

    function renderActiveCallControls() {
      callControlsEl.innerHTML = "";
      const isMin = callModal.classList.contains("minimized");

      const muteBtn = document.createElement("button");
      muteBtn.type = "button";
      muteBtn.className = "icon-btn";
      muteBtn.innerHTML = micMuted ? SVG_ICONS.micOff : SVG_ICONS.micOn;
      muteBtn.title = micMuted ? "Unmute microphone" : "Mute microphone";
      muteBtn.onclick = () => {
        micMuted = !micMuted;
        if (callStream) callStream.getAudioTracks().forEach(t => { t.enabled = !micMuted; });
        renderActiveCallControls();
      };
      callControlsEl.appendChild(muteBtn);

      if (callIsVideo) {
        const screenBtn = document.createElement("button");
        screenBtn.type = "button";
        screenBtn.className = isSharingScreen ? "primary-btn" : "icon-btn";
        screenBtn.style.padding = "8px";
        screenBtn.style.borderRadius = "999px";
        screenBtn.innerHTML = isSharingScreen ? SVG_ICONS.screenStop : SVG_ICONS.screenShare;
        screenBtn.title = isSharingScreen ? "Stop Sharing Screen" : "Share Screen";
        screenBtn.onclick = toggleScreenShare;
        callControlsEl.appendChild(screenBtn);
      }

      if (callIsVideo && !isMin) {
        const fsBtn = document.createElement("button");
        fsBtn.type = "button";
        fsBtn.className = "icon-btn";
        fsBtn.innerHTML = SVG_ICONS.fullscreen;
        fsBtn.title = "Fullscreen";
        fsBtn.onclick = () => {
          if (remoteVideo.requestFullscreen) remoteVideo.requestFullscreen().catch(() => {});
          else if (callVideosEl.requestFullscreen) callVideosEl.requestFullscreen().catch(() => {});
        };
        callControlsEl.appendChild(fsBtn);
      }

      const minBtn = document.createElement("button");
      minBtn.type = "button";
      minBtn.className = "icon-btn";
      minBtn.innerHTML = isMin ? SVG_ICONS.expand : SVG_ICONS.minimize;
      minBtn.title = isMin ? "Expand call" : "Hide call & show chat";
      minBtn.onclick = () => toggleCallMinimized();
      callControlsEl.appendChild(minBtn);

      const hangBtn = document.createElement("button");
      hangBtn.type = "button";
      hangBtn.className = "danger-btn";
      hangBtn.style.padding = "8px 12px";
      hangBtn.style.borderRadius = "999px";
      hangBtn.innerHTML = SVG_ICONS.hangup;
      hangBtn.title = "Hang Up";
      hangBtn.onclick = () => endCall(true);
      callControlsEl.appendChild(hangBtn);
    }

    function createPeerConnection(peer) {
      const conn = new RTCPeerConnection({ iceServers: [] });
      conn.onicecandidate = (e) => {
        if (e.candidate) sendSignal(peer, "ice", e.candidate);
      };
      conn.ontrack = (e) => {
        if (e.track.kind === "video") {
          callIsVideo = true;
          callVideosEl.style.display = "flex";
          renderActiveCallControls();
        }
        if (e.streams && e.streams[0]) {
          remoteVideo.srcObject = e.streams[0];
        } else {
          const stream = remoteVideo.srcObject instanceof MediaStream ? remoteVideo.srcObject : new MediaStream();
          stream.addTrack(e.track);
          remoteVideo.srcObject = stream;
        }
        remoteVideo.play().catch(() => {});
      };
      conn.oniceconnectionstatechange = () => {
        const state = conn.iceConnectionState;
        if (state === "checking") {
          callStatusEl.textContent = "ICE: checking network path...";
        } else if (state === "connected" || state === "completed") {
          callStatusEl.textContent = isSharingScreen ? "Sharing screen • ICE: connected" : "ICE: connected";
        } else if (state === "failed") {
          callStatusEl.textContent = "ICE: failed (check Wi-Fi/hotspot firewall)";
        } else if (state === "disconnected") {
          callStatusEl.textContent = "ICE: disconnected";
        }
      };
      conn.onconnectionstatechange = () => {
        if (conn.connectionState === "closed") {
          endCall(false);
        }
      };
      return conn;
    }

    async function startCall(isVideo) {
      if (!activeRoom.peer) return;
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        alert("Calling requires HTTPS or 127.0.0.1 in this browser.");
        return;
      }
      try {
        callPeer = activeRoom.peer;
        callIsVideo = isVideo;
        callStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: isVideo });
        callVideosEl.style.display = isVideo ? "flex" : "none";
        localVideo.srcObject = isVideo ? callStream : null;

        pc = createPeerConnection(callPeer);
        callStream.getTracks().forEach(t => pc.addTrack(t, callStream));

        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        sendSignal(callPeer, "offer", offer, isVideo);

        callPeerEl.textContent = callPeer;
        callStatusEl.textContent = isVideo ? "Calling (Video)..." : "Calling (Voice)...";
        toggleCallMinimized(false);
        callModal.classList.add("active");
      } catch (err) {
        alert("Could not start call: " + (err.message || err));
        endCall(false);
      }
    }

    async function acceptIncomingCall() {
      if (!pendingOffer || !callPeer) return;
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        alert("Calling requires HTTPS or 127.0.0.1 in this browser.");
        sendSignal(callPeer, "reject");
        endCall(false);
        return;
      }
      try {
        try {
          callStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: callIsVideo });
        } catch {
          // Fallback to audio-only if recipient has no webcam (e.g., viewing someone's shared screen on a desktop PC)
          callStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
        }
        callVideosEl.style.display = callIsVideo ? "flex" : "none";
        localVideo.srcObject = (callStream && callStream.getVideoTracks().length > 0) ? callStream : null;

        pc = createPeerConnection(callPeer);
        callStream.getTracks().forEach(t => pc.addTrack(t, callStream));
        await pc.setRemoteDescription(new RTCSessionDescription(pendingOffer));
        await flushPendingCandidates();
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        sendSignal(callPeer, "answer", answer, callIsVideo);

        pendingOffer = null;
        callStatusEl.textContent = "Connected";
        renderActiveCallControls();
      } catch (err) {
        alert("Could not accept call: " + (err.message || err));
        endCall(true);
      }
    }

    async function handleWebRTCSignal(data) {
      const { from, signal_type, payload, video } = data;
      if (signal_type === "offer") {
        if (pc || pendingOffer) {
          sendSignal(from, "reject");
          return;
        }
        callPeer = from;
        callIsVideo = Boolean(video);
        pendingOffer = payload;
        callPeerEl.textContent = from;
        callStatusEl.textContent = callIsVideo ? "Incoming Video / Screen Call..." : "Incoming Voice Call...";
        callVideosEl.style.display = callIsVideo ? "flex" : "none";
        callControlsEl.innerHTML = "";

        const acceptBtn = document.createElement("button");
        acceptBtn.type = "button";
        acceptBtn.className = "primary-btn";
        acceptBtn.textContent = "Accept";
        acceptBtn.onclick = acceptIncomingCall;

        const rejectBtn = document.createElement("button");
        rejectBtn.type = "button";
        rejectBtn.className = "danger-btn";
        rejectBtn.textContent = "Decline";
        rejectBtn.onclick = () => {
          sendSignal(from, "reject");
          endCall(false);
        };
        callControlsEl.appendChild(acceptBtn);
        callControlsEl.appendChild(rejectBtn);
        callModal.classList.add("active");
        playChime();
      } else if (signal_type === "renegotiate" && pc) {
        callIsVideo = true;
        callVideosEl.style.display = "flex";
        await pc.setRemoteDescription(new RTCSessionDescription(payload));
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        sendSignal(from, "answer", answer, true);
        renderActiveCallControls();
      } else if (signal_type === "screen_stopped") {
        callStatusEl.textContent = "Screen sharing ended";
      } else if (signal_type === "answer" && pc) {
        await pc.setRemoteDescription(new RTCSessionDescription(payload));
        await flushPendingCandidates();
        callStatusEl.textContent = "ICE: connected";
      } else if (signal_type === "ice" && payload) {
        if (pc && pc.remoteDescription) {
          try { await pc.addIceCandidate(new RTCIceCandidate(payload)); } catch {}
        } else {
          pendingCandidates.push(payload);
        }
      } else if (signal_type === "hangup" || signal_type === "reject") {
        endCall(false);
      }
    }

    document.getElementById("voice-call-btn").onclick = () => startCall(false);
    document.getElementById("video-call-btn").onclick = () => startCall(true);

    // Swipe-down pull-to-refresh with floating circular spinner
    const pullCircle = document.getElementById("pull-refresh-circle");
    const pullSvg = pullCircle.querySelector("svg");
    let pullStartY = null;
    let pullDistance = 0;
    messagesEl.addEventListener("touchstart", (e) => {
      if (messagesEl.scrollTop <= 0 && e.touches.length === 1) {
        pullStartY = e.touches[0].clientY;
        pullCircle.style.transition = "none";
      } else {
        pullStartY = null;
      }
    }, { passive: true });
    messagesEl.addEventListener("touchmove", (e) => {
      if (pullStartY === null) return;
      pullDistance = e.touches[0].clientY - pullStartY;
      if (pullDistance > 8 && messagesEl.scrollTop <= 0) {
        const offset = Math.min(48, pullDistance * 0.45) - 48;
        const progress = Math.min(1, pullDistance / 80);
        pullCircle.style.opacity = String(progress);
        pullCircle.style.transform = `translate(-50%, ${offset + 48}px) scale(${0.8 + progress * 0.2})`;
        pullSvg.style.transform = `rotate(${Math.round(pullDistance * 2.5)}deg)`;
        pullCircle.classList.toggle("ready", pullDistance > 80);
      }
    }, { passive: true });
    messagesEl.addEventListener("touchend", () => {
      pullCircle.style.transition = "transform 0.18s ease, opacity 0.18s ease, color 0.15s ease";
      if (pullStartY !== null && pullDistance > 80 && messagesEl.scrollTop <= 0) {
        pullCircle.classList.add("ready", "spinning");
        pullCircle.style.opacity = "1";
        pullCircle.style.transform = "translate(-50%, 16px) scale(1)";
        pullSvg.style.transform = "";
        setTimeout(async () => {
          if ("caches" in window) {
            const keys = await caches.keys();
            await Promise.all(keys.filter(k => k.startsWith("lan-chat-shell")).map(k => caches.delete(k)));
          }
          location.reload();
        }, 180);
      } else {
        pullCircle.style.opacity = "0";
        pullCircle.style.transform = "translate(-50%, -48px) scale(0.8)";
        pullCircle.classList.remove("ready");
      }
      pullStartY = null;
      pullDistance = 0;
    });

    if ("serviceWorker" in navigator) {
      let refreshing = false;
      navigator.serviceWorker.addEventListener("controllerchange", () => {
        if (!refreshing) {
          refreshing = true;
          location.reload();
        }
      });
      navigator.serviceWorker.register("/sw.js", { updateViaCache: "none" })
        .then(reg => reg.update().catch(() => {}))
        .catch(() => {});
    }

    (async () => {
      const saved = localStorage.getItem("lan_chat_auth");
      if (!saved) return;
      try {
        const { username, token } = JSON.parse(saved);
        const test = await fetch("/api/rooms", { headers: { "X-Auth-Token": token } });
        if (test.ok) await enterApp(username, token);
        else localStorage.removeItem("lan_chat_auth");
      } catch {
        localStorage.removeItem("lan_chat_auth");
      }
    })();
  </script>
</body>
</html>
"""


def print_terminal_qr(url: str) -> None:
    try:
        import qrcode  # type: ignore

        qr = qrcode.QRCode(border=1)
        qr.add_data(url)
        qr.make(fit=True)
        print("\nScan to join from your phone:")
        qr.print_ascii(invert=True)
    except ImportError:
        print("  (Tip: run 'pip install qrcode' to show a scannable terminal QR code.)")


def start_mdns(lan_ip: str, port: int = 8000) -> tuple[Any, Any] | None:
    try:
        from zeroconf import ServiceInfo, Zeroconf  # type: ignore

        zc = Zeroconf(interfaces=[lan_ip])
        info = ServiceInfo(
            "_http._tcp.local.",
            "LAN Chat._http._tcp.local.",
            addresses=[socket.inet_aton(lan_ip)],
            port=port,
            server="chat.local.",
        )
        zc.register_service(info)
        return zc, info
    except ImportError:
        print("  (Tip: run 'pip install zeroconf' to enable http://chat.local:8000 discovery.)")
        return None
    except Exception as exc:
        print(f"  (mDNS disabled: {exc})")
        return None


def ensure_self_signed_cert(lan_ip: str, cert_file: Path, key_file: Path) -> bool:
    try:
        import datetime
        import ipaddress
        from cryptography import x509  # type: ignore
        from cryptography.hazmat.primitives import hashes, serialization  # type: ignore
        from cryptography.hazmat.primitives.asymmetric import rsa  # type: ignore
        from cryptography.x509.oid import NameOID  # type: ignore
    except ImportError:
        if cert_file.is_file() and key_file.is_file():
            return True
        print("  (Tip: run 'pip install cryptography' to auto-generate HTTPS certs for Mic support.)")
        return False

    target_ip = ipaddress.ip_address(lan_ip)
    if cert_file.is_file() and key_file.is_file():
        try:
            existing = x509.load_pem_x509_certificate(cert_file.read_bytes())
            san = existing.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            if target_ip in san.get_values_for_type(x509.IPAddress):
                return True
            print(f"  LAN IP changed to {lan_ip}; regenerating cert.pem...")
        except Exception:
            pass

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "chat.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    san_entries: list[x509.GeneralName] = [
        x509.DNSName("chat.local"),
        x509.IPAddress(target_ip),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
    ]
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"  Generated HTTPS cert.pem & key.pem for {lan_ip} and chat.local")
    return True


if __name__ == "__main__":
    port = 8000
    lan_ip = get_lan_ip()
    cert_file = BASE_DIR / "cert.pem"
    key_file = BASE_DIR / "key.pem"
    use_https = ensure_self_signed_cert(lan_ip, cert_file, key_file)
    scheme = "https" if use_https else "http"

    ip_url = f"{scheme}://{lan_ip}:{port}"
    mdns_handle = start_mdns(lan_ip, port)
    mdns_url = f"{scheme}://chat.local:{port}"

    all_ips = get_all_lan_ips()
    print("LAN Chat running on:")
    print(f"  Local:   {scheme}://127.0.0.1:{port}")
    if mdns_handle:
        print(f"  mDNS:    {mdns_url}")
    for idx, ip in enumerate(all_ips):
        label = "Network" if idx == 0 else "Alt IP "
        print(f"  {label}: {scheme}://{ip}:{port}")
    print_terminal_qr(ip_url)

    ssl_kwargs = (
        {"ssl_certfile": str(cert_file), "ssl_keyfile": str(key_file)}
        if use_https
        else {}
    )
    try:
        uvicorn.run(app, host="0.0.0.0", port=port, **ssl_kwargs)
    finally:
        if mdns_handle:
            zc, info = mdns_handle
            zc.unregister_service(info)
            zc.close()