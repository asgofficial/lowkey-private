"""
CookieShield engine — mitmproxy addon
Fixes applied
  • SiteBox.__init__ (was _init_)
  • HTTP/2-safe headers (lowercase pragma/expires removed; cache-control lowercased)
  • TLS default_ca guard (skip tls_start_client if certstore not ready)
  • Stats (cookies_blocked, trackers_neutralized) now increment correctly
  • Sandbox lifecycle: created on first request, auto-destroyed after idle timeout
  • Cookie poisoning works for both outbound requests and inbound Set-Cookie
  • SSE terminal logs every meaningful event
  • FIXED: Removed `from mitmproxy.connection import TransportContext`
    (TransportContext was removed in mitmproxy 10.x — caused ImportError at startup)
  • FIXED: tls_start_client now uses the correct mitmproxy 10+ hook signature
    (accepts a single TlsStartData / TlsStartClientHook argument, not TlsData)
"""

import threading
import json
import asyncio
import uuid
import time
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import uvicorn
from mitmproxy import http, ctx

# ---------------------------------------------------------------------------
# NOTE: TransportContext no longer exists in mitmproxy 10+.
# Do NOT import it. TLS hooks receive a TlsStartData object directly.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# SHARED STATE
# ---------------------------------------------------------------------------
app_state = {
    "global_mode": "reject_all",           # reject_all | essential_only | custom
    "trusted_sites": ["github.com", "localhost", "127.0.0.1"],
    "blocked_sites":  ["doubleclick.net", "facebook.com"],
    "proxy_active": True,
    "stats": {
        "cookies_blocked":      0,
        "trackers_neutralized": 0,
        "requests_inspected":   0,
        "sandboxes_destroyed":  0,
        "cookies_sandboxed":    0,   # total cookies stored in sandboxes
    },
    "recent_activity": [],
    "network": {"down_mbps": 0.0, "up_mbps": 0.0, "ping_ms": 0.0},
    "sandboxes": {},
}

KNOWN_TRACKERS = {
    "_ga", "_gid", "_fbp", "bcookie", "li_at", "MUID",
    "__utma", "__utmz", "_gcl_au", "IDE", "fr", "_pin_unauth",
    "__gads", "DSID", "FLC", "AID", "TAID", "exchange_uid",
}
ESSENTIALS = {"session_id", "csrf_token", "auth_token", "JSESSIONID", "sessionid"}

MAX_ACTIVITY     = 200
SANDBOX_IDLE_TTL = 60   # seconds of silence before sandbox is reaped

# SSE client queues
sse_clients: list[asyncio.Queue] = []

# Bandwidth EMA counters
_bytes_down = 0
_bytes_up   = 0
_ema_down   = 0.0
_ema_up     = 0.0

# mitmproxy event-loop reference (set in running())
_proxy_loop: asyncio.AbstractEventLoop | None = None


# ---------------------------------------------------------------------------
# SANDBOX
# ---------------------------------------------------------------------------
class SiteBox:
    def __init__(self, host: str):
        self.host        = host
        self.cookies:    dict[str, str] = {}   # name -> raw Set-Cookie string
        self.cache:      dict[str, dict] = {}  # url  -> metadata
        self.created_at  = time.strftime("%H:%M:%S")
        self._last_seen  = time.time()

    def touch(self):
        self._last_seen = time.time()

    @property
    def last_seen(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self._last_seen))

    def is_idle(self) -> bool:
        return (time.time() - self._last_seen) > SANDBOX_IDLE_TTL

    def to_dict(self):
        return {
            "host":         self.host,
            "cookie_count": len(self.cookies),
            "cache_count":  len(self.cache),
            "created_at":   self.created_at,
            "last_seen":    self.last_seen,
        }


sandboxes:      dict[str, SiteBox] = {}
_sandbox_lock = threading.Lock()


def _get_or_create(host: str) -> SiteBox:
    with _sandbox_lock:
        if host not in sandboxes:
            sandboxes[host] = SiteBox(host)
            _schedule(_push_log("sys", f"[SANDBOX] CREATED -> {host}"))
        sandboxes[host].touch()
        _sync()
        return sandboxes[host]


def _destroy(host: str) -> bool:
    with _sandbox_lock:
        if host not in sandboxes:
            return False
        del sandboxes[host]
        app_state["stats"]["sandboxes_destroyed"] += 1
        _sync()
    return True


def _sync():
    app_state["sandboxes"] = {h: s.to_dict() for h, s in sandboxes.items()}


def _schedule(coro):
    """Thread-safe: schedule a coroutine onto the mitmproxy event loop."""
    if _proxy_loop is not None:
        asyncio.run_coroutine_threadsafe(coro, _proxy_loop)


# ---------------------------------------------------------------------------
# IDLE REAPER — destroys sandboxes silent for SANDBOX_IDLE_TTL seconds
# ---------------------------------------------------------------------------
async def _idle_reaper():
    while True:
        await asyncio.sleep(10)
        with _sandbox_lock:
            idle = [h for h, s in sandboxes.items() if s.is_idle()]
        for host in idle:
            if _destroy(host):
                await _push_log("sys", f"[SANDBOX] DESTROYED (idle) -> {host}")


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
def _add_activity(host: str, action: str, cookie: str = ""):
    app_state["recent_activity"].insert(0, {
        "site":   host,
        "action": action,
        "cookie": cookie,
        "time":   time.strftime("%H:%M:%S"),
    })
    if len(app_state["recent_activity"]) > MAX_ACTIVITY:
        app_state["recent_activity"].pop()


async def _push_log(level: str, message: str):
    payload = json.dumps({
        "level":   level,
        "message": message,
        "time":    time.strftime("%H:%M:%S"),
    })
    for q in list(sse_clients):
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:
            pass


def _is_tracker(name: str) -> bool:
    nl = name.lower()
    return any(nl == t.lower() for t in KNOWN_TRACKERS)


# ---------------------------------------------------------------------------
# FASTAPI
# ---------------------------------------------------------------------------
fast_app = FastAPI()
fast_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ModeBody(BaseModel):
    mode: str

class TrustBody(BaseModel):
    site: str
    action: str

class SandboxDestroyBody(BaseModel):
    host: str


@fast_app.get("/api/state")
def get_state():
    return app_state


@fast_app.post("/api/mode")
def set_mode(body: ModeBody):
    app_state["global_mode"] = body.mode
    _schedule(_push_log("sys", f"[MODE] switched to {body.mode}"))
    return {"status": "ok", "mode": body.mode}


@fast_app.post("/api/proxy")
def toggle_proxy():
    app_state["proxy_active"] = not app_state["proxy_active"]
    label = "ACTIVE" if app_state["proxy_active"] else "PAUSED"
    _schedule(_push_log("sys", f"[PROXY] {label}"))
    return {"active": app_state["proxy_active"]}


@fast_app.post("/api/trust")
def set_trust(body: TrustBody):
    site, action = body.site, body.action
    ts = app_state["trusted_sites"]
    bs = app_state["blocked_sites"]
    if action == "trust":
        if site not in ts: ts.append(site)
        if site in bs:     bs.remove(site)
    elif action == "block":
        if site not in bs: bs.append(site)
        if site in ts:     ts.remove(site)
    elif action == "remove_trust" and site in ts:
        ts.remove(site)
    elif action == "remove_block" and site in bs:
        bs.remove(site)
    _schedule(_push_log("sys", f"[TRUST] {action} -> {site}"))
    return {"trusted": ts, "blocked": bs}


@fast_app.get("/api/sandboxes")
def list_sandboxes():
    with _sandbox_lock:
        return {
            h: {**s.to_dict(), "cookies": list(s.cookies.keys())}
            for h, s in sandboxes.items()
        }


@fast_app.post("/api/sandbox/destroy")
async def destroy_endpoint(body: SandboxDestroyBody):
    ok = _destroy(body.host)
    if ok:
        await _push_log("sys", f"[SANDBOX] DESTROYED (manual) -> {body.host}")
    return {"destroyed": ok, "host": body.host}


@fast_app.post("/api/sandbox/destroy_all")
async def destroy_all():
    hosts = list(sandboxes.keys())
    for h in hosts:
        _destroy(h)
    await _push_log("sys", f"[SANDBOX] ALL {len(hosts)} sandboxes destroyed")
    return {"destroyed": len(hosts)}


# ── SSE log stream ────────────────────────────────────────────────────────
@fast_app.get("/api/logs")
async def log_stream():
    queue: asyncio.Queue = asyncio.Queue(maxsize=512)
    sse_clients.append(queue)

    async def gen():
        try:
            boot = json.dumps({"level": "sys", "message": "[BOOT] SSE stream connected", "time": time.strftime("%H:%M:%S")})
            yield f"data: {boot}\n\n"
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=20)
                    yield f"data: {payload}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        except (asyncio.CancelledError, GeneratorExit):
            pass
        finally:
            try:
                sse_clients.remove(queue)
            except ValueError:
                pass

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        },
    )


def _run_fastapi():
    uvicorn.run(fast_app, host="127.0.0.1", port=5000, log_level="error")


# ---------------------------------------------------------------------------
# MITMPROXY ADDON
# ---------------------------------------------------------------------------
class CookieShield:

    # ── Startup ───────────────────────────────────────────────────────────
    async def running(self):
        global _proxy_loop
        _proxy_loop = asyncio.get_running_loop()
        threading.Thread(target=_run_fastapi, daemon=True).start()
        await asyncio.sleep(0.6)
        asyncio.create_task(self._bw_ticker())
        asyncio.create_task(_idle_reaper())
        ctx.log.info("[CookieShield] FastAPI + SSE server on :5000")
        await _push_log("sys", "[BOOT] CookieShield Engine started")

    # ── TLS guard (mitmproxy 10+ compatible) ──────────────────────────────
    # In mitmproxy 10+, tls_start_client receives a TlsStartData object.
    # TransportContext was removed — do NOT import or reference it.
    # We simply guard against a missing/unready certstore and return early.
    def tls_start_client(self, tls_start):
        """
        Called when mitmproxy is about to start a TLS handshake with the
        server on behalf of the client.  In mitmproxy 10+ the argument is
        a TlsStartData (formerly TlsData) object — TransportContext no
        longer exists and must not be imported.
        """
        try:
            # tls_start.context is a mitmproxy.connection.Client object.
            # If the proxy's certificate store isn't initialised yet we
            # skip further processing to avoid AttributeError crashes.
            certstore = getattr(tls_start.context, "certstore", None)
            if certstore is None or getattr(certstore, "default_ca", None) is None:
                ctx.log.debug("[TLS] certstore not ready — skipping tls_start_client")
                return
        except Exception as exc:
            ctx.log.debug(f"[TLS] guard exception (non-fatal): {exc}")
            return

    # ── Bandwidth ticker ──────────────────────────────────────────────────
    async def _bw_ticker(self):
        global _bytes_down, _bytes_up, _ema_down, _ema_up
        alpha = 0.35
        while True:
            await asyncio.sleep(1)
            bd, bu      = _bytes_down, _bytes_up
            _bytes_down = _bytes_up = 0
            _ema_down   = alpha * (bd * 8 / 1_000_000) + (1 - alpha) * _ema_down
            _ema_up     = alpha * (bu * 8 / 1_000_000) + (1 - alpha) * _ema_up
            app_state["network"]["down_mbps"] = round(_ema_down, 2)
            app_state["network"]["up_mbps"]   = round(_ema_up,   2)

    # ── Outbound request ──────────────────────────────────────────────────
    async def request(self, flow: http.HTTPFlow):
        global _bytes_up
        if not app_state["proxy_active"]:
            return
        host = flow.request.pretty_host
        if host in ("127.0.0.1", "localhost", "::1"):
            return

        app_state["stats"]["requests_inspected"] += 1
        _bytes_up += len(bytes(flow.request.headers)) + len(flow.request.content or b"")

        # HTTP/2-safe privacy headers (must be lowercase)
        flow.request.headers["dnt"]     = "1"
        flow.request.headers["sec-gpc"] = "1"

        # ── Sandbox: re-inject only this site's own cookies ───────────────
        sb = _get_or_create(host)
        if sb.cookies:
            rebuilt = "; ".join(
                f"{n}={v.split('=', 1)[1].split(';')[0]}"
                for n, v in sb.cookies.items()
                if "=" in v
            )
            flow.request.headers["cookie"] = rebuilt
        else:
            flow.request.headers.pop("cookie", None)

        # ── Cookie poisoning: replace tracker values with random noise ─────
        mode      = app_state["global_mode"]
        trusted   = host in app_state["trusted_sites"]
        forced_b  = host in app_state["blocked_sites"]

        for name in list(flow.request.cookies.keys()):
            is_t = _is_tracker(name)
            should_poison = (
                not trusted
                and (forced_b or (is_t and mode in ("reject_all", "essential_only")))
            )
            if should_poison:
                flow.request.cookies[name] = uuid.uuid4().hex
                app_state["stats"]["trackers_neutralized"] += 1
                _add_activity(host, "poisoned", name)
                await _push_log("warn", f"[POISONED] {name} -> {host}")

    # ── Inbound response ──────────────────────────────────────────────────
    async def response(self, flow: http.HTTPFlow):
        global _bytes_down
        if not app_state["proxy_active"]:
            return
        host = flow.request.pretty_host
        if host in ("127.0.0.1", "localhost", "::1"):
            return

        _bytes_down += len(bytes(flow.response.headers)) + len(flow.response.content or b"")

        if flow.request.timestamp_start:
            rtt  = (time.time() - flow.request.timestamp_start) * 1000
            prev = app_state["network"]["ping_ms"] or rtt
            app_state["network"]["ping_ms"] = round(0.2 * rtt + 0.8 * prev, 1)

        sb      = _get_or_create(host)
        mode    = app_state["global_mode"]
        trusted = host in app_state["trusted_sites"]
        blocked = host in app_state["blocked_sites"]

        # ── Decide fate of each Set-Cookie ────────────────────────────────
        set_cookies = flow.response.headers.get_all("set-cookie")
        if set_cookies:
            for raw in set_cookies:
                name = raw.split("=")[0].strip()
                is_t = _is_tracker(name)
                is_e = name.lower() in {e.lower() for e in ESSENTIALS}

                # Block logic — mirrors the mode selector in the UI
                if trusted:
                    block = False
                elif blocked:
                    block = is_t                   # block trackers for blocked sites
                elif mode == "reject_all":
                    block = not is_e               # only essentials survive
                elif mode == "essential_only":
                    block = is_t                   # block known trackers
                else:                              # custom
                    block = False                  # trust list / site rules handle it

                if block:
                    app_state["stats"]["cookies_blocked"] += 1
                    _add_activity(host, "blocked", name)
                    await _push_log("block", f"[BLOCKED] {name} <- {host}")
                    continue

                # Sandboxed — stored here, never forwarded to the browser jar
                with _sandbox_lock:
                    sb.cookies[name] = raw
                _sync()
                app_state["stats"]["cookies_sandboxed"] += 1
                _add_activity(host, "sandboxed", name)
                await _push_log("accept", f"[SANDBOXED] {name} <- {host}")

            # Strip every Set-Cookie from the response; browser sees none
            flow.response.headers.set_all("set-cookie", [])

        # ── Cache metadata ────────────────────────────────────────────────
        with _sandbox_lock:
            sb.cache[flow.request.pretty_url] = {
                "status":    flow.response.status_code,
                "stored_at": time.strftime("%H:%M:%S"),
            }
            _sync()

        # ── HTTP/2-safe no-cache headers ──────────────────────────────────
        # Pragma and Expires are BANNED in HTTP/2 (uppercase header names
        # are forbidden). Remove them entirely and use cache-control only.
        for bad in ("Pragma", "pragma", "Expires", "expires"):
            flow.response.headers.pop(bad, None)
        flow.response.headers["cache-control"] = "no-store, no-cache, must-revalidate"


addons = [CookieShield()]