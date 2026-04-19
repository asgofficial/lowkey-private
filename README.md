# LowKeyPrivate — Universal Consent Manager

A transparent proxy-based cookie firewall built on mitmproxy + Electron.

---

## Architecture

```
Browser (Electron)
    ↓  all HTTP/S traffic
mitmproxy :8080          ← CookieShield engine  (engine.py)
    │
    └── FastAPI  :5000   ← REST API  +  SSE log stream  (GET /api/logs)
```

The frontend (`index.html`) connects to the SSE stream with a native
`EventSource('http://127.0.0.1:5000/api/logs')` — no extra library needed.

---

## Setup

### 1. Install Python dependencies
```bash
pip install mitmproxy fastapi uvicorn
```

> **Note:** `flask`, `flask-cors`, and `websockets` are NOT needed.  
> The engine uses FastAPI + uvicorn with Server-Sent Events.

### 2. Install Node / Electron dependencies
```bash
npm install
```

### 3. Trust the mitmproxy CA certificate (required for HTTPS inspection)

Run mitmproxy once so it generates its self-signed CA:
```bash
mitmdump --listen-port 8080
```
Then install the generated certificate:

| OS | Location | Action |
|----|----------|--------|
| **macOS** | `~/.mitmproxy/mitmproxy-ca-cert.pem` | Keychain Access → trust for SSL |
| **Linux** | `~/.mitmproxy/mitmproxy-ca-cert.pem` | Follow your distro's CA install steps |
| **Windows** | `%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.p12` | Double-click → install to Trusted Root |

### 4. Run the app
```bash
npm start
```

The Electron app will:
1. Spawn `mitmdump -s engine.py --listen-port 8080 --ssl-insecure`
2. The `CookieShield.running()` hook starts FastAPI (uvicorn) on port 5000
3. Electron routes all its traffic through `127.0.0.1:8080`  
   (loopback addresses bypass the proxy so the UI can reach the API directly)
4. Load `index.html` which polls `/api/state` every 2 s and subscribes to `/api/logs` via SSE

---

## Running the engine standalone (no Electron)
```bash
mitmdump -s engine.py --listen-port 8080
```
Then open `index.html` directly in any browser (configure the browser's proxy
to `127.0.0.1:8080` manually).

---

## Protection Modes

| Mode | Outbound (request) | Inbound (Set-Cookie) |
|---|---|---|
| **Reject All** | Poisons all known tracker cookies | Drops all tracker Set-Cookie headers |
| **Essential Only** | Poisons trackers, keeps session/auth | Drops trackers, keeps essentials |
| **Custom** | Respects per-site trust/block list | Drops only from explicitly blocked hosts |

Trusted sites always bypass all cookie filtering.

---

## Ports

| Port | Service |
|------|---------|
| 8080 | mitmproxy intercept proxy |
| 5000 | FastAPI REST API + SSE log stream (`GET /api/logs`) |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Proxy pill stays OFF | mitmproxy not found | `pip install mitmproxy`, ensure `mitmdump` is on your PATH |
| SSE terminal says "Retrying…" | FastAPI not started yet | Wait 2–3 s after launch; engine starts async |
| HTTPS sites show SSL error | CA cert not trusted | Re-do Step 3 above |
| `npm start` fails | Electron not installed | Run `npm install` first |
| Port 5000 already in use | Another process on 5000 | `lsof -i :5000` and kill it, or change the port in `engine.py` + `index.html` |
