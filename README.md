# 🎬 FamTube

**A secure, family-friendly video sharing platform** built with Python Flask. Share videos, go live, manage playlists, and stay connected with your loved ones — all in one private, self-hosted application.

---

## ✨ Features

### 📹 Video Sharing
- Upload videos in **MP4, WEBM, or OGG** format
- Automatically generate missing thumbnails from each video's first decodable frame (requires `ffmpeg` installed and available on `PATH`)
- Add **titles, captions, and hashtags** for easy discovery
- **Privacy controls**: Public or Private videos with allowed user lists
- **Magic byte validation** to prevent fake file uploads

### 🔴 Live Streaming
- Real-time **WebRTC-based** live broadcasting
- One-click start/stop with custom stream titles
- Admin can **force-end streams** instantly

> ℹ️ **HTTP works for ordinary use on a trusted home network.**
> You can run FamTube on a home PC/server and open `http://<server-LAN-IP>:5000` from your phone, tablet, or other home devices. By default, FamTube does not force HTTPS or send HSTS, so this mode does not get broken by transport-security redirects.
>
> **Important:** plain HTTP does not encrypt passwords, session cookies, or video traffic. Use it only on a trusted private LAN; do not expose port 5000 to the internet or use HTTP over public/untrusted Wi-Fi. Browser camera/microphone access for WebRTC live streaming still requires HTTPS, except when using `http://localhost:5000` on the same device.
>
> Need HTTPS for local or remote use? Use our companion tool [**http2https**](https://github.com/giriaryan694-a11y/http2https) for local development, or configure a properly managed HTTPS reverse proxy for a server deployment.

### 📱 PWA and installation

FamTube includes a web app manifest, 192×192 and 512×512 icons, and a privacy-conscious service worker. On a supported browser, open FamTube through HTTPS and use the browser's **Install app** or **Add to Home Screen** command. The installed app opens in a standalone window. When offline, it can show a generic reconnect page, but it does not store private pages, account data, video files, thumbnails, or API responses for offline access. Watching videos and using account features still requires the FamTube server and a network connection to it.

**HTTP LAN compatibility is preserved:** FamTube continues to work as a normal website at `http://<server-LAN-IP>:5000` on trusted home networks. However, browsers restrict service workers and full PWA installation to secure origins (HTTPS, or `localhost`/loopback for local development). On a phone connecting to another device's LAN IP over HTTP, PWA installation/offline support will therefore be unavailable; this is a browser security rule, not an HTTPS redirect in FamTube. To install on multiple home devices, serve FamTube through HTTPS with a certificate each device trusts. Do not expose plain HTTP to the internet or untrusted Wi-Fi.

### 🔔 Social Features
- **Subscribe** to family members and get notified of new uploads
- **Comments & Replies** with @mentions and like system
- **Save videos** to your personal collection
- **Playlists** — create and organize video collections
- **Watch History** with engagement tracking (total minutes watched)

### 🛡️ Admin Dashboard
- **IP Access Control** — blocklist / strict allowlist modes
- **Content Moderation** — hide/unhide or permanently delete videos
- **Live Stream Management** — kill active streams
- **Session Control** — revoke user sessions remotely (paginated, 7 per page)
- **User Management** — create, edit, rename, or delete users with 3 modes:
  - **Backup & Delete** — download all user videos before deletion
  - **Delete Everything** — remove user and all their content
  - **Keep Videos** — delete user but preserve their uploads
- **User Watch History** — detailed per-user engagement metrics
- **Activity Logging** — full audit trail of all actions

### 🎨 UI/UX
- **Light, Dark, and System themes** with a persistent cookie preference; theme selector is available on the login screen and authenticated pages, and System follows the device setting
- **Responsive, YouTube-inspired interface** — adaptive navigation, searchable header, video grids, and comfortable layouts across mobile, tablet, and desktop
- **PWA support** — installable app manifest, home-screen icons, standalone display, and a small offline fallback shell
- **Real-time notifications** via WebSocket with browser push support
- **Sidebar navigation** for quick access to all sections
- **Toast notifications** for live alerts

### 🧭 Interface and usability improvements
- Desktop navigation stays visible with a collapsible sidebar; mobile navigation uses a bottom bar and an accessible slide-out menu.
- Search can be opened directly from the mobile header, and the Light/Dark/System theme selector is available from the main navigation and the signed-out login header.
- Video player sizing, cards, form controls, tables, and notifications adapt to narrow screens and respect device safe areas.
- Private/hidden video media is checked at the media endpoint as well as in page listings, and video-related APIs validate access before updating saves, history, or engagement.

### 🔒 Security
- **CSRF Protection** on all forms
- **Rate Limiting** — 200/day, 50/hour default; 10/minute login; 10/hour upload
- **Secure session cookies** (HttpOnly, SameSite=Lax; Secure flag configurable for HTTPS)
- **Path traversal prevention** on all file operations
- **Content Security Policy (CSP)** via Flask-Talisman
- **Password hashing** with Werkzeug
- **File content validation** (magic bytes for images & videos)
- **Username validation** — 3-30 chars, alphanumeric + underscores only

---

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- pip

### Installation

```bash
# 1. Clone or download the project
git clone https://github.com/giriaryan694-a11y/FamTube
cd FamTube

# 2. Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python main.py
```

### First Login
On first startup, an **admin account** is auto-generated with a secure random password. Check your terminal console for:

```
=============================================================
🚨 SECURE ADMIN GENERATED
Username: admin
Password: <random-12-char-password>
=============================================================
```

**Log in immediately and change the admin password** via Settings → Credentials.

---

## 🔐 Enabling HTTPS for Live Streaming (WebRTC)

Browsers require a secure context (`https://` or `localhost`) to access camera and microphone for WebRTC live streaming.

### Option 1: Use http2https (Recommended for Local/Dev)

[**http2https**](https://github.com/giriaryan694-a11y/http2https) is a lightweight Python CLI tool that wraps your HTTP-only FamTube instance with HTTPS using auto-generated TLS certificates.

**Setup:**

```bash
# 1. Install http2https
git clone https://github.com/giriaryan694-a11y/http2https
cd http2https
pip install cryptography pyfiglet termcolor colorama requests

# 2. Start FamTube on its default port
#    (from the FamTube directory)
python main.py

# 3. In a new terminal, run http2https
python http2https.py
#    - Certificate Title: FamTubeDevCA
#    - Domains / IPs: localhost, 127.0.0.1
#    - Internal Port: 5000
#    - HTTPS Port: 8443

# 4. Open https://localhost:8443 in your browser
#    Trust the certificate when prompted for first use
```

> 📖 See the [http2https README](https://github.com/giriaryan694-a11y/http2https#trusting-the-certificate) for detailed certificate-trust instructions per OS.

### Option 2: Use localhost directly

If running FamTube on the same machine you are streaming from, simply open:

```
http://localhost:5000
```

`localhost` is treated as a secure context by browsers, so camera/microphone access is allowed without HTTPS.

### Option 3: Production HTTPS (Reverse Proxy)

For production or network access, place FamTube behind a reverse proxy (Nginx, Caddy, Traefik) with valid TLS certificates.

---

## ⚙️ Configuration

### Environment Variables
| Variable | Description | Default |
|----------|-------------|---------|
| `FAMTUBE_SECRET_KEY` | Stable Flask session/CSRF signing key. Strongly recommended in production. | Persistent local key file if unset |
| `FAMTUBE_SECRET_KEY_FILE` | Optional path for the persistent local signing-key file. | `famtube_admin/.secret_key` |
| `FAMTUBE_COOKIE_SECURE` | Set to `1`/`true` when served over HTTPS to mark session cookies Secure. | `0` for local HTTP development |

### File Storage (Auto-Created)
```
famtube_admin/
├── .secret_key      # Persistent local Flask session/CSRF signing key (keep private)
├── videos/          # Uploaded video files
├── profiles/        # Profile pictures
├── backups/         # User deletion backups
├── config.json      # IP filter settings
├── users.json       # User accounts
├── videos.json      # Video metadata
├── engagement.json  # Watch time tracking
├── comments.json    # Comments & replies
├── notifications.json
├── sessions.json    # Active sessions
├── playlists.json
├── saved_videos.json
├── watch_history.json
├── subscriptions.json
└── logs.json        # Activity audit trail
```

---

## 📋 User Guide

### For Family Members
1. **Login** with your username and password
2. **Upload** videos from the navbar (+ Upload button)
3. **Explore** videos by hashtag on the Explore page
4. **Subscribe** to family members to see their uploads in your feed
5. **Go Live** to start a real-time video stream *(requires HTTPS or localhost)*
6. **Save videos** and organize them into **Playlists**
7. **Check History** to revisit previously watched videos

### For Admins
1. Access **🛡️ Admin Dashboard** from the sidebar
2. **Create Users** with the built-in form (use `#` button to add content filters)
3. **Manage Videos** — review, hide, or delete inappropriate content
4. **Control Access** via IP filtering (blocklist or strict allowlist)
5. **Monitor Engagement** — see total watch time and video history per user
6. **End Streams** — force-stop any active live broadcast

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Python 3, Flask |
| Real-time | Flask-SocketIO (threading mode), WebRTC |
| Security | Flask-Talisman, Flask-Limiter, Flask-WTF, CSRFProtect |
| Frontend | Vanilla HTML/CSS/JS (Jinja2 templates) |
| Database | JSON file-based (no external DB required) |
| Media | HTML5 `<video>` with MP4/WebM/OGG support |

---

## 🔐 Security Notes

- **HTTP is intentionally supported for trusted home-LAN use** — start FamTube on the host, then visit `http://<server-LAN-IP>:5000` from devices on the same private network. The built-in secure response headers do not force HTTPS in this default mode. Plain HTTP is not encrypted, so never expose this setup to the internet or use it on an untrusted network.
- **PWA cache is deliberately narrow** — the service worker caches only the generic offline page and public app icons. It does not cache authenticated HTML, API calls, video media, thumbnails, uploads, or Socket.IO traffic, avoiding stale CSRF tokens and leakage of private content on shared devices. Full PWA features require HTTPS or local loopback as described above.
- **Use HTTPS for internet-facing or untrusted-network deployments** — set `FAMTUBE_COOKIE_SECURE=1` only when the browser-facing origin genuinely uses HTTPS. This opts into Secure cookies, HTTPS redirects, and HSTS. If TLS terminates at a reverse proxy, configure the proxy/app HTTPS boundary correctly and have the proxy set HSTS only for HTTPS responses.
- **Debug mode is disabled by the normal launcher** (`debug=False`, `use_reloader=False`); do not enable the interactive debugger on a network-accessible deployment
- **The built-in launcher is for local/small deployments**; use a production-capable deployment setup and valid TLS for internet-facing hosting
- **Socket.IO explicitly uses `threading` mode** and `simple-websocket` is included in `requirements.txt` for WebSocket transport.
- **Change the default admin password immediately**
- **Set `FAMTUBE_SECRET_KEY`** to a strong, stable secret in production and keep it identical across workers/instances. The development fallback is stored in `famtube_admin/.secret_key` so local restarts do not invalidate CSRF/session cookies. Back up and protect that file.
- **`FAMTUBE_COOKIE_SECURE` defaults to `0`** to preserve plain-HTTP access on a trusted home LAN. Set it to `1` only for a correctly configured HTTPS deployment; doing so enables the Secure cookie flag and Talisman's HTTPS/HSTS behavior. Do not set it for plain-HTTP access.
- **Response headers:** FamTube adds `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and a restrictive CSP (including `object-src`, `base-uri`, and `frame-ancestors`). CSP still allows inline scripts/styles because the existing UI uses them; that remaining trade-off is documented in code. HSTS is TLS-only and disabled by default for HTTP compatibility.
- **CSRF troubleshooting:** do not disable CSRF protection. Load the form with GET first, preserve cookies, use the same hostname consistently (for example, do not switch between `localhost` and `127.0.0.1`), avoid caching HTML that contains CSRF tokens, and keep the signing key stable across restarts/instances. Talisman's default `session_cookie_secure=True` can cause the browser to withhold the cookie over plain HTTP; FamTube now passes the explicit `FAMTUBE_COOKIE_SECURE` policy to Talisman so local HTTP and HTTPS production setups behave deliberately. The signing key is persisted in `famtube_admin/.secret_key` if `FAMTUBE_SECRET_KEY` is not set, so restarts do not invalidate every session and CSRF token. A custom CSRF error page gives recovery guidance without disabling protection.
- **IP Filtering** is disabled by default — enable it from the Admin Dashboard when needed
- All file uploads are validated by **magic bytes**, not just extensions
- For local WebRTC testing, use `http2https` or `localhost` to satisfy browser secure-context requirements

---

## Runtime requirements

Use Python 3.10 or newer and install the dependency requirements from `requirements.txt`. `ffmpeg` must also be installed and available on `PATH` for first-frame thumbnail generation.

---

## 🧪 Testing

Run the standard-library regression suite from the repository root:

```bash
python -m unittest discover -s tests -v
```

The tests use temporary directories and do not initialize or modify your real FamTube data. They cover path traversal checks, atomic JSON writes, the IP-filter denial path, video-signature validation, and generation of a missing thumbnail from the actual first frame. The thumbnail regression test is skipped automatically when `ffmpeg` is unavailable.

For a quick syntax check of the application itself, run `python -m py_compile main.py`. Install `requirements.txt` before launching the full web application.

---

## 📄 License

MIT License — Free for personal and family use.

---

**Made By Aryan Giri | giriaryan694-a11y**
