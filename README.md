# 🎬 FamTube

**A secure, family-friendly video sharing platform** built with Python Flask. Share videos, go live, manage playlists, and stay connected with your loved ones — all in one private, self-hosted application.

---

## ✨ Features

### 📹 Video Sharing
- Upload videos in **MP4, WEBM, or OGG** format 
- Add **titles, captions, and hashtags** for easy discovery
- **Privacy controls**: Public or Private videos with allowed user lists
- **Magic byte validation** to prevent fake file uploads

### 🔴 Live Streaming
- Real-time **WebRTC-based** live broadcasting
- One-click start/stop with custom stream titles
- Admin can **force-end streams** instantly

> ⚠️ **HTTPS Required for Live Streaming**
> Your browser blocks camera/microphone on HTTP (except localhost). Please:
> - Access via `https://` (recommended)
> - Or use `http://localhost:5000` only
>
> Need HTTPS for local development? Use our companion tool [**http2https**](https://github.com/giriaryan694-a11y/http2https) to wrap your HTTP service with a local HTTPS reverse proxy and auto-generated TLS certificates.

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
- **Dark/Light mode** toggle with persistent cookie preference
- **Responsive design** — works on mobile, tablet, and desktop
- **Real-time notifications** via WebSocket with browser push support
- **Sidebar navigation** for quick access to all sections
- **Toast notifications** for live alerts

### 🔒 Security
- **CSRF Protection** on all forms
- **Rate Limiting** — 200/day, 50/hour default; 10/minute login; 10/hour upload
- **Secure session cookies** (HttpOnly, SameSite=Lax)
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
| `FAMTUBE_SECRET_KEY` | Flask session secret key | Auto-generated random |

### File Storage (Auto-Created)
```
famtube_admin/
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
| Real-time | Flask-SocketIO, WebRTC |
| Security | Flask-Talisman, Flask-Limiter, Flask-WTF, CSRFProtect |
| Frontend | Vanilla HTML/CSS/JS (Jinja2 templates) |
| Database | JSON file-based (no external DB required) |
| Media | HTML5 `<video>` with MP4/WebM/OGG support |

---

## 🔐 Security Notes

- **Always use HTTPS in production** — set `SESSION_COOKIE_SECURE = True` and `force_https=True` in Talisman
- **Change the default admin password immediately**
- **Set `FAMTUBE_SECRET_KEY`** to a fixed value in production to prevent session invalidation on restart
- **IP Filtering** is disabled by default — enable it from the Admin Dashboard when needed
- All file uploads are validated by **magic bytes**, not just extensions
- For local WebRTC testing, use `http2https` or `localhost` to satisfy browser secure-context requirements

---

## 📄 License

MIT License — Free for personal and family use.

---

**Made By Aryan Giri | giriaryan694-a11y**
