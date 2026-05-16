# 🎬 FamTube

**A secure, family-friendly video sharing platform** built with Python Flask. Share videos, go live, manage playlists, and stay connected with your loved ones — all in one private, self-hosted application.

---

## ✨ Features

### 📹 Video Sharing
- Upload videos in **MP4, WEBM, or OGG** format (up to 500MB)
- Add **titles, captions, and hashtags** for easy discovery
- **Privacy controls**: Public or Private videos with allowed user lists
- **Magic byte validation** to prevent fake file uploads

### 🔴 Live Streaming
- Real-time **WebRTC-based** live broadcasting
- One-click start/stop with custom stream titles
- Admin can **force-end streams** instantly

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
git clone <https://github.com/giriaryan694-a11y/FamTube
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
5. **Go Live** to start a real-time video stream
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

---

## 📄 License

MIT License — Free for personal and family use.

---

**Made By Aryan Giri | giriaryan694-a11y**
