import os
import json
import datetime
import uuid
import secrets
import re
import shutil
import subprocess
import threading
from functools import wraps
from flask import Flask, request, session, redirect, url_for, render_template, jsonify, abort, send_from_directory, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from jinja2 import DictLoader
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_socketio import SocketIO, emit

app = Flask(__name__)
# Never expose Werkzeug's interactive debugger or automatic reloader from the normal launcher.
app.config['DEBUG'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = False
app.secret_key = os.environ.get('FAMTUBE_SECRET_KEY', secrets.token_urlsafe(32))
app.permanent_session_lifetime = datetime.timedelta(days=365)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"], storage_uri="memory://")
csrf = CSRFProtect(app)

csp = {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
    'style-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", "data:", "blob:"],
    'media-src': ["'self'", "blob:"]
}
talisman = Talisman(app, content_security_policy=csp, force_https=False)
socketio = SocketIO(app, cors_allowed_origins=None, max_http_buffer_size=1_000_000)

online_users = {}
user_status = {}
live_streams = {}
stream_viewers = {}

ADMIN_DIR = 'famtube_admin'
VIDEO_DIR = os.path.join(ADMIN_DIR, 'videos')
THUMBNAIL_DIR = os.path.join(ADMIN_DIR, 'thumbnails')
PROFILE_DIR = os.path.join(ADMIN_DIR, 'profiles')
BACKUP_DIR = os.path.join(ADMIN_DIR, 'backups')

CONFIG_FILE = os.path.join(ADMIN_DIR, 'config.json')
USERS_FILE = os.path.join(ADMIN_DIR, 'users.json')
LOGS_FILE = os.path.join(ADMIN_DIR, 'logs.json')
VIDEOS_FILE = os.path.join(ADMIN_DIR, 'videos.json')
ENGAGE_FILE = os.path.join(ADMIN_DIR, 'engagement.json')
COMMENTS_FILE = os.path.join(ADMIN_DIR, 'comments.json')
NOTIFS_FILE = os.path.join(ADMIN_DIR, 'notifications.json')
SESSIONS_FILE = os.path.join(ADMIN_DIR, 'sessions.json')
PLAYLISTS_FILE = os.path.join(ADMIN_DIR, 'playlists.json')
SAVED_FILE = os.path.join(ADMIN_DIR, 'saved_videos.json')
HISTORY_FILE = os.path.join(ADMIN_DIR, 'watch_history.json')
SUBS_FILE = os.path.join(ADMIN_DIR, 'subscriptions.json')

ALLOWED_EXTENSIONS = {'mp4', 'webm', 'ogg'}
ALLOWED_PICS = {'png', 'jpg', 'jpeg', 'webp'}
USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_]{3,30}$')

for d in [ADMIN_DIR, VIDEO_DIR, THUMBNAIL_DIR, PROFILE_DIR, BACKUP_DIR]:
    if not os.path.exists(d): os.makedirs(d)

def allowed_file(filename, allowed_set):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_set

def load_json(filepath):
    if not os.path.exists(filepath): return {}
    try:
        with open(filepath, 'r', encoding='utf-8') as f: return json.load(f)
    except (json.JSONDecodeError, IOError, PermissionError): return {}

def save_json(filepath, data):
    with open(filepath, 'w', encoding='utf-8') as f: json.dump(data, f, indent=4)

def extract_thumbnail(video_path, thumbnail_path):
    try:
        cmd = ['ffmpeg', '-i', video_path, '-ss', '00:00:01', '-vframes', '1', '-vf', 'scale=320:180', thumbnail_path, '-y']
        subprocess.run(cmd, capture_output=True, timeout=10)
        return os.path.exists(thumbnail_path)
    except Exception: return False

def generate_thumbnail(video_filename):
    video_path = os.path.join(VIDEO_DIR, video_filename)
    thumb_name = video_filename.rsplit('.', 1)[0] + '.jpg'
    thumb_path = os.path.join(THUMBNAIL_DIR, thumb_name)
    if os.path.exists(video_path) and extract_thumbnail(video_path, thumb_path): return thumb_name
    return None

def generate_missing_thumbnails():
    videos = load_json(VIDEOS_FILE); updated = False
    for vid, v in videos.items():
        if not v.get('thumbnail') or not os.path.exists(os.path.join(THUMBNAIL_DIR, v['thumbnail'])):
            thumb = generate_thumbnail(v['filename'])
            if thumb: v['thumbnail'] = thumb; updated = True
    if updated: save_json(VIDEOS_FILE, videos)

def log_activity(action, username="Guest"):
    try:
        logs = load_json(LOGS_FILE)
        logs.append({"timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "ip": request.remote_addr, "user_agent": request.headers.get('User-Agent'), "username": username, "action": action})
        save_json(LOGS_FILE, logs)
    except Exception: pass

def notify_user(target_username, message, link, sender=None):
    if not is_valid_username(target_username): return
    notifs = load_json(NOTIFS_FILE)
    if target_username not in notifs: notifs[target_username] = []
    notif_obj = {"id": str(uuid.uuid4()), "message": str(message)[:200], "link": link, "read": False, "timestamp": datetime.datetime.now().strftime("%H:%M"), "sender": sender}
    notifs[target_username].insert(0, notif_obj)
    save_json(NOTIFS_FILE, notifs)
    if target_username in online_users:
        try: socketio.emit('receive_notification', notif_obj, to=online_users[target_username])
        except Exception: pass

def can_view_video(v, user, role):
    """Return whether the current account may view a video's metadata and media."""
    if not isinstance(v, dict):
        return False
    if v.get('visibility', 'visible') == 'hidden' and role != 'admin':
        return False
    uploader = v.get('uploader', '')
    if v.get('privacy') == 'private' and role != 'admin' and user != uploader:
        raw_allowed = v.get('allowed_users', '')
        allowed = [name.strip() for name in raw_allowed.split(',') if name.strip()] if isinstance(raw_allowed, str) else []
        if not user or user not in allowed:
            return False
    return True

def is_valid_username(username):
    if not username or not isinstance(username, str): return False
    return bool(USERNAME_REGEX.match(username))

def validate_file_content(filepath, expected_type):
    try:
        with open(filepath, 'rb') as f: header = f.read(16)
        if expected_type == 'image': return (header.startswith(b'\x89PNG\r\n\x1a\n') or header.startswith(b'\xff\xd8\xff') or (header.startswith(b'RIFF') and header[8:12] == b'WEBP'))
        elif expected_type == 'video':
            if header.startswith(b'\x1a\x45\xdf\xa3') or header.startswith(b'OggS'): return True
            if len(header) >= 8 and header[4:8] in (b'ftyp', b'moov', b'mdat', b'free', b'skip', b'wide', b'pnot'): return True
            return False
        return False
    except Exception: return False

def safe_filename_check(filename):
    if not filename or '..' in filename or filename.startswith('/') or filename.startswith('\\'): return False
    return True

def revoke_all_user_sessions(username):
    sessions = load_json(SESSIONS_FILE)
    to_remove = [sid for sid, sdata in sessions.items() if sdata.get('username') == username]
    for sid in to_remove: del sessions[sid]
    save_json(SESSIONS_FILE, sessions)

def get_max_upload_bytes():
    config = load_json(CONFIG_FILE); size = config.get('max_upload_size', 1); unit = config.get('max_upload_unit', 'GB')
    if size == 0: return 0
    multipliers = {'MB': 1024*1024, 'GB': 1024*1024*1024, 'TB': 1024*1024*1024*1024}
    return size * multipliers.get(unit, 1024*1024*1024)

def update_max_content_length():
    max_bytes = get_max_upload_bytes()
    app.config['MAX_CONTENT_LENGTH'] = None if max_bytes == 0 else max_bytes

def get_user_data(username): return load_json(USERS_FILE).get(username, {})
def update_user_data(username, data): users = load_json(USERS_FILE); users[username] = data; save_json(USERS_FILE, users)

def rename_user_references(old_username, new_username):
    """Keep user-owned content and social references consistent after a rename."""
    if not old_username or not new_username or old_username == new_username:
        return

    videos = load_json(VIDEOS_FILE)
    for video in videos.values():
        if video.get('uploader') == old_username:
            video['uploader'] = new_username
        allowed = video.get('allowed_users', '')
        if isinstance(allowed, str) and allowed.strip():
            names = [name.strip() for name in allowed.split(',') if name.strip()]
            video['allowed_users'] = ', '.join(new_username if name == old_username else name for name in names)
    save_json(VIDEOS_FILE, videos)

    subscriptions = load_json(SUBS_FILE)
    if old_username in subscriptions:
        subscriptions[new_username] = subscriptions.pop(old_username)
    for subscriber, followed_users in subscriptions.items():
        if isinstance(followed_users, list):
            subscriptions[subscriber] = [new_username if name == old_username else name for name in followed_users]
    save_json(SUBS_FILE, subscriptions)

    # These stores are keyed by the account name.
    for filepath in (ENGAGE_FILE, SAVED_FILE, HISTORY_FILE, NOTIFS_FILE):
        data = load_json(filepath)
        if isinstance(data, dict) and old_username in data:
            data[new_username] = data.pop(old_username)
        if filepath == NOTIFS_FILE and isinstance(data, dict):
            for notification_list in data.values():
                if not isinstance(notification_list, list):
                    continue
                for notification in notification_list:
                    if notification.get('sender') == old_username:
                        notification['sender'] = new_username
                    link = notification.get('link')
                    if isinstance(link, str):
                        notification['link'] = link.replace(f'/user/{old_username}', f'/user/{new_username}')
        save_json(filepath, data)

    playlists = load_json(PLAYLISTS_FILE)
    for playlist in playlists.values():
        if playlist.get('owner') == old_username:
            playlist['owner'] = new_username
    save_json(PLAYLISTS_FILE, playlists)

    comments_db = load_json(COMMENTS_FILE)
    def rename_comment_authors(items):
        if not isinstance(items, list):
            return
        for comment in items:
            if comment.get('user') == old_username:
                comment['user'] = new_username
            rename_comment_authors(comment.get('replies', []))
    if isinstance(comments_db, dict):
        for items in comments_db.values():
            rename_comment_authors(items)
    save_json(COMMENTS_FILE, comments_db)

    sessions = load_json(SESSIONS_FILE)
    for session_data in sessions.values():
        if session_data.get('username') == old_username:
            session_data['username'] = new_username
    save_json(SESSIONS_FILE, sessions)

    if old_username in online_users:
        online_users[new_username] = online_users.pop(old_username)
    if old_username in user_status:
        user_status[new_username] = user_status.pop(old_username)
    # End an existing stream cleanly; its old watch URL would otherwise become stale.
    if old_username in live_streams:
        live_streams.pop(old_username, None)
        stream_viewers.pop(old_username, None)
        try:
            socketio.emit('stream_ended', {'broadcaster': old_username}, broadcast=True)
        except Exception:
            pass

# ==================== SECURITY MIDDLEWARE ====================
@app.before_request
def security_checks():
    if request.endpoint in ('static', 'login', None): return
    try:
        config = load_json(CONFIG_FILE)
        if config.get('ip_filter_enabled'):
            client_ip = request.remote_addr or '127.0.0.1'
            if client_ip in config.get('blocked_ips', []): abort(403)
            if config.get('strict_allowlist_mode') and client_ip not in config.get('allowed_ips', []): abort(403)
    except Exception: pass

@app.after_request
def add_permissions_policy(response):
    response.headers['Permissions-Policy'] = 'camera=(self), microphone=(self)'
    return response

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'session_id' not in session or 'username' not in session: session.clear(); return redirect(url_for('login'))
        users = load_json(USERS_FILE)
        if not is_valid_username(session['username']) or session['username'] not in users: session.clear(); return redirect(url_for('login'))
        sessions = load_json(SESSIONS_FILE)
        if session['session_id'] not in sessions: session.clear(); return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin': abort(403)
        users = load_json(USERS_FILE)
        if session.get('username') not in users: session.clear(); return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def init_db(filepath, default_data):
    if not os.path.exists(filepath):
        with open(filepath, 'w', encoding='utf-8') as f: json.dump(default_data, f, indent=4)

init_db(CONFIG_FILE, {"allowed_ips": [], "blocked_ips": [], "strict_allowlist_mode": False, "ip_filter_enabled": False, "max_upload_size": 1, "max_upload_unit": "GB"})
init_db(USERS_FILE, {})
update_max_content_length()

users_db = load_json(USERS_FILE)
if not any(u.get('role') == 'admin' for u in users_db.values()):
    initial_admin_password = secrets.token_urlsafe(12)[:12]
    users_db["admin"] = {"password_hash": generate_password_hash(initial_admin_password), "role": "admin", "feed_preference": "all", "bio": "Administrator", "profile_pic": "", "hide_last_seen": False, "device_notif_enabled": False}
    save_json(USERS_FILE, users_db)
    print("\n" + "="*65 + f"\n🚨 SECURE ADMIN GENERATED\nUsername: admin\nPassword: {initial_admin_password}\n" + "="*65 + "\n")

for f, d in [(LOGS_FILE,[]), (VIDEOS_FILE,{}), (ENGAGE_FILE,{}), (COMMENTS_FILE,{}), (NOTIFS_FILE,{}), (SESSIONS_FILE,{}), (PLAYLISTS_FILE,{}), (SAVED_FILE,{}), (HISTORY_FILE,{}), (SUBS_FILE,{})]: 
    init_db(f, d)

def get_all_hashtags():
    videos = load_json(VIDEOS_FILE)
    hashtags = set()
    for video in videos.values():
        raw_tags = video.get('hashtags', '')
        if isinstance(raw_tags, str):
            hashtags.update(tag.lower() for tag in re.findall(r'#[\w-]+', raw_tags))
    return sorted(hashtags)

# ==================== ROUTES ====================
@app.route('/')
@login_required
def index():
    videos = load_json(VIDEOS_FILE); users = load_json(USERS_FILE); current_user = session.get('username'); role = session.get('role')
    feed_videos = []; subscribed_content = []; subs = load_json(SUBS_FILE).get(current_user, []) if current_user else []
    for vid, v in videos.items():
        if not can_view_video(v, current_user, role): continue
        v['id'] = vid; v['uploader_pic'] = users.get(v['uploader'], {}).get('profile_pic', ''); v['thumbnail'] = v.get('thumbnail')
        if current_user and v['uploader'] in subs: subscribed_content.append(v)
        else: feed_videos.append(v)
    
    current_user_data = users.get(current_user, {}); feed_pref = current_user_data.get('feed_preference', 'all')
    if feed_pref and feed_pref.lower() != 'all':
        pref_tags = [tag.strip().lower().strip('#') for tag in re.split(r'[,\s]+', feed_pref) if tag.strip()]
        if pref_tags:
            filtered_feed = []
            for v in feed_videos:
                vid_tag_set = {t.strip().strip('#') for t in v.get('hashtags', '').lower().replace(',', ' ').split() if t.strip()}
                if any(tag in vid_tag_set for tag in pref_tags): filtered_feed.append(v)
            feed_videos = filtered_feed
            
    feed_videos.sort(key=lambda x: x.get('timestamp', ''), reverse=True); subscribed_content.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    live_data = {u: meta for u, meta in live_streams.items()}; unread = 0; current_user_obj = {}
    if current_user: notifs = load_json(NOTIFS_FILE).get(current_user, []); unread = sum(1 for n in notifs if not n.get('read')); current_user_obj = users.get(current_user, {})
    return render_template('index.html', videos=feed_videos[:50], subscribed_content=subscribed_content[:20], live_streams=live_data, unread_notifs=unread, current_user_obj=current_user_obj)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    error_msg = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip(); password = request.form.get('password', ''); remember = request.form.get('remember')
        if not is_valid_username(username): error_msg = "Invalid username format."; log_activity('failed_login_invalid_format', username or 'Guest'); return render_template('login.html', error_msg=error_msg)
        users = load_json(USERS_FILE); user_data = users.get(username)
        if user_data and check_password_hash(user_data['password_hash'], password):
            session.clear(); session['username'] = username; session['role'] = user_data.get('role', 'user'); session['session_id'] = str(uuid.uuid4())
            if remember: session.permanent = True
            sessions = load_json(SESSIONS_FILE); sessions[session['session_id']] = {'username': username, 'ip': request.remote_addr, 'user_agent': request.headers.get('User-Agent', ''), 'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            save_json(SESSIONS_FILE, sessions); log_activity('login', username); return redirect(url_for('index'))
        else: error_msg = "Invalid username or password."; log_activity('failed_login', username or 'Guest')
    return render_template('login.html', error_msg=error_msg)

@app.route('/logout')
def logout():
    if 'session_id' in session: sessions = load_json(SESSIONS_FILE); sessions.pop(session.get('session_id'), None); save_json(SESSIONS_FILE, sessions)
    session.clear(); return redirect(url_for('login'))

@app.route('/explore')
@login_required
def explore():
    videos = load_json(VIDEOS_FILE); users = load_json(USERS_FILE); current_user = session.get('username'); role = session.get('role')
    hashtags = get_all_hashtags(); tags_param = request.args.get('tags', '').strip()
    sort_mode = request.args.get('sort', 'latest')
    selected_tags = [t.strip().lower().lstrip('#') for t in tags_param.split(',') if t.strip()] if tags_param else []
    comments_db = load_json(COMMENTS_FILE)
    filtered = []
    for vid, v in videos.items():
        if not can_view_video(v, current_user, role): continue
        v['id'] = vid; v['thumbnail'] = v.get('thumbnail'); v['uploader_pic'] = users.get(v['uploader'], {}).get('profile_pic', '')
        v['comment_count'] = len(comments_db.get(vid, []))
        if selected_tags:
            raw_tags = v.get('hashtags', '')
            vid_tags = {tag.lower().lstrip('#') for tag in re.findall(r'#[\w-]+', raw_tags)} if isinstance(raw_tags, str) else set()
            if vid_tags.intersection(selected_tags):
                filtered.append(v)
        else:
            filtered.append(v)

    if sort_mode == 'discussed': filtered.sort(key=lambda x: x.get('comment_count', 0), reverse=True)
    else: filtered.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

    unread = 0; current_user_obj = {}
    if current_user: notifs = load_json(NOTIFS_FILE).get(current_user, []); unread = sum(1 for n in notifs if not n.get('read')); current_user_obj = users.get(current_user, {})
    return render_template('explore.html', videos=filtered, hashtags=hashtags, selected_tags=selected_tags, sort_mode=sort_mode, all_videos_mode=not selected_tags, unread_notifs=unread, current_user_obj=current_user_obj)

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '').strip(); current_user = session.get('username'); role = session.get('role')
    users = load_json(USERS_FILE); videos = load_json(VIDEOS_FILE); result_users = []; result_videos = []
    if query:
        for u, data in users.items():
            if query.lower() in u.lower(): result_users.append(u)
        for vid, v in videos.items():
            if not can_view_video(v, current_user, role): continue
            if query.lower() in v.get('title','').lower() or query.lower() in v.get('hashtags','').lower() or query.lower() in v.get('captions','').lower():
                v['id'] = vid; v['thumbnail'] = v.get('thumbnail'); v['uploader_pic'] = users.get(v['uploader'], {}).get('profile_pic', ''); result_videos.append(v)
    unread = 0; current_user_obj = {}
    if current_user: notifs = load_json(NOTIFS_FILE).get(current_user, []); unread = sum(1 for n in notifs if not n.get('read')); current_user_obj = users.get(current_user, {})
    return render_template('search.html', query=query, users=result_users, videos=result_videos, unread_notifs=unread, current_user_obj=current_user_obj)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per hour")
def upload():
    if request.method == 'POST':
        if 'video_file' not in request.files: return redirect(url_for('upload'))
        file = request.files['video_file']
        title = request.form.get('title', '').strip()[:180]
        captions = request.form.get('captions', '').strip()[:10000]
        hashtags = request.form.get('hashtags', '').strip()[:500]
        privacy = request.form.get('privacy', 'public').strip().lower()
        allowed_users = request.form.get('allowed_users', '').strip()[:1000]
        if not title:
            users = load_json(USERS_FILE)
            current_user_obj = users.get(session.get('username'), {})
            return render_template('upload.html', error_msg='A video title is required.', unread_notifs=0, current_user_obj=current_user_obj, max_upload_size=load_json(CONFIG_FILE).get('max_upload_size', 1), max_upload_unit=load_json(CONFIG_FILE).get('max_upload_unit', 'GB'))
        if privacy not in ('public', 'private'):
            privacy = 'public'
        if file.filename == '': return redirect(url_for('upload'))
        if file and allowed_file(file.filename, ALLOWED_EXTENSIONS):
            file.seek(0, os.SEEK_END); file_size = file.tell(); file.seek(0); max_bytes = get_max_upload_bytes()
            if max_bytes > 0 and file_size > max_bytes:
                config = load_json(CONFIG_FILE); m_size = config.get('max_upload_size', 1); m_unit = config.get('max_upload_unit', 'GB')
                return render_template('upload.html', error_msg=f"File too large. Max: {m_size} {m_unit}.", unread_notifs=0, current_user_obj={}, max_upload_size=m_size, max_upload_unit=m_unit)
            
            filename = secure_filename(file.filename); unique_name = f"{uuid.uuid4().hex}_{filename}"; filepath = os.path.join(VIDEO_DIR, unique_name); file.save(filepath)
            if not validate_file_content(filepath, 'video'):
                os.remove(filepath); config = load_json(CONFIG_FILE); m_size = config.get('max_upload_size', 1); m_unit = config.get('max_upload_unit', 'GB')
                return render_template('upload.html', error_msg="Invalid video file content.", unread_notifs=0, current_user_obj={}, max_upload_size=m_size, max_upload_unit=m_unit)
            
            thumbnail = None
            if 'thumbnail' in request.files:
                thumb_file = request.files['thumbnail']
                if thumb_file and thumb_file.filename and allowed_file(thumb_file.filename, ALLOWED_PICS):
                    thumb_filename = secure_filename(thumb_file.filename); thumb_unique = f"{uuid.uuid4().hex}_{thumb_filename}"; thumb_path = os.path.join(THUMBNAIL_DIR, thumb_unique); thumb_file.save(thumb_path)
                    if validate_file_content(thumb_path, 'image'): thumbnail = thumb_unique
                    else: os.remove(thumb_path)
            if not thumbnail: thumbnail = generate_thumbnail(unique_name)
            
            videos = load_json(VIDEOS_FILE); video_id = str(uuid.uuid4())
            videos[video_id] = {'title': title, 'captions': captions, 'hashtags': hashtags, 'privacy': privacy, 'allowed_users': allowed_users, 'uploader': session['username'], 'filename': unique_name, 'thumbnail': thumbnail, 'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), 'visibility': 'visible'}
            save_json(VIDEOS_FILE, videos); subs = load_json(SUBS_FILE)
            for subscriber, sub_list in subs.items():
                if session['username'] in sub_list: notify_user(subscriber, f"{session['username']} uploaded: {title}", f"/watch/{video_id}", sender=session['username'])
            log_activity('upload', session['username']); return redirect(url_for('watch', video_id=video_id))
            
    users = load_json(USERS_FILE); current_user_obj = users.get(session.get('username'), {}); notifs = load_json(NOTIFS_FILE).get(session.get('username'), []); unread = sum(1 for n in notifs if not n.get('read')); config = load_json(CONFIG_FILE); m_size = config.get('max_upload_size', 1); m_unit = config.get('max_upload_unit', 'GB')
    return render_template('upload.html', unread_notifs=unread, current_user_obj=current_user_obj, error_msg=None, max_upload_size=m_size, max_upload_unit=m_unit)

@app.route('/watch/<video_id>', methods=['GET', 'POST'])
@login_required
def watch(video_id):
    videos = load_json(VIDEOS_FILE); users = load_json(USERS_FILE); comments_db = load_json(COMMENTS_FILE); saved_db = load_json(SAVED_FILE); video = videos.get(video_id)
    if not video: abort(404)
    if not can_view_video(video, session.get('username'), session.get('role')): abort(403)
    
    if request.method == 'POST':
        text = request.form.get('comment_text', '').strip(); parent_id = request.form.get('parent_id', '').strip()
        if text:
            text = text[:2000]
            comment_id = str(uuid.uuid4()); comment_obj = {'id': comment_id, 'user': session['username'], 'text': text, 'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), 'likes': [], 'user_pic': users.get(session['username'], {}).get('profile_pic', '')}
            if video_id not in comments_db: comments_db[video_id] = []
            if parent_id:
                for c in comments_db.get(video_id, []):
                    if c['id'] == parent_id:
                        if 'replies' not in c: c['replies'] = []
                        reply_obj = {'id': comment_id, 'user': session['username'], 'text': text, 'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), 'likes': [], 'user_pic': users.get(session['username'], {}).get('profile_pic', '')}
                        c['replies'].append(reply_obj)
                        if c['user'] != session['username']: notify_user(c['user'], f"{session['username']} replied to your comment", f"/watch/{video_id}", sender=session['username'])
                        break
            else:
                comments_db[video_id].append(comment_obj)
                if video['uploader'] != session['username']: notify_user(video['uploader'], f"{session['username']} commented on your video", f"/watch/{video_id}", sender=session['username'])
            save_json(COMMENTS_FILE, comments_db); return redirect(url_for('watch', video_id=video_id))
            
    comments = comments_db.get(video_id, []); is_saved = video_id in saved_db.get(session['username'], []); uploader_pic = users.get(video['uploader'], {}).get('profile_pic', ''); video['thumbnail'] = video.get('thumbnail')
    unread = 0; notifs = load_json(NOTIFS_FILE).get(session['username'], []); unread = sum(1 for n in notifs if not n.get('read')); current_user_obj = users.get(session['username'], {})
    return render_template('watch.html', video=video, video_id=video_id, comments=comments, is_saved=is_saved, uploader_pic=uploader_pic, unread_notifs=unread, current_user_obj=current_user_obj)

@app.route('/user/<username>', methods=['GET', 'POST'])
@login_required
def user_profile(username):
    if not is_valid_username(username): abort(404)
    users = load_json(USERS_FILE); videos = load_json(VIDEOS_FILE); subs = load_json(SUBS_FILE); playlists = load_json(PLAYLISTS_FILE); profile = users.get(username)
    if not profile: abort(404)
    
    if request.method == 'POST':
        action = request.form.get('action'); target = request.form.get('target_user')
        if action in ['subscribe', 'unsubscribe'] and target and is_valid_username(target):
            current = session['username']; user_subs = subs.get(current, [])
            if action == 'subscribe' and target not in user_subs: user_subs.append(target); notify_user(target, f"{current} subscribed to you!", f"/user/{current}", sender=current)
            elif action == 'unsubscribe' and target in user_subs: user_subs.remove(target)
            subs[current] = user_subs; save_json(SUBS_FILE, subs); return redirect(url_for('user_profile', username=username))
            
    user_videos = []
    for vid, v in videos.items():
        if v['uploader'] == username and can_view_video(v, session.get('username'), session.get('role')): v['id'] = vid; v['thumbnail'] = v.get('thumbnail'); user_videos.append(v)
    user_videos.sort(key=lambda x: x.get('timestamp', ''), reverse=True); is_subscribed = username in subs.get(session['username'], [])
    
    user_playlists = []
    for pl_id, pl in playlists.items():
        if pl.get('owner') == username: pl['id'] = pl_id; pl['video_count'] = len(pl.get('videos', [])); user_playlists.append(pl)
        
    unread = 0; notifs = load_json(NOTIFS_FILE).get(session['username'], []); unread = sum(1 for n in notifs if not n.get('read')); current_user_obj = users.get(session['username'], {})
    return render_template('profile.html', profile_name=username, profile_pic=profile.get('profile_pic', ''), bio=profile.get('bio', ''), hide_last_seen=profile.get('hide_last_seen', False), last_seen=user_status.get(username, 'Never'), videos=user_videos, playlists=user_playlists, is_subscribed=is_subscribed, is_online=username in online_users, unread_notifs=unread, current_user_obj=current_user_obj)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    users = load_json(USERS_FILE); username = session['username']; user_data = users.get(username, {}); success_msg = None; error_msg = None
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'update_profile':
            bio = request.form.get('bio', '').strip()
            user_data['bio'] = bio[:500]
            if 'profile_pic' in request.files:
                file = request.files['profile_pic']
                if file and file.filename and allowed_file(file.filename, ALLOWED_PICS):
                    filename = secure_filename(file.filename); unique_name = f"{uuid.uuid4().hex}_{filename}"; filepath = os.path.join(PROFILE_DIR, unique_name); file.save(filepath)
                    if validate_file_content(filepath, 'image'): user_data['profile_pic'] = unique_name
                    else: os.remove(filepath); error_msg = "Invalid image file."
            if not error_msg: update_user_data(username, user_data); success_msg = "Profile updated!"; log_activity('update_profile', username)
        elif action == 'toggle_privacy': user_data['hide_last_seen'] = request.form.get('hide_last_seen') == 'yes'; update_user_data(username, user_data); success_msg = "Privacy settings saved."
        elif action == 'toggle_device_notif': user_data['device_notif_enabled'] = request.form.get('device_notif') == 'yes'; update_user_data(username, user_data); success_msg = "Notification settings saved."
        elif action == 'change_creds':
            new_username = request.form.get('new_username', '').strip()
            new_password = request.form.get('new_password', '')
            # Validate both requested changes before mutating either one.
            if new_password and len(new_password) < 6:
                error_msg = "Password must be at least 6 characters."
            if not error_msg and new_username and new_username != username:
                if not is_valid_username(new_username):
                    error_msg = "Invalid username format."
                elif new_username in users:
                    error_msg = "Username already taken."
                else:
                    old_username = username
                    users[new_username] = user_data
                    del users[old_username]
                    save_json(USERS_FILE, users)
                    rename_user_references(old_username, new_username)
                    session['username'] = new_username
                    username = new_username
                    success_msg = "Username updated."
            if new_password and not error_msg:
                user_data['password_hash'] = generate_password_hash(new_password)
                update_user_data(username, user_data)
                revoke_all_user_sessions(username)
                sessions = load_json(SESSIONS_FILE)
                sessions[session['session_id']] = {
                    'username': username,
                    'ip': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent', ''),
                    'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                save_json(SESSIONS_FILE, sessions)
                success_msg = success_msg or "Password updated."
            log_activity('change_credentials', username)
            
    unread = 0; notifs = load_json(NOTIFS_FILE).get(username, []); unread = sum(1 for n in notifs if not n.get('read')); current_user_obj = users.get(username, {})
    return render_template('settings.html', success_msg=success_msg, error_msg=error_msg, device_notif_enabled=user_data.get('device_notif_enabled', False), unread_notifs=unread, current_user_obj=current_user_obj)

@app.route('/notifications')
@login_required
def notifications():
    username = session['username']; notifs = load_json(NOTIFS_FILE).get(username, [])
    for n in notifs: n['read'] = True
    notifs_data = load_json(NOTIFS_FILE); notifs_data[username] = notifs; save_json(NOTIFS_FILE, notifs_data); unread = 0; current_user_obj = load_json(USERS_FILE).get(username, {})
    return render_template('notifications.html', notifications=notifs, unread_notifs=unread, current_user_obj=current_user_obj)

@app.route('/subscriptions', methods=['GET', 'POST'])
@login_required
def subscriptions():
    username = session['username']; subs = load_json(SUBS_FILE); users = load_json(USERS_FILE); videos = load_json(VIDEOS_FILE)
    if request.method == 'POST':
        action = request.form.get('action'); target = request.form.get('target_user')
        if action == 'unsubscribe' and target and is_valid_username(target):
            user_subs = subs.get(username, [])
            if target in user_subs: user_subs.remove(target)
            subs[username] = user_subs; save_json(SUBS_FILE, subs); return redirect(url_for('subscriptions'))
            
    user_subs = subs.get(username, []); subscriptions_list = [{'name': sub, 'profile_pic': users.get(sub, {}).get('profile_pic', '')} for sub in user_subs]; latest_videos = []
    for vid, v in videos.items():
        if v['uploader'] in user_subs and can_view_video(v, username, session.get('role')): v['id'] = vid; v['thumbnail'] = v.get('thumbnail'); v['uploader_pic'] = users.get(v['uploader'], {}).get('profile_pic', ''); latest_videos.append(v)
    latest_videos.sort(key=lambda x: x.get('timestamp', ''), reverse=True); unread = 0; notifs = load_json(NOTIFS_FILE).get(username, []); unread = sum(1 for n in notifs if not n.get('read')); current_user_obj = users.get(username, {})
    return render_template('subscriptions.html', subscriptions=subscriptions_list, latest_videos=latest_videos[:50], unread_notifs=unread, current_user_obj=current_user_obj)

@app.route('/playlists', methods=['GET', 'POST'])
@login_required
def playlists():
    username = session['username']; playlists_db = load_json(PLAYLISTS_FILE)
    if request.method == 'POST':
        name = request.form.get('playlist_name', '').strip()
        if name: pl_id = str(uuid.uuid4()); playlists_db[pl_id] = {'name': name, 'owner': username, 'videos': [], 'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}; save_json(PLAYLISTS_FILE, playlists_db); return redirect(url_for('playlists'))
    user_playlists = []
    for pl_id, pl in playlists_db.items():
        if pl.get('owner') == username: pl['id'] = pl_id; pl['video_count'] = len(pl.get('videos', [])); user_playlists.append(pl)
    unread = 0; notifs = load_json(NOTIFS_FILE).get(session['username'], []); unread = sum(1 for n in notifs if not n.get('read')); current_user_obj = load_json(USERS_FILE).get(session['username'], {})
    return render_template('playlists.html', playlists=user_playlists, unread_notifs=unread, current_user_obj=current_user_obj)

@app.route('/playlist/<pl_id>', methods=['GET', 'POST'])
@login_required
def playlist_detail(pl_id):
    playlists_db = load_json(PLAYLISTS_FILE); videos = load_json(VIDEOS_FILE); users = load_json(USERS_FILE); pl = playlists_db.get(pl_id)
    if not pl or pl.get('owner') != session['username']: abort(403)
    if request.method == 'POST' and request.form.get('action') == 'delete_playlist': del playlists_db[pl_id]; save_json(PLAYLISTS_FILE, playlists_db); return redirect(url_for('playlists'))
    pl_videos = []
    for vid in pl.get('videos', []):
        if vid in videos and can_view_video(videos[vid], session.get('username'), session.get('role')):
            v = videos[vid]
            v['id'] = vid
            v['thumbnail'] = v.get('thumbnail')
            v['uploader_pic'] = users.get(v.get('uploader', ''), {}).get('profile_pic', '')
            pl_videos.append(v)
    unread = 0; notifs = load_json(NOTIFS_FILE).get(session['username'], []); unread = sum(1 for n in notifs if not n.get('read')); current_user_obj = users.get(session['username'], {})
    return render_template('playlist_detail.html', playlist=pl, videos=pl_videos, unread_notifs=unread, current_user_obj=current_user_obj)

@app.route('/saved')
@login_required
def saved_videos():
    username = session['username']; saved_db = load_json(SAVED_FILE); videos = load_json(VIDEOS_FILE); users = load_json(USERS_FILE); saved_videos_list = []
    for vid in saved_db.get(username, []):
        if vid in videos:
            v = videos[vid]
            if can_view_video(v, username, session.get('role')): v['id'] = vid; v['thumbnail'] = v.get('thumbnail'); v['uploader_pic'] = users.get(v['uploader'], {}).get('profile_pic', ''); saved_videos_list.append(v)
    unread = 0; notifs = load_json(NOTIFS_FILE).get(username, []); unread = sum(1 for n in notifs if not n.get('read')); current_user_obj = users.get(username, {})
    return render_template('saved_videos.html', videos=saved_videos_list, unread_notifs=unread, current_user_obj=current_user_obj)

@app.route('/history', methods=['GET', 'POST'])
@login_required
def watch_history():
    username = session['username']; history_db = load_json(HISTORY_FILE); videos = load_json(VIDEOS_FILE)
    if request.method == 'POST' and request.form.get('action') == 'clear_history': history_db[username] = []; save_json(HISTORY_FILE, history_db); return redirect(url_for('watch_history'))
    history_list = []
    for h in history_db.get(username, []):
        vid = h.get('video_id')
        if vid and vid in videos and can_view_video(videos[vid], username, session.get('role')):
            v = videos[vid]
            history_list.append({'video_id': vid, 'title': v.get('title', 'Untitled'), 'uploader': v.get('uploader', 'Unknown'), 'watched_at': h.get('timestamp', ''), 'thumbnail': v.get('thumbnail')})
    history_list.reverse(); unread = 0; notifs = load_json(NOTIFS_FILE).get(username, []); unread = sum(1 for n in notifs if not n.get('read')); current_user_obj = load_json(USERS_FILE).get(username, {})
    return render_template('watch_history.html', history=history_list, unread_notifs=unread, current_user_obj=current_user_obj)

@app.route('/users')
@login_required
def users_list():
    users = load_json(USERS_FILE); current = session['username']; user_list = {u: {'bio': data.get('bio', ''), 'profile_pic': data.get('profile_pic', ''), 'is_online': u in online_users} for u, data in users.items() if u != current}; unread = 0; notifs = load_json(NOTIFS_FILE).get(current, []); unread = sum(1 for n in notifs if not n.get('read')); current_user_obj = users.get(current, {})
    return render_template('users_list.html', users=user_list, unread_notifs=unread, current_user_obj=current_user_obj)

@app.route('/famtube_admin', methods=['GET', 'POST'])
@login_required
@admin_required
@limiter.limit("50 per hour")
def admin_dashboard():
    config = load_json(CONFIG_FILE); users = load_json(USERS_FILE); videos = load_json(VIDEOS_FILE); sessions = load_json(SESSIONS_FILE); history_db = load_json(HISTORY_FILE); admin_msg = request.args.get('msg', ''); admin_msg_type = request.args.get('msg_type', '')
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'toggle_ip_filter':
            config['ip_filter_enabled'] = request.form.get('ip_filter_enabled') == 'yes'; config['strict_allowlist_mode'] = request.form.get('strict_allowlist_mode') == 'yes'
            config['blocked_ips'] = [ip.strip() for ip in request.form.get('blocked_ips', '').split('\n') if ip.strip()]; config['allowed_ips'] = [ip.strip() for ip in request.form.get('allowed_ips', '').split('\n') if ip.strip()]
            save_json(CONFIG_FILE, config); log_activity('update_ip_filter', session['username'])
        elif action == 'update_upload_settings': 
            try: size = max(0, int(request.form.get('max_upload_size', 1)))
            except: size = 1
            unit = request.form.get('max_upload_unit', 'GB'); config['max_upload_size'] = size; config['max_upload_unit'] = unit; save_json(CONFIG_FILE, config); update_max_content_length(); return redirect(url_for('admin_dashboard', msg='Upload settings updated', msg_type='success'))
        elif action == 'kill_stream':  
            target = request.form.get('target_user')
            if target and is_valid_username(target) and target in live_streams:
                try: socketio.emit('force_stream_end', room=online_users.get(target))
                except: pass
                live_streams.pop(target, None)
                stream_viewers.pop(target, None)
                socketio.emit('stream_ended', {'broadcaster': target}, broadcast=True)
                log_activity(f'killed_stream_{target}', session['username'])
        elif action == 'toggle_visibility': 
            vid = request.form.get('target_vid')
            if vid and vid in videos: videos[vid]['visibility'] = 'hidden' if videos[vid].get('visibility', 'visible') == 'visible' else 'visible'; save_json(VIDEOS_FILE, videos)
        elif action == 'delete_video': 
            vid = request.form.get('target_vid')
            if vid and vid in videos:
                video_entry = videos[vid]
                filename = video_entry.get('filename')
                thumbnail = video_entry.get('thumbnail')
                if filename and safe_filename_check(filename) and os.path.exists(os.path.join(VIDEO_DIR, filename)):
                    os.remove(os.path.join(VIDEO_DIR, filename))
                if thumbnail and safe_filename_check(thumbnail) and os.path.exists(os.path.join(THUMBNAIL_DIR, thumbnail)):
                    os.remove(os.path.join(THUMBNAIL_DIR, thumbnail))
                del videos[vid]
                save_json(VIDEOS_FILE, videos)
                comments = load_json(COMMENTS_FILE); comments.pop(vid, None); save_json(COMMENTS_FILE, comments)
                for filepath in (SAVED_FILE, HISTORY_FILE):
                    data = load_json(filepath)
                    for owner, entries in data.items():
                        if filepath == SAVED_FILE and isinstance(entries, list):
                            data[owner] = [entry for entry in entries if entry != vid]
                        elif filepath == HISTORY_FILE and isinstance(entries, list):
                            data[owner] = [entry for entry in entries if entry.get('video_id') != vid]
                    save_json(filepath, data)
        elif action == 'revoke_session': 
            sid = request.form.get('revoke_sid')
            if sid and sid in sessions: sessions.pop(sid, None); save_json(SESSIONS_FILE, sessions)
        elif action == 'create_user': 
            new_user = request.form.get('new_user', '').strip(); new_pass = request.form.get('new_pass', ''); preference = request.form.get('preference', 'all').strip()
            if not is_valid_username(new_user): return redirect(url_for('admin_dashboard', msg='Invalid username', msg_type='error'))
            elif new_user in users: return redirect(url_for('admin_dashboard', msg='User exists', msg_type='error'))
            elif len(new_pass) < 6: return redirect(url_for('admin_dashboard', msg='Password too short', msg_type='error'))
            else:
                users[new_user] = {"password_hash": generate_password_hash(new_pass), "role": "user", "feed_preference": preference, "bio": "", "profile_pic": "", "hide_last_seen": False, "device_notif_enabled": False}
                save_json(USERS_FILE, users); log_activity(f'created_user_{new_user}', session['username']); return redirect(url_for('admin_dashboard', msg=f'User {new_user} created', msg_type='success'))
        elif action == 'edit_user': 
            original = request.form.get('original_username', '').strip(); new_name = request.form.get('edit_username', '').strip(); new_pass = request.form.get('edit_password', ''); preference = request.form.get('edit_preference', 'all').strip()
            if original and is_valid_username(original) and original in users:
                user_data = users[original]
                if new_name and new_name != original:
                    if not is_valid_username(new_name): return redirect(url_for('admin_dashboard', msg='Invalid new username', msg_type='error'))
                    if new_name in users: return redirect(url_for('admin_dashboard', msg='New name exists', msg_type='error'))
                    old_name = original
                    users[new_name] = user_data
                    del users[old_name]
                    save_json(USERS_FILE, users)
                    rename_user_references(old_name, new_name)
                    sessions = load_json(SESSIONS_FILE)
                    original = new_name
                if new_pass:
                    if len(new_pass) < 6: return redirect(url_for('admin_dashboard', msg='Password too short', msg_type='error'))
                    user_data['password_hash'] = generate_password_hash(new_pass); revoke_all_user_sessions(original)
                user_data['feed_preference'] = preference; users[original] = user_data; save_json(USERS_FILE, users); return redirect(url_for('admin_dashboard', msg=f'User {original} updated', msg_type='success'))
        elif action == 'delete_user': 
            target = request.form.get('del_user'); mode = request.form.get('delete_mode', 'backup')
            if target and is_valid_username(target) and target in users and target != 'admin':
                if mode in ['backup', 'delete_videos']:
                    for vid, v in list(videos.items()):
                        if v['uploader'] == target:
                            if mode == 'backup':
                                if safe_filename_check(v['filename']) and os.path.exists(os.path.join(VIDEO_DIR, v['filename'])): 
                                    os.makedirs(os.path.join(BACKUP_DIR, secure_filename(target)), exist_ok=True)
                                    shutil.copy2(os.path.join(VIDEO_DIR, v['filename']), os.path.join(BACKUP_DIR, secure_filename(target)))
                            elif mode == 'delete_videos':
                                if safe_filename_check(v['filename']) and os.path.exists(os.path.join(VIDEO_DIR, v['filename'])): os.remove(os.path.join(VIDEO_DIR, v['filename']))
                            del videos[vid]
                    save_json(VIDEOS_FILE, videos)
                elif mode == 'keep_videos':
                    for v in videos.values(): 
                        if v['uploader'] == target: v['uploader'] = 'deleted_user'
                    save_json(VIDEOS_FILE, videos)
                revoke_all_user_sessions(target); online_users.pop(target, None); user_status.pop(target, None); live_streams.pop(target, None); del users[target]; save_json(USERS_FILE, users); return redirect(url_for('admin_dashboard', msg=f'User {target} deleted', msg_type='success'))
        return redirect(url_for('admin_dashboard'))

    metrics = [{'user': user, 'total_mins': sum(h.get('duration', 0) for h in history) // 60, 'history': ', '.join([videos.get(h.get('video_id'), {}).get('title', 'Unknown')[:20] for h in history[-5:]]) or 'No history'} for user, history in history_db.items()]
    unread = 0; notifs = load_json(NOTIFS_FILE).get(session['username'], []); unread = sum(1 for n in notifs if not n.get('read')); current_user_obj = users.get(session['username'], {})
    sessions_page = request.args.get('sessions_page', 1, type=int); per_page = 7; sessions_items = list(sessions.items()); total_sessions = len(sessions_items); total_pages = max(1, (total_sessions + per_page - 1) // per_page); sessions_page = max(1, min(sessions_page, total_pages)); start = (sessions_page - 1) * per_page; paginated_sessions = dict(sessions_items[start:start+per_page])
    return render_template('admin.html', config=config, users=users, videos=videos, live_streams=live_streams, active_sessions=paginated_sessions, sessions_page=sessions_page, sessions_total_pages=total_pages, sessions_total=total_sessions, metrics=metrics, unread_notifs=unread, current_user_obj=current_user_obj, admin_msg=admin_msg, admin_msg_type=admin_msg_type)

@app.route('/admin/user_history/<target_user>')
@login_required
@admin_required
def admin_user_history(target_user):
    if not is_valid_username(target_user): abort(404)
    history_db = load_json(HISTORY_FILE); videos = load_json(VIDEOS_FILE); users = load_json(USERS_FILE); history_list = []; total_mins = 0
    for h in history_db.get(target_user, []):
        vid = h.get('video_id')
        if vid and vid in videos:
            v = videos[vid]
            history_list.append({'video_id': vid, 'title': v.get('title', 'Untitled'), 'uploader': v.get('uploader', 'Unknown'), 'watched_at': h.get('timestamp', ''), 'thumbnail': v.get('thumbnail')})
            total_mins += h.get('duration', 0) // 60
    history_list.reverse(); unread = 0; notifs = load_json(NOTIFS_FILE).get(session['username'], []); unread = sum(1 for n in notifs if not n.get('read')); current_user_obj = users.get(session['username'], {})
    return render_template('admin_user_history.html', target_user=target_user, history=history_list, total_watch_mins=total_mins, video_count=len(history_list), unread_notifs=unread, current_user_obj=current_user_obj)

@app.route('/live/broadcast')
@login_required
def live_broadcast():
    users = load_json(USERS_FILE); unread = 0; notifs = load_json(NOTIFS_FILE).get(session['username'], []); unread = sum(1 for n in notifs if not n.get('read'))
    return render_template('live_broadcast.html', unread_notifs=unread, current_user_obj=users.get(session['username'], {}))

@app.route('/live/watch/<broadcaster>')
@login_required
def live_watch(broadcaster):
    if not is_valid_username(broadcaster) or broadcaster not in live_streams: return redirect(url_for('index'))
    users = load_json(USERS_FILE); unread = 0; notifs = load_json(NOTIFS_FILE).get(session['username'], []); unread = sum(1 for n in notifs if not n.get('read'))
    return render_template('live_watch.html', broadcaster=broadcaster, unread_notifs=unread, current_user_obj=users.get(session['username'], {}))

# ==================== API ROUTES ====================
@app.route('/api/track_engagement', methods=['POST'])
@login_required
@limiter.limit('1000 per hour')
def track_engagement():
    data = request.get_json(silent=True) or {}
    vid = data.get('video_id')
    videos = load_json(VIDEOS_FILE)
    if not isinstance(vid, str) or vid not in videos:
        return jsonify({'status': 'error', 'message': 'Video not found'}), 404
    if not can_view_video(videos[vid], session.get('username'), session.get('role')):
        return jsonify({'status': 'error', 'message': 'Forbidden'}), 403
    try:
        seconds = max(1, min(int(data.get('seconds', 5)), 5))
    except (TypeError, ValueError):
        seconds = 5
    engage = load_json(ENGAGE_FILE)
    user = session['username']
    if not isinstance(engage.get(user), dict):
        engage[user] = {}
    engage[user][vid] = int(engage[user].get(vid, 0)) + seconds
    save_json(ENGAGE_FILE, engage)
    return jsonify({'status': 'ok'})

@app.route('/api/like_comment', methods=['POST'])
@login_required
def like_comment():
    data = request.get_json(silent=True) or {}
    video_id = data.get('video_id')
    comment_id = data.get('comment_id')
    videos = load_json(VIDEOS_FILE)
    if not isinstance(video_id, str) or video_id not in videos:
        return jsonify({'status': 'error', 'message': 'Video not found'}), 404
    if not can_view_video(videos[video_id], session.get('username'), session.get('role')):
        return jsonify({'status': 'error', 'message': 'Forbidden'}), 403
    if not isinstance(comment_id, str):
        return jsonify({'status': 'error', 'message': 'Comment not found'}), 404
    comments_db = load_json(COMMENTS_FILE)
    comments = comments_db.get(video_id, [])
    def find_and_like(comment_list):
        for c in comment_list:
            if c['id'] == comment_id: likes = c.get('likes', []); (likes.remove(session['username']) if session['username'] in likes else likes.append(session['username'])); c['likes'] = likes; return len(likes)
            if 'replies' in c:
                res = find_and_like(c['replies'])
                if res is not None: return res
        return None
    likes_count = find_and_like(comments)
    if likes_count is not None: comments_db[video_id] = comments; save_json(COMMENTS_FILE, comments_db); return jsonify({'status': 'ok', 'likes': likes_count})
    return jsonify({'status': 'error'}), 404

@app.route('/api/save_video', methods=['POST'])
@login_required
def save_video():
    data = request.get_json(silent=True) or {}
    vid = data.get('video_id')
    videos = load_json(VIDEOS_FILE)
    if not isinstance(vid, str) or vid not in videos:
        return jsonify({'status': 'error', 'message': 'Video not found'}), 404
    if not can_view_video(videos[vid], session.get('username'), session.get('role')):
        return jsonify({'status': 'error', 'message': 'Forbidden'}), 403
    saved_db = load_json(SAVED_FILE)
    user = session['username']
    if not isinstance(saved_db.get(user), list):
        saved_db[user] = []
    if vid in saved_db[user]:
        saved_db[user].remove(vid)
        saved = False
    else:
        saved_db[user].append(vid)
        saved = True
    save_json(SAVED_FILE, saved_db)
    return jsonify({'status': 'ok', 'saved': saved})

@app.route('/api/watch_history', methods=['POST'])
@login_required
def api_watch_history():
    data = request.get_json(silent=True) or {}
    vid = data.get('video_id')
    videos = load_json(VIDEOS_FILE)
    if not isinstance(vid, str) or vid not in videos:
        return jsonify({'status': 'error', 'message': 'Video not found'}), 404
    if not can_view_video(videos[vid], session.get('username'), session.get('role')):
        return jsonify({'status': 'error', 'message': 'Forbidden'}), 403
    history_db = load_json(HISTORY_FILE)
    user = session['username']
    if not isinstance(history_db.get(user), list):
        history_db[user] = []
    history_db[user].append({'video_id': vid, 'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M'), 'duration': 5})
    history_db[user] = history_db[user][-500:]
    save_json(HISTORY_FILE, history_db)
    return jsonify({'status': 'ok'})

@app.route('/api/playlists', methods=['GET', 'POST'])
@login_required
def api_playlists():
    playlists_db = load_json(PLAYLISTS_FILE)
    user = session['username']
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        name = data.get('name', '')
        name = name.strip()[:100] if isinstance(name, str) else ''
        if not name:
            return jsonify({'status': 'error', 'message': 'Playlist name is required'}), 400
        pl_id = str(uuid.uuid4())
        playlists_db[pl_id] = {'name': name, 'owner': user, 'videos': [], 'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}
        save_json(PLAYLISTS_FILE, playlists_db)
        return jsonify({'status': 'ok', 'id': pl_id})
    user_playlists = [{'id': pl_id, 'name': pl.get('name', 'Untitled'), 'video_count': len(pl.get('videos', []))} for pl_id, pl in playlists_db.items() if pl.get('owner') == user]
    return jsonify({'playlists': user_playlists})

@app.route('/api/playlists/<pl_id>/videos', methods=['POST'])
@login_required
def api_add_to_playlist(pl_id):
    playlists_db = load_json(PLAYLISTS_FILE)
    data = request.get_json(silent=True) or {}
    video_id = data.get('video_id')
    pl = playlists_db.get(pl_id)
    if not pl or pl.get('owner') != session['username']:
        return jsonify({'status': 'error', 'message': 'Not found'}), 404
    videos = load_json(VIDEOS_FILE)
    if not isinstance(video_id, str) or video_id not in videos:
        return jsonify({'status': 'error', 'message': 'Video not found'}), 404
    if not can_view_video(videos[video_id], session.get('username'), session.get('role')):
        return jsonify({'status': 'error', 'message': 'Forbidden'}), 403
    if video_id not in pl.get('videos', []):
        pl.setdefault('videos', []).append(video_id)
        save_json(PLAYLISTS_FILE, playlists_db)
        return jsonify({'status': 'ok', 'message': 'Added to playlist'})
    return jsonify({'status': 'ok', 'message': 'Already in playlist'})

# ==================== MEDIA SERVING ====================
@app.route('/media/<filename>')
@login_required
def serve_media(filename):
    if not safe_filename_check(filename):
        abort(404)
    videos = load_json(VIDEOS_FILE)
    video = next((item for item in videos.values() if item.get('filename') == filename), None)
    if not video:
        abort(404)
    if not can_view_video(video, session.get('username'), session.get('role')):
        abort(403)
    return send_from_directory(VIDEO_DIR, filename)

@app.route('/thumbnails/<filename>')
@login_required
def serve_thumbnail(filename):
    if not safe_filename_check(filename):
        abort(404)
    videos = load_json(VIDEOS_FILE)
    video = next((item for item in videos.values() if item.get('thumbnail') == filename), None)
    if not video:
        abort(404)
    if not can_view_video(video, session.get('username'), session.get('role')):
        abort(403)
    return send_from_directory(THUMBNAIL_DIR, filename)

@app.route('/media/profiles/<filename>')
@login_required
def serve_profile(filename):
    if not safe_filename_check(filename):
        abort(404)
    users = load_json(USERS_FILE)
    if not any(user_data.get('profile_pic') == filename for user_data in users.values()):
        abort(404)
    return send_from_directory(PROFILE_DIR, filename)

# ==================== SOCKET.IO ====================
@socketio.on('connect')
def handle_connect(): pass

@socketio.on('register_user')
def handle_register(data):
    username = data.get('username')
    if username and is_valid_username(username) and session.get('username') == username:
        users = load_json(USERS_FILE)
        if username in users: online_users[username] = request.sid; user_status[username] = 'Online'; emit('user_online', {'username': username}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    for username, sid in list(online_users.items()):
        if sid == request.sid:
            del online_users[username]
            user_status[username] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
            break
    # Remove a disconnected viewer from every stream's peer list.
    for broadcaster, viewer_sids in list(stream_viewers.items()):
        viewer_sids.discard(request.sid)
        if not viewer_sids:
            stream_viewers.pop(broadcaster, None)
    # A broadcaster disconnect ends their stream and releases its viewers.
    for username, stream in list(live_streams.items()):
        if stream.get('sid') == request.sid:
            live_streams.pop(username, None)
            stream_viewers.pop(username, None)
            socketio.emit('stream_ended', {'broadcaster': username}, broadcast=True)
            break

@socketio.on('start_live_stream')
def handle_start_stream(data):
    username = session.get('username')
    data = data if isinstance(data, dict) else {}
    users = load_json(USERS_FILE)
    sessions = load_json(SESSIONS_FILE)
    sid = session.get('session_id')
    if username and is_valid_username(username) and username in users and sid in sessions:
        live_streams[username] = {'title': str(data.get('title', 'Untitled Stream'))[:100], 'sid': request.sid}
        stream_viewers[username] = set()
        emit('stream_started', {'broadcaster': username}, broadcast=True)

@socketio.on('stop_live_stream')
def handle_stop_stream():
    username = session.get('username')
    stream = live_streams.get(username) if username else None
    if stream and stream.get('sid') == request.sid:
        del live_streams[username]
        stream_viewers.pop(username, None)
        emit('stream_ended', {'broadcaster': username}, broadcast=True)

@socketio.on('join_live_stream')
def handle_join_stream(data):
    data = data if isinstance(data, dict) else {}
    username = session.get('username')
    sessions = load_json(SESSIONS_FILE)
    if not username or session.get('session_id') not in sessions:
        return
    broadcaster = data.get('broadcaster')
    stream = live_streams.get(broadcaster) if isinstance(broadcaster, str) else None
    if stream and is_valid_username(broadcaster):
        stream_viewers.setdefault(broadcaster, set()).add(request.sid)
        emit('viewer_joined', {'viewer_sid': request.sid}, room=stream['sid'])

@socketio.on('webrtc_signal')
def handle_webrtc(data):
    if not isinstance(data, dict) or session.get('session_id') not in load_json(SESSIONS_FILE):
        return
    target_sid = data.get('target_sid')
    if not isinstance(target_sid, str):
        return
    allowed = False
    for broadcaster, viewer_sids in stream_viewers.items():
        stream = live_streams.get(broadcaster)
        if not stream:
            continue
        broadcaster_sid = stream.get('sid')
        if request.sid == broadcaster_sid and target_sid in viewer_sids:
            allowed = True
            break
        if request.sid in viewer_sids and target_sid == broadcaster_sid:
            allowed = True
            break
    if not allowed:
        return
    payload = {'sender': request.sid}
    if isinstance(data.get('sdp'), dict):
        payload['sdp'] = data['sdp']
    if isinstance(data.get('candidate'), dict):
        payload['candidate'] = data['candidate']
    if len(payload) > 1:
        emit('webrtc_signal', payload, room=target_sid)

# ==================== TEMPLATES ====================
templates = {
"base.html": """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0, user-scalable=yes, viewport-fit=cover">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <meta name="theme-color" content="#ffffff" id="theme-color-meta">
    <title>FamTube</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.1/socket.io.js"></script>
    <script>
    /* Apply the theme before styles paint to avoid a light/dark flash. Supports old light/dark cookies. */
    (function () {
        function readCookie(name) {
            const match = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
            return match ? decodeURIComponent(match[1]) : null;
        }
        const validThemes = ['light', 'dark', 'system'];
        let preference = readCookie('theme');
        if (!validThemes.includes(preference)) preference = 'system';
        const systemPreference = window.matchMedia('(prefers-color-scheme: dark)');
        function applyTheme(theme) {
            const resolvedDark = theme === 'dark' || (theme === 'system' && systemPreference.matches);
            document.documentElement.dataset.theme = theme;
            document.documentElement.classList.toggle('dark-mode', resolvedDark);
            const meta = document.getElementById('theme-color-meta');
            if (meta) meta.content = resolvedDark ? '#0f0f0f' : '#ffffff';
        }
        window.famTubeThemePreference = preference;
        window.applyFamTubeTheme = applyTheme;
        applyTheme(preference);
        const onSystemChange = function () {
            if (window.famTubeThemePreference === 'system') applyTheme('system');
        };
        if (systemPreference.addEventListener) systemPreference.addEventListener('change', onSystemChange);
        else if (systemPreference.addListener) systemPreference.addListener(onSystemChange);
    })();
    </script>
    <style>
        :root {
            --bg: #ffffff; --surface: #ffffff; --text: #0f0f0f; --text2: #606060;
            --border: #e5e5e5; --primary: #065fd4; --accent: #ff0000;
            --hover: #f2f2f2; --shadow: 0 1px 2px rgba(0,0,0,0.1);
            --chip-bg: #f2f2f2; --chip-text: #0f0f0f; --chip-active-bg: #0f0f0f; --chip-active-text: #ffffff;
        }
        .dark-mode {
            --bg: #0f0f0f; --surface: #0f0f0f; --text: #f1f1f1; --text2: #aaaaaa;
            --border: #303030; --primary: #3ea6ff; --accent: #ff0000;
            --hover: #272727; --shadow: 0 1px 2px rgba(0,0,0,0.5);
            --chip-bg: #272727; --chip-text: #f1f1f1; --chip-active-bg: #f1f1f1; --chip-active-text: #0f0f0f;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Roboto, -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); transition: background 0.3s, color 0.3s; -webkit-tap-highlight-color: transparent; }
        
        /* Navbar */
        .navbar { background: var(--surface); position: sticky; top: 0; z-index: 100; border-bottom: 1px solid var(--border); padding: 8px 16px; display: flex; justify-content: space-between; align-items: center; gap: 12px; height: 56px; }
        .nav-left { display: flex; align-items: center; gap: 16px; }
        .nav-right { display: flex; align-items: center; gap: 16px; }
        .logo { font-size: 20px; font-weight: 700; color: var(--text); text-decoration: none; display: flex; align-items: center; gap: 4px; }
        .logo span { color: var(--accent); }
        .search-container { flex: 1; max-width: 600px; display: flex; }
        .search-input { flex: 1; padding: 0 16px; height: 40px; border: 1px solid var(--border); border-radius: 20px 0 0 20px; font-size: 16px; outline: none; background: var(--bg); color: var(--text); }
        .search-btn { width: 64px; height: 40px; background: var(--hover); border: 1px solid var(--border); border-left: none; border-radius: 0 20px 20px 0; cursor: pointer; color: var(--text); font-size: 16px; }
        .search-icon-mobile { display: none; font-size: 22px; color: var(--text); text-decoration: none; padding: 8px; }
        
        .icon-btn { background: none; border: none; font-size: 22px; cursor: pointer; padding: 8px; border-radius: 50%; color: var(--text); text-decoration: none; position: relative; display: flex; align-items: center; justify-content: center; width: 40px; height: 40px; }
        .theme-picker { width: auto; min-width: 112px; max-width: 132px; margin: 0; padding: 8px 10px; min-height: 38px; border-radius: 20px; background: var(--hover); color: var(--text); border: 1px solid var(--border); font-size: 14px; cursor: pointer; }
        .public-header { min-height: 60px; padding: 10px clamp(14px, 4vw, 32px); display: flex; align-items: center; justify-content: space-between; gap: 12px; background: var(--surface); border-bottom: 1px solid var(--border); }
        .public-header-actions { display: flex; align-items: center; gap: 8px; }
        .public-header .theme-label { margin: 0; color: var(--text2); font-size: 13px; }
        .avatar { width: 32px; height: 32px; border-radius: 50%; background: var(--primary); display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; text-decoration: none; overflow: hidden; flex-shrink: 0; }
        .avatar-img { width: 100%; height: 100%; border-radius: 50%; object-fit: cover; }
        .badge { position: absolute; top: 2px; right: 2px; background: var(--accent); color: white; font-size: 10px; padding: 2px 5px; border-radius: 10px; font-weight: bold; }

        /* Bottom Navigation */
        .bottom-nav { position: fixed; bottom: 0; left: 0; right: 0; height: 56px; background: var(--surface); border-top: 1px solid var(--border); display: flex; justify-content: space-around; align-items: center; z-index: 1000; padding-bottom: env(safe-area-inset-bottom); }
        .bottom-nav a { display: flex; flex-direction: column; align-items: center; justify-content: center; font-size: 10px; color: var(--text2); text-decoration: none; gap: 4px; flex: 1; height: 100%; padding: 4px 0; font-weight: 500; }
        .bottom-nav a.active { color: var(--text); }
        .bottom-nav .nav-icon { font-size: 24px; line-height: 1; }
        .bottom-nav .upload-btn { background: var(--text); color: var(--bg); width: 42px; height: 28px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 24px; font-weight: 300; }
        .dark-mode .bottom-nav .upload-btn { background: #f1f1f1; color: #0f0f0f; }

        /* Layout */
        .container { max-width: 1280px; margin: 0 auto; padding: 16px 16px 80px 16px; }
        
        /* Sidebar */
        .overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1001; display: none; }
        .sidebar { position: fixed; top: 0; left: -300px; width: 280px; height: 100%; background: var(--surface); border-right: 1px solid var(--border); z-index: 1002; transition: left 0.3s ease; overflow-y: auto; padding-bottom: 20px; }
        .sidebar.open { left: 0; }
        .sidebar-header { padding: 16px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
        .sidebar-links a { display: flex; align-items: center; gap: 24px; padding: 12px 24px; color: var(--text); text-decoration: none; font-size: 15px; font-weight: 500; }
        .sidebar-links a:hover { background: var(--hover); }
        .sidebar-links a span.icon { font-size: 22px; width: 24px; text-align: center; }

        /* Video Grid & Cards (YouTube Style) */
        .grid { display: grid; grid-template-columns: 1fr; gap: 24px; }
        @media(min-width: 768px) { .grid { grid-template-columns: repeat(2, 1fr); } }
        @media(min-width: 1024px) { .grid { grid-template-columns: repeat(3, 1fr); } }
        @media(min-width: 1400px) { .grid { grid-template-columns: repeat(4, 1fr); } }

        .video-card { text-decoration: none; color: inherit; display: block; margin-bottom: 0; }
        .thumbnail { position: relative; width: 100%; aspect-ratio: 16/9; background: #000; border-radius: 12px; overflow: hidden; display: flex; align-items: center; justify-content: center; font-size: 40px; color: white; }
        .thumbnail img { width: 100%; height: 100%; object-fit: cover; }
        .video-info { padding: 12px 0 0 0; display: flex; gap: 12px; }
        .channel-avatar { width: 36px; height: 36px; border-radius: 50%; flex-shrink: 0; overflow: hidden; background: var(--primary); display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; font-size: 16px; }
        .video-details { flex: 1; min-width: 0; }
        .video-title { font-size: 14px; font-weight: 500; line-height: 1.4; margin-bottom: 4px; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; color: var(--text); }
        .channel-name { font-size: 13px; color: var(--text2); line-height: 1.4; }
        .tags { color: var(--text2); font-size: 13px; margin-top: 2px; }

        /* Components */
        .admin-panel { background: var(--surface); border-radius: 12px; padding: 16px; margin-bottom: 16px; border: 1px solid var(--border); }
        .primary-btn { background: var(--primary); color: white; border: none; padding: 10px 20px; border-radius: 18px; font-weight: 500; cursor: pointer; font-size: 14px; text-decoration: none; display: inline-flex; align-items: center; justify-content: center; gap: 6px; transition: opacity 0.2s; min-height: 40px; }
        .primary-btn:hover { opacity: 0.9; }
        .danger-btn { background: #d32f2f; }
        
        input, textarea, select { padding: 12px; border: 1px solid var(--border); border-radius: 8px; font-size: 16px; width: 100%; margin-bottom: 16px; background: var(--bg); color: var(--text); transition: border-color 0.2s; }
        input:focus, textarea:focus, select:focus { outline: none; border-color: var(--primary); }
        label { font-size: 14px; font-weight: 500; margin-bottom: 6px; display: block; color: var(--text); }

        .toast-container { position: fixed; bottom: 70px; right: 16px; z-index: 9999; }
        .toast { background: #333; color: white; padding: 12px 16px; border-radius: 8px; margin-bottom: 8px; cursor: pointer; animation: slideIn 0.3s; font-size: 14px; }
        @keyframes slideIn { from { transform: translateX(100%); } to { transform: translateX(0); } }

        table { width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 14px; }
        th, td { padding: 12px 8px; border-bottom: 1px solid var(--border); text-align: left; }
        
        /* Chips / Tabs */
        .tabs { display: flex; gap: 8px; margin-bottom: 16px; overflow-x: auto; flex-wrap: nowrap; padding-bottom: 8px; -webkit-overflow-scrolling: touch; }
        .tabs::-webkit-scrollbar { display: none; }
        .tab { padding: 8px 12px; border-radius: 8px; background: var(--chip-bg); color: var(--chip-text); text-decoration: none; font-weight: 500; font-size: 14px; white-space: nowrap; border: none; cursor: pointer; }
        .tab.active { background: var(--chip-active-bg); color: var(--chip-active-text); }

        /* Mobile Overrides */
        @media(max-width: 768px) {
            .search-container { display: none; }
            .search-icon-mobile { display: block; }
            .navbar .logo { font-size: 18px; }
            .container { padding: 12px 0 80px 0; }
            .admin-panel { border-radius: 0; border-left: none; border-right: none; margin-bottom: 12px; }
            .grid { gap: 16px; }
            .video-card { padding: 0 16px; }
        }
        @media(min-width: 769px) {
            .bottom-nav { display: none; }
            .container { padding-bottom: 20px; }
        }

        /* Responsive refresh: YouTube-inspired shell, without removing FamTube features. */
        html { scroll-behavior: smooth; }
        body { min-height: 100vh; overflow-x: hidden; }
        button, input, textarea, select { font: inherit; }
        button, a, input, textarea, select { touch-action: manipulation; }
        a:focus-visible, button:focus-visible, input:focus-visible, textarea:focus-visible, select:focus-visible {
            outline: 2px solid var(--primary); outline-offset: 2px;
        }
        button:disabled { cursor: wait; opacity: .65; }
        .navbar { position: sticky; top: 0; padding-inline: clamp(10px, 1.6vw, 24px); gap: clamp(6px, 1vw, 18px); }
        .nav-left, .nav-right { gap: clamp(4px, .8vw, 14px); flex-shrink: 0; }
        .nav-left { min-width: 0; }
        .logo { white-space: nowrap; }
        .search-container { min-width: 0; }
        .overlay.open { display: block; }
        .search-form { display: flex; align-items: center; width: 100%; min-width: 0; }
        .search-input { margin: 0; min-width: 0; height: 40px; }
        .search-btn { flex: 0 0 64px; }
        .search-icon-mobile { display: none; border: 0; background: transparent; cursor: pointer; }
        .theme-toggle { font-size: 19px; }
        .avatar { flex-shrink: 0; }
        .container { min-width: 0; }
        .admin-panel { min-width: 0; overflow-wrap: anywhere; }
        .grid { align-items: start; }
        .video-card { min-width: 0; border-radius: 12px; }
        .thumbnail { aspect-ratio: 16 / 9; border-radius: 12px; }
        .thumbnail img { transition: transform .22s ease; }
        @media (hover: hover) and (pointer: fine) {
            .video-card:hover .thumbnail img { transform: scale(1.025); }
            .video-card:hover .video-title { color: var(--primary); }
        }
        .video-info { min-width: 0; }
        .video-details { overflow-wrap: anywhere; }
        .primary-btn, .tab, .icon-btn { -webkit-tap-highlight-color: transparent; }
        .watch-player-shell { margin: 0 0 16px; background: #000; border-radius: 14px; overflow: hidden; }
        .watch-player { display: block; width: 100%; height: auto; aspect-ratio: 16 / 9; max-height: calc(100vh - 110px); object-fit: contain; background: #000; }
        .toast-container { bottom: calc(76px + env(safe-area-inset-bottom)); max-width: min(380px, calc(100vw - 24px)); }
        .toast { box-shadow: 0 8px 24px rgba(0,0,0,.22); overflow-wrap: anywhere; }
        table { display: table; }
        .tabs { scrollbar-width: none; }

        @media (min-width: 769px) {
            .overlay { display: none !important; }
            .sidebar {
                top: 56px; left: 0; width: 240px; height: calc(100vh - 56px); height: calc(100dvh - 56px);
                border-right: 0; padding: 12px 10px 24px; z-index: 90; transition: left .22s ease;
                box-shadow: none;
            }
            .sidebar-header { display: none; }
            .sidebar-links a { gap: 20px; padding: 11px 14px; margin: 2px 0; border-radius: 10px; }
            .sidebar-links a:hover { background: var(--hover); }
            .sidebar-links a:active, .sidebar-links a.active { background: var(--hover); font-weight: 600; }
            body.authenticated .container { max-width: none; width: calc(100% - 240px); margin: 0 0 0 240px; padding: 24px clamp(20px, 2.5vw, 42px) 36px; }
            body.authenticated.sidebar-collapsed .sidebar { left: -260px; }
            body.authenticated.sidebar-collapsed .container { width: 100%; margin-left: 0; }
            .grid { grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 28px 18px; }
            .video-title { font-size: 15px; font-weight: 600; }
            .nav-left { min-width: 210px; }
            .watch-player-shell { border-radius: 14px; }
        }
        @media (min-width: 1450px) {
            body.authenticated .grid { grid-template-columns: repeat(4, minmax(0, 1fr)); }
        }
        @media (min-width: 769px) and (max-width: 1050px) {
            body.authenticated .container { padding-inline: 18px; }
            .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 22px 14px; }
            .sidebar { width: 220px; }
            body.authenticated .container { width: calc(100% - 220px); margin-left: 220px; }
            body.authenticated.sidebar-collapsed .container { width: 100%; margin-left: 0; }
        }
        @media (max-width: 768px) {
            .navbar { height: 56px; padding: 8px 10px; gap: 5px; }
            .nav-left { gap: 5px; }
            .nav-right { gap: 1px; }
            .navbar .logo { font-size: 17px; gap: 2px; }
            .navbar .icon-btn { width: 36px; height: 36px; padding: 5px; font-size: 20px; }
            .navbar .theme-picker { min-width: 88px; max-width: 92px; padding: 7px 4px; font-size: 12px; }
            .public-header { padding-inline: 12px; }
            .public-header .logo { font-size: 18px; }
            .public-header .theme-label { display: none; }
            .public-header .theme-picker { min-width: 94px; }
            .search-container { display: none; }
            .search-container.mobile-open {
                display: flex; position: absolute; top: 60px; left: 10px; right: 10px; width: auto; max-width: none;
                padding: 8px; background: var(--surface); border: 1px solid var(--border); border-radius: 14px;
                box-shadow: 0 8px 28px rgba(0,0,0,.2); z-index: 1100;
            }
            .search-container.mobile-open .search-input { font-size: 16px; }
            .search-icon-mobile { display: flex; align-items: center; justify-content: center; }
            .container { width: 100%; margin: 0; padding: 12px 0 calc(88px + env(safe-area-inset-bottom)); }
            .grid { grid-template-columns: minmax(0, 1fr); gap: 22px; }
            .video-card { padding: 0 12px; }
            .thumbnail { border-radius: 12px; }
            .video-info { padding-top: 10px; gap: 10px; }
            .video-title { font-size: 15px; line-height: 1.35; }
            .channel-name, .tags { font-size: 12px; }
            .admin-panel { border-radius: 12px; margin-inline: 12px; padding: 14px; border: 1px solid var(--border); }
            .watch-player-shell { margin: 0 0 14px; border-radius: 0; }
            .watch-player { max-height: none; }
            .bottom-nav { height: calc(60px + env(safe-area-inset-bottom)); padding: 3px 0 env(safe-area-inset-bottom); }
            .bottom-nav a { min-width: 0; font-size: 10px; gap: 3px; }
            .bottom-nav .nav-icon { font-size: 22px; }
            .bottom-nav .upload-btn { width: 40px; height: 30px; }
            .toast-container { bottom: calc(70px + env(safe-area-inset-bottom)); right: 10px; }
            .tabs { padding-inline: 12px; }
            body.nav-open { overflow: hidden; }
            .sidebar { width: min(300px, 86vw); padding-bottom: calc(20px + env(safe-area-inset-bottom)); }
            .sidebar-links a { min-height: 46px; }
            table { min-width: 560px; }
            .table-scroll, [style*="overflow-x:auto"] { max-width: 100%; }
            .watch-player-shell + div, .watch-player-shell ~ .admin-panel { margin-inline: 12px; }
        }
        @media (max-width: 380px) {
            .navbar .logo { font-size: 15px; }
            .navbar .icon-btn { width: 32px; height: 34px; }
            .navbar .theme-picker { min-width: 78px; max-width: 82px; padding: 6px 2px; font-size: 11px; }
            .navbar .nav-left .menu-toggle { width: 30px; }
            .nav-right { gap: 0; }
            .avatar { width: 29px; height: 29px; }
            .video-info { gap: 8px; }
            .channel-avatar { width: 32px; height: 32px; }
        }
        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after { scroll-behavior: auto !important; animation-duration: .01ms !important; animation-iteration-count: 1 !important; transition-duration: .01ms !important; }
        }
    </style>
</head>
<body class="{% if session.username %}authenticated{% endif %}">
{% if not session.username %}
    <header class="public-header">
        <a href="/login" class="logo"><span>▶</span> FamTube</a>
        <div class="public-header-actions">
            <label class="theme-label" for="publicThemeSelect">Theme</label>
            <select id="publicThemeSelect" class="theme-picker theme-select" aria-label="Color theme" title="Color theme">
                <option value="light">☀ Light</option>
                <option value="dark">☾ Dark</option>
                <option value="system">◐ System</option>
            </select>
        </div>
    </header>
{% endif %}
{% if session.username %}
    <div class="overlay" id="overlay" onclick="toggleSidebar()"></div>
    <div class="sidebar" id="sidebar">
        <div class="sidebar-header">
            <a href="/" class="logo"><span>▶</span> FamTube</a>
            <button class="icon-btn" type="button" onclick="toggleSidebar()" aria-label="Close navigation" style="font-size:24px;">✕</button>
        </div>
        <div class="sidebar-links">
            <a href="/" {% if request.endpoint == 'index' %}class="active"{% endif %}><span class="icon">🏠</span> Home</a>
            <a href="/explore" {% if request.endpoint == 'explore' %}class="active"{% endif %}><span class="icon">🔥</span> Explore</a>
            <a href="/subscriptions" {% if request.endpoint == 'subscriptions' %}class="active"{% endif %}><span class="icon">🔔</span> Subscriptions</a>
            <div style="height:1px;background:var(--border);margin:8px 0;"></div>
            <a href="/history" {% if request.endpoint == 'watch_history' %}class="active"{% endif %}><span class="icon">📜</span> History</a>
            <a href="/playlists" {% if request.endpoint in ['playlists', 'playlist_detail'] %}class="active"{% endif %}><span class="icon">📂</span> Playlists</a>
            <a href="/saved" {% if request.endpoint == 'saved_videos' %}class="active"{% endif %}><span class="icon">💾</span> Saved</a>
            <div style="height:1px;background:var(--border);margin:8px 0;"></div>
            <a href="/settings" {% if request.endpoint == 'settings' %}class="active"{% endif %}><span class="icon">⚙️</span> Settings</a>
            {% if session.role == 'admin' %}<a href="/famtube_admin" {% if request.endpoint in ['admin_dashboard', 'admin_user_history'] %}class="active"{% endif %}><span class="icon">🛡️</span> Admin</a>{% endif %}
            <a href="/logout"><span class="icon">🚪</span> Logout</a>
        </div>
    </div>

    <div class="navbar">
        <div class="nav-left">
            <button class="icon-btn menu-toggle" type="button" onclick="toggleSidebar()" aria-label="Toggle navigation">≡</button>
            <a href="/" class="logo"><span>▶</span> FamTube</a>
        </div>
        <div class="search-container" id="navSearch">
            <form class="search-form" action="/search" method="GET" role="search">
                <input class="search-input" type="search" name="q" placeholder="Search videos and people" aria-label="Search videos and people" required>
                <button class="search-btn" type="submit" aria-label="Submit search">🔍</button>
            </form>
        </div>
        <div class="nav-right">
            <button type="button" class="icon-btn search-icon-mobile" onclick="toggleMobileSearch()" aria-label="Open search">🔍</button>
            <select class="theme-picker theme-select" aria-label="Color theme" title="Color theme">
                <option value="light">☀ Light</option>
                <option value="dark">☾ Dark</option>
                <option value="system">◐ System</option>
            </select>
            <a href="/notifications" class="icon-btn" aria-label="Notifications">🔔<span class="badge" id="notif-badge" style="display:{% if unread_notifs > 0 %}flex{% else %}none{% endif %};">{{ unread_notifs }}</span></a>
            <a href="/user/{{ session.username }}" class="avatar">
                {% if current_user_obj.get('profile_pic') %}<img src="/media/profiles/{{ current_user_obj.profile_pic }}" class="avatar-img">{% else %}{{ session.username[0]|upper }}{% endif %}
            </a>
        </div>
    </div>
{% endif %}

<div class="toast-container" id="toast-container"></div>
<main class="container">{% block content %}{% endblock %}</main>

{% if session.username %}
    <div class="bottom-nav">
        <a href="/" class="{% if request.endpoint == 'index' %}active{% endif %}"><span class="nav-icon">🏠</span>Home</a>
        <a href="/explore" class="{% if request.endpoint == 'explore' %}active{% endif %}"><span class="nav-icon">🔥</span>Explore</a>
        <a href="/upload"><span class="upload-btn">+</span></a>
        <a href="/subscriptions" class="{% if request.endpoint == 'subscriptions' %}active{% endif %}"><span class="nav-icon">🔔</span>Subs</a>
        <a href="/user/{{ session.username }}" class="{% if request.endpoint == 'user_profile' %}active{% endif %}"><span class="nav-icon">👤</span>You</a>
    </div>
{% endif %}

{% if session.username %}
<script>
    const socket = io();
    socket.on('connect', () => { socket.emit('register_user', {username: '{{ session.username }}'}); });
    socket.on('receive_notification', (data) => {
        let badge = document.getElementById('notif-badge');
        if(badge) { badge.style.display = 'flex'; badge.innerText = parseInt(badge.innerText || 0) + 1; }
        showToast(data.message, data.link);
        if("Notification" in window && Notification.permission === "granted") { new Notification("FamTube", {body: data.message}); }
    });
    socket.on('force_stream_end', () => { alert("Stream ended by admin."); window.location.href = '/'; });
    function showToast(msg, link) {
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.textContent = '🔔 ' + String(msg || '').substring(0, 60);
        if (link && typeof link === 'string' && link.startsWith('/')) {
            toast.setAttribute('role', 'link');
            toast.tabIndex = 0;
            toast.onclick = () => { window.location.href = link; };
            toast.onkeydown = (event) => { if (event.key === 'Enter') window.location.href = link; };
        }
        document.getElementById('toast-container').appendChild(toast);
        setTimeout(() => toast.remove(), 5000);
    }
</script>
{% endif %}
<script>
    function toggleSidebar() {
        const sidebar = document.getElementById('sidebar');
        const overlay = document.getElementById('overlay');
        if (!sidebar || !overlay) return;
        if (window.matchMedia('(min-width: 769px)').matches) {
            document.body.classList.toggle('sidebar-collapsed');
            overlay.classList.remove('open');
        } else {
            sidebar.classList.toggle('open');
            overlay.classList.toggle('open', sidebar.classList.contains('open'));
            document.body.classList.toggle('nav-open', sidebar.classList.contains('open'));
        }
    }
    function toggleMobileSearch() {
        const search = document.getElementById('navSearch');
        if (!search) return;
        search.classList.toggle('mobile-open');
        if (search.classList.contains('mobile-open')) {
            const input = search.querySelector('input[name="q"]');
            if (input) input.focus();
        }
    }
    function setTheme(theme) {
        if (!['light', 'dark', 'system'].includes(theme)) theme = 'system';
        window.famTubeThemePreference = theme;
        window.applyFamTubeTheme(theme);
        const secureFlag = window.location.protocol === 'https:' ? ';Secure' : '';
        document.cookie = 'theme=' + encodeURIComponent(theme) + ';path=/;max-age=31536000;SameSite=Lax' + secureFlag;
        document.querySelectorAll('.theme-select').forEach((select) => { select.value = theme; });
    }
    document.querySelectorAll('.theme-select').forEach((select) => {
        select.value = window.famTubeThemePreference || 'system';
        select.addEventListener('change', () => setTheme(select.value));
    });
    window.addEventListener('resize', () => {
        const sidebar = document.getElementById('sidebar');
        const overlay = document.getElementById('overlay');
        const search = document.getElementById('navSearch');
        if (window.matchMedia('(min-width: 769px)').matches) {
            if (sidebar) sidebar.classList.remove('open');
            if (overlay) overlay.classList.remove('open');
            document.body.classList.remove('nav-open');
        } else {
            document.body.classList.remove('sidebar-collapsed');
        }
        if (search && window.innerWidth > 768) search.classList.remove('mobile-open');
    });
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            const sidebar = document.getElementById('sidebar');
            const overlay = document.getElementById('overlay');
            const search = document.getElementById('navSearch');
            if (sidebar) sidebar.classList.remove('open');
            if (overlay) overlay.classList.remove('open');
            if (search) search.classList.remove('mobile-open');
            document.body.classList.remove('nav-open');
        }
    });
</script>
</body>
</html>
""",
"login.html": """
{% extends 'base.html' %}
{% block content %}
<div style="max-width:400px;margin:80px auto;background:var(--surface);border-radius:16px;padding:32px;border:1px solid var(--border);">
    <h2 style="text-align:center;margin-bottom:24px;font-size:24px;">Sign in to FamTube</h2>
    {% if error_msg %}<div style="background:#ffebee;color:#c62828;padding:12px;border-radius:8px;margin-bottom:20px;font-size:14px;">{{ error_msg }}</div>{% endif %}
    <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <label>Username</label><input type="text" name="username" placeholder="Enter username" required>
        <label>Password</label><input type="password" name="password" placeholder="Enter password" required>
        <label style="display:flex;align-items:center;gap:8px;font-weight:normal;"><input type="checkbox" name="remember" value="yes" style="width:auto;margin:0;"> Remember me</label>
        <button type="submit" class="primary-btn" style="width:100%;background:var(--accent);padding:12px;margin-top:16px;font-size:16px;">Sign In</button>
    </form>
</div>
{% endblock %}
""",
"index.html": """
{% extends 'base.html' %}
{% block content %}
{% if live_streams %}
<div style="margin-bottom:24px;">
    <h3 style="margin-bottom:16px;font-size:18px;">🔴 Live Now</h3>
    <div class="grid">
        {% for u, meta in live_streams.items() %}
        <a href="/live/watch/{{ u }}" class="video-card">
            <div class="thumbnail" style="background:var(--accent);display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:bold;color:white;">🔴 LIVE</div>
            <div class="video-info"><div><div class="video-title">{{ meta.title }}</div><div class="channel-name">{{ u }} • Streaming now</div></div></div>
        </a>
        {% endfor %}
    </div>
</div>
{% endif %}

{% if subscribed_content %}
<div style="margin-bottom:24px;">
    <h3 style="margin-bottom:16px;font-size:18px;">Latest from Subscriptions</h3>
    <div class="grid">
        {% for v in subscribed_content %}
        <a href="/watch/{{ v.id }}" class="video-card">
            <div class="thumbnail">{% if v.thumbnail %}<img src="/thumbnails/{{ v.thumbnail }}">{% else %}▶{% endif %}</div>
            <div class="video-info">
                <div class="channel-avatar">{% if v.uploader_pic %}<img src="/media/profiles/{{ v.uploader_pic }}" class="avatar-img">{% else %}{{ v.uploader[0]|upper }}{% endif %}</div>
                <div class="video-details"><div class="video-title">{{ v.title }}</div><div class="channel-name">{{ v.uploader }} • {{ v.timestamp }}</div></div>
            </div>
        </a>
        {% endfor %}
    </div>
</div>
{% endif %}

<h3 style="margin-bottom:16px;font-size:18px;">📹 Recommended</h3>
<div class="grid">
    {% for v in videos %}
    <a href="/watch/{{ v.id }}" class="video-card">
        <div class="thumbnail">{% if v.thumbnail %}<img src="/thumbnails/{{ v.thumbnail }}">{% else %}▶{% endif %}</div>
        <div class="video-info">
            <div class="channel-avatar">{% if v.uploader_pic %}<img src="/media/profiles/{{ v.uploader_pic }}" class="avatar-img">{% else %}{{ v.uploader[0]|upper }}{% endif %}</div>
            <div class="video-details">
                <div class="video-title">{{ v.title }}</div>
                <div class="channel-name">{{ v.uploader }}</div>
                <div class="tags">{{ v.timestamp }}</div>
            </div>
        </div>
    </a>
    {% endfor %}
</div>
{% if not videos and not subscribed_content %}
<p style="text-align:center;color:var(--text2);margin-top:50px;">Feed is empty. <a href="/explore" style="color:var(--primary);">Explore All Videos</a>!</p>
{% endif %}
{% endblock %}
""",
"explore.html": """
{% extends 'base.html' %}
{% block content %}
<h2 style="margin-bottom:16px;font-size:20px;">🔥 Explore</h2>
<div class="tabs">
    <a href="/explore?sort={{ sort_mode }}" class="tab {% if not selected_tags %}active{% endif %}">All</a>
    {% for tag in hashtags %}
    <a href="/explore?tags={{ tag[1:] }}&sort={{ sort_mode }}" class="tab {% if tag[1:] in selected_tags %}active{% endif %}">{{ tag }}</a>
    {% endfor %}
</div>
<div class="grid">
    {% for v in videos %}
    <a href="/watch/{{ v.id }}" class="video-card">
        <div class="thumbnail">{% if v.thumbnail %}<img src="/thumbnails/{{ v.thumbnail }}">{% else %}▶{% endif %}</div>
        <div class="video-info">
            <div class="channel-avatar">{% if v.uploader_pic %}<img src="/media/profiles/{{ v.uploader_pic }}" class="avatar-img">{% else %}{{ v.uploader[0]|upper }}{% endif %}</div>
            <div class="video-details">
                <div class="video-title">{{ v.title }}</div>
                <div class="channel-name">{{ v.uploader }}</div>
                <div class="tags">{{ v.timestamp }}</div>
            </div>
        </div>
    </a>
    {% endfor %}
</div>
{% endblock %}
""",
"upload.html": """
{% extends 'base.html' %}
{% block content %}
<div style="max-width:600px;margin:0 auto;">
    <h2 style="margin-bottom:20px;font-size:20px;">📤 Upload Video</h2>
    {% if error_msg %}<div style="background:#ffebee;color:#c62828;padding:12px;border-radius:8px;margin-bottom:20px;">{{ error_msg }}</div>{% endif %}
    <div class="admin-panel">
        <p style="font-size:13px;color:var(--text2);margin-bottom:16px;">Max size: {% if max_upload_size==0 %}Unlimited{% else %}{{ max_upload_size }} {{ max_upload_unit }}{% endif %}</p>
        <form id="uploadForm" method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <label>Video File *</label> <input type="file" name="video_file" accept="video/mp4,video/webm,video/ogg,.mp4,.webm,.ogg" required>
            <label>Thumbnail (optional)</label> <input type="file" name="thumbnail" accept="image/png,image/jpeg,image/webp">
            <label>Title *</label> <input type="text" name="title" placeholder="Video title" required>
            <label>Description</label> <textarea name="captions" rows="4" placeholder="Describe your video..."></textarea>
            <label>Hashtags</label> <input type="text" name="hashtags" placeholder="#fun #vlog">
            <label>Privacy</label> <select name="privacy"> <option value="public">Public</option> <option value="private">Private</option> </select>
            <label>Allowed Users (for private)</label> <input type="text" name="allowed_users" placeholder="user1, user2">
            <button type="submit" id="uploadBtn" class="primary-btn" style="width:100%;margin-top:10px;background:var(--accent);">Upload Video</button>
        </form>
    </div>
</div>
<script>
document.getElementById('uploadForm').addEventListener('submit', function() {
    const btn = document.getElementById('uploadBtn');
    if (this.reportValidity()) {
        btn.disabled = true;
        btn.textContent = 'Uploading…';
    }
});
</script>
{% endblock %}
""",
"watch.html": """
{% extends 'base.html' %}
{% block content %}
<div style="max-width:1000px;margin:0 auto;">
    <div class="watch-player-shell">
        <video id="videoPlayer" class="watch-player" controls playsinline preload="metadata">
            <source src="/media/{{ video.filename }}">
        </video>
    </div>
    
    <div style="padding: 0 0 16px 0;">
        <h2 style="font-size:18px;font-weight:600;margin-bottom:12px;">{{ video.title }}</h2>
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:16px;">
            <div style="display:flex;align-items:center;gap:12px;">
                <a href="/user/{{ video.uploader }}" class="avatar" style="width:40px;height:40px;font-size:18px;">{% if uploader_pic %}<img src="/media/profiles/{{ uploader_pic }}" class="avatar-img">{% else %}{{ video.uploader[0]|upper }}{% endif %}</a>
                <div> <a href="/user/{{ video.uploader }}" style="font-weight:600;color:var(--text);text-decoration:none;font-size:15px;">{{ video.uploader }}</a> <div style="font-size:12px;color:var(--text2);">{{ video.timestamp }}</div> </div>
            </div>
        </div>
        
        <div style="display:flex;gap:8px;overflow-x:auto;padding-bottom:8px;margin-bottom:16px;">
            <button onclick="saveVideo()" class="primary-btn" style="background:var(--chip-bg);color:var(--chip-text);border-radius:20px;font-size:13px;padding:8px 16px;white-space:nowrap;">{% if is_saved %}✅ Saved{% else %}💾 Save{% endif %}</button>
            <button onclick="addToPlaylist()" class="primary-btn" style="background:var(--chip-bg);color:var(--chip-text);border-radius:20px;font-size:13px;padding:8px 16px;white-space:nowrap;">➕ Playlist</button>
            <button id="musicModeToggle" onclick="toggleMusicMode()" class="primary-btn" style="background:var(--chip-bg);color:var(--chip-text);border-radius:20px;font-size:13px;padding:8px 16px;white-space:nowrap;">🎧 Music</button>
        </div>

        <div class="admin-panel"> <p style="white-space:pre-wrap;font-size:14px;line-height:1.5;">{{ video.captions }}</p> <div class="tags" style="margin-top:12px;color:var(--primary);">{{ video.hashtags }}</div> </div>
    </div>

    <div class="admin-panel">
        <h3 style="margin-bottom:16px;font-size:16px;">💬 Comments ({{ comments|length }})</h3>
        <form method="POST" style="display:flex;gap:12px;margin-bottom:24px;">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"> <input type="text" name="comment_text" placeholder="Add a comment..." required style="margin:0;flex:1;"> <button type="submit" class="primary-btn" style="padding:0 20px;">Post</button>
        </form>
        {% for c in comments %}
        <div style="padding:12px 0;border-bottom:1px solid var(--border);display:flex;gap:12px;">
            <div class="avatar" style="width:32px;height:32px;font-size:14px;">{% if c.user_pic %}<img src="/media/profiles/{{ c.user_pic }}" class="avatar-img">{% else %}{{ c.user[0]|upper }}{% endif %}</div>
            <div style="flex:1;">
                <div> <a href="/user/{{ c.user }}" style="font-weight:600;color:var(--text);text-decoration:none;font-size:13px;">{{ c.user }}</a>  <span style="font-size:12px;color:var(--text2);margin-left:4px;">{{ c.timestamp }}</span> </div>
                <p style="margin:8px 0;font-size:14px;line-height:1.4;">{{ c.text }}</p>
                <div style="display:flex;gap:16px;align-items:center;">
                    <button onclick="likeComment('{{ c.id }}')" style="background:none;border:none;color:var(--text2);cursor:pointer;font-size:13px;display:flex;align-items:center;gap:4px;">👍 <span id="like-{{ c.id }}">{{ c.likes|length }}</span></button>
                    <button onclick="document.getElementById('reply-{{ c.id }}').style.display='flex'" style="background:none;border:none;color:var(--text2);cursor:pointer;font-size:13px;">Reply</button>
                </div>
                <form id="reply-{{ c.id }}" method="POST" style="display:none;gap:10px;margin-top:10px;">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"> <input type="hidden" name="parent_id" value="{{ c.id }}"> <input type="text" name="comment_text" placeholder="Reply..." required style="margin:0;flex:1;"> <button type="submit" class="primary-btn" style="padding:8px 16px;">Reply</button>
                </form>
                {% if c.replies %}
                <div style="border-left:2px solid var(--border);padding-left:15px;margin-top:10px;">
                    {% for r in c.replies %} <div style="display:flex;gap:10px;margin-bottom:10px;"> <div class="avatar" style="width:24px;height:24px;font-size:10px;">{% if r.user_pic %}<img src="/media/profiles/{{ r.user_pic }}" class="avatar-img">{% else %}{{ r.user[0]|upper }}{% endif %}</div> <div> <a href="/user/{{ r.user }}" style="font-weight:600;color:var(--text);text-decoration:none;font-size:13px;">{{ r.user }}</a>  <span style="font-size:12px;color:var(--text2);">{{ r.timestamp }}</span> <p style="margin:4px 0;font-size:14px;">{{ r.text }}</p> </div> </div>{% endfor %}
                </div>{% endif %}
            </div>
        </div>
        {% endfor %}
    </div>
</div>

<div id="playlistModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:1000;align-items:center;justify-content:center;">
    <div class="admin-panel" style="max-width:400px;width:90%;margin:0;"> <h3 style="margin-bottom:16px;">Add to Playlist</h3> <div id="playlistList"></div> <input type="text" id="newPlaylistName" placeholder="New playlist name" style="margin:12px 0;"> <button onclick="createPlaylist()" class="primary-btn">Create</button> <button onclick="closeModal()" style="margin-left:8px;background:#888;" class="primary-btn">Cancel</button> </div>
</div>
<script>
const videoId = '{{ video_id }}'; const csrfToken = document.querySelector('meta[name="csrf-token"]').content; let watchInterval, isMusicMode = false; const vp = document.getElementById('videoPlayer'); const ap = new Audio('/media/{{ video.filename }}');
function startTracking() {
    stopTracking();
    watchInterval = setInterval(() => {
        fetch('/api/track_engagement', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrfToken}, body: JSON.stringify({video_id: videoId, seconds: 5})}).catch(() => {});
    }, 5000);
}
function stopTracking() { if (watchInterval) { clearInterval(watchInterval); watchInterval = null; } }
vp.onplay = () => { startTracking(); fetch('/api/watch_history', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrfToken}, body: JSON.stringify({video_id: videoId})}); }; vp.onpause = stopTracking; vp.onended = stopTracking; ap.onpause = stopTracking; ap.onended = stopTracking; ap.onplay = startTracking;
function toggleMusicMode() { isMusicMode = !isMusicMode; const btn = document.getElementById('musicModeToggle'); if(isMusicMode) { ap.currentTime = vp.currentTime; vp.pause(); vp.style.display = 'none'; ap.style.display = 'block'; ap.play(); btn.innerText = "🎧 Video"; } else { vp.currentTime = ap.currentTime; ap.pause(); ap.style.display = 'none'; vp.style.display = 'block'; vp.play(); btn.innerText = "🎧 Music"; } }
function saveVideo() { fetch('/api/save_video', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrfToken}, body: JSON.stringify({video_id: videoId})}).then(r => r.json()).then(() => location.reload()); }
function likeComment(cid) { fetch('/api/like_comment', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrfToken}, body: JSON.stringify({video_id: videoId, comment_id: cid})}).then(r => r.json()).then(data => { if(data.likes !== undefined) document.getElementById('like-' + cid).innerText = data.likes; }); }
function addToPlaylist() { fetch('/api/playlists').then(r => r.json()).then(data => { const list = document.getElementById('playlistList'); list.innerHTML = ''; data.playlists.forEach(pl => { const div = document.createElement('div'); div.innerHTML = `<div style="padding:12px;cursor:pointer;border-bottom:1px solid var(--border);">${pl.name} (${pl.video_count})</div>`; div.onclick = () => addVideoToPlaylist(pl.id); list.appendChild(div); }); document.getElementById('playlistModal').style.display = 'flex'; }); }
function addVideoToPlaylist(plId) { fetch(`/api/playlists/${plId}/videos`, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrfToken}, body: JSON.stringify({video_id: videoId})}).then(r => r.json()).then(() => { alert('Added!'); closeModal(); }); }
function createPlaylist() { const name = document.getElementById('newPlaylistName').value.trim(); if(!name) return; fetch('/api/playlists', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrfToken}, body: JSON.stringify({name: name})}).then(r => r.json()).then(data => { if(data.id) addVideoToPlaylist(data.id); }); }
function closeModal() { document.getElementById('playlistModal').style.display = 'none'; }
</script>
{% endblock %}
""",
"settings.html": """
{% extends 'base.html' %}
{% block content %}
<div style="max-width:600px;margin:0 auto;">
    <h2 style="margin-bottom:20px;font-size:20px;">⚙️ Settings</h2>
    {% if success_msg %}<div style="background:#e8f5e9;color:#2e7d32;padding:12px;border-radius:8px;margin-bottom:20px;">{{ success_msg }}</div>{% endif %}
    {% if error_msg %}<div style="background:#ffebee;color:#c62828;padding:12px;border-radius:8px;margin-bottom:20px;">{{ error_msg }}</div>{% endif %}
    
    <div class="admin-panel">
        <h3 style="margin-bottom:16px;font-size:16px;">Profile & Photo</h3>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"> <input type="hidden" name="action" value="update_profile">
            <label>Change Profile Picture</label> <input type="file" name="profile_pic" accept="image/*">
            <label>Update Bio</label> <textarea name="bio" rows="3">{{ current_user_obj.get('bio', '') }}</textarea>
            <button class="primary-btn" style="width:100%;">Save Profile</button>
        </form>
    </div>

    <div class="admin-panel">
        <h3 style="margin-bottom:16px;font-size:16px;">Change Credentials</h3>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"> <input type="hidden" name="action" value="change_creds">
            <label>New Username</label> <input type="text" name="new_username" placeholder="{{ session.username }}">
            <label>New Password</label> <input type="password" name="new_password" placeholder="Leave blank to keep current">
            <button class="primary-btn" style="width:100%;">Update Credentials</button>
        </form>
    </div>

    <div class="admin-panel">
        <h3 style="margin-bottom:16px;font-size:16px;">Privacy</h3>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"> <input type="hidden" name="action" value="toggle_privacy">
            <label style="display:flex;align-items:center;gap:10px;font-size:14px;cursor:pointer;margin-bottom:15px;font-weight:normal;"> <input type="checkbox" name="hide_last_seen" value="yes" style="width:auto;margin:0;" {% if current_user_obj.get('hide_last_seen') %}checked{% endif %}> Hide my last seen status</label>
            <button class="primary-btn" style="width:100%;">Save Privacy</button>
        </form>
    </div>
</div>
{% endblock %}
""",
"search.html": """
{% extends 'base.html' %}
{% block content %}
<h2 style="margin-bottom:20px;font-size:20px;">Search: "{{ query }}"</h2>
{% if users %}
<div class="admin-panel"> <h3 style="margin-bottom:12px;">Users</h3> <div style="display:flex;flex-wrap:wrap;gap:12px;">{% for u in users %} <a href="/user/{{ u }}" class="primary-btn" style="background:var(--chip-bg);color:var(--chip-text);border-radius:20px;">{{ u }}</a>{% endfor %}</div> </div>
{% endif %}
<div class="grid">
    {% for v in videos %}
    <a href="/watch/{{ v.id }}" class="video-card">
        <div class="thumbnail">{% if v.thumbnail %}<img src="/thumbnails/{{ v.thumbnail }}">{% else %}▶{% endif %}</div>
        <div class="video-info"> <div class="video-title">{{ v.title }}</div> <div class="channel-name">{{ v.uploader }} • {{ v.timestamp }}</div> </div>
    </a>
    {% endfor %}
</div>
{% endblock %}
""",
"profile.html": """
{% extends 'base.html' %}
{% block content %}
<div style="max-width:800px;margin:0 auto;">
    <div class="admin-panel" style="text-align:center;padding:32px 16px;">
        <div class="avatar" style="width:100px;height:100px;margin:0 auto 16px;font-size:40px;">{% if profile_pic %}<img src="/media/profiles/{{ profile_pic }}" class="avatar-img">{% else %}{{ profile_name[0]|upper }}{% endif %}</div>
        <h2 style="font-size:22px;margin-bottom:8px;">{{ profile_name }}</h2>
        {% if bio %}<p style="color:var(--text2);margin-bottom:8px;">{{ bio }}</p>{% endif %}
        {% if not hide_last_seen %}<p style="color:var(--text2);font-size:13px;margin-bottom:16px;">Last seen: {{ last_seen }}</p>{% endif %}
        {% if session.username != profile_name %}
        <form method="POST" style="margin-top:16px;">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"> <input type="hidden" name="action" value="{% if is_subscribed %}unsubscribe{% else %}subscribe{% endif %}"> <input type="hidden" name="target_user" value="{{ profile_name }}">
            <button class="primary-btn" style="background:{% if is_subscribed %}var(--chip-bg){% else %}var(--accent){% endif %};color:{% if is_subscribed %}var(--chip-text){% else %}white{% endif %};padding:10px 32px;border-radius:20px;font-size:15px;">{% if is_subscribed %}Unsubscribe{% else %}Subscribe{% endif %}</button>
        </form>{% endif %}
    </div>
    <h3 style="margin:24px 0 16px 0;font-size:18px;">📹 Videos</h3>
    <div class="grid">{% for v in videos %} <a href="/watch/{{ v.id }}" class="video-card"> <div class="thumbnail">{% if v.thumbnail %}<img src="/thumbnails/{{ v.thumbnail }}">{% else %}▶{% endif %}</div> <div class="video-info"> <div class="video-title">{{ v.title }}</div> <div class="channel-name">{{ v.timestamp }}</div> </div> </a>{% endfor %}</div>
</div>
{% endblock %}
""",
"notifications.html": """
{% extends 'base.html' %}
{% block content %}
<h2 style="margin-bottom:20px;font-size:20px;">🔔 Notifications</h2>
<div class="admin-panel">{% for n in notifications %} <a href="{{ n.link }}" style="text-decoration:none;color:inherit;display:block;"> <div style="padding:16px;border-left:4px solid {% if not n.read %}var(--primary){% else %}var(--border){% endif %};margin-bottom:8px;background:{% if not n.read %}rgba(6,95,212,0.05){% endif %};border-radius:8px;font-size:14px;">{{ n.message }} <br><span style="font-size:12px;color:var(--text2);">{{ n.timestamp }}</span></div> </a>{% endfor %}</div>
{% endblock %}
""",
"playlists.html": """
{% extends 'base.html' %}
{% block content %}
<h2 style="margin-bottom:20px;font-size:20px;">📂 My Playlists</h2>
<button onclick="document.getElementById('createForm').style.display='block'" class="primary-btn" style="margin-bottom:20px;background:var(--accent);">+ New Playlist</button>
<div id="createForm" style="display:none;" class="admin-panel"> <form method="POST"> <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"> <input type="text" name="playlist_name" placeholder="Playlist name" required> <button class="primary-btn">Create</button> </form> </div>
<div class="grid">{% for pl in playlists %} <a href="/playlist/{{ pl.id }}" class="video-card"> <div class="thumbnail" style="background:linear-gradient(135deg,var(--primary),#3ea6ff);display:flex;align-items:center;justify-content:center;font-size:48px;">📂</div> <div class="video-info"> <div class="video-title">{{ pl.name }}</div> <div class="channel-name">{{ pl.video_count }} videos</div> </div> </a>{% endfor %}</div>
{% endblock %}
""",
"playlist_detail.html": """
{% extends 'base.html' %}
{% block content %}
<h2 style="margin-bottom:20px;font-size:20px;">📂 {{ playlist.name }}</h2>
<form method="POST" style="margin-bottom:20px;"> <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"> <input type="hidden" name="action" value="delete_playlist"> <button class="primary-btn danger-btn" onclick="return confirm('Delete playlist?')">Delete Playlist</button> </form>
<div class="grid">{% for v in videos %} <a href="/watch/{{ v.id }}" class="video-card"> <div class="thumbnail">{% if v.thumbnail %}<img src="/thumbnails/{{ v.thumbnail }}">{% else %}▶{% endif %}</div> <div class="video-info"> <div class="video-title">{{ v.title }}</div> <div class="channel-name">{{ v.uploader }}</div> </div> </a>{% endfor %}</div>
{% endblock %}
""",
"saved_videos.html": """
{% extends 'base.html' %}
{% block content %}
<h2 style="margin-bottom:20px;font-size:20px;">💾 Saved Videos</h2>
<div class="grid">{% for v in videos %} <a href="/watch/{{ v.id }}" class="video-card"> <div class="thumbnail">{% if v.thumbnail %}<img src="/thumbnails/{{ v.thumbnail }}">{% else %}▶{% endif %}</div> <div class="video-info"> <div class="video-title">{{ v.title }}</div> <div class="channel-name">{{ v.uploader }} • {{ v.timestamp }}</div> </div> </a>{% endfor %}</div>
{% endblock %}
""",
"watch_history.html": """
{% extends 'base.html' %}
{% block content %}
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;"> <h2 style="font-size:20px;">📜 Watch History</h2> <form method="POST"> <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"> <input type="hidden" name="action" value="clear_history"> <button class="primary-btn danger-btn">Clear</button> </form> </div>
<div class="grid">{% for h in history %} <a href="/watch/{{ h.video_id }}" class="video-card"> <div class="thumbnail">{% if h.thumbnail %}<img src="/thumbnails/{{ h.thumbnail }}">{% else %}▶{% endif %}</div> <div class="video-info"> <div class="video-title">{{ h.title }}</div> <div class="channel-name">Watched {{ h.watched_at }}</div> </div> </a>{% endfor %}</div>
{% endblock %}
""",
"subscriptions.html": """
{% extends 'base.html' %}
{% block content %}
<h2 style="margin-bottom:20px;font-size:20px;">🔔 Subscriptions</h2>
{% if subscriptions %}
<div style="display:flex;flex-wrap:wrap;gap:12px;margin-bottom:24px;">{% for sub in subscriptions %} <div style="display:flex;align-items:center;gap:8px;background:var(--surface);padding:8px 16px;border-radius:24px;border:1px solid var(--border);"> <div class="avatar" style="width:28px;height:28px;">{% if sub.profile_pic %}<img src="/media/profiles/{{ sub.profile_pic }}" class="avatar-img">{% else %}{{ sub.name[0]|upper }}{% endif %}</div> <a href="/user/{{ sub.name }}" style="font-weight:500;color:var(--text);text-decoration:none;font-size:14px;">{{ sub.name }}</a> <form method="POST" style="margin:0;"> <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"> <input type="hidden" name="action" value="unsubscribe"> <input type="hidden" name="target_user" value="{{ sub.name }}"> <button type="submit" style="background:none;border:none;color:var(--accent);cursor:pointer;font-weight:bold;font-size:16px;">✕</button> </form> </div>{% endfor %}</div>
{% if latest_videos %} <h3 style="margin-bottom:16px;font-size:18px;">Latest Uploads</h3> <div class="grid">{% for v in latest_videos %} <a href="/watch/{{ v.id }}" class="video-card"> <div class="thumbnail">{% if v.thumbnail %}<img src="/thumbnails/{{ v.thumbnail }}">{% else %}▶{% endif %}</div> <div class="video-info"> <div class="video-title">{{ v.title }}</div> <div class="channel-name">{{ v.uploader }} • {{ v.timestamp }}</div> </div> </a>{% endfor %}</div>{% endif %}
{% else %} <p style="color:var(--text2);">No subscriptions yet. <a href="/users" style="color:var(--primary);">Explore users!</a></p>{% endif %}
{% endblock %}
""",
"users_list.html": """
{% extends 'base.html' %}
{% block content %}
<h2 style="margin-bottom:20px;font-size:20px;">👥 Users</h2>
<div class="grid">{% for u, data in users.items() %} <a href="/user/{{ u }}" class="video-card" style="text-align:center;padding:20px;border:1px solid var(--border);border-radius:12px;"> <div class="avatar" style="width:80px;height:80px;margin:0 auto 12px;font-size:36px;">{% if data.profile_pic %}<img src="/media/profiles/{{ data.profile_pic }}" class="avatar-img">{% else %}{{ u[0]|upper }}{% endif %}</div> <div class="video-title" style="font-size:16px;">{{ u }}</div> <div class="channel-name">{% if data.is_online %}🟢 Online{% else %}⚪ Offline{% endif %}</div> </a>{% endfor %}</div>
{% endblock %}
""",
"admin.html": """
{% extends 'base.html' %}
{% block content %}
<h2 style="margin-bottom:20px;font-size:20px;">🛡️ Admin Dashboard</h2>
{% if admin_msg %}<div style="background:{% if admin_msg_type == 'error' %}#ffebee;color:#c62828{% else %}#e8f5e9;color:#2e7d32{% endif %};padding:12px;border-radius:8px;margin-bottom:20px;font-weight:bold;">{{ admin_msg }}</div>{% endif %}

<div class="admin-panel"> <h3 style="margin-bottom:16px;">🌐 IP Access Control</h3> 
<form method="POST"> <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"> <input type="hidden" name="action" value="toggle_ip_filter"> 
<label style="display:flex;align-items:center;gap:10px;margin-bottom:15px;font-weight:normal;"> <input type="checkbox" name="ip_filter_enabled" value="yes" {% if config.ip_filter_enabled %}checked{% endif %} style="width:auto;margin:0;"> <b>Enable IP Filtering</b> </label> 
<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:15px;"> <div style="flex:1;min-width:250px;"> <label>Blocked IPs</label> <textarea name="blocked_ips" rows="4">{{ config.blocked_ips | join('\\n') }}</textarea> </div> <div style="flex:1;min-width:250px;"> <label>Allowed IPs</label> <textarea name="allowed_ips" rows="4">{{ config.allowed_ips | join('\\n') }}</textarea> </div> </div> 
<label style="display:flex;align-items:center;gap:10px;margin-bottom:15px;font-weight:normal;"> <input type="checkbox" name="strict_allowlist_mode" value="yes" {% if config.strict_allowlist_mode %}checked{% endif %} style="width:auto;margin:0;"> <b>Strict Allowlist Mode</b> </label> 
<button class="primary-btn" style="width:100%;">💾 Save IP Settings</button> </form> </div>

<div class="admin-panel"> <h3 style="margin-bottom:16px;">📤 Upload Settings</h3> 
<form method="POST"> <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"> <input type="hidden" name="action" value="update_upload_settings"> 
<div style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap;"> <div style="flex:1;min-width:150px;"> <label>Max Upload Size</label> <input type="number" name="max_upload_size" value="{{ config.get('max_upload_size', 1) }}" min="0"> </div> <div style="min-width:120px;"> <label>Unit</label> <select name="max_upload_unit"> <option value="MB" {% if config.get('max_upload_unit') == 'MB' %}selected{% endif %}>MB</option> <option value="GB" {% if config.get('max_upload_unit', 'GB') == 'GB' %}selected{% endif %}>GB</option> <option value="TB" {% if config.get('max_upload_unit') == 'TB' %}selected{% endif %}>TB</option> </select> </div> </div> 
<button class="primary-btn" style="width:100%;margin-top:10px;">💾 Save Upload Settings</button> </form> </div>

<div class="admin-panel"> <h3 style="margin-bottom:16px;">🛡️ Content Moderation</h3>
{% if live_streams %} <h4 style="margin-bottom:8px;">Active Streams</h4> <div style="overflow-x:auto;"><table><tr><th>Broadcaster</th><th>Title</th><th>Action</th></tr>{% for u, meta in live_streams.items() %}<tr><td><b>{{ u }}</b></td><td>{{ meta.title }}</td><td><form method="POST" style="margin:0;"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input type="hidden" name="action" value="kill_stream"><input type="hidden" name="target_user" value="{{ u }}"><button type="submit" class="primary-btn danger-btn" style="padding:6px 12px;font-size:12px;">Force End</button></form></td></tr>{% endfor %}</table></div>{% endif %} 
<h4 style="margin:16px 0 8px 0;">Video Library</h4> <div style="overflow-x:auto;max-height:400px;"><table><tr><th>Title</th><th>Uploader</th><th>Vis</th><th>Actions</th></tr>{% for vid, v in videos.items() %}<tr><td style="max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{{ v.title }}</td><td>{{ v.uploader }}</td><td><span style="padding:2px 6px;border-radius:4px;font-size:11px;background:{% if v.get('visibility','visible')=='visible' %}#4CAF50{% else %}#9e9e9e{% endif %};color:white;">{{ v.get('visibility', 'visible')|upper }}</span></td><td style="display:flex;gap:5px;"><form method="POST" style="margin:0;"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input type="hidden" name="action" value="toggle_visibility"><input type="hidden" name="target_vid" value="{{ vid }}"><button type="submit" class="primary-btn" style="padding:6px 10px;font-size:12px;background:{% if v.get('visibility')=='hidden' %}#4CAF50{% else %}#555{% endif %};">{% if v.get('visibility')=='hidden' %}Unhide{% else %}Hide{% endif %}</button></form><form method="POST" style="margin:0;"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input type="hidden" name="action" value="delete_video"><input type="hidden" name="target_vid" value="{{ vid }}"><button type="submit" class="primary-btn danger-btn" style="padding:6px 10px;font-size:12px;" onclick="return confirm('Delete?');">Del</button></form></td></tr>{% endfor %}</table></div> </div>

<div class="admin-panel"> <h3 style="margin-bottom:16px;">📱 Active Sessions</h3> 
<div style="overflow-x:auto;"><table><tr><th>User</th><th>IP Address</th><th>Action</th></tr>{% for sid, sdata in active_sessions.items() %}<tr><td><b>{{ sdata.username }}</b></td><td>{{ sdata.ip }}</td><td><form method="POST" style="margin:0;"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input type="hidden" name="action" value="revoke_session"><input type="hidden" name="revoke_sid" value="{{ sid }}"><button type="submit" class="primary-btn danger-btn" style="padding:6px 12px;font-size:12px;">Log Out</button></form></td></tr>{% endfor %}</table></div> 
<div style="display:flex;justify-content:center;align-items:center;gap:15px;margin-top:15px;">{% if sessions_page > 1 %}<a href="?sessions_page={{ sessions_page - 1 }}" class="primary-btn" style="background:#555;">← Prev</a>{% endif %}<span style="font-size:13px;color:var(--text2);">Page {{ sessions_page }} of {{ sessions_total_pages }}</span>{% if sessions_page < sessions_total_pages %}<a href="?sessions_page={{ sessions_page + 1 }}" class="primary-btn">Next →</a>{% endif %}</div> </div>

<div class="admin-panel"> <h3 style="margin-bottom:16px;">📊 User Engagement</h3> 
<div style="overflow-x:auto;"><table><tr><th>User</th><th>Total Watch Time</th><th>Action</th></tr>{% for m in metrics %}<tr><td><b>{{ m.user }}</b></td><td>{{ m.total_mins }} mins</td><td><a href="/admin/user_history/{{ m.user }}" class="primary-btn" style="padding:6px 12px;font-size:12px;">View Details</a></td></tr>{% endfor %}</table></div> </div>

<div class="admin-panel"> <h3 style="margin-bottom:16px;">👤 User Management</h3> 
<form method="POST" style="margin-bottom:20px;"> <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"> <input type="hidden" name="action" value="create_user"> 
<div style="display:flex;gap:10px;flex-wrap:wrap;"> <input type="text" name="new_user" placeholder="New Username" required style="margin:0;flex:1;min-width:150px;"> <input type="password" name="new_pass" placeholder="Password" required style="margin:0;flex:1;min-width:150px;"> <input type="text" name="preference" placeholder="#all or #edu" value="#all" style="margin:0;flex:1;min-width:100px;"> <button class="primary-btn" style="margin:0;">+ Create</button> </div> </form> 
<div style="overflow-x:auto;"><table><tr><th>User</th><th>Filter</th><th>Actions</th></tr>{% for u, data in users.items() %}<tr><td><b>{{u}}</b></td><td>{{data.feed_preference}}</td><td style="display:flex;gap:5px;"><button onclick="document.getElementById('edit-{{u}}').style.display='table-row'" class="primary-btn" style="padding:6px 12px;font-size:12px;background:#555;">Edit</button>{% if data.role != 'admin' %}<button onclick="document.getElementById('del-{{u}}').style.display='table-row'" class="primary-btn danger-btn" style="padding:6px 12px;font-size:12px;">Del</button>{% endif %}</td></tr><tr id="edit-{{u}}" style="display:none;"><td colspan="3" style="background:var(--hover);padding:15px;"><form method="POST"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input type="hidden" name="action" value="edit_user"><input type="hidden" name="original_username" value="{{u}}"><input type="text" name="edit_username" value="{{u}}" required><input type="password" name="edit_password" placeholder="New Password"><input type="text" name="edit_preference" value="{{ data.feed_preference }}"><button type="submit" class="primary-btn" style="background:#2e7d32;">Save</button><button type="button" onclick="document.getElementById('edit-{{u}}').style.display='none'" class="primary-btn" style="background:#888;">Cancel</button></form></td></tr><tr id="del-{{u}}" style="display:none;"><td colspan="3" style="background:#ffebee;padding:15px;"><form method="POST"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input type="hidden" name="action" value="delete_user"><input type="hidden" name="del_user" value="{{u}}"><select name="delete_mode"><option value="backup">Backup & Delete</option><option value="delete_videos">Delete Everything</option><option value="keep_videos">Keep Videos</option></select><button type="submit" class="primary-btn danger-btn">Confirm Delete</button><button type="button" onclick="document.getElementById('del-{{u}}').style.display='none'" class="primary-btn" style="background:#888;">Cancel</button></form></td></tr>{% endfor %}</table></div> </div>
{% endblock %}
""",
"admin_user_history.html": """
{% extends 'base.html' %}
{% block content %}
<h2 style="margin-bottom:20px;font-size:20px;">📊 Watch History: {{ target_user }}</h2>
<div class="admin-panel" style="margin-bottom:20px;"> <h3 style="margin-bottom:16px;">User Stats</h3> <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:15px;"> <div style="background:var(--hover);padding:15px;border-radius:8px;text-align:center;"> <div style="font-size:24px;font-weight:bold;color:var(--primary);">{{ total_watch_mins }}</div> <div style="font-size:12px;color:var(--text2);">Total Minutes</div> </div> <div style="background:var(--hover);padding:15px;border-radius:8px;text-align:center;"> <div style="font-size:24px;font-weight:bold;color:var(--primary);">{{ video_count }}</div> <div style="font-size:12px;color:var(--text2);">Videos Watched</div> </div> </div> </div>
<div class="grid">{% for h in history %} <a href="/watch/{{ h.video_id }}" class="video-card"> <div class="thumbnail">{% if h.thumbnail %}<img src="/thumbnails/{{ h.thumbnail }}">{% else %}▶{% endif %}</div> <div class="video-info"> <div class="video-title">{{ h.title }}</div> <div class="channel-name">Watched {{ h.watched_at }}</div> </div> </a>{% endfor %}</div>
{% endblock %}
""",
"live_broadcast.html": """
{% extends 'base.html' %}
{% block content %}
<div style="max-width:800px;margin:0 auto;text-align:center;">
    <h2 style="margin-bottom:20px;font-size:20px;">🔴 Go Live</h2>
    <div class="admin-panel">
        <div id="permWarning" style="display:none;background:#fff3e0;color:#e65100;padding:12px;border-radius:8px;margin-bottom:15px;text-align:left;font-size:13px;">⚠️ <b>Camera/Microphone Access Required</b><br>Live streaming requires browser permission. You MUST access this site via HTTPS or localhost.<br><br><button onclick="requestMediaAccess()" class="primary-btn" style="background:#ff9800;width:100%;">🔐 Request Permission</button></div>
        <input type="text" id="streamTitle" placeholder="Stream Title" style="max-width:400px;margin:0 auto 15px;display:block;">
        <div style="display:flex;gap:15px;justify-content:center;margin-bottom:20px;flex-wrap:wrap;">
            <button id="startBtn" class="primary-btn" style="background:#ff0000;display:none;">Start Stream</button>
            <button id="requestBtn" class="primary-btn" style="background:#ff9800;" onclick="requestMediaAccess()">🔐 Allow Camera & Mic</button>
            <button id="stopBtn" class="primary-btn" style="background:#555;display:none;">Stop Stream</button>
        </div>
        <video id="localVideo" autoplay muted playsinline style="width:100%;max-width:600px;background:#000;border-radius:8px;"></video>
        <p id="statusText" style="color:var(--text2);margin-top:10px;">Ready to broadcast</p>
    </div>
</div>
<script>
const liveSocket = io(); let localStream = null, peerConnections = {}; const rtcConfig = {iceServers: [{urls: 'stun:stun.l.google.com:19302'}]};
function isSecure() { return window.isSecureContext || location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1'; }
async function requestMediaAccess() { if(!isSecure()) { alert('Insecure Context. Please use HTTPS or localhost.'); return; } try { localStream = await navigator.mediaDevices.getUserMedia({video: {width: {ideal: 1280}, height: {ideal: 720}}, audio: true}); document.getElementById('localVideo').srcObject = localStream; document.getElementById('permWarning').style.display = 'none'; document.getElementById('requestBtn').style.display = 'none'; document.getElementById('startBtn').style.display = 'inline-block'; document.getElementById('statusText').innerText = '✅ Ready. Click Start Stream.'; } catch(e) { document.getElementById('statusText').innerText = 'Error: ' + e.message; document.getElementById('permWarning').style.display = 'block'; } }
document.getElementById('startBtn').onclick = () => { const title = document.getElementById('streamTitle').value || 'Untitled Stream'; if(!localStream) return; liveSocket.emit('start_live_stream', {title: title}); document.getElementById('startBtn').style.display = 'none'; document.getElementById('stopBtn').style.display = 'inline-block'; document.getElementById('statusText').innerText = '🔴 LIVE: ' + title; };
document.getElementById('stopBtn').onclick = () => { if(localStream) localStream.getTracks().forEach(t => t.stop()); localStream = null; Object.values(peerConnections).forEach(pc => pc.close()); peerConnections = {}; liveSocket.emit('stop_live_stream'); document.getElementById('localVideo').srcObject = null; document.getElementById('startBtn').style.display = 'inline-block'; document.getElementById('stopBtn').style.display = 'none'; document.getElementById('statusText').innerText = 'Stream ended'; };
liveSocket.on('viewer_joined', (data) => { if(!localStream) return; const viewerSid = data.viewer_sid; const pc = new RTCPeerConnection(rtcConfig); peerConnections[viewerSid] = pc; localStream.getTracks().forEach(track => pc.addTrack(track, localStream)); pc.onicecandidate = (e) => { if(e.candidate) liveSocket.emit('webrtc_signal', {target_sid: viewerSid, candidate: e.candidate}); }; pc.createOffer().then(offer => { pc.setLocalDescription(offer); liveSocket.emit('webrtc_signal', {target_sid: viewerSid, sdp: offer}); }); });
liveSocket.on('webrtc_signal', (data) => { const pc = peerConnections[data.sender]; if(!pc) return; if(data.sdp) pc.setRemoteDescription(new RTCSessionDescription(data.sdp)).then(() => { if(data.sdp.type === 'offer') pc.createAnswer().then(ans => { pc.setLocalDescription(ans); liveSocket.emit('webrtc_signal', {target_sid: data.sender, sdp: ans}); }); }); if(data.candidate) pc.addIceCandidate(new RTCIceCandidate(data.candidate)); });
liveSocket.on('force_stream_end', () => { document.getElementById('stopBtn').click(); });
</script>
{% endblock %}
""",
"live_watch.html": """
{% extends 'base.html' %}
{% block content %}
<div style="max-width:800px;margin:0 auto;text-align:center;">
    <h2 style="margin-bottom:20px;font-size:20px;">📺 Watching {{ broadcaster }}</h2>
    <div class="admin-panel">
        <video id="remoteVideo" autoplay playsinline style="width:100%;max-width:600px;background:#000;border-radius:8px;"></video>
        <p id="statusText" style="color:var(--text2);margin-top:10px;">Connecting to stream...</p>
    </div>
</div>
<script>
const watchSocket = io(); const broadcaster = '{{ broadcaster }}'; let pc = null, broadcasterSid = null; const rtcConfig = {iceServers: [{urls: 'stun:stun.l.google.com:19302'}]};
if(!window.isSecureContext && location.protocol !== 'https:') { document.getElementById('statusText').innerText = 'Connection blocked: insecure context. Use HTTPS.'; } else {
    watchSocket.on('connect', () => { watchSocket.emit('join_live_stream', {broadcaster: broadcaster}); });
    watchSocket.on('stream_ended', (data) => {
        if (!data || data.broadcaster !== broadcaster) return;
        if (pc) { pc.close(); pc = null; }
        document.getElementById('remoteVideo').srcObject = null;
        document.getElementById('statusText').innerText = 'This stream has ended.';
    });
    watchSocket.on('webrtc_signal', async (data) => {
        broadcasterSid = data.sender;
        if(!pc) { pc = new RTCPeerConnection(rtcConfig); pc.ontrack = e => { document.getElementById('remoteVideo').srcObject = e.streams[0]; document.getElementById('statusText').innerText = 'Connected'; }; pc.onicecandidate = e => { if(e.candidate) watchSocket.emit('webrtc_signal', {target_sid: broadcasterSid, candidate: e.candidate}); }; }
        if(data.sdp) await pc.setRemoteDescription(new RTCSessionDescription(data.sdp));
        if(data.sdp && data.sdp.type === 'offer') { const answer = await pc.createAnswer(); await pc.setLocalDescription(answer); watchSocket.emit('webrtc_signal', {target_sid: broadcasterSid, sdp: answer}); }
        if(data.candidate) await pc.addIceCandidate(new RTCIceCandidate(data.candidate));
    });
}
</script>
{% endblock %}
"""
}

app.jinja_loader = DictLoader(templates)

if __name__ == '__main__':
    threading.Thread(target=generate_missing_thumbnails, daemon=True).start()
    socketio.run(app, debug=False, use_reloader=False, host='0.0.0.0', port=5000)
