import os
import json
import datetime
import uuid
import secrets
import re
import shutil
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
app.secret_key = os.environ.get('FAMTUBE_SECRET_KEY', secrets.token_urlsafe(32))  # Secure random default

app.permanent_session_lifetime = datetime.timedelta(days=365)
app.config['SESSION_COOKIE_HTTPONLY'] = True  
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' 
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"], storage_uri="memory://")
csrf = CSRFProtect(app)

csp = {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"], 
    'style-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", "data:", "https://via.placeholder.com", "blob:"],
    'media-src': ["'self'", "blob:"] 
}
talisman = Talisman(app, content_security_policy=csp, force_https=False) 

socketio = SocketIO(app, cors_allowed_origins="*", max_http_buffer_size=500000000)
online_users = {} 
user_status = {}  
live_streams = {}

ADMIN_DIR = 'famtube_admin'
VIDEO_DIR = os.path.join(ADMIN_DIR, 'videos')
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
ALLOWED_PICS = {'png', 'jpg', 'jpeg'}
USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_]{3,30}$')

for d in [ADMIN_DIR, VIDEO_DIR, PROFILE_DIR, BACKUP_DIR]:
    if not os.path.exists(d): os.makedirs(d)

def allowed_file(filename, allowed_set):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_set

def load_json(filepath):
    if not os.path.exists(filepath):
        return {}
    try:
        with open(filepath, 'r', encoding='utf-8') as f: 
            return json.load(f)
    except (json.JSONDecodeError, IOError, PermissionError):
        return {}

def save_json(filepath, data):
    with open(filepath, 'w', encoding='utf-8') as f: 
        json.dump(data, f, indent=4)

def log_activity(action, username="Guest"):
    try:
        logs = load_json(LOGS_FILE)
        logs.append({
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
            "ip": request.remote_addr, 
            "user_agent": request.headers.get('User-Agent'), 
            "username": username, 
            "action": action
        })
        save_json(LOGS_FILE, logs)
    except Exception:
        pass

def notify_user(target_username, message, link, sender=None):
    if not is_valid_username(target_username):
        return
    notifs = load_json(NOTIFS_FILE)
    if target_username not in notifs: 
        notifs[target_username] = []
    notif_obj = {
        "id": str(uuid.uuid4()), 
        "message": str(message)[:200], 
        "link": link, 
        "read": False, 
        "timestamp": datetime.datetime.now().strftime("%H:%M"), 
        "sender": sender
    }
    notifs[target_username].insert(0, notif_obj)
    save_json(NOTIFS_FILE, notifs)
    if target_username in online_users: 
        try:
            socketio.emit('receive_notification', notif_obj, to=online_users[target_username])
        except Exception:
            pass

def can_view_video(v, user, role):
    if v.get('visibility') == 'hidden' and role != 'admin': 
        return False
    if v.get('privacy') == 'private' and role != 'admin' and user != v['uploader']:
        allowed = [u.strip() for u in v.get('allowed_users', "").split(',') if u.strip()]
        if user not in allowed:
            return False
    return True

def is_valid_username(username):
    if not username or not isinstance(username, str):
        return False
    return bool(USERNAME_REGEX.match(username))

def validate_file_content(filepath, expected_type):
    """Verify actual file magic bytes match expected type. Pure Python, no libmagic needed."""
    try:
        with open(filepath, 'rb') as f:
            header = f.read(16)

        if expected_type == 'image':
            return (
                header.startswith(b'\x89PNG\r\n\x1a\n') or  # PNG
                header.startswith(b'\xff\xd8\xff')           # JPEG/JPG
            )

        elif expected_type == 'video':
            # WEBM (EBML header)
            if header.startswith(b'\x1a\x45\xdf\xa3'):
                return True
            # OGG
            if header.startswith(b'OggS'):
                return True
            # MP4 / MOV (ISO base media file format)
            if len(header) >= 8:
                box_type = header[4:8]
                if box_type in (b'ftyp', b'moov', b'mdat', b'free', b'skip', b'wide', b'pnot'):
                    return True
            return False

        return False
    except Exception:
        return False

def safe_filename_check(filename):
    """Prevent path traversal in user-supplied filenames."""
    if not filename or '..' in filename or filename.startswith('/') or filename.startswith('\\'):
        return False
    return True

def revoke_all_user_sessions(username):
    """Remove all active sessions for a user (called on deletion/password change)."""
    sessions = load_json(SESSIONS_FILE)
    to_remove = [sid for sid, sdata in sessions.items() if sdata.get('username') == username]
    for sid in to_remove:
        del sessions[sid]
    save_json(SESSIONS_FILE, sessions)

# ==================== SECURITY MIDDLEWARE ====================

@app.before_request
def security_checks():
    # Skip static files and login page
    if request.endpoint in ('static', 'login', None):
        return
    
    # Enforce IP filtering
    try:
        config = load_json(CONFIG_FILE)
        if config.get('ip_filter_enabled'):
            client_ip = request.remote_addr or '127.0.0.1'
            blocked = config.get('blocked_ips', [])
            allowed = config.get('allowed_ips', [])
            strict = config.get('strict_allowlist_mode', False)
            
            if client_ip in blocked:
                abort(403)
            if strict and client_ip not in allowed:
                abort(403)
    except Exception:
        pass

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'session_id' not in session or 'username' not in session:
            session.clear()
            return redirect(url_for('login'))
        
        # CRITICAL FIX: Verify user still exists in database
        users = load_json(USERS_FILE)
        if not is_valid_username(session['username']) or session['username'] not in users:
            session.clear()
            return redirect(url_for('login'))
        
        # Verify session is still valid in sessions file
        sessions = load_json(SESSIONS_FILE)
        if session['session_id'] not in sessions:
            session.clear()
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            abort(403)
        # Also run user existence check
        users = load_json(USERS_FILE)
        if session.get('username') not in users:
            session.clear()
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def init_db(filepath, default_data):
    if not os.path.exists(filepath):
        with open(filepath, 'w', encoding='utf-8') as f: 
            json.dump(default_data, f, indent=4)

init_db(CONFIG_FILE, {"allowed_ips": [], "blocked_ips": [], "strict_allowlist_mode": False, "ip_filter_enabled": False})
init_db(USERS_FILE, {})

users_db = load_json(USERS_FILE)
if not any(u.get('role') == 'admin' for u in users_db.values()):
    initial_admin_password = secrets.token_urlsafe(12)[:12]
    users_db["admin"] = {
        "password_hash": generate_password_hash(initial_admin_password),
        "role": "admin",
        "feed_preference": "all",
        "bio": "Administrator",
        "profile_pic": "",
        "hide_last_seen": False,
        "device_notif_enabled": False
    }
    save_json(USERS_FILE, users_db)
    print("\n" + "="*65 + f"\n🚨 SECURE ADMIN GENERATED\nUsername: admin\nPassword: {initial_admin_password}\n" + "="*65 + "\n")

for f, d in [(LOGS_FILE,[]), (VIDEOS_FILE,{}), (ENGAGE_FILE,{}), (COMMENTS_FILE,{}), (NOTIFS_FILE,{}), (SESSIONS_FILE,{}), (PLAYLISTS_FILE,{}), (SAVED_FILE,{}), (HISTORY_FILE,{}), (SUBS_FILE,{})]: 
    init_db(f, d)

def get_all_hashtags():
    videos = load_json(VIDEOS_FILE)
    hashtags = set()
    for v in videos.values():
        for tag in v.get('hashtags', '').split():
            tag = tag.strip().lower()
            if tag.startswith('#') and len(tag) > 1:
                hashtags.add(tag)
    return sorted(list(hashtags))

def get_user_data(username):
    users = load_json(USERS_FILE)
    return users.get(username, {})

def update_user_data(username, data):
    users = load_json(USERS_FILE)
    users[username] = data
    save_json(USERS_FILE, users)

# ==================== ROUTES ====================

@app.route('/')
def index():
    videos = load_json(VIDEOS_FILE)
    users = load_json(USERS_FILE)
    current_user = session.get('username')
    role = session.get('role')
    
    feed_videos = []
    subscribed_content = []
    subs = load_json(SUBS_FILE).get(current_user, []) if current_user else []
    
    for vid, v in videos.items():
        if not can_view_video(v, current_user, role):
            continue
        v['id'] = vid
        uploader_data = users.get(v['uploader'], {})
        v['uploader_pic'] = uploader_data.get('profile_pic', '')
        
        if current_user and v['uploader'] in subs:
            subscribed_content.append(v)
        else:
            feed_videos.append(v)
    
    feed_videos.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    subscribed_content.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    live_data = {}
    for u, meta in live_streams.items():
        live_data[u] = meta
    
    unread = 0
    current_user_obj = {}
    if current_user:
        notifs = load_json(NOTIFS_FILE).get(current_user, [])
        unread = sum(1 for n in notifs if not n.get('read'))
        current_user_obj = users.get(current_user, {})
    
    return render_template('index.html', 
                         videos=feed_videos[:50], 
                         subscribed_content=subscribed_content[:20],
                         live_streams=live_data,
                         unread_notifs=unread,
                         current_user_obj=current_user_obj)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    error_msg = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember')
        
        if not is_valid_username(username):
            error_msg = "Invalid username format."
            log_activity('failed_login_invalid_format', username or 'Guest')
            return render_template('login.html', error_msg=error_msg)
        
        users = load_json(USERS_FILE)
        user_data = users.get(username)
        
        if user_data and check_password_hash(user_data['password_hash'], password):
            session.clear()
            session['username'] = username
            session['role'] = user_data.get('role', 'user')
            session['session_id'] = str(uuid.uuid4())
            
            if remember:
                session.permanent = True
            
            sessions = load_json(SESSIONS_FILE)
            sessions[session['session_id']] = {
                'username': username,
                'ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', ''),
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            save_json(SESSIONS_FILE, sessions)
            
            log_activity('login', username)
            return redirect(url_for('index'))
        else:
            error_msg = "Invalid username or password."
            log_activity('failed_login', username or 'Guest')
    
    return render_template('login.html', error_msg=error_msg)

@app.route('/logout')
def logout():
    if 'session_id' in session:
        sessions = load_json(SESSIONS_FILE)
        sessions.pop(session.get('session_id'), None)
        save_json(SESSIONS_FILE, sessions)
    session.clear()
    return redirect(url_for('login'))

@app.route('/explore')
def explore():
    videos = load_json(VIDEOS_FILE)
    users = load_json(USERS_FILE)
    current_user = session.get('username')
    role = session.get('role')
    
    hashtags = get_all_hashtags()
    tags_param = request.args.get('tags', '').strip()
    selected_tags = [t.strip().lower() for t in tags_param.split(',') if t.strip()] if tags_param else []
    
    filtered = []
    for vid, v in videos.items():
        if not can_view_video(v, current_user, role):
            continue
        
        v['id'] = vid
        uploader_data = users.get(v['uploader'], {})
        v['uploader_pic'] = uploader_data.get('profile_pic', '')
        
        if selected_tags:
            vid_tags = v.get('hashtags', '').lower()
            if any('#'+tag in vid_tags or tag in vid_tags for tag in selected_tags):
                filtered.append(v)
        else:
            filtered.append(v)
    
    filtered.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    unread = 0
    current_user_obj = {}
    if current_user:
        notifs = load_json(NOTIFS_FILE).get(current_user, [])
        unread = sum(1 for n in notifs if not n.get('read'))
        current_user_obj = users.get(current_user, {})
    
    return render_template('explore.html',
                         videos=filtered,
                         hashtags=hashtags,
                         selected_tags=selected_tags,
                         all_videos_mode=not selected_tags,
                         unread_notifs=unread,
                         current_user_obj=current_user_obj)

@app.route('/search')
def search():
    query = request.args.get('q', '').strip()
    current_user = session.get('username')
    role = session.get('role')
    users = load_json(USERS_FILE)
    videos = load_json(VIDEOS_FILE)
    
    result_users = []
    result_videos = []
    
    if query:
        for u, data in users.items():
            if query.lower() in u.lower():
                result_users.append(u)
        
        for vid, v in videos.items():
            if not can_view_video(v, current_user, role):
                continue
            if query.lower() in v.get('title','').lower() or query.lower() in v.get('hashtags','').lower() or query.lower() in v.get('captions','').lower():
                v['id'] = vid
                uploader_data = users.get(v['uploader'], {})
                v['uploader_pic'] = uploader_data.get('profile_pic', '')
                result_videos.append(v)
    
    unread = 0
    current_user_obj = {}
    if current_user:
        notifs = load_json(NOTIFS_FILE).get(current_user, [])
        unread = sum(1 for n in notifs if not n.get('read'))
        current_user_obj = users.get(current_user, {})
    
    return render_template('search.html',
                         query=query,
                         users=result_users,
                         videos=result_videos,
                         unread_notifs=unread,
                         current_user_obj=current_user_obj)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per hour")
def upload():
    if request.method == 'POST':
        if 'video_file' not in request.files:
            return redirect(url_for('upload'))
        
        file = request.files['video_file']
        if file.filename == '':
            return redirect(url_for('upload'))
        
        if file and allowed_file(file.filename, ALLOWED_EXTENSIONS):
            filename = secure_filename(file.filename)
            unique_name = f"{uuid.uuid4().hex}_{filename}"
            filepath = os.path.join(VIDEO_DIR, unique_name)
            file.save(filepath)
            
            # SECURITY FIX: Validate actual file content
            if not validate_file_content(filepath, 'video'):
                os.remove(filepath)
                users = load_json(USERS_FILE)
                unread = sum(1 for n in load_json(NOTIFS_FILE).get(session['username'], []) if not n.get('read'))
                return render_template('upload.html', 
                                     error_msg="Invalid video file content.",
                                     unread_notifs=unread,
                                     current_user_obj=users.get(session['username'], {}))
            
            title = request.form.get('title', 'Untitled').strip()
            captions = request.form.get('captions', '').strip()
            hashtags = request.form.get('hashtags', '').strip()
            privacy = request.form.get('privacy', 'public')
            allowed_users = request.form.get('allowed_users', '').strip()
            
            videos = load_json(VIDEOS_FILE)
            video_id = str(uuid.uuid4())
            videos[video_id] = {
                'title': title,
                'captions': captions,
                'hashtags': hashtags,
                'privacy': privacy,
                'allowed_users': allowed_users,
                'uploader': session['username'],
                'filename': unique_name,
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                'visibility': 'visible'
            }
            save_json(VIDEOS_FILE, videos)
            
            subs = load_json(SUBS_FILE)
            for subscriber, sub_list in subs.items():
                if session['username'] in sub_list:
                    notify_user(subscriber, f"{session['username']} uploaded: {title}", f"/watch/{video_id}", sender=session['username'])
            
            log_activity('upload', session['username'])
            return redirect(url_for('watch', video_id=video_id))
    
    users = load_json(USERS_FILE)
    current_user_obj = users.get(session.get('username'), {})
    notifs = load_json(NOTIFS_FILE).get(session.get('username'), [])
    unread = sum(1 for n in notifs if not n.get('read'))
    
    return render_template('upload.html', 
                         unread_notifs=unread,
                         current_user_obj=current_user_obj,
                         error_msg=None)

@app.route('/watch/<video_id>', methods=['GET', 'POST'])
@login_required
def watch(video_id):
    videos = load_json(VIDEOS_FILE)
    users = load_json(USERS_FILE)
    comments_db = load_json(COMMENTS_FILE)
    saved_db = load_json(SAVED_FILE)
    playlists_db = load_json(PLAYLISTS_FILE)
    
    video = videos.get(video_id)
    if not video:
        abort(404)
    
    if not can_view_video(video, session.get('username'), session.get('role')):
        abort(403)
    
    if request.method == 'POST':
        text = request.form.get('comment_text', '').strip()
        parent_id = request.form.get('parent_id', '').strip()
        if text:
            comment_id = str(uuid.uuid4())
            comment_obj = {
                'id': comment_id,
                'user': session['username'],
                'text': text,
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                'likes': [],
                'user_pic': users.get(session['username'], {}).get('profile_pic', '')
            }
            
            if video_id not in comments_db:
                comments_db[video_id] = []
            
            if parent_id:
                for c in comments_db.get(video_id, []):
                    if c['id'] == parent_id:
                        if 'replies' not in c:
                            c['replies'] = []
                        reply_obj = {
                            'id': comment_id,
                            'user': session['username'],
                            'text': text,
                            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                            'likes': [],
                            'user_pic': users.get(session['username'], {}).get('profile_pic', '')
                        }
                        c['replies'].append(reply_obj)
                        
                        if c['user'] != session['username']:
                            notify_user(c['user'], f"{session['username']} replied to your comment", f"/watch/{video_id}", sender=session['username'])
                        break
            else:
                comments_db[video_id].append(comment_obj)
                if video['uploader'] != session['username']:
                    notify_user(video['uploader'], f"{session['username']} commented on your video", f"/watch/{video_id}", sender=session['username'])
            
            save_json(COMMENTS_FILE, comments_db)
            return redirect(url_for('watch', video_id=video_id))
    
    comments = comments_db.get(video_id, [])
    user_saved = saved_db.get(session['username'], [])
    is_saved = video_id in user_saved
    uploader_pic = users.get(video['uploader'], {}).get('profile_pic', '')
    
    unread = 0
    notifs = load_json(NOTIFS_FILE).get(session.get('username'), [])
    unread = sum(1 for n in notifs if not n.get('read'))
    current_user_obj = users.get(session.get('username'), {})
    
    return render_template('watch.html',
                         video=video,
                         video_id=video_id,
                         comments=comments,
                         is_saved=is_saved,
                         uploader_pic=uploader_pic,
                         unread_notifs=unread,
                         current_user_obj=current_user_obj)

@app.route('/user/<username>', methods=['GET', 'POST'])
@login_required
def user_profile(username):
    if not is_valid_username(username):
        abort(404)
    
    users = load_json(USERS_FILE)
    videos = load_json(VIDEOS_FILE)
    subs = load_json(SUBS_FILE)
    playlists = load_json(PLAYLISTS_FILE)
    
    profile = users.get(username)
    if not profile:
        abort(404)
    
    if request.method == 'POST':
        action = request.form.get('action')
        target = request.form.get('target_user')
        if action in ['subscribe', 'unsubscribe'] and target and is_valid_username(target):
            current = session['username']
            user_subs = subs.get(current, [])
            if action == 'subscribe' and target not in user_subs:
                user_subs.append(target)
                notify_user(target, f"{current} subscribed to you!", f"/user/{current}", sender=current)
            elif action == 'unsubscribe' and target in user_subs:
                user_subs.remove(target)
            subs[current] = user_subs
            save_json(SUBS_FILE, subs)
            return redirect(url_for('user_profile', username=username))
    
    user_videos = []
    for vid, v in videos.items():
        if v['uploader'] == username:
            if can_view_video(v, session.get('username'), session.get('role')):
                v['id'] = vid
                user_videos.append(v)
    
    user_videos.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    is_subscribed = username in subs.get(session['username'], [])
    
    user_playlists = []
    for pl_id, pl in playlists.items():
        if pl.get('owner') == username:
            pl['id'] = pl_id
            pl['video_count'] = len(pl.get('videos', []))
            user_playlists.append(pl)
    
    unread = 0
    notifs = load_json(NOTIFS_FILE).get(session['username'], [])
    unread = sum(1 for n in notifs if not n.get('read'))
    current_user_obj = users.get(session['username'], {})
    is_online = username in online_users
    
    return render_template('profile.html',
                         profile_name=username,
                         profile_pic=profile.get('profile_pic', ''),
                         bio=profile.get('bio', ''),
                         hide_last_seen=profile.get('hide_last_seen', False),
                         last_seen=user_status.get(username, 'Never'),
                         videos=user_videos,
                         playlists=user_playlists,
                         is_subscribed=is_subscribed,
                         is_online=is_online,
                         unread_notifs=unread,
                         current_user_obj=current_user_obj)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    users = load_json(USERS_FILE)
    username = session['username']
    user_data = users.get(username, {})
    
    success_msg = None
    error_msg = None
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_profile':
            bio = request.form.get('bio', '').strip()
            if bio:
                user_data['bio'] = bio[:500]  # Limit bio length
            
            if 'profile_pic' in request.files:
                file = request.files['profile_pic']
                if file and file.filename and allowed_file(file.filename, ALLOWED_PICS):
                    filename = secure_filename(file.filename)
                    unique_name = f"{uuid.uuid4().hex}_{filename}"
                    filepath = os.path.join(PROFILE_DIR, unique_name)
                    file.save(filepath)
                    
                    # Validate image content
                    if validate_file_content(filepath, 'image'):
                        user_data['profile_pic'] = unique_name
                    else:
                        os.remove(filepath)
                        error_msg = "Invalid image file."
            
            if not error_msg:
                update_user_data(username, user_data)
                success_msg = "Profile updated successfully!"
                log_activity('update_profile', username)
        
        elif action == 'toggle_privacy':
            hide = request.form.get('hide_last_seen') == 'yes'
            user_data['hide_last_seen'] = hide
            update_user_data(username, user_data)
            success_msg = "Privacy settings saved."
        
        elif action == 'toggle_device_notif':
            enabled = request.form.get('device_notif') == 'yes'
            user_data['device_notif_enabled'] = enabled
            update_user_data(username, user_data)
            success_msg = "Notification settings saved."
        
        elif action == 'change_creds':
            new_username = request.form.get('new_username', '').strip()
            new_password = request.form.get('new_password', '')
            
            if new_username and new_username != username:
                if not is_valid_username(new_username):
                    error_msg = "Username must be 3-30 characters, alphanumeric and underscores only."
                elif new_username in users:
                    error_msg = "Username already taken."
                else:
                    users[new_username] = user_data
                    del users[username]
                    save_json(USERS_FILE, users)
                    session['username'] = new_username
                    username = new_username
                    success_msg = "Username updated."
            
            if new_password and not error_msg:
                if len(new_password) < 6:
                    error_msg = "Password must be at least 6 characters."
                else:
                    user_data['password_hash'] = generate_password_hash(new_password)
                    update_user_data(username, user_data)
                    revoke_all_user_sessions(username)
                    # Keep current session
                    sessions = load_json(SESSIONS_FILE)
                    sessions[session['session_id']] = {
                        'username': username,
                        'ip': request.remote_addr,
                        'user_agent': request.headers.get('User-Agent', ''),
                        'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    save_json(SESSIONS_FILE, sessions)
                    success_msg = success_msg or "Password updated. All other sessions logged out."
            
            log_activity('change_credentials', username)
    
    unread = 0
    notifs = load_json(NOTIFS_FILE).get(username, [])
    unread = sum(1 for n in notifs if not n.get('read'))
    current_user_obj = users.get(username, {})
    
    return render_template('settings.html',
                         success_msg=success_msg,
                         error_msg=error_msg,
                         device_notif_enabled=user_data.get('device_notif_enabled', False),
                         unread_notifs=unread,
                         current_user_obj=current_user_obj)

@app.route('/notifications')
@login_required
def notifications():
    username = session['username']
    notifs = load_json(NOTIFS_FILE).get(username, [])
    
    for n in notifs:
        n['read'] = True
    notifs_data = load_json(NOTIFS_FILE)
    notifs_data[username] = notifs
    save_json(NOTIFS_FILE, notifs_data)
    
    users = load_json(USERS_FILE)
    unread = 0
    current_user_obj = users.get(username, {})
    
    return render_template('notifications.html',
                         notifications=notifs,
                         unread_notifs=unread,
                         current_user_obj=current_user_obj)

@app.route('/subscriptions', methods=['GET', 'POST'])
@login_required
def subscriptions():
    username = session['username']
    subs = load_json(SUBS_FILE)
    users = load_json(USERS_FILE)
    videos = load_json(VIDEOS_FILE)
    
    if request.method == 'POST':
        action = request.form.get('action')
        target = request.form.get('target_user')
        if action == 'unsubscribe' and target and is_valid_username(target):
            user_subs = subs.get(username, [])
            if target in user_subs:
                user_subs.remove(target)
            subs[username] = user_subs
            save_json(SUBS_FILE, subs)
            return redirect(url_for('subscriptions'))
    
    user_subs = subs.get(username, [])
    subscriptions_list = []
    for sub in user_subs:
        sub_data = users.get(sub, {})
        subscriptions_list.append({
            'name': sub,
            'profile_pic': sub_data.get('profile_pic', '')
        })
    
    latest_videos = []
    for vid, v in videos.items():
        if v['uploader'] in user_subs:
            if can_view_video(v, username, session.get('role')):
                v['id'] = vid
                uploader_data = users.get(v['uploader'], {})
                v['uploader_pic'] = uploader_data.get('profile_pic', '')
                latest_videos.append(v)
    
    latest_videos.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    unread = 0
    notifs = load_json(NOTIFS_FILE).get(username, [])
    unread = sum(1 for n in notifs if not n.get('read'))
    current_user_obj = users.get(username, {})
    
    return render_template('subscriptions.html',
                         subscriptions=subscriptions_list,
                         latest_videos=latest_videos[:50],
                         unread_notifs=unread,
                         current_user_obj=current_user_obj)

@app.route('/playlists', methods=['GET', 'POST'])
@login_required
def playlists():
    username = session['username']
    playlists_db = load_json(PLAYLISTS_FILE)
    
    if request.method == 'POST':
        name = request.form.get('playlist_name', '').strip()
        if name:
            pl_id = str(uuid.uuid4())
            playlists_db[pl_id] = {
                'name': name,
                'owner': username,
                'videos': [],
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            }
            save_json(PLAYLISTS_FILE, playlists_db)
            return redirect(url_for('playlists'))
    
    user_playlists = []
    for pl_id, pl in playlists_db.items():
        if pl.get('owner') == username:
            pl['id'] = pl_id
            pl['video_count'] = len(pl.get('videos', []))
            user_playlists.append(pl)
    
    users = load_json(USERS_FILE)
    unread = 0
    notifs = load_json(NOTIFS_FILE).get(username, [])
    unread = sum(1 for n in notifs if not n.get('read'))
    current_user_obj = users.get(username, {})
    
    return render_template('playlists.html',
                         playlists=user_playlists,
                         unread_notifs=unread,
                         current_user_obj=current_user_obj)

@app.route('/playlist/<pl_id>', methods=['GET', 'POST'])
@login_required
def playlist_detail(pl_id):
    playlists_db = load_json(PLAYLISTS_FILE)
    videos = load_json(VIDEOS_FILE)
    users = load_json(USERS_FILE)
    
    pl = playlists_db.get(pl_id)
    if not pl or pl.get('owner') != session['username']:
        abort(403)
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'delete_playlist':
            del playlists_db[pl_id]
            save_json(PLAYLISTS_FILE, playlists_db)
            return redirect(url_for('playlists'))
    
    pl_videos = []
    for vid in pl.get('videos', []):
        if vid in videos:
            v = videos[vid]
            v['id'] = vid
            uploader_data = users.get(v['uploader'], {})
            v['uploader_pic'] = uploader_data.get('profile_pic', '')
            pl_videos.append(v)
    
    unread = 0
    notifs = load_json(NOTIFS_FILE).get(session.get('username'), [])
    unread = sum(1 for n in notifs if not n.get('read'))
    current_user_obj = users.get(session.get('username'), {})
    
    return render_template('playlist_detail.html',
                         playlist=pl,
                         videos=pl_videos,
                         unread_notifs=unread,
                         current_user_obj=current_user_obj)

@app.route('/saved')
@login_required
def saved_videos():
    username = session['username']
    saved_db = load_json(SAVED_FILE)
    videos = load_json(VIDEOS_FILE)
    users = load_json(USERS_FILE)
    
    user_saved = saved_db.get(username, [])
    saved_videos_list = []
    for vid in user_saved:
        if vid in videos:
            v = videos[vid]
            if can_view_video(v, username, session.get('role')):
                v['id'] = vid
                uploader_data = users.get(v['uploader'], {})
                v['uploader_pic'] = uploader_data.get('profile_pic', '')
                saved_videos_list.append(v)
    
    unread = 0
    notifs = load_json(NOTIFS_FILE).get(username, [])
    unread = sum(1 for n in notifs if not n.get('read'))
    current_user_obj = users.get(username, {})
    
    return render_template('saved_videos.html',
                         videos=saved_videos_list,
                         unread_notifs=unread,
                         current_user_obj=current_user_obj)

@app.route('/history', methods=['GET', 'POST'])
@login_required
def watch_history():
    username = session['username']
    history_db = load_json(HISTORY_FILE)
    videos = load_json(VIDEOS_FILE)
    users = load_json(USERS_FILE)
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'clear_history':
            history_db[username] = []
            save_json(HISTORY_FILE, history_db)
            return redirect(url_for('watch_history'))
    
    user_history = history_db.get(username, [])
    history_list = []
    for h in user_history:
        vid = h.get('video_id')
        if vid and vid in videos:
            v = videos[vid]
            history_list.append({
                'video_id': vid,
                'title': v.get('title', 'Untitled'),
                'uploader': v.get('uploader', 'Unknown'),
                'watched_at': h.get('timestamp', '')
            })
    
    history_list.reverse()
    
    unread = 0
    notifs = load_json(NOTIFS_FILE).get(username, [])
    unread = sum(1 for n in notifs if not n.get('read'))
    current_user_obj = users.get(username, {})
    
    return render_template('watch_history.html',
                         history=history_list,
                         unread_notifs=unread,
                         current_user_obj=current_user_obj)

@app.route('/users')
@login_required
def users_list():
    users = load_json(USERS_FILE)
    current = session['username']
    
    user_list = {}
    for u, data in users.items():
        if u != current:
            user_list[u] = {
                'bio': data.get('bio', ''),
                'profile_pic': data.get('profile_pic', ''),
                'is_online': u in online_users
            }
    
    unread = 0
    notifs = load_json(NOTIFS_FILE).get(current, [])
    unread = sum(1 for n in notifs if not n.get('read'))
    current_user_obj = users.get(current, {})
    
    return render_template('users_list.html',
                         users=user_list,
                         unread_notifs=unread,
                         current_user_obj=current_user_obj)

@app.route('/famtube_admin', methods=['GET', 'POST'])
@login_required
@admin_required
@limiter.limit("50 per hour")
def admin_dashboard():
    config = load_json(CONFIG_FILE)
    users = load_json(USERS_FILE)
    videos = load_json(VIDEOS_FILE)
    sessions = load_json(SESSIONS_FILE)
    history_db = load_json(HISTORY_FILE)
    engage_db = load_json(ENGAGE_FILE)
    
    admin_msg = request.args.get('msg', '')
    admin_msg_type = request.args.get('msg_type', '')
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'toggle_ip_filter':
            config['ip_filter_enabled'] = request.form.get('ip_filter_enabled') == 'yes'
            config['strict_allowlist_mode'] = request.form.get('strict_allowlist_mode') == 'yes'
            config['blocked_ips'] = [ip.strip() for ip in request.form.get('blocked_ips', '').split('\n') if ip.strip()]
            config['allowed_ips'] = [ip.strip() for ip in request.form.get('allowed_ips', '').split('\n') if ip.strip()]
            save_json(CONFIG_FILE, config)
            log_activity('update_ip_filter', session['username'])
        
        elif action == 'kill_stream':
            target = request.form.get('target_user')
            if target and is_valid_username(target) and target in live_streams:
                try:
                    socketio.emit('force_stream_end', room=online_users.get(target))
                except Exception:
                    pass
                live_streams.pop(target, None)
                log_activity(f'killed_stream_{target}', session['username'])
        
        elif action == 'toggle_visibility':
            vid = request.form.get('target_vid')
            if vid and vid in videos:
                current = videos[vid].get('visibility', 'visible')
                videos[vid]['visibility'] = 'hidden' if current == 'visible' else 'visible'
                save_json(VIDEOS_FILE, videos)
        
        elif action == 'delete_video':
            vid = request.form.get('target_vid')
            if vid and vid in videos:
                filename = videos[vid].get('filename')
                if filename and safe_filename_check(filename):
                    filepath = os.path.join(VIDEO_DIR, filename)
                    if os.path.exists(filepath):
                        os.remove(filepath)
                del videos[vid]
                save_json(VIDEOS_FILE, videos)
        
        elif action == 'revoke_session':
            sid = request.form.get('revoke_sid')
            if sid and sid in sessions:
                del sessions[sid]
                save_json(SESSIONS_FILE, sessions)
        
        elif action == 'create_user':
            new_user = request.form.get('new_user', '').strip()
            new_pass = request.form.get('new_pass', '')
            preference = request.form.get('preference', 'all').strip()

            if not is_valid_username(new_user):
                return redirect(url_for('admin_dashboard', msg='Invalid username format (3-30 chars, alphanumeric/underscore only)', msg_type='error'))
            elif new_user in users:
                return redirect(url_for('admin_dashboard', msg='Username already exists', msg_type='error'))
            elif not new_pass or len(new_pass) < 6:
                return redirect(url_for('admin_dashboard', msg='Password must be at least 6 characters', msg_type='error'))
            else:
                users[new_user] = {
                    "password_hash": generate_password_hash(new_pass),
                    "role": "user",
                    "feed_preference": preference,
                    "bio": "",
                    "profile_pic": "",
                    "hide_last_seen": False,
                    "device_notif_enabled": False
                }
                save_json(USERS_FILE, users)
                log_activity(f'created_user_{new_user}', session['username'])
                return redirect(url_for('admin_dashboard', msg=f'User {new_user} created successfully', msg_type='success'))
        elif action == 'edit_user':
            original = request.form.get('original_username', '').strip()
            new_name = request.form.get('edit_username', '').strip()
            new_pass = request.form.get('edit_password', '')
            preference = request.form.get('edit_preference', 'all').strip()

            if original and is_valid_username(original) and original in users:
                user_data = users[original]
                if new_name and new_name != original:
                    if not is_valid_username(new_name):
                        return redirect(url_for('admin_dashboard', msg='Invalid new username format', msg_type='error'))
                    if new_name in users:
                        return redirect(url_for('admin_dashboard', msg='New username already exists', msg_type='error'))
                    users[new_name] = user_data
                    del users[original]
                    # Update sessions for renamed user
                    for sid, sdata in sessions.items():
                        if sdata.get('username') == original:
                            sdata['username'] = new_name
                    save_json(SESSIONS_FILE, sessions)
                    original = new_name

                if new_pass:
                    if len(new_pass) < 6:
                        return redirect(url_for('admin_dashboard', msg='Password must be at least 6 characters', msg_type='error'))
                    user_data['password_hash'] = generate_password_hash(new_pass)
                    revoke_all_user_sessions(original)

                user_data['feed_preference'] = preference
                users[original] = user_data
                save_json(USERS_FILE, users)
                return redirect(url_for('admin_dashboard', msg=f'User {original} updated successfully', msg_type='success'))
            else:
                return redirect(url_for('admin_dashboard', msg='Original user not found', msg_type='error'))
        elif action == 'delete_user':
            target = request.form.get('del_user')
            mode = request.form.get('delete_mode', 'backup')
            if target and is_valid_username(target) and target in users and target != 'admin':
                if mode == 'backup':
                    user_videos = {vid: v for vid, v in videos.items() if v['uploader'] == target}
                    if user_videos:
                        safe_target = secure_filename(target)
                        backup_path = os.path.join(BACKUP_DIR, safe_target)
                        os.makedirs(backup_path, exist_ok=True)
                        for vid, v in user_videos.items():
                            src = os.path.join(VIDEO_DIR, v['filename'])
                            if os.path.exists(src) and safe_filename_check(v['filename']):
                                shutil.copy2(src, backup_path)
                            del videos[vid]
                        save_json(VIDEOS_FILE, videos)
                elif mode == 'delete_videos':
                    user_videos = [vid for vid, v in videos.items() if v['uploader'] == target]
                    for vid in user_videos:
                        filename = videos[vid].get('filename')
                        if filename and safe_filename_check(filename):
                            filepath = os.path.join(VIDEO_DIR, filename)
                            if os.path.exists(filepath):
                                os.remove(filepath)
                        del videos[vid]
                    save_json(VIDEOS_FILE, videos)
                elif mode == 'keep_videos':
                    for vid, v in videos.items():
                        if v['uploader'] == target:
                            v['uploader'] = 'deleted_user'
                    save_json(VIDEOS_FILE, videos)

                # CRITICAL FIX: Revoke all sessions for deleted user
                revoke_all_user_sessions(target)

                # Remove from online users
                online_users.pop(target, None)
                user_status.pop(target, None)
                live_streams.pop(target, None)

                del users[target]
                save_json(USERS_FILE, users)
                return redirect(url_for('admin_dashboard', msg=f'User {target} deleted successfully', msg_type='success'))
            else:
                return redirect(url_for('admin_dashboard', msg='Cannot delete admin or invalid user', msg_type='error'))
        return redirect(url_for('admin_dashboard'))
    
    metrics = []
    for user, history in history_db.items():
        total_mins = sum(h.get('duration', 0) for h in history) // 60
        video_count = len(history)
        history_str = ', '.join([videos.get(h.get('video_id'), {}).get('title', 'Unknown')[:20] for h in history[-5:]])
        metrics.append({
            'user': user,
            'total_mins': total_mins,
            'history': history_str or 'No history'
        })
    
    unread = 0
    notifs = load_json(NOTIFS_FILE).get(session['username'], [])
    unread = sum(1 for n in notifs if not n.get('read'))
    current_user_obj = users.get(session['username'], {})
    
    # Pagination for active sessions
    sessions_page = request.args.get('sessions_page', 1, type=int)
    per_page = 7
    sessions_items = list(sessions.items())
    total_sessions = len(sessions_items)
    total_pages = max(1, (total_sessions + per_page - 1) // per_page)
    sessions_page = max(1, min(sessions_page, total_pages))
    start = (sessions_page - 1) * per_page
    end = start + per_page
    paginated_sessions = dict(sessions_items[start:end])

    return render_template('admin.html',
                         config=config,
                         users=users,
                         videos=videos,
                         live_streams=live_streams,
                         active_sessions=paginated_sessions,
                         sessions_page=sessions_page,
                         sessions_total_pages=total_pages,
                         sessions_total=total_sessions,
                         metrics=metrics,
                         unread_notifs=unread,
                         current_user_obj=current_user_obj,
                         admin_msg=admin_msg,
                         admin_msg_type=admin_msg_type)

@app.route('/admin/user_history/<target_user>')
@login_required
@admin_required
def admin_user_history(target_user):
    if not is_valid_username(target_user):
        abort(404)
    
    history_db = load_json(HISTORY_FILE)
    videos = load_json(VIDEOS_FILE)
    users = load_json(USERS_FILE)
    
    user_history = history_db.get(target_user, [])
    history_list = []
    total_mins = 0
    
    for h in user_history:
        vid = h.get('video_id')
        if vid and vid in videos:
            v = videos[vid]
            history_list.append({
                'video_id': vid,
                'title': v.get('title', 'Untitled'),
                'uploader': v.get('uploader', 'Unknown'),
                'watched_at': h.get('timestamp', '')
            })
            total_mins += h.get('duration', 0) // 60
    
    history_list.reverse()
    
    unread = 0
    notifs = load_json(NOTIFS_FILE).get(session['username'], [])
    unread = sum(1 for n in notifs if not n.get('read'))
    current_user_obj = users.get(session['username'], {})
    
    return render_template('admin_user_history.html',
                         target_user=target_user,
                         history=history_list,
                         total_watch_mins=total_mins,
                         video_count=len(history_list),
                         unread_notifs=unread,
                         current_user_obj=current_user_obj)

@app.route('/live/broadcast')
@login_required
def live_broadcast():
    users = load_json(USERS_FILE)
    unread = 0
    notifs = load_json(NOTIFS_FILE).get(session['username'], [])
    unread = sum(1 for n in notifs if not n.get('read'))
    current_user_obj = users.get(session['username'], {})
    return render_template('live_broadcast.html',
                         unread_notifs=unread,
                         current_user_obj=current_user_obj)

@app.route('/live/watch/<broadcaster>')
@login_required
def live_watch(broadcaster):
    if not is_valid_username(broadcaster) or broadcaster not in live_streams:
        return redirect(url_for('index'))
    users = load_json(USERS_FILE)
    unread = 0
    notifs = load_json(NOTIFS_FILE).get(session['username'], [])
    unread = sum(1 for n in notifs if not n.get('read'))
    current_user_obj = users.get(session['username'], {})
    return render_template('live_watch.html',
                         broadcaster=broadcaster,
                         unread_notifs=unread,
                         current_user_obj=current_user_obj)

# ==================== API ROUTES ====================

@app.route('/api/track_engagement', methods=['POST'])
@login_required
def track_engagement():
    data = request.get_json()
    video_id = data.get('video_id')
    seconds = data.get('seconds', 5)
    
    engage = load_json(ENGAGE_FILE)
    user = session['username']
    
    if user not in engage:
        engage[user] = {}
    if video_id not in engage[user]:
        engage[user][video_id] = 0
    engage[user][video_id] += seconds
    save_json(ENGAGE_FILE, engage)
    
    return jsonify({'status': 'ok'})

@app.route('/api/like_comment', methods=['POST'])
@login_required
def like_comment():
    data = request.get_json()
    video_id = data.get('video_id')
    comment_id = data.get('comment_id')
    
    comments_db = load_json(COMMENTS_FILE)
    comments = comments_db.get(video_id, [])
    
    def find_and_like(comment_list):
        for c in comment_list:
            if c['id'] == comment_id:
                likes = c.get('likes', [])
                if session['username'] in likes:
                    likes.remove(session['username'])
                else:
                    likes.append(session['username'])
                c['likes'] = likes
                return len(likes)
            if 'replies' in c:
                result = find_and_like(c['replies'])
                if result is not None:
                    return result
        return None
    
    likes_count = find_and_like(comments)
    if likes_count is not None:
        comments_db[video_id] = comments
        save_json(COMMENTS_FILE, comments_db)
        return jsonify({'status': 'ok', 'likes': likes_count})
    
    return jsonify({'status': 'error'}), 404

@app.route('/api/save_video', methods=['POST'])
@login_required
def save_video():
    data = request.get_json()
    video_id = data.get('video_id')
    
    saved_db = load_json(SAVED_FILE)
    user = session['username']
    
    if user not in saved_db:
        saved_db[user] = []
    
    saved = False
    if video_id in saved_db[user]:
        saved_db[user].remove(video_id)
    else:
        saved_db[user].append(video_id)
        saved = True
    
    save_json(SAVED_FILE, saved_db)
    return jsonify({'status': 'ok', 'saved': saved})

@app.route('/api/watch_history', methods=['POST'])
@login_required
def api_watch_history():
    data = request.get_json()
    video_id = data.get('video_id')
    
    history_db = load_json(HISTORY_FILE)
    videos = load_json(VIDEOS_FILE)
    user = session['username']
    
    if user not in history_db:
        history_db[user] = []
    
    history_db[user].append({
        'video_id': video_id,
        'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        'duration': 5
    })
    
    history_db[user] = history_db[user][-500:]
    save_json(HISTORY_FILE, history_db)
    
    return jsonify({'status': 'ok'})

@app.route('/api/playlists', methods=['GET', 'POST'])
@login_required
def api_playlists():
    playlists_db = load_json(PLAYLISTS_FILE)
    user = session['username']
    
    if request.method == 'POST':
        name = request.get_json().get('name', '').strip()
        if name:
            pl_id = str(uuid.uuid4())
            playlists_db[pl_id] = {
                'name': name,
                'owner': user,
                'videos': [],
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            }
            save_json(PLAYLISTS_FILE, playlists_db)
            return jsonify({'status': 'ok', 'id': pl_id})
    
    user_playlists = []
    for pl_id, pl in playlists_db.items():
        if pl.get('owner') == user:
            user_playlists.append({
                'id': pl_id,
                'name': pl['name'],
                'video_count': len(pl.get('videos', []))
            })
    
    return jsonify({'playlists': user_playlists})

@app.route('/api/playlists/<pl_id>/videos', methods=['POST'])
@login_required
def api_add_to_playlist(pl_id):
    playlists_db = load_json(PLAYLISTS_FILE)
    data = request.get_json()
    video_id = data.get('video_id')
    
    pl = playlists_db.get(pl_id)
    if not pl or pl.get('owner') != session['username']:
        return jsonify({'status': 'error', 'message': 'Not found'}), 404
    
    if video_id not in pl.get('videos', []):
        pl['videos'].append(video_id)
        save_json(PLAYLISTS_FILE, playlists_db)
        return jsonify({'status': 'ok', 'message': 'Added to playlist'})
    
    return jsonify({'status': 'ok', 'message': 'Already in playlist'})

# ==================== MEDIA SERVING ====================

@app.route('/media/<filename>')
@login_required
def serve_media(filename):
    # SECURITY FIX: Prevent path traversal
    if not safe_filename_check(filename):
        abort(404)
    return send_from_directory(VIDEO_DIR, filename)

@app.route('/media/profiles/<filename>')
@login_required
def serve_profile(filename):
    if not safe_filename_check(filename):
        abort(404)
    return send_from_directory(PROFILE_DIR, filename)

# ==================== SOCKET.IO ====================

@socketio.on('connect')
def handle_connect():
    pass

@socketio.on('register_user')
def handle_register(data):
    username = data.get('username')
    # SECURITY FIX: Verify user exists before registering socket
    if username and is_valid_username(username):
        users = load_json(USERS_FILE)
        if username in users and session.get('username') == username:
            online_users[username] = request.sid
            user_status[username] = 'Online'
            emit('user_online', {'username': username}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    for username, sid in list(online_users.items()):
        if sid == request.sid:
            del online_users[username]
            user_status[username] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            break

@socketio.on('start_live_stream')
def handle_start_stream(data):
    username = session.get('username')
    # SECURITY FIX: Verify user exists
    if username and is_valid_username(username):
        users = load_json(USERS_FILE)
        if username in users:
            live_streams[username] = {
                'title': str(data.get('title', 'Untitled Stream'))[:100],
                'sid': request.sid
            }
            emit('stream_started', {'broadcaster': username}, broadcast=True)

@socketio.on('stop_live_stream')
def handle_stop_stream():
    username = session.get('username')
    if username and username in live_streams:
        del live_streams[username]
        emit('stream_ended', {'broadcaster': username}, broadcast=True)

@socketio.on('join_live_stream')
def handle_join_stream(data):
    broadcaster = data.get('broadcaster')
    if broadcaster and is_valid_username(broadcaster) and broadcaster in live_streams:
        emit('viewer_joined', {'viewer_sid': request.sid}, room=live_streams[broadcaster]['sid'])

@socketio.on('webrtc_signal')
def handle_webrtc(data):
    target = data.get('target') or data.get('target_user')
    if target and is_valid_username(target):
        target_sid = None
        for u, meta in live_streams.items():
            if u == target:
                target_sid = meta['sid']
                break
        if not target_sid:
            target_sid = online_users.get(target)
        
        if target_sid:
            emit('webrtc_signal', {
                'sender': request.sid,
                'sdp': data.get('sdp'),
                'candidate': data.get('candidate')
            }, room=target_sid)

# ==================== TEMPLATES ====================

templates = {
    "base.html": """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><meta name="csrf-token" content="{{ csrf_token() }}">
    <title>FamTube</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.1/socket.io.js"></script>
    <script>function getCookie(n) { let m = document.cookie.match(new RegExp('(^| )'+n+'=([^;]+)')); return m?m[2]:null; } if (getCookie('theme') === 'dark') document.documentElement.classList.add('dark-mode');</script>
    <style>
        html, body { margin: 0; height: 100%; font-family: 'Roboto', Arial, sans-serif; background: #f9f9f9; color: #0f0f0f; display: flex; flex-direction: column; }
        .navbar { display: flex; justify-content: space-between; align-items: center; padding: 10px 20px; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); position: sticky; top: 0; z-index: 100; }
        .logo { font-size: 22px; font-weight: bold; color: #ff0000; text-decoration: none; display: flex; align-items: center; gap: 10px; }
        .search-bar { display: flex; flex: 1; max-width: 500px; margin: 0 20px; }
        .search-bar input { width: 100%; padding: 8px 15px; border-radius: 20px 0 0 20px; border: 1px solid #ccc; border-right: none; }
        .search-bar button { padding: 8px 20px; border-radius: 0 20px 20px 0; border: 1px solid #ccc; background: #f8f8f8; cursor: pointer; color: black; }
        .nav-links { display: flex; align-items: center; gap: 15px; }
        .nav-links a { text-decoration: none; color: #0f0f0f; font-weight: 500; font-size: 14px; position: relative;}
        .btn-upload, .btn-live { padding: 8px 15px; border-radius: 20px; text-decoration: none; font-weight: bold; border: 1px solid #ccc; font-size: 13px; }
        .btn-upload { background: #f2f2f2; color: black !important; }
        .btn-live { background: #ff0000; color: white !important; border: none; animation: pulse 2s infinite; }
        .badge { position: absolute; top: -8px; right: -10px; background: #ff0000; color: white; font-size: 10px; padding: 2px 6px; border-radius: 10px; font-weight: bold; }
        .sidebar { position: fixed; top: 0; left: -250px; width: 250px; height: 100%; background: white; box-shadow: 2px 0 5px rgba(0,0,0,0.1); transition: left 0.3s ease; z-index: 1000; display: flex; flex-direction: column; }
        .sidebar.open { left: 0; }
        .sidebar-header { padding: 20px; border-bottom: 1px solid #ddd; display: flex; justify-content: space-between; align-items: center; }
        .sidebar-links a { display: block; padding: 15px 20px; color: inherit; text-decoration: none; font-weight: bold; border-bottom: 1px solid #eee; }
        .overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: none; z-index: 999; }
        .overlay.open { display: block; }
        .container { padding: 25px; max-width: 1200px; margin: auto; flex: 1 0 auto; width: 100%; box-sizing: border-box; }
        .footer { text-align: center; padding: 20px; color: #888; font-size: 13px; font-weight: bold; border-top: 1px solid #eaeaea;}
        .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 20px; }
        .card { background: white; border-radius: 12px; overflow: hidden; text-decoration: none; color: inherit; display: block; box-shadow: 0 2px 5px rgba(0,0,0,0.05); position:relative;}
        .thumbnail { width: 100%; height: 160px; background: #000; display:flex; align-items:center; justify-content:center; color:white; font-size: 40px; }
        .card-info { padding: 12px; display: flex; gap: 10px;}
        .card-title { margin: 0 0 5px 0; font-size: 16px; font-weight: bold; }
        .card-meta { margin: 0; color: #606060; font-size: 14px; }

        .avatar-container { position: relative; display: inline-block; flex-shrink: 0; width: 40px; height: 40px; }
        .avatar-container-large { width: 100px; height: 100px; margin: auto; margin-bottom: 15px; }
        .avatar { width: 100%; height: 100%; border-radius: 50%; background: #065fd4; color: white; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 18px; object-fit: cover;}
        .avatar-large { font-size: 40px; }
        .online-dot { position: absolute; bottom: 0; right: 0; width: 12px; height: 12px; background-color: #4CAF50; border-radius: 50%; border: 2px solid white; box-sizing: border-box; }
        .offline-dot { background-color: #9e9e9e !important; }

        .admin-panel { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }
        th, td { padding: 10px; border-bottom: 1px solid #ddd; text-align: left; }
        input[type="text"], input[type="password"], textarea, select { padding: 10px; margin: 5px 0; border-radius: 6px; border: 1px solid #ccc; width: 100%; box-sizing: border-box; }
        button.primary-btn { background: #065fd4; color: white; border: none; cursor: pointer; font-weight: bold; padding: 10px 15px; border-radius: 6px; }
        #toast-container { position: fixed; bottom: 20px; right: 20px; z-index: 9999; display: flex; flex-direction: column; gap: 10px; }
        .toast { background: #333; color: white; padding: 15px 20px; border-radius: 8px; transform: translateX(120%); transition: transform 0.3s ease; display: flex; align-items: center; gap: 10px;}
        .toast.show { transform: translateX(0); }
        .private-badge { position:absolute; top:10px; right:10px; background:rgba(0,0,0,0.7); color:white; padding:4px 8px; border-radius:4px; font-size:11px; font-weight:bold;}

        .hashtag-chip { display: inline-block; padding: 6px 14px; border-radius: 20px; background: #f0f0f0; color: #065fd4; font-weight: bold; font-size: 13px; text-decoration: none; margin: 4px; transition: all 0.2s; cursor: pointer; border: none; }
        .hashtag-chip:hover, .hashtag-chip.active { background: #065fd4; color: white; }
        .hashtag-chip.active { box-shadow: 0 0 0 2px #3ea6ff; }
        html.dark-mode .hashtag-chip { background: #2c2c2c; color: #3ea6ff; }
        html.dark-mode .hashtag-chip:hover, html.dark-mode .hashtag-chip.active { background: #3ea6ff; color: #121212; }

        html.dark-mode, html.dark-mode body { background-color: #121212; color: #e0e0e0; }
        html.dark-mode .navbar, html.dark-mode .sidebar { background-color: #1e1e1e; border-color: #333; box-shadow: none; }
        html.dark-mode .sidebar-header, html.dark-mode .sidebar-links a { border-color: #333; }
        html.dark-mode .search-bar input, html.dark-mode input, html.dark-mode textarea, html.dark-mode select { background-color: #2c2c2c; color: #fff; border-color: #444; }
        html.dark-mode .search-bar button, html.dark-mode .btn-upload { background-color: #333; border-color: #444; color: white !important; }
        html.dark-mode .card, html.dark-mode .admin-panel { background-color: #1e1e1e; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        html.dark-mode th, html.dark-mode td { border-color: #333; }
        html.dark-mode .card-meta { color: #aaa; }
        html.dark-mode .footer { border-color: #333; color: #666; }
        html.dark-mode .dark-box { background-color: #2a2a2a !important; border-left: 4px solid #3ea6ff;}
        html.dark-mode .online-dot { border-color: #1e1e1e; }
        .tags { color: #065fd4; font-size: 13px; font-weight: bold; }
        html.dark-mode .tags { color: #3ea6ff; }
        @keyframes pulse { 0% { transform: scale(1); } 50% { transform: scale(1.05); } 100% { transform: scale(1); } }

        @media (max-width: 768px) {
            .navbar { flex-wrap: wrap; padding: 8px 12px; }
            .search-bar { order: 3; max-width: 100%; margin: 10px 0 0 0; width: 100%; }
            .nav-links { gap: 8px; }
            .btn-upload, .btn-live { padding: 6px 10px; font-size: 11px; }
            .grid { grid-template-columns: 1fr; gap: 15px; }
            .container { padding: 12px; }
            .sidebar { width: 80%; left: -80%; }
            .sidebar.open { left: 0; }
            .card-info { gap: 8px; }
            .avatar-container { width: 36px; height: 36px; }
            table { font-size: 12px; }
            th, td { padding: 6px; }
            h2 { font-size: 20px; }
            .thumbnail { height: 200px; }
        }
        @media (min-width: 769px) and (max-width: 1024px) {
            .grid { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
</head>
<body>
    {% if session.username %}
    <div id="overlay" class="overlay" onclick="toggleSidebar()"></div>
    <div id="sidebar" class="sidebar">
        <div class="sidebar-header"><h2 style="margin:0; color:#ff0000;">▶ FamTube</h2><button onclick="toggleSidebar()" style="background:none; border:none; font-size:20px; cursor:pointer; color:inherit;">✕</button></div>
        <div class="sidebar-links">
            <a href="/">🏠 Home</a>
            <a href="/explore">🔥 Explore</a>
            <a href="/subscriptions">🔔 Subscriptions</a>
            <a href="/playlists">📂 Playlists</a>
            <a href="/saved">💾 Saved</a>
            <a href="/history">📜 History</a>
            <a href="/users">👥 Users</a>
            <a href="/settings">⚙️ Settings</a>
            {% if session.role == 'admin' %}<a href="/famtube_admin">🛡️ Admin</a>{% endif %}
            <a href="/logout">🚪 Logout</a>
        </div>
    </div>
    {% endif %}

    <div class="navbar">
        <div style="display: flex; align-items: center;">
            {% if session.username %}<button style="background:none;border:none;font-size:24px;cursor:pointer;margin-right:10px;" onclick="toggleSidebar()">≡</button>{% endif %}
            <a href="/" class="logo">▶ FamTube</a>
        </div>
        {% if session.username %}
        <form class="search-bar" action="/search" method="GET">
            <input type="text" name="q" placeholder="Search videos, users, or #hashtags..." required><button type="submit">🔍</button>
        </form>
        {% endif %}
        <div class="nav-links">
            <button id="theme-toggle" onclick="toggleTheme()" style="background:none; border:none; font-size:20px; cursor:pointer;">🌙</button>
            {% if session.username %}
                <a href="/live/broadcast" class="btn-live">🔴 Live</a>
                <a href="/upload" class="btn-upload">+ Upload</a>
                <a href="/notifications" style="font-size: 18px; text-decoration:none;">🔔<span class="badge" id="notif-badge" style="display: {% if unread_notifs > 0 %}block{% else %}none{% endif %};">{{ unread_notifs }}</span></a>
                <a href="/user/{{ session.username }}" style="font-weight: bold; display: flex; align-items: center; gap: 5px;">
                    <div class="avatar-container">
                        {% if current_user_obj.get('profile_pic') %}<img src="/media/profiles/{{ current_user_obj.profile_pic }}" class="avatar">
                        {% else %}<div class="avatar">{{ session.username[0]|upper }}</div>{% endif %}
                    </div>
                </a>
            {% endif %}
        </div>
    </div>

    <div id="toast-container"></div>
    <div class="container">{% block content %}{% endblock %}</div>
    <footer class="footer">Made By Aryan Giri | giriaryan694-a11y</footer>

    {% if session.username %}
    <script>
        const socket = io();
        socket.on('connect', () => { socket.emit('register_user', {username: '{{ session.username }}'}); });
        socket.on('receive_notification', (data) => {
            let badge = document.getElementById('notif-badge'); 
            if(badge) { badge.style.display = 'block'; badge.innerText = parseInt(badge.innerText || 0) + 1; }
            showToast(data.message, data.link);
            if ("Notification" in window && Notification.permission === "granted") { 
                new Notification("FamTube", { body: data.message, icon: '/favicon.ico' }); 
            }
        });
        socket.on('force_stream_end', () => { alert("Your live stream was securely ended by an Admin."); window.location.href = '/'; });

        function showToast(msg, link) {
            const toast = document.createElement('div'); 
            toast.className = 'toast'; 
            toast.innerHTML = `<span>🔔</span> <div>${msg.substring(0, 60)}${msg.length>60?'...':''}</div>`;
            toast.style.cursor = 'pointer';
            toast.onclick = () => { if(link) window.location.href = link; };
            document.getElementById('toast-container').appendChild(toast);
            setTimeout(() => toast.classList.add('show'), 100);
            setTimeout(() => { toast.classList.remove('show'); setTimeout(() => toast.remove(), 300); }, 6000);
        }
    </script>
    {% endif %}
    <script>
        function toggleSidebar() {
            document.getElementById('sidebar').classList.toggle('open');
            document.getElementById('overlay').classList.toggle('open');
        }
        function toggleTheme() {
            const html = document.documentElement;
            html.classList.toggle('dark-mode');
            const isDark = html.classList.contains('dark-mode');
            document.cookie = 'theme=' + (isDark ? 'dark' : 'light') + ';path=/;max-age=31536000';
            const btn = document.getElementById('theme-toggle');
            if(btn) btn.innerText = isDark ? '☀️' : '🌙';
        }
        (function(){
            const btn = document.getElementById('theme-toggle');
            if(btn && document.documentElement.classList.contains('dark-mode')) btn.innerText = '☀️';
        })();
    </script>
</body>
</html>
    """,
    "login.html": """
{% extends 'base.html' %}
{% block content %}
<div style="max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);" class="dark-box">
    <h2 style="text-align: center; margin-bottom: 20px;">🔐 Login to FamTube</h2>
    {% if error_msg %}
    <div style="background: #ffebee; color: #c62828; padding: 10px; border-radius: 6px; margin-bottom: 15px; font-size: 14px; font-weight: bold;">{{ error_msg }}</div>
    {% endif %}
    <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
        <label style="font-size: 12px; font-weight: bold;">Username</label>
        <input type="text" name="username" placeholder="Username" required style="margin-bottom: 15px;">
        <label style="font-size: 12px; font-weight: bold;">Password</label>
        <input type="password" name="password" placeholder="Password" required style="margin-bottom: 15px;">
        <label style="display: flex; align-items: center; gap: 8px; font-size: 14px; margin-bottom: 20px; cursor: pointer;">
            <input type="checkbox" name="remember" value="yes" style="width: auto; margin: 0;"> Remember me for a year
        </label>
        <button class="primary-btn" type="submit" style="width: 100%;">Login</button>
    </form>
</div>
{% endblock %}
    """,
    "index.html": """
{% extends 'base.html' %}
{% block content %}
{% if live_streams %}
<div style="margin-bottom: 25px;">
    <h3 style="margin-bottom: 15px;">🔴 Live Now</h3>
    <div class="grid">
        {% for u, meta in live_streams.items() %}
        <a href="/live/watch/{{ u }}" class="card" style="border: 2px solid #ff0000;">
            <div class="thumbnail" style="background: #ff0000; font-size: 24px; font-weight: bold;">🔴 LIVE<br>{{ u }}</div>
            <div class="card-info"><div><div class="card-title">{{ meta.title }}</div><div class="card-meta">{{ u }} • Streaming now</div></div></div>
        </a>
        {% endfor %}
    </div>
</div>
{% endif %}

{% if subscribed_content %}
<div style="margin-bottom: 25px;">
    <h3 style="margin-bottom: 15px;">🔔 Latest from Subscriptions</h3>
    <div class="grid">
        {% for v in subscribed_content %}
        <a href="/watch/{{ v.id }}" class="card">
            <div class="thumbnail">▶</div>
            <div class="card-info">
                <div class="avatar-container">
                    {% if v.uploader_pic %}<img src="/media/profiles/{{ v.uploader_pic }}" class="avatar">
                    {% else %}<div class="avatar">{{ v.uploader[0]|upper }}</div>{% endif %}
                </div>
                <div>
                    <div class="card-title">{{ v.title }}</div>
                    <div class="card-meta">{{ v.uploader }} • {{ v.timestamp }}</div>
                    <div class="card-meta" style="font-size: 12px; color: #065fd4;">{{ v.hashtags }}</div>
                </div>
            </div>
            {% if v.privacy == 'private' %}<div class="private-badge">PRIVATE</div>{% endif %}
        </a>
        {% endfor %}
    </div>
</div>
{% endif %}

<h3 style="margin-bottom: 15px;">📹 For You</h3>
<div class="grid">
    {% for v in videos %}
    <a href="/watch/{{ v.id }}" class="card">
        <div class="thumbnail">▶</div>
        <div class="card-info">
            <div class="avatar-container">
                {% if v.uploader_pic %}<img src="/media/profiles/{{ v.uploader_pic }}" class="avatar">
                {% else %}<div class="avatar">{{ v.uploader[0]|upper }}</div>{% endif %}
            </div>
            <div>
                <div class="card-title">{{ v.title }}</div>
                <div class="card-meta">{{ v.uploader }} • {{ v.timestamp }}</div>
                <div class="card-meta" style="font-size: 12px; color: #065fd4;">{{ v.hashtags }}</div>
            </div>
        </div>
        {% if v.privacy == 'private' %}<div class="private-badge">PRIVATE</div>{% endif %}
    </a>
    {% endfor %}
</div>
{% if not videos %}
<p style="text-align: center; color: #888; margin-top: 50px;">No videos found. Be the first to <a href="/upload" style="color: #065fd4;">upload</a>!</p>
{% endif %}
{% endblock %}
    """,
    "explore.html": """
{% extends 'base.html' %}
{% block content %}
<h2>🔥 Explore Hashtags</h2>
<div class="admin-panel" style="margin-bottom: 20px;">
    <div style="display: flex; flex-wrap: wrap; gap: 8px; align-items: center;">
        <a href="/explore" class="hashtag-chip {% if not selected_tags %}active{% endif %}" style="background: #ff0000; color: white;">📺 All Videos</a>
        {% for tag in hashtags %}
        <a href="/explore?tags={{ tag[1:] }}" class="hashtag-chip {% if tag[1:] in selected_tags %}active{% endif %}">{{ tag }}</a>
        {% endfor %}
    </div>
    {% if not hashtags %}
    <p style="text-align: center; color: #888; margin-top: 15px;">No hashtags yet. Upload videos with hashtags to see them here!</p>
    {% endif %}

    {% if selected_tags %}
    <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #eee;">
        <p style="font-size: 13px; color: #888; margin-bottom: 10px;">Showing videos with any of these hashtags (OR filter):</p>
        <div style="display: flex; flex-wrap: wrap; gap: 5px;">
            {% for st in selected_tags %}
            <span style="background: #065fd4; color: white; padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: bold;">#{{ st }}</span>
            {% endfor %}
        </div>
    </div>
    {% endif %}
</div>

{% if all_videos_mode %}
<h3 style="margin-bottom: 15px;">📹 All Videos on FamTube</h3>
{% elif selected_tags %}
<h3 style="margin-bottom: 15px;">📹 Videos matching selected hashtags</h3>
{% endif %}

{% if videos %}
<div class="grid">
    {% for v in videos %}
    <a href="/watch/{{ v.id }}" class="card">
        <div class="thumbnail">▶</div>
        <div class="card-info">
            <div class="avatar-container">
                {% if v.uploader_pic %}<img src="/media/profiles/{{ v.uploader_pic }}" class="avatar">
                {% else %}<div class="avatar">{{ v.uploader[0]|upper }}</div>{% endif %}
            </div>
            <div>
                <div class="card-title">{{ v.title }}</div>
                <div class="card-meta">{{ v.uploader }} • {{ v.timestamp }}</div>
                <div class="card-meta" style="font-size: 12px; color: #065fd4;">{{ v.hashtags }}</div>
            </div>
        </div>
        {% if v.privacy == 'private' %}<div class="private-badge">PRIVATE</div>{% endif %}
    </a>
    {% endfor %}
</div>
{% else %}
{% if selected_tags or all_videos_mode %}
<p style="text-align: center; color: #888;">No videos found.</p>
{% endif %}
{% endif %}
{% endblock %}
    """,
    "subscriptions.html": """
{% extends 'base.html' %}
{% block content %}
<h2>🔔 My Subscriptions</h2>
{% if subscriptions %}
<div style="display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 20px;">
    {% for sub in subscriptions %}
    <div style="display: flex; align-items: center; gap: 10px; background: white; padding: 10px 15px; border-radius: 25px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);" class="dark-box">
        <div class="avatar-container" style="width: 30px; height: 30px;">
            {% if sub.profile_pic %}<img src="/media/profiles/{{ sub.profile_pic }}" class="avatar" style="font-size: 14px;">
            {% else %}<div class="avatar" style="font-size: 14px;">{{ sub.name[0]|upper }}</div>{% endif %}
        </div>
        <a href="/user/{{ sub.name }}" style="text-decoration: none; color: inherit; font-weight: bold;">{{ sub.name }}</a>
        <form method="POST" style="margin:0;">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
            <input type="hidden" name="action" value="unsubscribe">
            <input type="hidden" name="target_user" value="{{ sub.name }}">
            <button type="submit" style="background:#ff0000; color:white; border:none; padding:4px 10px; border-radius:12px; font-size:11px; cursor:pointer;">Unsub</button>
        </form>
    </div>
    {% endfor %}
</div>

{% if latest_videos %}
<h3 style="margin-bottom: 15px;">📹 Latest Uploads</h3>
<div class="grid">
    {% for v in latest_videos %}
    <a href="/watch/{{ v.id }}" class="card">
        <div class="thumbnail">▶</div>
        <div class="card-info">
            <div class="avatar-container">
                {% if v.uploader_pic %}<img src="/media/profiles/{{ v.uploader_pic }}" class="avatar">
                {% else %}<div class="avatar">{{ v.uploader[0]|upper }}</div>{% endif %}
            </div>
            <div>
                <div class="card-title">{{ v.title }}</div>
                <div class="card-meta">{{ v.uploader }} • {{ v.timestamp }}</div>
            </div>
        </div>
    </a>
    {% endfor %}
</div>
{% else %}
<p style="text-align: center; color: #888;">No new uploads from subscriptions.</p>
{% endif %}

{% else %}
<p style="text-align: center; color: #888; margin-top: 50px;">You haven't subscribed to anyone yet. Explore <a href="/users" style="color: #065fd4;">users</a> to subscribe!</p>
{% endif %}
{% endblock %}
    """,
    "upload.html": """
{% extends 'base.html' %}
{% block content %}
<div style="max-width: 600px; margin: auto;">
    <h2>📤 Upload Video</h2>
    {% if error_msg %}
    <div style="background: #ffebee; color: #c62828; padding: 12px; border-radius: 6px; margin-bottom: 15px; font-weight: bold;">{{ error_msg }}</div>
    {% endif %}
    <div class="admin-panel">
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
            <label style="font-size: 12px; font-weight: bold;">Video File (MP4, WEBM, OGG)</label>
            <input type="file" name="video_file" accept="video/*" required style="padding: 8px;">
            <label style="font-size: 12px; font-weight: bold;">Title</label>
            <input type="text" name="title" placeholder="Enter video title" required>
            <label style="font-size: 12px; font-weight: bold;">Captions / Description</label>
            <textarea name="captions" rows="4" placeholder="Describe your video..."></textarea>
            <label style="font-size: 12px; font-weight: bold;">Hashtags</label>
            <input type="text" name="hashtags" placeholder="#fun #family #vlog">
            <label style="font-size: 12px; font-weight: bold;">Privacy</label>
            <select name="privacy">
                <option value="public">Public</option>
                <option value="private">Private</option>
            </select>
            <label style="font-size: 12px; font-weight: bold;">Allowed Users (comma-separated, for private videos)</label>
            <input type="text" name="allowed_users" placeholder="user1, user2, user3">
            <button class="primary-btn" type="submit" style="width: 100%; margin-top: 10px;">Upload Video</button>
        </form>
    </div>
</div>
{% endblock %}
    """,
    "search.html": """
{% extends 'base.html' %}
{% block content %}
<h2>Search Results for "{{ query }}"</h2>

{% if users %}
<div class="admin-panel" style="margin-bottom: 20px;">
    <h3>👤 Users</h3>
    <div style="display: flex; flex-wrap: wrap; gap: 10px;">
        {% for u in users %}
        <a href="/user/{{ u }}" style="text-decoration: none;">
            <div style="background: #f0f0f0; padding: 10px 15px; border-radius: 20px; font-weight: bold; color: #0f0f0f;" class="dark-box">{{ u }}</div>
        </a>
        {% endfor %}
    </div>
</div>
{% endif %}

{% if videos %}
<div class="grid">
    {% for v in videos %}
    <a href="/watch/{{ v.id }}" class="card">
        <div class="thumbnail">▶</div>
        <div class="card-info">
            <div class="avatar-container">
                {% if v.uploader_pic %}<img src="/media/profiles/{{ v.uploader_pic }}" class="avatar">
                {% else %}<div class="avatar">{{ v.uploader[0]|upper }}</div>{% endif %}
            </div>
            <div>
                <div class="card-title">{{ v.title }}</div>
                <div class="card-meta">{{ v.uploader }} • {{ v.timestamp }}</div>
                <div class="card-meta" style="font-size: 12px; color: #065fd4;">{{ v.hashtags }}</div>
            </div>
        </div>
        {% if v.privacy == 'private' %}<div class="private-badge">PRIVATE</div>{% endif %}
    </a>
    {% endfor %}
</div>
{% endif %}

{% if not users and not videos %}
<p style="text-align: center; color: #888; margin-top: 50px;">No results found.</p>
{% endif %}
{% endblock %}
    """,

    "profile.html": """
{% extends 'base.html' %}
{% block content %}
<div style="max-width: 800px; margin: auto;">
    <div class="admin-panel" style="text-align: center;">
        <div class="avatar-container avatar-container-large" style="margin: auto;">
            {% if profile_pic %}<img src="/media/profiles/{{ profile_pic }}" class="avatar avatar-large">
            {% else %}<div class="avatar avatar-large">{{ profile_name[0]|upper }}</div>{% endif %}
        </div>
        <h2 style="margin: 10px 0 5px;">{{ profile_name }}</h2>
        {% if bio %}<p style="color: #606060; margin: 5px 0; font-size: 14px;">{{ bio }}</p>{% endif %}
        {% if not hide_last_seen %}
        <p style="color: #888; font-size: 12px; margin: 5px 0;">Last seen: {{ last_seen }}</p>
        {% endif %}
        <div style="display: flex; justify-content: center; gap: 10px; margin-top: 15px;">
            {% if session.username != profile_name %}
            <form method="POST" style="margin:0;">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
                <input type="hidden" name="action" value="{% if is_subscribed %}unsubscribe{% else %}subscribe{% endif %}">
                <input type="hidden" name="target_user" value="{{ profile_name }}">
                <button type="submit" class="primary-btn" style="background: {% if is_subscribed %}#888{% else %}#ff0000{% endif %};">
                    {% if is_subscribed %}✓ Subscribed{% else %}🔔 Subscribe{% endif %}
                </button>
            </form>
            {% endif %}
            {% if session.role == 'admin' and session.username != profile_name %}
            <a href="/admin/user_history/{{ profile_name }}" class="primary-btn" style="text-decoration:none; display:inline-block; background:#065fd4;">📊 Watch History</a>
            {% endif %}
        </div>
    </div>

    <h3 style="margin: 20px 0 15px;">📹 Videos by {{ profile_name }}</h3>
    {% if videos %}
    <div class="grid">
        {% for v in videos %}
        <a href="/watch/{{ v.id }}" class="card">
            <div class="thumbnail">▶</div>
            <div class="card-info">
                <div>
                    <div class="card-title">{{ v.title }}</div>
                    <div class="card-meta">{{ v.timestamp }}</div>
                    <div class="card-meta" style="font-size: 12px; color: #065fd4;">{{ v.hashtags }}</div>
                </div>
            </div>
            {% if v.privacy == 'private' %}<div class="private-badge">PRIVATE</div>{% endif %}
        </a>
        {% endfor %}
    </div>
    {% else %}
    <p style="text-align: center; color: #888;">No videos yet.</p>
    {% endif %}

    <h3 style="margin: 20px 0 15px;">📂 Playlists</h3>
    {% if playlists %}
    <div class="grid">
        {% for pl in playlists %}
        <a href="/playlist/{{ pl.id }}" class="card" style="padding: 20px;">
            <div class="thumbnail" style="height: 120px; background: linear-gradient(135deg, #065fd4, #3ea6ff); font-size: 30px;">📂</div>
            <div class="card-info">
                <div>
                    <div class="card-title">{{ pl.name }}</div>
                    <div class="card-meta">{{ pl.video_count }} videos</div>
                </div>
            </div>
        </a>
        {% endfor %}
    </div>
    {% else %}
    <p style="text-align: center; color: #888;">No playlists yet.</p>
    {% endif %}
</div>
{% endblock %}
    """,
    "live_broadcast.html": """
{% extends 'base.html' %}
{% block content %}
<div style="max-width: 800px; margin: auto; text-align: center;">
    <h2>🔴 Go Live</h2>
    <div class="admin-panel">
        <input type="text" id="streamTitle" placeholder="Stream Title" style="max-width: 400px; margin: 0 auto 15px; display: block;">
        <div style="display: flex; gap: 15px; justify-content: center; margin-bottom: 20px;">
            <button id="startBtn" class="primary-btn" style="background: #ff0000;">Start Stream</button>
            <button id="stopBtn" class="primary-btn" style="background: #555; display: none;">Stop Stream</button>
        </div>
        <video id="localVideo" autoplay muted playsinline style="width: 100%; max-width: 600px; background: #000; border-radius: 8px;"></video>
        <p id="statusText" style="color: #888; margin-top: 10px;">Ready to broadcast</p>
    </div>
</div>
<script>
const socket = io();
let localStream = null;
let peerConnections = {};
const rtcConfig = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };

document.getElementById('startBtn').onclick = async () => {
    const title = document.getElementById('streamTitle').value || 'Untitled Stream';
    try {
        localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
        document.getElementById('localVideo').srcObject = localStream;
        socket.emit('start_live_stream', { title: title });
        document.getElementById('startBtn').style.display = 'none';
        document.getElementById('stopBtn').style.display = 'inline-block';
        document.getElementById('statusText').innerText = '🔴 LIVE: ' + title;
    } catch (err) {
        alert('Could not access camera: ' + err.message);
    }
};

document.getElementById('stopBtn').onclick = () => {
    if (localStream) {
        localStream.getTracks().forEach(t => t.stop());
        localStream = null;
    }
    Object.values(peerConnections).forEach(pc => pc.close());
    peerConnections = {};
    socket.emit('stop_live_stream');
    document.getElementById('localVideo').srcObject = null;
    document.getElementById('startBtn').style.display = 'inline-block';
    document.getElementById('stopBtn').style.display = 'none';
    document.getElementById('statusText').innerText = 'Stream ended';
};

socket.on('viewer_joined', (data) => {
    if (!localStream) return;
    const viewerSid = data.viewer_sid;
    const pc = new RTCPeerConnection(rtcConfig);
    peerConnections[viewerSid] = pc;
    localStream.getTracks().forEach(track => pc.addTrack(track, localStream));
    pc.onicecandidate = (e) => {
        if (e.candidate) socket.emit('webrtc_signal', { target: viewerSid, candidate: e.candidate });
    };
    pc.createOffer().then(offer => {
        pc.setLocalDescription(offer);
        socket.emit('webrtc_signal', { target: viewerSid, sdp: offer });
    });
});

socket.on('webrtc_signal', (data) => {
    const pc = peerConnections[data.sender];
    if (!pc) return;
    if (data.sdp) {
        pc.setRemoteDescription(new RTCSessionDescription(data.sdp)).then(() => {
            if (data.sdp.type === 'offer') {
                pc.createAnswer().then(answer => {
                    pc.setLocalDescription(answer);
                    socket.emit('webrtc_signal', { target: data.sender, sdp: answer });
                });
            }
        });
    }
    if (data.candidate) pc.addIceCandidate(new RTCIceCandidate(data.candidate));
});

socket.on('force_stream_end', () => {
    document.getElementById('stopBtn').click();
});
</script>
{% endblock %}
    """,
    "live_watch.html": """
{% extends 'base.html' %}
{% block content %}
<div style="max-width: 800px; margin: auto; text-align: center;">
    <h2>📺 Watching {{ broadcaster }}</h2>
    <div class="admin-panel">
        <video id="remoteVideo" autoplay playsinline style="width: 100%; max-width: 600px; background: #000; border-radius: 8px;"></video>
        <p id="statusText" style="color: #888; margin-top: 10px;">Connecting to stream...</p>
    </div>
</div>
<script>
const socket = io();
const broadcaster = '{{ broadcaster }}';
let pc = null;
const rtcConfig = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };

socket.on('connect', () => {
    socket.emit('join_live_stream', { broadcaster: broadcaster });
});

socket.on('webrtc_signal', (data) => {
    if (!pc) createPeerConnection();
    if (data.sdp) {
        pc.setRemoteDescription(new RTCSessionDescription(data.sdp)).then(() => {
            if (data.sdp.type === 'offer') {
                pc.createAnswer().then(answer => {
                    pc.setLocalDescription(answer);
                    socket.emit('webrtc_signal', { target: data.sender, sdp: answer });
                });
            }
        });
    }
    if (data.candidate) pc.addIceCandidate(new RTCIceCandidate(data.candidate));
});

function createPeerConnection() {
    pc = new RTCPeerConnection(rtcConfig);
    pc.ontrack = (e) => {
        document.getElementById('remoteVideo').srcObject = e.streams[0];
        document.getElementById('statusText').innerText = 'Connected';
    };
    pc.onicecandidate = (e) => {
        if (e.candidate) socket.emit('webrtc_signal', { target_user: broadcaster, candidate: e.candidate });
    };
    pc.onconnectionstatechange = () => {
        if (pc.connectionState === 'disconnected' || pc.connectionState === 'failed') {
            document.getElementById('statusText').innerText = 'Stream disconnected';
        }
    };
}
</script>
{% endblock %}
    """,
    "users_list.html": """
{% extends 'base.html' %}
{% block content %}
<h2>👥 Explore Users</h2>
<div class="grid">
    {% for u, data in users.items() %}
    <a href="/user/{{ u }}" class="card" style="padding: 20px; text-align: center;">
        <div class="avatar-container" style="width: 80px; height: 80px; margin: 0 auto 15px;">
            {% if data.get('profile_pic') %}<img src="/media/profiles/{{ data.profile_pic }}" class="avatar" style="font-size: 36px;">
            {% else %}<div class="avatar" style="font-size: 36px;">{{ u[0]|upper }}</div>{% endif %}
            <div class="online-dot {% if not data.is_online %}offline-dot{% endif %}" style="width: 16px; height: 16px;"></div>
        </div>
        <div class="card-title">{{ u }}</div>
        <div class="card-meta">{{ data.get('bio', 'No bio')[:30] }}{% if data.get('bio', '')|length > 30 %}...{% endif %}</div>
        <div class="card-meta" style="margin-top: 5px; font-size: 12px; color: {% if data.is_online %}#4CAF50{% else %}#888{% endif %};">
            {% if data.is_online %}🟢 Online{% else %}⚪ Offline{% endif %}
        </div>
    </a>
    {% endfor %}
</div>
{% if not users %}
<p style="text-align: center; color: #888; margin-top: 50px;">No users found.</p>
{% endif %}
{% endblock %}
    """,
    "notifications.html": """
{% extends 'base.html' %}
{% block content %}
<h2>🔔 Notifications</h2>
<div class="admin-panel">
    {% if notifications %}
    <div style="display: flex; flex-direction: column; gap: 12px;">
        {% for n in notifications %}
        <a href="{{ n.link }}" style="text-decoration: none; color: inherit;">
            <div style="padding: 15px; border-radius: 8px; border-left: 4px solid {% if not n.read %}#065fd4{% else %}#ccc{% endif %}; background: {% if not n.read %}rgba(6, 95, 212, 0.08){% else %}transparent{% endif %};">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span style="font-weight: bold; font-size: 14px;">{{ n.message }}</span>
                        {% if n.sender %}<span style="font-size: 12px; color: #888; margin-left: 8px;">from {{ n.sender }}</span>{% endif %}
                    </div>
                    <span style="font-size: 12px; color: #888;">{{ n.timestamp }}</span>
                </div>
            </div>
        </a>
        {% endfor %}
    </div>
    {% else %}
    <p style="text-align: center; color: #888;">No notifications yet.</p>
    {% endif %}
</div>
{% endblock %}
    """,
    "settings.html": """
{% extends 'base.html' %}
{% block content %}
<div style="max-width: 600px; margin: auto;">
    <h2>⚙️ Settings</h2>

    {% if success_msg %}
    <div style="background: #e8f5e9; color: #2e7d32; padding: 12px; border-radius: 6px; margin-bottom: 20px; font-weight: bold;">{{ success_msg }}</div>
    {% endif %}
    {% if error_msg %}
    <div style="background: #ffebee; color: #c62828; padding: 12px; border-radius: 6px; margin-bottom: 20px; font-weight: bold;">{{ error_msg }}</div>
    {% endif %}

    <div class="admin-panel" style="margin-bottom: 20px;">
        <h3>🔔 Device Notifications</h3>
        <p style="font-size: 13px; color: #888; margin-bottom: 15px;">Get browser push notifications for new uploads from subscriptions, comments, and replies.</p>
        <button onclick="askPermission()" class="primary-btn" style="width: 100%; margin-bottom: 10px;">🔔 Enable Browser Notifications</button>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
            <input type="hidden" name="action" value="toggle_device_notif">
            <label style="display: flex; align-items: center; gap: 10px; font-size: 14px; cursor: pointer; margin-bottom: 15px;">
                <input type="checkbox" name="device_notif" value="yes" {% if device_notif_enabled %}checked{% endif %} style="width: auto; margin: 0;">
                <b>Enable Browser Push Notifications</b>
            </label>
            <button class="primary-btn" type="submit" style="width: 100%;">Save Notification Settings</button>
        </form>
    </div>

    <div class="admin-panel" style="margin-bottom: 20px;">
        <h3>👤 Profile</h3>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
            <input type="hidden" name="action" value="update_profile">
            <label style="font-size: 12px; font-weight: bold;">Profile Picture</label>
            <input type="file" name="profile_pic" accept="image/png, image/jpeg" style="padding: 8px;">
            <label style="font-size: 12px; font-weight: bold;">Bio</label>
            <textarea name="bio" rows="3" placeholder="Tell us about yourself..."></textarea>
            <button class="primary-btn" type="submit" style="width: 100%;">Update Profile</button>
        </form>
    </div>

    <div class="admin-panel" style="margin-bottom: 20px;">
        <h3>🔒 Privacy</h3>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
            <input type="hidden" name="action" value="toggle_privacy">
            <label style="display: flex; align-items: center; gap: 10px; font-size: 14px; cursor: pointer; margin-bottom: 15px;">
                <input type="checkbox" name="hide_last_seen" value="yes" style="width: auto; margin: 0;"> Hide my last seen status
            </label>
            <button class="primary-btn" type="submit" style="width: 100%;">Save Privacy Settings</button>
        </form>
    </div>

    <div class="admin-panel">
        <h3>🔑 Credentials</h3>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
            <input type="hidden" name="action" value="change_creds">
            <label style="font-size: 12px; font-weight: bold;">New Username</label>
            <input type="text" name="new_username" placeholder="Leave blank to keep current">
            <label style="font-size: 12px; font-weight: bold;">New Password</label>
            <input type="password" name="new_password" placeholder="Leave blank to keep current">
            <button class="primary-btn" type="submit" style="width: 100%; margin-top: 10px;">Update Credentials</button>
        </form>
    </div>
</div>

<script>
async function askPermission() {
    if (!("Notification" in window)) {
        alert("This browser does not support notifications.");
        return;
    }
    const permission = await Notification.requestPermission();
    if (permission === "granted") {
        new Notification("Welcome!", {
            body: "Notifications enabled successfully 🎯",
            icon: "/favicon.ico"
        });
        const cb = document.querySelector('input[name="device_notif"]');
        if(cb && !cb.checked) {
            cb.checked = true;
            cb.closest('form').submit();
        }
    } else if (permission === "denied") {
        alert("Notification permission denied.");
    } else {
        alert("Permission dismissed.");
    }
}

{% if device_notif_enabled %}
(function(){
    if ("Notification" in window && Notification.permission === "default") {
        setTimeout(() => askPermission(), 1000);
    }
})();
{% endif %}
</script>
{% endblock %}
    """,

    "admin.html": """
{% extends 'base.html' %}
{% block content %}
<h2>⚙️ FamTube Admin Dashboard</h2>

{% if admin_msg %}
<div style="background: {% if admin_msg_type == 'error' %}#ffebee; color: #c62828;{% else %}#e8f5e9; color: #2e7d32;{% endif %} padding: 12px; border-radius: 6px; margin-bottom: 20px; font-weight: bold;">
    {{ admin_msg }}
</div>
{% endif %}

<div class="admin-panel" style="border-left: 5px solid #9c27b0; margin-bottom: 20px;">
    <h3>🌐 IP Access Control</h3>
    <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
        <input type="hidden" name="action" value="toggle_ip_filter">
        <label style="display: flex; align-items: center; gap: 10px; font-size: 14px; cursor: pointer; margin-bottom: 15px;">
            <input type="checkbox" name="ip_filter_enabled" value="yes" {% if config.ip_filter_enabled %}checked{% endif %} style="width: auto; margin: 0;">
            <b>Enable IP Filtering</b> (Default: OFF)
        </label>
        <div style="display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 15px;">
            <div style="flex: 1; min-width: 250px;">
                <label style="font-size: 12px; font-weight: bold;">Blocked IPs (one per line)</label>
                <textarea name="blocked_ips" rows="4" placeholder="192.168.1.1\\n10.0.0.5">{{ config.blocked_ips | join('\\n') }}</textarea>
            </div>
            <div style="flex: 1; min-width: 250px;">
                <label style="font-size: 12px; font-weight: bold;">Allowed IPs (one per line)</label>
                <textarea name="allowed_ips" rows="4" placeholder="192.168.1.100\\n10.0.0.1">{{ config.allowed_ips | join('\\n') }}</textarea>
            </div>
        </div>
        <label style="display: flex; align-items: center; gap: 10px; font-size: 14px; cursor: pointer; margin-bottom: 15px;">
            <input type="checkbox" name="strict_allowlist_mode" value="yes" {% if config.strict_allowlist_mode %}checked{% endif %} style="width: auto; margin: 0;">
            <b>Strict Allowlist Mode</b> — Only allow listed IPs, block everything else
        </label>
        <button class="primary-btn" type="submit" style="width: 100%;">💾 Save IP Settings</button>
    </form>
    <div style="background: #f5f5f5; padding: 12px; border-radius: 6px; margin-top: 15px; font-size: 13px;" class="dark-box">
        <b>How it works:</b><br>
        • <b>OFF:</b> All IPs allowed (default)<br>
        • <b>ON (Blocklist):</b> Block listed IPs, allow all others<br>
        • <b>ON + Strict:</b> Only allow listed IPs, block all others
    </div>
</div>

<div class="admin-panel" style="border-left: 5px solid #d32f2f; margin-bottom: 20px;">
    <h3>🛡️ Content Moderation</h3>
    {% if live_streams %}
    <h4>Active Streams</h4>
    <table><tr><th>Broadcaster</th><th>Title</th><th>Action</th></tr>
        {% for u, meta in live_streams.items() %}
        <tr><td><b>{{ u }}</b></td><td>{{ meta.title }}</td>
            <td><form method="POST" style="margin:0;"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/><input type="hidden" name="action" value="kill_stream"><input type="hidden" name="target_user" value="{{ u }}"><button type="submit" style="background:#d32f2f; color:white; padding:4px 8px; border:none; border-radius:4px; font-size:11px; cursor:pointer;">Force End Stream</button></form></td>
        </tr>{% endfor %}
    </table>
    {% endif %}
    <h4>Video Library</h4>
    <div style="overflow-x: auto; max-height:400px;">
        <table>
            <tr><th>Title</th><th>Uploader</th><th>Visibility</th><th>Privacy</th><th>Actions</th></tr>
            {% for vid, v in videos.items() %}
            <tr>
                <td style="max-width:150px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">{{ v.title }}</td><td>{{ v.uploader }}</td>
                <td><span style="padding:2px 6px; border-radius:4px; font-size:11px; background: {% if v.get('visibility','visible')=='visible' %}#4CAF50{% else %}#9e9e9e{% endif %}; color:white;">{{ v.get('visibility', 'visible')|upper }}</span></td>
                <td><span style="font-size:11px; color:#555; font-weight:bold;">{{ v.get('privacy', 'public')|upper }}</span></td>
                <td style="display:flex; gap:5px;">
                    <a href="/watch/{{ vid }}" class="primary-btn" style="background:#065fd4; color:white; padding:4px 8px; border:none; border-radius:4px; font-size:11px; text-decoration:none;" target="_blank">Review</a>

                    {% set is_hidden = v.get('visibility') == 'hidden' %}
                    <form method="POST" style="margin:0;">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
                        <input type="hidden" name="action" value="toggle_visibility">
                        <input type="hidden" name="target_vid" value="{{ vid }}">
                        <button type="submit" style="background:#555; color:white; padding:4px 8px; border:none; border-radius:4px; font-size:11px; cursor:pointer;">
                            {% if is_hidden %}Unhide{% else %}Hide{% endif %}
                        </button>
                    </form>
                    <form method="POST" style="margin:0;"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/><input type="hidden" name="action" value="delete_video"><input type="hidden" name="target_vid" value="{{ vid }}"><button type="submit" style="background:#d32f2f; color:white; padding:4px 8px; border:none; border-radius:4px; font-size:11px; cursor:pointer;" onclick="return confirm('Permanently delete?');">Delete</button></form>
                </td>
            </tr>
            {% endfor %}
        </table>
    </div>
</div>

<div class="admin-panel" style="border-left: 5px solid #ff9800; margin-bottom: 20px;">
    <h3>📱 Active Sessions</h3>
    <div style="overflow-x: auto;">
        <table>
            <tr><th>User</th><th>IP Address</th><th>Browser</th><th>Action</th></tr>
            {% for sid, sdata in active_sessions.items() %}
            <tr><td><b>{{ sdata.username }}</b></td><td>{{ sdata.ip }}</td><td style="font-size: 11px;">{{ sdata.user_agent[:40] }}...</td>
                <td><form method="POST" style="margin:0;"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/><input type="hidden" name="action" value="revoke_session"><input type="hidden" name="revoke_sid" value="{{ sid }}"><button type="submit" style="background:#d32f2f; color: white; border: none; padding: 4px 8px; font-size: 11px; border-radius: 4px;">Log Out</button></form></td>
            </tr>
            {% endfor %}
        </table>
    </div>
    <div style="display: flex; justify-content: center; align-items: center; gap: 15px; margin-top: 15px;">
        {% if sessions_page > 1 %}
        <a href="?sessions_page={{ sessions_page - 1 }}" style="text-decoration: none; background: #555; color: white; padding: 6px 12px; border-radius: 4px; font-size: 13px; font-weight: bold;">← Prev</a>
        {% endif %}
        <span style="font-size: 13px; color: #888; font-weight: bold;">Page {{ sessions_page }} of {{ sessions_total_pages }} ({{ sessions_total }} total)</span>
        {% if sessions_page < sessions_total_pages %}
        <a href="?sessions_page={{ sessions_page + 1 }}" style="text-decoration: none; background: #065fd4; color: white; padding: 6px 12px; border-radius: 4px; font-size: 13px; font-weight: bold;">Next →</a>
        {% endif %}
    </div>
</div>

<div class="admin-panel" style="border-left: 5px solid #4CAF50; margin-bottom: 20px;">
    <h3>📊 User Engagement & Watch History</h3>
    <div style="overflow-x: auto;">
        <table>
            <tr><th>User Account</th><th>Total Watch Time</th><th>Videos Watched (Time)</th><th>Action</th></tr>
            {% for m in metrics %}
            <tr><td><b>{{ m.user }}</b></td><td>{{ m.total_mins }} mins</td><td style="font-size: 13px; color: #555;">{{ m.history }}</td>
                <td><a href="/admin/user_history/{{ m.user }}" class="primary-btn" style="background:#065fd4; color:white; padding:4px 8px; border:none; border-radius:4px; font-size:11px; text-decoration:none;">View Details</a></td>
            </tr>
            {% endfor %}
            {% if not metrics %}<tr><td colspan="4">No watch history recorded yet.</td></tr>{% endif %}
        </table>
    </div>
</div>

<div class="grid">
    <div class="admin-panel">
        <h3>👤 User Management</h3>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
            <input type="hidden" name="action" value="create_user"/>
            <input type="text" name="new_user" placeholder="New Username" required/>
            <input type="password" name="new_pass" placeholder="Password" required/>
            <div style="display: flex; gap: 5px; align-items: center; margin: 5px 0;">
                <input type="text" id="newPrefInput" name="preference" placeholder="Click # button to add tags" required style="flex:1; margin:0; background:#f5f5f5;" readonly onkeydown="return false;"/>
                <button type="button" onclick="addHashtagToNew()" style="background:#065fd4; color:white; border:none; padding:8px 12px; border-radius:6px; cursor:pointer; font-weight:bold;">#</button>
            </div>
            <button class="primary-btn" type="submit" style="width: 100%;">+ Create User</button>
        </form>
        <hr style="border-color: #ddd; margin: 20px 0;">
        <table>
            <tr><th>User</th><th>Filter</th><th>Actions</th></tr>
            {% for u, data in users.items() %}
            <tr>
                <td><b>{{u}}</b></td><td>{{data.feed_preference}}</td>
                <td>
                    <button onclick="document.getElementById('edit-{{u}}').style.display='block'" style="background:#555; color: white; border: none; padding: 5px 10px; font-size:12px; border-radius: 4px; cursor: pointer;">Edit</button>
                    {% if data.role != 'admin' %}
                    <button onclick="document.getElementById('del-{{u}}').style.display='block'" style="background:#c62828; color: white; border: none; padding: 5px 10px; font-size:12px; border-radius: 4px; cursor: pointer;">Del</button>
                    {% endif %}
                </td>
            </tr>
            <tr id="edit-{{u}}" style="display:none;">
                <td colspan="3">
                    <div style="background: #f0f0f0; padding: 15px; margin-top: 10px; border-radius: 8px; border-left: 4px solid #065fd4;" class="dark-box">
                        <h4 style="margin-top:0;">Edit User: {{u}}</h4>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
                            <input type="hidden" name="action" value="edit_user">
                            <input type="hidden" name="original_username" value="{{u}}">
                            <label style="font-size:12px; font-weight:bold;">Username</label>
                            <input type="text" name="edit_username" value="{{u}}" required>
                            <label style="font-size:12px; font-weight:bold;">New Password</label>
                            <input type="password" name="edit_password" placeholder="Leave blank to keep current password">
                            <label style="font-size:12px; font-weight:bold;">Content Filter (hashtags comma-separated, or 'all')</label>
                            <div style="display: flex; gap: 5px; align-items: center; margin: 5px 0;">
                                <input type="text" id="editPref-{{u}}" name="edit_preference" value="{{data.feed_preference}}" required style="flex:1; margin:0; background:#f5f5f5;" readonly onkeydown="return false;">
                                <button type="button" onclick="addHashtagToEdit('{{u}}')" style="background:#065fd4; color:white; border:none; padding:8px 12px; border-radius:6px; cursor:pointer; font-weight:bold;">#</button>
                            </div>
                            <div style="margin-top: 10px;">
                                <button type="submit" style="background:#2e7d32; color: white; border: none; padding: 8px 12px; border-radius: 4px; cursor: pointer;">Save Changes</button>
                                <button type="button" onclick="document.getElementById('edit-{{u}}').style.display='none'" style="background:#777; color: white; border: none; padding: 8px 12px; border-radius: 4px; cursor: pointer;">Cancel</button>
                            </div>
                        </form>
                    </div>
                </td>
            </tr>
            <tr id="del-{{u}}" style="display:none;">
                <td colspan="3">
                    <div style="background: #ffebee; padding: 15px; margin-top: 10px; border-radius: 8px; border-left: 4px solid #c62828;" class="dark-box">
                        <h4 style="margin-top:0; color: #c62828;">⚠️ Delete User: {{u}}</h4>
                        <p style="font-size: 13px; margin-bottom: 15px;">Choose how to handle this user's videos:</p>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
                            <input type="hidden" name="action" value="delete_user">
                            <input type="hidden" name="del_user" value="{{u}}">
                            <div style="display: flex; flex-direction: column; gap: 10px;">
                                <label style="display: flex; align-items: center; gap: 8px; font-size: 14px; cursor: pointer;">
                                    <input type="radio" name="delete_mode" value="backup" checked style="width: auto; margin: 0;">
                                    <b>Backup & Delete</b> — Download all videos to admin computer, then delete user
                                </label>
                                <label style="display: flex; align-items: center; gap: 8px; font-size: 14px; cursor: pointer;">
                                    <input type="radio" name="delete_mode" value="delete_videos" style="width: auto; margin: 0;">
                                    <b>Delete Everything</b> — Delete user and all their videos permanently
                                </label>
                                <label style="display: flex; align-items: center; gap: 8px; font-size: 14px; cursor: pointer;">
                                    <input type="radio" name="delete_mode" value="keep_videos" style="width: auto; margin: 0;">
                                    <b>Keep Videos</b> — Delete user but keep all videos on platform
                                </label>
                            </div>
                            <div style="margin-top: 15px;">
                                <button type="submit" style="background:#c62828; color: white; border: none; padding: 8px 12px; border-radius: 4px; cursor: pointer; font-weight: bold;">Confirm Delete</button>
                                <button type="button" onclick="document.getElementById('del-{{u}}').style.display='none'" style="background:#777; color: white; border: none; padding: 8px 12px; border-radius: 4px; cursor: pointer;">Cancel</button>
                            </div>
                        </form>
                    </div>
                </td>
            </tr>
            {% endfor %}
        </table>
    </div>
</div>

<script>
function addHashtagToNew() {
    const input = document.getElementById('newPrefInput');
    const val = input.value.trim();
    const tags = val ? val.split(',').map(t => t.trim()).filter(t => t) : [];
    const newTag = prompt('Enter hashtag (without #):');
    if (newTag && newTag.trim()) {
        const cleanTag = newTag.trim().replace(/^#/, '');
        if (!tags.includes(cleanTag)) {
            tags.push(cleanTag);
        }
        input.value = tags.join(', ');
    }
}
function addHashtagToEdit(user) {
    const input = document.getElementById('editPref-' + user);
    const val = input.value.trim();
    const tags = val ? val.split(',').map(t => t.trim()).filter(t => t) : [];
    const newTag = prompt('Enter hashtag (without #):');
    if (newTag && newTag.trim()) {
        const cleanTag = newTag.trim().replace(/^#/, '');
        if (!tags.includes(cleanTag)) {
            tags.push(cleanTag);
        }
        input.value = tags.join(', ');
    }
}
</script>
{% endblock %}
    """,
    "watch.html": """
{% extends 'base.html' %}
{% block content %}
<div class="admin-panel" style="max-width: 900px; margin: auto; padding: 20px;">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; flex-wrap: wrap; gap: 10px;">
        <h2 style="margin: 0; font-size: 18px;">{{ video.title }}</h2>
        <div style="display: flex; gap: 10px;">
            <button onclick="saveVideo('{{ video_id }}')" id="saveBtn" class="primary-btn" style="background: #2e7d32; font-size: 13px;">{% if is_saved %}✅ Saved{% else %}💾 Save{% endif %}</button>
            <button id="musicModeToggle" style="background: #ff9800; color: white; padding: 8px 15px; border-radius: 20px; border: none; cursor: pointer; font-weight: bold; font-size: 13px;">🎧 Music Mode: OFF</button>
        </div>
    </div>
    <div id="videoContainer" style="position: relative; padding-bottom: 56.25%; height: 0; overflow: hidden; border-radius: 8px;">
        <video id="vidPlayer" controls style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; background: black;">
            <source src="/media/{{ video.filename }}" type="video/mp4">
        </video>
    </div>
    <div id="audioContainer" style="display: none; background: #222; padding: 60px 20px; border-radius: 8px; text-align: center; color: white;">
        <div style="font-size: 80px; margin-bottom: 20px; animation: pulse 2s infinite;">🎵</div>
        <audio id="audPlayer" controls style="width: 100%; max-width: 500px;"><source src="/media/{{ video.filename }}" type="video/mp4"></audio>
        <p style="color:#aaa; font-size:13px; margin-top:15px;">Background play enabled.</p>
    </div>
    <div style="margin-top: 15px; display: flex; gap: 15px; align-items: center;">
        <a href="/user/{{ video.uploader }}" style="text-decoration:none;">
            <div class="avatar-container">
                {% if uploader_pic %}<img src="/media/profiles/{{ uploader_pic }}" class="avatar">
                {% else %}<div class="avatar">{{ video.uploader[0]|upper }}</div>{% endif %}
            </div>
        </a>
        <div style="flex: 1;">
            <span class="tags">{{ video.hashtags }}</span>
            <p class="card-meta" style="font-weight: bold; margin-top: 5px;">
                <a href="/user/{{ video.uploader }}" style="color:#065fd4; text-decoration:none;">{{ video.uploader }}</a> • {{ video.timestamp }}
            </p>
        </div>
        <div style="display: flex; gap: 10px;">
            <button onclick="addToPlaylist('{{ video_id }}')" class="primary-btn" style="background: #065fd4; font-size: 13px;">➕ Playlist</button>
        </div>
    </div>
    <div style="background: #f0f0f0; padding: 15px; margin-top: 15px; border-radius: 8px;" class="dark-box">
        <p style="margin:0; white-space: pre-wrap; font-size: 14px; line-height: 1.5;">{{ video.captions }}</p>
    </div>
</div>

<div class="admin-panel" style="max-width: 900px; margin: 20px auto; padding: 20px;">
    <h3>💬 Comments ({{ comments|length }})</h3>
    <form method="POST" style="display:flex; gap:10px; margin-bottom: 30px;">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
        <input type="text" name="comment_text" placeholder="Add a comment... (Use @username to mention!)" required style="margin:0; flex:1;">
        <button class="primary-btn" type="submit" style="margin:0;">Post</button>
    </form>
    <div>
        {% for c in comments %}
        <div style="padding-bottom: 15px; display:flex; gap:10px; border-bottom:1px solid #eee; margin-bottom:15px;" class="comment-wrapper">
            <div class="avatar-container">
                {% if c.user_pic %}<img src="/media/profiles/{{ c.user_pic }}" class="avatar">
                {% else %}<div class="avatar">{{ c.user[0]|upper }}</div>{% endif %}
            </div>
            <div style="flex:1;">
                <a href="/user/{{ c.user }}" style="font-weight:bold; color:#065fd4; text-decoration:none;">{{ c.user }}</a><span style="font-size: 12px; color: #888; margin-left: 10px;">{{ c.timestamp }}</span>
                <p style="margin: 5px 0;">{{ c.text }}</p>
                <div style="display:flex; gap: 10px; align-items: center; margin-bottom: 10px;">
                    <button onclick="likeComment('{{ video_id }}', '{{ c.id }}')" style="background:none; border:none; color:#888; font-weight:bold; cursor:pointer; font-size:12px;">👍 <span id="like-count-{{ c.id }}">{{ c.likes|length if c.likes else 0 }}</span></button>
                    <button onclick="toggleReply('{{ c.id }}')" style="background:none; border:none; color:#888; font-weight:bold; cursor:pointer; font-size:12px;">💬 Reply</button>
                </div>
                <form id="reply-form-{{ c.id }}" method="POST" style="display:none; gap:10px; margin-bottom: 15px;">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
                    <input type="hidden" name="parent_id" value="{{ c.id }}">
                    <input type="text" name="comment_text" placeholder="Reply to {{ c.user }}..." required style="margin:0; flex:1; padding: 8px; font-size: 13px;">
                    <button class="primary-btn" type="submit" style="margin:0; padding: 8px 12px; font-size: 13px;">Reply</button>
                </form>
                {% if c.replies %}
                <div style="border-left: 2px solid #ddd; padding-left: 15px; margin-top: 10px;" class="replies-box">
                    {% for r in c.replies %}
                    <div style="display:flex; gap:10px; margin-bottom:10px;">
                        <div class="avatar-container">
                            {% if r.user_pic %}<img src="/media/profiles/{{ r.user_pic }}" class="avatar" style="width:25px; height:25px; font-size:12px;">
                            {% else %}<div class="avatar" style="width:25px; height:25px; font-size:12px;">{{ r.user[0]|upper }}</div>{% endif %}
                        </div>
                        <div>
                            <a href="/user/{{ r.user }}" style="font-weight:bold; color:#065fd4; text-decoration:none;">{{ r.user }}</a><span style="font-size: 12px; color: #888; margin-left: 10px;">{{ r.timestamp }}</span>
                            <p style="margin: 5px 0;">{{ r.text }}</p>
                            <button onclick="likeComment('{{ video_id }}', '{{ r.id }}')" style="background:none; border:none; color:#888; font-weight:bold; cursor:pointer; font-size:12px;">👍 <span id="like-count-{{ r.id }}">{{ r.likes|length if r.likes else 0 }}</span></button>
                        </div>
                    </div>
                    {% endfor %}
                </div>
                {% endif %}
            </div>
        </div>
        {% endfor %}
    </div>
</div>

<div id="playlistModal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.5); z-index:2000; align-items:center; justify-content:center;">
    <div style="background:white; padding:25px; border-radius:12px; max-width:400px; width:90%;" class="dark-box">
        <h3 style="margin-top:0;">➕ Add to Playlist</h3>
        <div id="playlistList" style="max-height: 200px; overflow-y: auto; margin-bottom: 15px;"></div>
        <div style="display:flex; gap:10px;">
            <input type="text" id="newPlaylistName" placeholder="New playlist name..." style="flex:1; margin:0;">
            <button onclick="createPlaylist()" class="primary-btn" style="margin:0;">Create</button>
        </div>
        <button onclick="closePlaylistModal()" style="margin-top:15px; width:100%; background:#888; color:white; border:none; padding:8px; border-radius:6px; cursor:pointer;">Cancel</button>
    </div>
</div>

<script>
    const vidPlayer = document.getElementById('vidPlayer'); const audPlayer = document.getElementById('audPlayer');
    const videoContainer = document.getElementById('videoContainer'); const audioContainer = document.getElementById('audioContainer');
    const musicModeToggle = document.getElementById('musicModeToggle');
    let isMusicMode = false; let activePlayer = vidPlayer;
    let currentVideoId = '{{ video_id }}';
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

    musicModeToggle.onclick = () => {
        isMusicMode = !isMusicMode;
        if (isMusicMode) {
            musicModeToggle.innerText = "🎧 Music Mode: ON"; musicModeToggle.style.background = "#4CAF50"; 
            audPlayer.currentTime = vidPlayer.currentTime; vidPlayer.pause();
            videoContainer.style.display = "none"; audioContainer.style.display = "block";
            activePlayer = audPlayer; audPlayer.play();
        } else {
            musicModeToggle.innerText = "🎧 Music Mode: OFF"; musicModeToggle.style.background = "#ff9800"; 
            vidPlayer.currentTime = audPlayer.currentTime; audPlayer.pause();
            audioContainer.style.display = "none"; videoContainer.style.display = "block";
            activePlayer = vidPlayer; vidPlayer.play();
        }
    };

    let watchTimer;
    const startTracking = () => { clearInterval(watchTimer); watchTimer = setInterval(() => { fetch('/api/track_engagement', { method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrfToken}, body: JSON.stringify({ video_id: currentVideoId, seconds: 5 }) }); }, 5000); };
    const stopTracking = () => clearInterval(watchTimer);
    vidPlayer.onplay = startTracking; vidPlayer.onpause = stopTracking; vidPlayer.onended = stopTracking;
    audPlayer.onplay = startTracking; audPlayer.onpause = stopTracking; audPlayer.onended = stopTracking;

    vidPlayer.onplay = () => { startTracking(); recordWatchHistory(currentVideoId); };

    function toggleReply(commentId) { const form = document.getElementById('reply-form-' + commentId); form.style.display = form.style.display === 'none' ? 'flex' : 'none'; }
    function likeComment(videoId, commentId) {
        fetch('/api/like_comment', { method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrfToken}, body: JSON.stringify({ video_id: videoId, comment_id: commentId }) })
        .then(response => response.json()).then(data => { if(data.status === 'ok') document.getElementById('like-count-' + commentId).innerText = data.likes; });
    }

    function saveVideo(vid) {
        fetch('/api/save_video', { method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrfToken}, body: JSON.stringify({ video_id: vid }) })
        .then(r => r.json()).then(data => {
            const btn = document.getElementById('saveBtn');
            if(data.saved) { btn.innerText = '✅ Saved'; btn.style.background = '#4CAF50'; }
            else { btn.innerText = '💾 Save'; btn.style.background = '#2e7d32'; }
        });
    }

    function recordWatchHistory(vid) {
        fetch('/api/watch_history', { method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrfToken}, body: JSON.stringify({ video_id: vid }) });
    }

    function addToPlaylist(vid) {
        currentVideoId = vid;
        fetch('/api/playlists').then(r => r.json()).then(data => {
            const list = document.getElementById('playlistList');
            list.innerHTML = '';
            if(data.playlists.length === 0) {
                list.innerHTML = '<p style="color:#888; text-align:center;">No playlists yet. Create one below.</p>';
            } else {
                data.playlists.forEach(pl => {
                    const div = document.createElement('div');
                    div.style.cssText = 'padding:10px; border-bottom:1px solid #eee; cursor:pointer; display:flex; justify-content:space-between; align-items:center;';
                    div.innerHTML = `<span><b>${pl.name}</b> (${pl.video_count} videos)</span><button class="primary-btn" style="padding:4px 10px; font-size:12px;">Add</button>`;
                    div.onclick = () => addVideoToPlaylist(pl.id, vid);
                    list.appendChild(div);
                });
            }
            document.getElementById('playlistModal').style.display = 'flex';
        });
    }

    function createPlaylist() {
        const name = document.getElementById('newPlaylistName').value.trim();
        if(!name) return;
        fetch('/api/playlists', { method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrfToken}, body: JSON.stringify({ name: name }) })
        .then(r => r.json()).then(data => {
            if(data.id) addVideoToPlaylist(data.id, currentVideoId);
        });
    }

    function addVideoToPlaylist(playlistId, videoId) {
        fetch('/api/playlists/' + playlistId + '/videos', { method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrfToken}, body: JSON.stringify({ video_id: videoId }) })
        .then(r => r.json()).then(data => {
            alert(data.message || 'Added to playlist!');
            closePlaylistModal();
        });
    }

    function closePlaylistModal() {
        document.getElementById('playlistModal').style.display = 'none';
        document.getElementById('newPlaylistName').value = '';
    }

    document.getElementById('playlistModal').onclick = (e) => {
        if(e.target.id === 'playlistModal') closePlaylistModal();
    };
</script>
{% endblock %}
    """,
    "playlists.html": """
{% extends 'base.html' %}
{% block content %}
<div style="max-width: 800px; margin: auto;">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h2>📂 My Playlists</h2>
        <button onclick="document.getElementById('createPlForm').style.display='block'" class="primary-btn">➕ New Playlist</button>
    </div>
    <div id="createPlForm" style="display:none; margin-bottom: 20px;" class="admin-panel">
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
            <input type="text" name="playlist_name" placeholder="Playlist Name" required style="margin-bottom: 10px;">
            <button class="primary-btn" type="submit" style="width: 100%;">Create Playlist</button>
        </form>
    </div>
    {% if playlists %}
    <div class="grid">
        {% for pl in playlists %}
        <a href="/playlist/{{ pl.id }}" class="card" style="padding: 20px;">
            <div class="thumbnail" style="height: 160px; background: linear-gradient(135deg, #065fd4, #3ea6ff); font-size: 50px;">📂</div>
            <div class="card-info">
                <div>
                    <div class="card-title">{{ pl.name }}</div>
                    <div class="card-meta">{{ pl.video_count }} videos • {{ pl.timestamp }}</div>
                </div>
            </div>
        </a>
        {% endfor %}
    </div>
    {% else %}
    <p style="text-align: center; color: #888; margin-top: 50px;">No playlists yet. Create your first playlist!</p>
    {% endif %}
</div>
{% endblock %}
    """,
    "playlist_detail.html": """
{% extends 'base.html' %}
{% block content %}
<div style="max-width: 800px; margin: auto;">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 10px;">
        <h2>📂 {{ playlist.name }}</h2>
        <form method="POST" style="margin:0;" onsubmit="return confirm('Delete this playlist?');">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
            <input type="hidden" name="action" value="delete_playlist">
            <button type="submit" style="background:#c62828; color:white; border:none; padding:8px 15px; border-radius:6px; cursor:pointer; font-weight:bold;">🗑️ Delete</button>
        </form>
    </div>
    {% if videos %}
    <div class="grid">
        {% for v in videos %}
        <a href="/watch/{{ v.id }}" class="card">
            <div class="thumbnail">▶</div>
            <div class="card-info">
                <div class="avatar-container">
                    {% if v.uploader_pic %}<img src="/media/profiles/{{ v.uploader_pic }}" class="avatar">
                    {% else %}<div class="avatar">{{ v.uploader[0]|upper }}</div>{% endif %}
                </div>
                <div>
                    <div class="card-title">{{ v.title }}</div>
                    <div class="card-meta">{{ v.uploader }} • {{ v.timestamp }}</div>
                </div>
            </div>
        </a>
        {% endfor %}
    </div>
    {% else %}
    <p style="text-align: center; color: #888;">No videos in this playlist yet.</p>
    {% endif %}
</div>
{% endblock %}
    """,
    "saved_videos.html": """
{% extends 'base.html' %}
{% block content %}
<div style="max-width: 800px; margin: auto;">
    <h2>💾 Saved Videos</h2>
    {% if videos %}
    <div class="grid">
        {% for v in videos %}
        <a href="/watch/{{ v.id }}" class="card">
            <div class="thumbnail">▶</div>
            <div class="card-info">
                <div class="avatar-container">
                    {% if v.uploader_pic %}<img src="/media/profiles/{{ v.uploader_pic }}" class="avatar">
                    {% else %}<div class="avatar">{{ v.uploader[0]|upper }}</div>{% endif %}
                </div>
                <div>
                    <div class="card-title">{{ v.title }}</div>
                    <div class="card-meta">{{ v.uploader }} • {{ v.timestamp }}</div>
                </div>
            </div>
        </a>
        {% endfor %}
    </div>
    {% else %}
    <p style="text-align: center; color: #888; margin-top: 50px;">No saved videos yet.</p>
    {% endif %}
</div>
{% endblock %}
    """,
    "watch_history.html": """
{% extends 'base.html' %}
{% block content %}
<div style="max-width: 800px; margin: auto;">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h2>📜 Watch History</h2>
        <form method="POST" style="margin:0;">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
            <input type="hidden" name="action" value="clear_history">
            <button type="submit" style="background:#888; color:white; border:none; padding:8px 15px; border-radius:6px; cursor:pointer; font-weight:bold;">🗑️ Clear History</button>
        </form>
    </div>
    {% if history %}
    <div style="display: flex; flex-direction: column; gap: 12px;">
        {% for h in history %}
        <a href="/watch/{{ h.video_id }}" style="text-decoration: none; color: inherit;">
            <div class="admin-panel" style="display: flex; gap: 15px; align-items: center; margin-bottom: 0;">
                <div class="thumbnail" style="width: 160px; height: 90px; flex-shrink: 0; border-radius: 8px;">▶</div>
                <div style="flex: 1;">
                    <div style="font-weight: bold; font-size: 16px; margin-bottom: 5px;">{{ h.title }}</div>
                    <div style="color: #888; font-size: 13px;">{{ h.uploader }} • Watched {{ h.watched_at }}</div>
                </div>
            </div>
        </a>
        {% endfor %}
    </div>
    {% else %}
    <p style="text-align: center; color: #888; margin-top: 50px;">No watch history yet.</p>
    {% endif %}
</div>
{% endblock %}
    """,
    "admin_user_history.html": """
{% extends 'base.html' %}
{% block content %}
<div style="max-width: 900px; margin: auto;">
    <h2>📊 Watch History: {{ target_user }}</h2>
    <div class="admin-panel" style="margin-bottom: 20px;">
        <h3>User Stats</h3>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px;">
            <div style="background: #f0f0f0; padding: 15px; border-radius: 8px; text-align: center;" class="dark-box">
                <div style="font-size: 24px; font-weight: bold; color: #065fd4;">{{ total_watch_mins }}</div>
                <div style="font-size: 12px; color: #888;">Total Minutes</div>
            </div>
            <div style="background: #f0f0f0; padding: 15px; border-radius: 8px; text-align: center;" class="dark-box">
                <div style="font-size: 24px; font-weight: bold; color: #065fd4;">{{ video_count }}</div>
                <div style="font-size: 12px; color: #888;">Videos Watched</div>
            </div>
        </div>
    </div>
    {% if history %}
    <div style="display: flex; flex-direction: column; gap: 12px;">
        {% for h in history %}
        <a href="/watch/{{ h.video_id }}" style="text-decoration: none; color: inherit;">
            <div class="admin-panel" style="display: flex; gap: 15px; align-items: center; margin-bottom: 0;">
                <div class="thumbnail" style="width: 160px; height: 90px; flex-shrink: 0; border-radius: 8px;">▶</div>
                <div style="flex: 1;">
                    <div style="font-weight: bold; font-size: 16px; margin-bottom: 5px;">{{ h.title }}</div>
                    <div style="color: #888; font-size: 13px;">{{ h.uploader }} • Watched {{ h.watched_at }}</div>
                </div>
            </div>
        </a>
        {% endfor %}
    </div>
    {% else %}
    <p style="text-align: center; color: #888;">No watch history for this user.</p>
    {% endif %}
</div>
{% endblock %}
    """
}

app.jinja_loader = DictLoader(templates)

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
