"""
Encrypted Vault – Flask application.

All file data is AES-256-GCM encrypted on disk.  Decrypted bytes only
ever exist in RAM (streamed via generators).  Each user has their own
independent encryption key — User A cannot decrypt User B's files even
with full disk access, admin privileges, or their own valid account.
"""

import io
import logging
import math
import os
import threading
import uuid
import mimetypes
from functools import wraps
from zipstream import ZipStream, ZIP_DEFLATED

from flask import (
    Flask, request, Response, jsonify, render_template,
    redirect, url_for, flash, abort,
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash

import config
from crypto import (
    generate_master_key, encrypt_master_key, decrypt_master_key,
    ChunkEncryptor,
)
from models import (
    init_db, get_config, set_config, is_setup_done,
    create_user, get_user, get_user_by_id, list_users,
    delete_user, update_user_password, set_user_admin,
    list_files, get_file, get_file_by_name, create_file_record,
    rename_file, move_file, delete_file_record,
    get_breadcrumbs, get_folders, get_folder_info, search_files,
    get_user_preferences, set_user_preferences,
    get_video_preferences, set_video_preferences, clear_all_video_preferences,
    get_all_video_last_accessed,
    _compute_recursive_sizes,  # recursive directory size computation
    migrate_user_fields,
    get_audio_cache_info, clear_audio_cache, has_audio_cache,
    get_cbz_preferences, set_cbz_preferences, clear_cbz_preferences,
)
# ── Core modules (consolidated from helpers/) ────────────────
import core  # noqa: E402 — provides access to all consolidated route handlers
from transcoder import get_session, destroy_session

# ── logging ──────────────────────────────────────────────────────────
os.makedirs(config.DATA_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.DEBUG if config.DEBUG else logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(config.DATA_DIR, 'vault.log')),
    ],
)
logger = logging.getLogger('vault')

# Suppress werkzeug's per-request access log (every GET/POST at INFO level).
# Errors (500s etc.) still come through because they're logged at WARNING+.
logging.getLogger('werkzeug').setLevel(logging.WARNING)

# ── Flask app ────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Per-user keys live ONLY in RAM — never written to disk unencrypted.
# Dict maps user_id -> (master_key_bytes, ChunkEncryptor)
_user_keys: dict[int, tuple[bytes, 'ChunkEncryptor']] = {}


# ── user model for flask-login ───────────────────────────────────────
class User(UserMixin):
    def __init__(self, uid, username, is_admin=False):
        self.id = uid
        self.username = username
        self.is_admin = is_admin


@login_manager.user_loader
def _load_user(user_id):
    row = get_user_by_id(int(user_id))
    if row:
        return User(row['id'], row['username'], bool(row['is_admin']))
    return None


def admin_required(f):
    """Decorator: require logged-in admin user."""
    @wraps(f)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return wrapped


def _get_encryptor() -> ChunkEncryptor | None:
    """Return the ChunkEncryptor for the currently logged-in user, or None."""
    if not current_user.is_authenticated:
        return None
    entry = _user_keys.get(current_user.id)
    return entry[1] if entry else None


def _get_master_key() -> bytes | None:
    """Return the raw master key for the currently logged-in user."""
    if not current_user.is_authenticated:
        return None
    entry = _user_keys.get(current_user.id)
    return entry[0] if entry else None


# ── request guards ───────────────────────────────────────────────────
_last_data_dir = None  # Track which data dir the current user keys belong to

@app.before_request
def _clear_stale_user_keys():
    """Clear cached user keys if DATA_DIR changed (e.g., between pytest tmp_path fixtures)."""  
    global _user_keys, _last_data_dir
    current_ddir = os.environ.get('DATA_DIR', '')
    if _last_data_dir is None:
        _last_data_dir = current_ddir
    elif _last_data_dir != current_ddir:
        # DATA_DIR changed — clear all cached user keys so they get reloaded fresh  
        _user_keys.clear()
        _last_data_dir = current_ddir

@app.before_request
def _before():
    ep = request.endpoint or ''
    if ep == 'static':
        return
    if not is_setup_done():
        if ep != 'setup':
            return redirect(url_for('setup'))
        return
    # If server restarted the user's key is gone → force re-login
    if current_user.is_authenticated and current_user.id not in _user_keys:
        if ep not in ('login', 'logout'):
            logout_user()
            flash('Session expired. Please log in again.', 'warning')
            return redirect(url_for('login'))


# ── setup (first run) ───────────────────────────────────────────────
@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if is_setup_done():
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')

        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('setup.html')
        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('setup.html')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('setup.html')

        # Generate a unique master key for this user and wrap it with their password
        mk = generate_master_key()
        salt, nonce, enc_key = encrypt_master_key(mk, password)

        set_config('flask_secret', os.urandom(32))

        create_user(
            username,
            generate_password_hash(password),
            is_admin=True,
            key_salt=salt,
            key_nonce=nonce,
            key_encrypted=enc_key,
        )
        os.makedirs(config.VAULT_DIR, exist_ok=True)

        flash('Vault created! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('setup.html')


# ── authentication ───────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if not is_setup_done():
        return redirect(url_for('setup'))

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        row = get_user(username)

        if row and check_password_hash(row['password_hash'], password):
            try:
                mk = decrypt_master_key(
                    row['key_salt'],
                    row['key_nonce'],
                    row['key_encrypted'],
                    password,
                )
                _user_keys[row['id']] = (mk, ChunkEncryptor(mk, config.CHUNK_SIZE))
            except Exception:
                flash('Failed to unlock vault.', 'error')
                return render_template('login.html')

            # Migrate plaintext file names → encrypted (one-time per user)
            migrate_user_fields(row['id'], mk)

            login_user(User(row['id'], row['username'], bool(row['is_admin'])),
                       remember=False)
            return redirect(url_for('explorer'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    _user_keys.pop(current_user.id, None)
    logout_user()
    return redirect(url_for('login'))


# ── file explorer page ───────────────────────────────────────────────
@app.route('/', endpoint='root_explorer')
@login_required
@app.route('/explorer')
@login_required
def explorer():
    return _explorer_page()


# ── JSON API (delegation to helpers) ────────────────────────────────
@app.route('/api/files')
@login_required
def api_list_files():
    return core.files_api.api_list_files()


@app.route('/api/search')
@login_required
def api_search_files():
    return core.files_api.api_search_files()


@app.route('/api/folders')  
@login_required
def api_list_folders():
    return core.files_api.api_list_folders()


@app.route('/api/folder-breadcrumbs/<int:folder_id>')
@login_required
def api_folder_breadcrumbs(folder_id):
    return core.files_api.api_folder_breadcrumbs(folder_id)


@app.route('/api/folder/<int:folder_id>/parent')
@login_required
def api_get_folder_parent(folder_id):
    return core.files_api.api_get_folder_parent(folder_id)


@app.route('/api/mkdir', methods=['POST'])
@login_required
def api_mkdir():
    return core.files_api.api_mkdir()


@app.route('/api/mkdirp', methods=['POST'])
@login_required
def api_mkdirp():
    return core.files_api.api_mkdirp()


@app.route('/api/upload', methods=['POST'])
@login_required
def api_upload():
    return core.files_api.api_upload()


@app.route('/api/rename', methods=['POST'])
@login_required
def api_rename():
    return core.files_api.api_rename()


@app.route('/api/move', methods=['POST'])
@login_required
def api_move():
    return core.files_api.api_move()


@app.route('/api/delete', methods=['POST'])
@login_required
def api_delete():
    return core.files_api.api_delete()


@app.route('/api/bulk-delete', methods=['POST'])
@login_required
def api_bulk_delete():
    return core.files_api.api_bulk_delete()


@app.route('/api/bulk-move', methods=['POST'])
@login_required
def api_bulk_move():
    return core.files_api.api_bulk_move()


@app.route('/api/file/<int:file_id>/info')
@login_required
def api_file_info(file_id):
    return core.files_api.api_file_info(file_id)


# ── streaming / download (delegation to helpers) ───────────────
@app.route('/stream/<int:file_id>')
@login_required
def stream_file(file_id):
    return core.streaming.stream_file(file_id)

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    return core.streaming.download_file(file_id)

@app.route('/download-folder/<int:folder_id>')
@login_required
def download_folder(folder_id):
    return core.streaming.download_folder(folder_id)


import random as _random


# ── media player page ────────────────────────────────────────────────
@app.route('/api/random-sibling/<int:file_id>')
@login_required
def api_random_sibling(file_id):
    return core.media_player.api_random_sibling(file_id)

@app.route('/player/<int:file_id>', endpoint='player_view')
@login_required
def player(file_id):
    f = get_file(file_id, current_user.id, key=_get_master_key())
    if not f or f['is_directory']:
        abort(404)
    mk = _get_master_key()
    prefs = get_user_preferences(current_user.id, key=mk)
    vprefs = get_video_preferences(current_user.id, file_id, key=mk)
    # Touch last_accessed for "recently accessed" sort
    set_video_preferences(current_user.id, file_id, key=mk)
    return render_template('player.html', file=dict(f), prefs=prefs, vprefs=vprefs)


# ── Media utilities consolidated in core.media_player
# Re-exported via helpers/__init__.py for discoverability
# ── Core imports (consolidated from helpers/) ────────────────
from core.files_api import (
    api_list_files,
    api_search_files,
    api_mkdir,
    api_upload,
    api_rename,
    api_move,
    api_delete,
    api_bulk_delete,
    api_folder_breadcrumbs,
    api_get_folder_parent,
)
from core.streaming import (
    stream_file, download_file, download_folder,
    api_hls_status, api_hls_master, api_hls_video_playlist,
    api_hls_audio_playlist, api_hls_subtitle_playlist,
    api_hls_segment, api_hls_subtitle_file, api_hls_tracks,
)
from core.media_player import (
    collect_recursive,
    media_category,
    sort_files,
    api_siblings,
    api_random_sibling,
    explorer_page as _explorer_page,
    player_page as _player_page,
)
from core.text_editor import editor, api_read_text, api_write_text, api_create_text
from core.preferences import (
    settings_page,
    api_get_preferences,
    api_set_preferences,
    api_get_video_prefs,
    api_set_video_prefs,
    api_clear_video_prefs,
)
from core.audio_reencode import (
    api_overwrite_audio,
    api_reencode_dir,
    api_reencode_status,
    api_reencode_jobs,
    api_reencode_clear,
)
from core.users_api import (
    api_export_keys,
    users_page as _users_page,
    api_list_users,
    api_create_user,
    api_delete_user,
    api_reset_password,
    api_toggle_admin,
    api_change_password,
)

@app.route('/api/siblings/<int:file_id>')
@login_required
def api_siblings(file_id):
    return core.media_player.api_siblings(file_id)


@app.route('/editor/<int:file_id>')
@login_required
def editor(file_id):
    return core.text_editor.editor(file_id)


@app.route('/api/file/<int:file_id>/text')
@login_required
def api_read_text(file_id):
    return core.text_editor.api_read_text(file_id)


@app.route('/api/file/<int:file_id>/text', methods=['POST'])
@login_required
def api_write_text(file_id):
    return core.text_editor.api_write_text(file_id)


@app.route('/api/create-text', methods=['POST'])
@login_required
def api_create_text():
    return core.text_editor.api_create_text()


@app.route('/api/file/<int:file_id>/editable')
@login_required
def api_is_editable(file_id):
    return core.text_editor.api_is_editable(file_id)


# ── user settings / preferences (delegation to helpers) ────────────
@app.route('/settings')
@login_required
def settings_page():
    return core.preferences.settings_page()


@app.route('/api/preferences', methods=['GET'])
@login_required
def api_get_preferences():
    return core.preferences.api_get_preferences()


@app.route('/api/preferences', methods=['POST'])
@login_required
def api_set_preferences():
    return core.preferences.api_set_preferences()


@app.route('/api/video/<int:file_id>/prefs', methods=['GET'])
@login_required
def api_get_video_prefs(file_id):
    return core.preferences.api_get_video_prefs(file_id)


@app.route('/api/video/<int:file_id>/prefs', methods=['POST'])
@login_required
def api_set_video_prefs(file_id):
    return core.preferences.api_set_video_prefs(file_id)


@app.route('/api/video/prefs/clear', methods=['POST'])
@login_required
def api_clear_video_prefs():
    return core.preferences.api_clear_video_prefs()


# ── CBZ reader (delegation to helpers) ───────────────────

@app.route('/cbz/<int:file_id>')
@login_required
def cbz_reader(file_id):
    return core.preferences.cbz_reader(file_id)


@app.route('/api/cbz/<int:file_id>/image')
@login_required
def api_cbz_image(file_id):
    return core.preferences.api_cbz_image(file_id)


@app.route('/api/cbz/<int:file_id>/pages')
@login_required
def api_cbz_pages(file_id):
    return core.preferences.api_cbz_pages(file_id)


@app.route('/api/cbz/<int:file_id>/prefs', methods=['GET'])
@login_required
def api_get_cbz_prefs(file_id):
    return core.preferences.api_get_cbz_prefs(file_id)


@app.route('/api/cbz/<int:file_id>/prefs', methods=['POST'])
@login_required
def api_set_cbz_prefs(file_id):
    return core.preferences.api_set_cbz_prefs(file_id)


# ── audio cache management ───────────────────────────────────────────

@app.route('/api/audio-cache/<int:file_id>', methods=['GET'])
@login_required
def api_get_audio_cache(file_id):
    return core.audio_reencode.api_get_audio_cache(file_id)


@app.route('/api/audio-cache/<int:file_id>/clear', methods=['POST'])
@login_required
def api_clear_audio_cache(file_id):
    return core.audio_reencode.api_clear_audio_cache(file_id)


@app.route('/api/audio-cache/clear-all', methods=['POST'])
@login_required
def api_clear_all_audio_cache():
    return core.audio_reencode.api_clear_all_audio_cache()


@app.route('/api/overwrite-audio/<int:file_id>', methods=['POST'])
@login_required
def api_overwrite_audio(file_id):
    return core.audio_reencode.api_overwrite_audio(file_id)


@app.route('/api/reencode-dir/<int:dir_id>', methods=['POST'])
@login_required
def api_reencode_dir(dir_id):
    return core.audio_reencode.api_reencode_dir(dir_id)


@app.route('/api/reencode-status')
@login_required
def api_reencode_status():
    return core.audio_reencode.api_reencode_status()


@app.route('/api/reencode-jobs')
@login_required
def api_reencode_jobs():
    return core.audio_reencode.api_reencode_jobs()


@app.route('/api/reencode-clear', methods=['POST'])
@login_required
def api_reencode_clear():
    return core.audio_reencode.api_reencode_clear()



@app.route('/api/export-keys')
@login_required
def api_export_keys():
    return core.users_api.api_export_keys()


@app.route('/users')
@admin_required
def users_page():
    return _users_page()


@app.route('/api/users')
@admin_required
def api_list_users():
    return core.users_api.api_list_users()

@app.route('/api/users/create', methods=['POST'])
@admin_required
def api_create_user():
    return core.users_api.api_create_user()


@app.route('/api/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def api_delete_user(user_id):
    return core.users_api.api_delete_user(user_id)


@app.route('/api/users/<int:user_id>/reset-password', methods=['POST'])
@admin_required
def api_reset_password(user_id):
    return core.users_api.api_reset_password(user_id)


@app.route('/api/users/<int:user_id>/toggle-admin', methods=['POST'])
@admin_required
def api_toggle_admin(user_id):
    return core.users_api.api_toggle_admin(user_id)


@app.route('/api/change-password', methods=['POST'])
@login_required
def api_change_password():
    return core.users_api.api_change_password()


# ── HLS streaming API

@app.route('/api/hls/<int:file_id>/status')
@login_required
def api_hls_status(file_id):
    return core.streaming.api_hls_status(file_id)


@app.route('/api/hls/<int:file_id>/master.m3u8')
@login_required
def api_hls_master(file_id):
    return core.streaming.api_hls_master(file_id)


@app.route('/api/hls/<int:file_id>/video/playlist.m3u8')
@login_required
def api_hls_video_playlist(file_id):
    return core.streaming.api_hls_video_playlist(file_id)


@app.route('/api/hls/<int:file_id>/audio/<int:track>/playlist.m3u8')
@login_required
def api_hls_audio_playlist(file_id, track):
    return core.streaming.api_hls_audio_playlist(file_id, track)


@app.route('/api/hls/<int:file_id>/subtitle/<int:track>/playlist.m3u8')
@login_required
def api_hls_subtitle_playlist(file_id, track):
    return core.streaming.api_hls_subtitle_playlist(file_id, track)


@app.route('/api/hls/<int:file_id>/<stream>/<int:track>/segment/<int:seg_index>.ts')
@login_required
def api_hls_segment(file_id, stream, track, seg_index):
    return core.streaming.api_hls_segment(file_id, stream, track, seg_index)


@app.route('/api/hls/<int:file_id>/subtitle/<int:track>/file.vtt')
@login_required
def api_hls_subtitle_file(file_id, track):
    return core.streaming.api_hls_subtitle_file(file_id, track)


@app.route('/api/hls/<int:file_id>/tracks')
@login_required
def api_hls_tracks(file_id):
    return core.streaming.api_hls_tracks(file_id)


# ── app factory ──────────────────────────────────────────────────────
def create_app():
    os.makedirs(config.DATA_DIR, exist_ok=True)
    os.makedirs(config.VAULT_DIR, exist_ok=True)
    init_db()

    secret = get_config('flask_secret')
    app.secret_key = secret if secret else os.urandom(32)
    logger.info('Vault server starting on %s:%s', config.HOST, config.PORT)
    return app
