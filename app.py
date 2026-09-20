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
    from helpers.app_helpers_media_player import explorer_page as _ep  # noqa: F811
    return _ep()


# ── JSON API (delegation to helpers) ────────────────────────────────
@app.route('/api/files')
@login_required
def api_list_files():
    from helpers.app_helpers_files import api_list_files as _alf  # noqa: F811
    return _alf()


@app.route('/api/search')
@login_required
def api_search_files():
    from helpers.app_helpers_files import api_search_files as _asf  # noqa: F811
    return _asf()


@app.route('/api/folders')  
@login_required
def api_list_folders():
    from helpers.app_helpers_files import api_list_folders as _alfd  # noqa: F811
    return _alfd()


@app.route('/api/folder-breadcrumbs/<int:folder_id>')
@login_required
def api_folder_breadcrumbs(folder_id):
    from helpers.app_helpers_files import api_folder_breadcrumbs as _afbc  # noqa: F811
    return _afbc(folder_id)


@app.route('/api/folder/<int:folder_id>/parent')
@login_required
def api_get_folder_parent(folder_id):
    from helpers.app_helpers_files import api_get_folder_parent as _afgp  # noqa: F811
    return _afgp(folder_id)


@app.route('/api/mkdir', methods=['POST'])
@login_required
def api_mkdir():
    from helpers.app_helpers_files import api_mkdir as _amk  # noqa: F811
    return _amk()


@app.route('/api/mkdirp', methods=['POST'])
@login_required
def api_mkdirp():
    from helpers.app_helpers_files import api_mkdirp as _ampd  # noqa: F811
    return _ampd()


@app.route('/api/upload', methods=['POST'])
@login_required
def api_upload():
    from helpers.app_helpers_files import api_upload as _aupload  # noqa: F811
    return _aupload()


@app.route('/api/rename', methods=['POST'])
@login_required
def api_rename():
    from helpers.app_helpers_files import api_rename as _arename  # noqa: F811
    return _arename()


@app.route('/api/move', methods=['POST'])
@login_required
def api_move():
    from helpers.app_helpers_files import api_move as _amove  # noqa: F811
    return _amove()


@app.route('/api/delete', methods=['POST'])
@login_required
def api_delete():
    from helpers.app_helpers_files import api_delete as _adelete  # noqa: F811
    return _adelete()


@app.route('/api/bulk-delete', methods=['POST'])
@login_required
def api_bulk_delete():
    from helpers.app_helpers_files import api_bulk_delete as _abdel  # noqa: F811
    return _abdel()


@app.route('/api/bulk-move', methods=['POST'])
@login_required
def api_bulk_move():
    from helpers.app_helpers_files import api_bulk_move as _abmove  # noqa: F811
    return _abmove()


@app.route('/api/file/<int:file_id>/info')
@login_required
def api_file_info(file_id):
    from helpers.app_helpers_files import api_file_info as _afileinfo  # noqa: F811
    return _afileinfo(file_id)


# ── streaming / download (delegation to helpers) ───────────────
@app.route('/stream/<int:file_id>')
@login_required
def stream_file(file_id):
    from helpers.app_helpers_streaming import stream_file as _sfile  # noqa: F811
    return _sfile(file_id)

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    from helpers.app_helpers_streaming import download_file as _dld  # noqa: F811
    return _dld(file_id)

@app.route('/download-folder/<int:folder_id>')
@login_required
def download_folder(folder_id):
    from helpers.app_helpers_streaming import download_folder as _dldf  # noqa: F811
    return _dldf(folder_id)


import random as _random


# ── media player page ────────────────────────────────────────────────
@app.route('/api/random-sibling/<int:file_id>')
@login_required
def api_random_sibling(file_id):
    from helpers.app_helpers_media_player import api_random_sibling as _ars  # noqa: F811
    return _ars(file_id)

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


def _media_category(mime):
    """Return a broad category string for grouping sibling navigation."""
    mime = (mime or '').lower()
    if mime.startswith('video/'):
        return 'video'
    if mime.startswith('audio/'):
        return 'audio'
    if mime.startswith('image/'):
        return 'image'
    if mime.startswith('text/') or mime in {
        'application/json', 'application/xml', 'application/javascript',
        'application/x-yaml', 'application/yaml', 'application/toml',
        'application/x-sh', 'application/x-shellscript',
        'application/sql', 'application/xhtml+xml', 'application/x-httpd-php',
    }:
        return 'text'
    if mime == 'application/pdf':
        return 'document'
    return 'other'


# ── sort helpers for sibling navigation ────────────────────────
def _sort_files(files, sort_by='name'):
    """Sort a list of file dicts by the given preference.

    Returns files sorted in ascending order so prev/next indices work correctly.
    For 'recent' and 'added', descending means newest first (reverse = True).
    For 'size', largest first (descending).
    """
    if sort_by == 'name':
        # Ascending alphabetical
        files.sort(key=lambda d: (d.get('name') or '').lower())
    elif sort_by in ('recent', 'added', 'size'):
        # Descending = newest/largest first, so we reverse for ascending prev/next logic
        if sort_by == 'recent':
            files.sort(key=lambda d: (d.get('last_accessed') or ''), reverse=True)
        elif sort_by == 'added':
            files.sort(key=lambda d: (d.get('created_at') or ''), reverse=True)
        else:
            # size descending
            files.sort(key=lambda d: int(d.get('size') or 0), reverse=True)
    return files


def _collect_recursive(uid, parent_id, cat, mk, exclude_id=None):
    """Collect all non-directory files of a given category recursively."""
    items = list_files(uid, parent_id, key=mk)
    result = []
    for item in items:
        if item['is_directory']:
            result.extend(_collect_recursive(uid, item['id'], cat, mk, exclude_id))
        elif _media_category(item.get('mime_type')) == cat:
            if exclude_id is None or item['id'] != exclude_id:
                result.append(item)
    return result


@app.route('/api/siblings/<int:file_id>')
@login_required
def api_siblings(file_id):
    from helpers.app_helpers_media_player import api_siblings as _sib  # noqa: F811
    return _sib(file_id)
    """Return prev/next file IDs and recursive total for same-type files.

    Accepts optional ?root=<parent_id> (or 'null' for vault root) to
    compute the recursive total from a specific ancestor directory
    instead of the file's immediate parent. Also accepts:
      - sort_by=name|recent|added|size  – which sort order prev/next uses (default: name)
      - recurse=0|1                    – whether navigation spans subdirs (default: 1)
    """
    uid = current_user.id
    mk = _get_master_key()
    f = get_file(file_id, uid, key=mk)
    if not f:
        return jsonify({'error': 'Not found'}), 404

    cat = _media_category(f.get('mime_type'))

    # ── resolve sort_by from query params (falls back to user pref) ────
    raw_sort = request.args.get('sort_by', '').strip().lower()
    if raw_sort in ('name', 'recent', 'added', 'size'):
        sort_by = raw_sort
    else:
        # fall back to stored preference
        prefs = get_user_preferences(uid, key=mk)
        sort_by = (prefs.get('sort_preference') or 'name').strip().lower()
        if sort_by not in ('name', 'recent', 'added', 'size'):
            sort_by = 'name'

    # ── resolve recurse from query params (falls back to 1) ───────────
    raw_recurse = request.args.get('recurse', '').strip()
    if raw_recurse in ('0', 'no', 'false'):
        do_recurse = False
    else:
        # default: recurse through subdirs when browsing from a root context
        do_recurse = True

    # Use explicit root if provided, otherwise file's parent
    root_raw = request.args.get('root', None)
    if root_raw is not None:
        root_id = None if root_raw in ('null', '') else int(root_raw)
    else:
        root_id = f['parent_id']

    # ── Build the collection to navigate within (prev/next) ────────────
    if do_recurse:
        # Full recursive collection sorted by current preference
        all_recursive = _collect_recursive(uid, root_id, cat, mk)
        typed_collection = _sort_files(all_recursive, sort_by)
    else:
        # Direct siblings only in the same folder, using active sort
        direct_siblings = list_files(uid, f['parent_id'], key=mk)
        typed_collection = [s for s in direct_siblings if not s['is_directory'] and _media_category(s.get('mime_type')) == cat]
        typed_collection = _sort_files(typed_collection, sort_by)

    ids_in_order = [s['id'] for s in typed_collection]
    try:
        idx = ids_in_order.index(file_id)
    except ValueError:
        idx = -1

    prev_id = ids_in_order[idx - 1] if idx > 0 else None
    next_id = ids_in_order[idx + 1] if idx >= 0 and idx < len(ids_in_order) - 1 else None

    # ── Total & position (match recursion mode used for navigation) ─
    total_count = len(typed_collection)
    current_position = idx + 1 if idx >= 0 else 0

    return jsonify({
        'prev_id': prev_id,
        'next_id': next_id,
        'total': total_count,
        'position': current_position,
        'root_parent_id': root_id,
        'sort_by': sort_by,
        'recurse': do_recurse,
    })


@app.route('/editor/<int:file_id>')
@login_required
def editor(file_id):
    from helpers.app_helpers_text import editor as _ed  # noqa: F811
    return _ed(file_id)


@app.route('/api/file/<int:file_id>/text')
@login_required
def api_read_text(file_id):
    from helpers.app_helpers_text import api_read_text as _artx  # noqa: F811
    return _artx(file_id)


@app.route('/api/file/<int:file_id>/text', methods=['POST'])
@login_required
def api_write_text(file_id):
    from helpers.app_helpers_text import api_write_text as _awtx  # noqa: F811
    return _awtx(file_id)


@app.route('/api/create-text', methods=['POST'])
@login_required
def api_create_text():
    from helpers.app_helpers_text import api_create_text as _actx  # noqa: F811
    return _actx()


@app.route('/api/file/<int:file_id>/editable')
@login_required
def api_is_editable(file_id):
    from helpers.app_helpers_text import api_is_editable as _aie  # noqa: F811
    return _aie(file_id)


# ── user settings / preferences (delegation to helpers) ────────────
@app.route('/settings')
@login_required
def settings_page():
    from helpers._prefs_settings import settings_page as _sp  # noqa: F811
    return _sp()


@app.route('/api/preferences', methods=['GET'])
@login_required
def api_get_preferences():
    from helpers._prefs_settings import api_get_preferences as _agp  # noqa: F811
    return _agp()


@app.route('/api/preferences', methods=['POST'])
@login_required
def api_set_preferences():
    from helpers._prefs_settings import api_set_preferences as _asp  # noqa: F811
    return _asp()


@app.route('/api/video/<int:file_id>/prefs', methods=['GET'])
@login_required
def api_get_video_prefs(file_id):
    from helpers._prefs_settings import api_get_video_prefs as _agvp  # noqa: F811
    return _agvp(file_id)


@app.route('/api/video/<int:file_id>/prefs', methods=['POST'])
@login_required
def api_set_video_prefs(file_id):
    from helpers._prefs_settings import api_set_video_prefs as _asvp  # noqa: F811
    return _asvp(file_id)


@app.route('/api/video/prefs/clear', methods=['POST'])
@login_required
def api_clear_video_prefs():
    from helpers._prefs_settings import api_clear_video_prefs as _acvp  # noqa: F811
    return _acvp()


# ── CBZ reader (delegation to helpers) ───────────────────

@app.route('/cbz/<int:file_id>')
@login_required
def cbz_reader(file_id):
    from helpers._cbz_reader import cbz_reader as _cr  # noqa: F811
    return _cr(file_id)


@app.route('/api/cbz/<int:file_id>/image')
@login_required
def api_cbz_image(file_id):
    from helpers._cbz_reader import api_cbz_image as _cimg  # noqa: F811
    return _cimg(file_id)


@app.route('/api/cbz/<int:file_id>/pages')
@login_required
def api_cbz_pages(file_id):
    from helpers._cbz_reader import api_cbz_pages as _cpages  # noqa: F811
    return _cpages(file_id)


@app.route('/api/cbz/<int:file_id>/prefs', methods=['GET'])
@login_required
def api_get_cbz_prefs(file_id):
    from helpers._cbz_reader import api_get_cbz_prefs as _cgcp  # noqa: F811
    return _cgcp(file_id)


@app.route('/api/cbz/<int:file_id>/prefs', methods=['POST'])
@login_required
def api_set_cbz_prefs(file_id):
    from helpers._cbz_reader import api_set_cbz_prefs as _cscp  # noqa: F811
    return _cscp(file_id)


# ── audio cache management ───────────────────────────────────────────

@app.route('/api/audio-cache/<int:file_id>', methods=['GET'])
@login_required
def api_get_audio_cache(file_id):
    from helpers._audio_cache import api_get_audio_cache as _agac  # noqa: F811
    return _agac(file_id)


@app.route('/api/audio-cache/<int:file_id>/clear', methods=['POST'])
@login_required
def api_clear_audio_cache(file_id):
    from helpers._audio_cache import api_clear_audio_cache as _caac  # noqa: F811
    return _caac(file_id)


@app.route('/api/audio-cache/clear-all', methods=['POST'])
@login_required
def api_clear_all_audio_cache():
    from helpers._audio_cache import api_clear_all_audio_cache as _caaac  # noqa: F811
    return _caaac()


@app.route('/api/overwrite-audio/<int:file_id>', methods=['POST'])
@login_required
def api_overwrite_audio(file_id):
    from helpers._reencode_tasks import api_overwrite_audio as _aoa  # noqa: F811
    return _aoa(file_id)


@app.route('/api/reencode-dir/<int:dir_id>', methods=['POST'])
@login_required
def api_reencode_dir(dir_id):
    from helpers._reencode_tasks import api_reencode_dir as _ard  # noqa: F811
    return _ard(dir_id)


@app.route('/api/reencode-status')
@login_required
def api_reencode_status():
    from helpers._reencode_tasks import api_reencode_status as _ars  # noqa: F811
    return _ars()


@app.route('/api/reencode-jobs')
@login_required
def api_reencode_jobs():
    from helpers._reencode_tasks import api_reencode_jobs as _arj  # noqa: F811
    return _arj()


@app.route('/api/reencode-clear', methods=['POST'])
@login_required
def api_reencode_clear():
    from helpers._reencode_tasks import api_reencode_clear as _arc  # noqa: F811
    return _arc()



@app.route('/api/export-keys')
@login_required
def api_export_keys():
    from helpers.app_helpers_users import api_export_keys as _aek  # noqa: F811
    return _aek()
    """Download a .txt file containing encryption info needed to
    restore / transfer the vault data.  Available to any logged-in user."""
    from datetime import datetime

    mk = _get_master_key()
    mk_hex = mk.hex() if mk else '(vault locked — log out and back in)'

    lines = [
        '═══════════════════════════════════════════════════════',
        '  Encrypted Vault — Key Backup',
        f'  Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
        f'  User:      {current_user.username}',
        '═══════════════════════════════════════════════════════',
        '',
        '── Your Master Key ──────────────────────────────────',
        '',
        f'  MASTER_KEY = {mk_hex}',
        '',
        '  This 256-bit AES key encrypts ALL your vault files',
        '  AND the file names / metadata in the database.',
        '  It is normally wrapped (encrypted) by your login',
        '  password — you do NOT need this key for everyday use.',
        '',
        '  ONLY use this key if you need to recover data after',
        '  losing your password, or for programmatic access.',
        '',
        '── How to transfer your vault ──────────────────────',
        '',
        '  1. Copy the entire  data/  folder (vault.db + vault/)',
        '  2. Start the vault server on the new machine',
        '  3. Log in with YOUR SAME PASSWORD — that is all',
        '',
        '  Your password unlocks the master key which is stored',
        '  (encrypted) inside vault.db.  No separate key file',
        '  is needed.',
        '',
        '══════════════════════════════════════════════════════',
        '  KEEP THIS FILE SECRET.  Anyone with the master key',
        '  can decrypt ALL your vault files and read all your',
        '  encrypted file names.  Delete after backing up.',
        '══════════════════════════════════════════════════════',
        '',
    ]
    content = '\n'.join(lines)
    return Response(
        content,
        mimetype='text/plain',
        headers={
            'Content-Disposition': f'attachment; filename="vault-keys-{current_user.username}.txt"',
            'Cache-Control': 'no-store',
        },
    )


@app.route('/users')
@admin_required
def users_page():
    from helpers.app_helpers_users import users_page as _up  # noqa: F811
    return _up()


@app.route('/api/users')
@admin_required
def api_list_users():
    from helpers.app_helpers_users import api_list_users as _alu  # noqa: F811
    return _alu()

@app.route('/api/users/create', methods=['POST'])
@admin_required
def api_create_user():
    from helpers.app_helpers_users import api_create_user as _acu  # noqa: F811
    return _acu()
    """Admin creates a new user.  Each user gets their own independent
    encryption key — the admin cannot access the new user's files."""
    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    is_admin = bool(data.get('is_admin', False))

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    if get_user(username):
        return jsonify({'error': 'Username already exists'}), 409

    # Generate a UNIQUE key for this user (not shared with anyone)
    mk = generate_master_key()
    salt, nonce, enc_key = encrypt_master_key(mk, password)
    try:
        uid = create_user(
            username,
            generate_password_hash(password),
            is_admin=is_admin,
            key_salt=salt,
            key_nonce=nonce,
            key_encrypted=enc_key,
        )
        return jsonify({'id': uid, 'username': username, 'is_admin': is_admin})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 400


@app.route('/api/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def api_delete_user(user_id):
    from helpers.app_helpers_users import api_delete_user as _adu  # noqa: F811
    return _adu(user_id)
    for vf in vault_files:
        p = os.path.join(config.VAULT_DIR, vf)
        if os.path.exists(p):
            os.remove(p)
    _user_keys.pop(user_id, None)
    return jsonify({'success': True})


@app.route('/api/users/<int:user_id>/reset-password', methods=['POST'])
@admin_required
def api_reset_password(user_id):
    from helpers.app_helpers_users import api_reset_password as _arp  # noqa: F811
    return _arp(user_id)
    """Admin resets a user's password; re-wraps that user's own key."""
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    row = get_user_by_id(user_id)
    if not row:
        return jsonify({'error': 'User not found'}), 404

    # We need the user's key in RAM to re-wrap it.  If that user is
    # currently logged in we can use it; otherwise we can't reset.
    entry = _user_keys.get(user_id)
    if entry is None:
        return jsonify({'error': 'That user must be logged in (key in RAM) to reset their password. '
                        'Ask them to log in first, or they can change their own password.'}), 409

    mk = entry[0]
    salt, nonce, enc_key = encrypt_master_key(mk, password)
    update_user_password(user_id, generate_password_hash(password),
                         salt, nonce, enc_key)
    # Evict their cached key so they must re-login with new password
    _user_keys.pop(user_id, None)
    return jsonify({'success': True})


@app.route('/api/users/<int:user_id>/toggle-admin', methods=['POST'])
@admin_required
def api_toggle_admin(user_id):
    from helpers.app_helpers_users import api_toggle_admin as _ata  # noqa: F811
    return _ata(user_id)
    if user_id == current_user.id:
        return jsonify({'error': 'Cannot change your own admin status'}), 400
    row = get_user_by_id(user_id)
    if not row:
        return jsonify({'error': 'User not found'}), 404
    new_val = not bool(row['is_admin'])
    set_user_admin(user_id, new_val)
    return jsonify({'success': True, 'is_admin': new_val})


@app.route('/api/change-password', methods=['POST'])
@login_required
def api_change_password():
    from helpers.app_helpers_users import api_change_password as _acpw  # noqa: F811
    return _acpw()
    data = request.get_json(silent=True) or {}
    current_pw = data.get('current_password', '')
    new_pw = data.get('new_password', '')

    if len(new_pw) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    row = get_user_by_id(current_user.id)
    if not row or not check_password_hash(row['password_hash'], current_pw):
        return jsonify({'error': 'Current password is incorrect'}), 403

    mk = _get_master_key()
    if mk is None:
        return jsonify({'error': 'Vault is locked'}), 403

    salt, nonce, enc_key = encrypt_master_key(mk, new_pw)
    update_user_password(current_user.id, generate_password_hash(new_pw),
                         salt, nonce, enc_key)
    # Update in-memory key wrapping
    _user_keys[current_user.id] = (mk, ChunkEncryptor(mk, config.CHUNK_SIZE))
    return jsonify({'success': True})


# ── HLS streaming API (on-demand, Jellyfin-style) ───────────────────

def _get_or_start_session(file_id):
    """Helper: get/create an HLS session for file_id, or abort."""
    enc = _get_encryptor()
    if enc is None:
        abort(403)
    f = get_file(file_id, current_user.id, key=_get_master_key())
    if not f or f['is_directory']:
        abort(404)
    if not (f['mime_type'] or '').startswith('video/'):
        abort(400)
    mk = _get_master_key()
    prefs = get_user_preferences(current_user.id, key=mk)
    audio_lang = (prefs.get('default_audio_lang') or '').strip().lower()
    cache_mode = (prefs.get('audio_cache_mode') or 'keep').strip().lower()
    if cache_mode not in ('keep', 'save', 'overwrite'):
        cache_mode = 'keep'

    # Always load cached audio tracks — use them regardless of mode
    cached_tracks = get_audio_cache_info(file_id) or None

    # Overwrite callback to update file size in DB after re-mux
    overwrite_cb = None
    if cache_mode == 'overwrite':
        uid = current_user.id
        fid = file_id

        def overwrite_cb(new_size):
            from models import get_db, _encrypt_value, encrypt_field
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            db = get_db()
            db.execute(
                'UPDATE files SET size = ?, modified_at = ? '
                'WHERE id = ? AND owner_id = ?',
                (_encrypt_value(mk, new_size),
                 encrypt_field(mk, now),
                 fid, uid))
            db.commit()
            db.close()

    sess = get_session(file_id, encryptor=enc,
                       vault_filename=f['vault_filename'],
                       preferred_audio_lang=audio_lang,
                       cache_mode=cache_mode,
                       cached_tracks=cached_tracks,
                       overwrite_callback=overwrite_cb)
    if sess is None:
        abort(500)
    return sess


@app.route('/api/hls/<int:file_id>/status')
@login_required
def api_hls_status(file_id):
    from helpers.app_helpers_hls import api_hls_status as _hls_st  # noqa: F811
    return _hls_st(file_id)


@app.route('/api/hls/<int:file_id>/master.m3u8')
@login_required
def api_hls_master(file_id):
    from helpers.app_helpers_hls import api_hls_master as _hls_m  # noqa: F811
    return _hls_m(file_id)


@app.route('/api/hls/<int:file_id>/video/playlist.m3u8')
@login_required
def api_hls_video_playlist(file_id):
    from helpers.app_helpers_hls import api_hls_video_playlist as _hls_vp  # noqa: F811
    return _hls_vp(file_id)


@app.route('/api/hls/<int:file_id>/audio/<int:track>/playlist.m3u8')
@login_required
def api_hls_audio_playlist(file_id, track):
    from helpers.app_helpers_hls import api_hls_audio_playlist as _hls_ap  # noqa: F811
    return _hls_ap(file_id, track)


@app.route('/api/hls/<int:file_id>/subtitle/<int:track>/playlist.m3u8')
@login_required
def api_hls_subtitle_playlist(file_id, track):
    from helpers.app_helpers_hls import api_hls_subtitle_playlist as _hls_sp  # noqa: F811
    return _hls_sp(file_id, track)


@app.route('/api/hls/<int:file_id>/<stream>/<int:track>/segment/<int:seg_index>.ts')
@login_required
def api_hls_segment(file_id, stream, track, seg_index):
    from helpers.app_helpers_hls import api_hls_segment as _hls_sg  # noqa: F811
    return _hls_sg(file_id, stream, track, seg_index)


@app.route('/api/hls/<int:file_id>/subtitle/<int:track>/file.vtt')
@login_required
def api_hls_subtitle_file(file_id, track):
    from helpers.app_helpers_hls import api_hls_subtitle_file as _hls_sf  # noqa: F811
    return _hls_sf(file_id, track)


@app.route('/api/hls/<int:file_id>/tracks')
@login_required
def api_hls_tracks(file_id):
    from helpers.app_helpers_hls import api_hls_tracks as _hls_tr  # noqa: F811
    return _hls_tr(file_id)


# ── app factory ──────────────────────────────────────────────────────
def create_app():
    os.makedirs(config.DATA_DIR, exist_ok=True)
    os.makedirs(config.VAULT_DIR, exist_ok=True)
    init_db()

    secret = get_config('flask_secret')
    app.secret_key = secret if secret else os.urandom(32)
    logger.info('Vault server starting on %s:%s', config.HOST, config.PORT)
    return app
