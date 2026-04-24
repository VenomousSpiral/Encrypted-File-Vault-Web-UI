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
import zipfile
from functools import wraps

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
@app.route('/')
@login_required
def explorer():
    mk = _get_master_key()
    prefs = get_user_preferences(current_user.id, key=mk)
    return render_template('explorer.html', sort_preference=prefs.get('sort_preference', 'name'))


# ── JSON API ─────────────────────────────────────────────────────────
@app.route('/api/files')
@login_required
def api_list_files():
    parent_id = request.args.get('parent_id', None, type=int)
    uid = current_user.id
    mk = _get_master_key()
    rows = list_files(uid, parent_id, key=mk)

    # Attach last_accessed from video_preferences for sort support
    accessed_map = get_all_video_last_accessed(uid, key=mk)

    file_list = []
    for r in rows:
        d = dict(r)
        d['last_accessed'] = accessed_map.get(d['id'], '')
        file_list.append(d)

    crumbs = get_breadcrumbs(uid, parent_id, key=mk)
    return jsonify({
        'files': file_list,
        'breadcrumbs': crumbs,
        'parent_id': parent_id,
    })


@app.route('/api/search')
@login_required
def api_search_files():
    query = request.args.get('q', '').strip()
    if not query or len(query) < 1:
        return jsonify({'files': []})
    uid = current_user.id
    mk = _get_master_key()
    # parent_id scopes search to a specific folder; None = root; 'all' = global
    raw_pid = request.args.get('parent_id', None)
    if raw_pid is None:
        parent_id = None          # root
    elif raw_pid == 'all':
        parent_id = 'all'         # global search (not currently used by UI)
    else:
        try:
            parent_id = int(raw_pid)
        except ValueError:
            parent_id = None
    results = search_files(uid, query, parent_id=parent_id, key=mk)

    # Attach last_accessed from encrypted video_preferences
    accessed_map = get_all_video_last_accessed(uid, key=mk)

    file_list = []
    for r in results:
        d = dict(r) if not isinstance(r, dict) else r
        d['last_accessed'] = accessed_map.get(d['id'], '')
        file_list.append(d)

    return jsonify({'files': file_list})


@app.route('/api/folders')
@login_required
def api_list_folders():
    parent_id = request.args.get('parent_id', None, type=int)
    return jsonify({'folders': get_folders(current_user.id, parent_id, key=_get_master_key()), 'parent_id': parent_id})


@app.route('/api/folder-breadcrumbs/<int:folder_id>')
@login_required
def api_folder_breadcrumbs(folder_id):
    """Get breadcrumb path to a folder (all ancestors including it)."""
    try:
        breadcrumbs = get_breadcrumbs(current_user.id, folder_id, key=_get_master_key())
        return jsonify({'breadcrumbs': breadcrumbs})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 400


@app.route('/api/folder/<int:folder_id>/parent')
@login_required
def api_get_folder_parent(folder_id):
    """Get parent folder ID for a given folder (for 'up' navigation)."""
    info = get_folder_info(folder_id, current_user.id, key=_get_master_key())
    if not info:
        return jsonify({'error': 'Folder not found'}), 404
    return jsonify({'parent_id': info['parent_id']})


@app.route('/api/mkdir', methods=['POST'])
@login_required
def api_mkdir():
    data = request.get_json(silent=True) or {}
    name = data.get('name', '').strip()
    parent_id = data.get('parent_id')

    if not name:
        return jsonify({'error': 'Name is required'}), 400
    if '/' in name or '\\' in name:
        return jsonify({'error': 'Name cannot contain slashes'}), 400
    try:
        fid = create_file_record(current_user.id, parent_id, name, True, key=_get_master_key())
        return jsonify({'id': fid, 'name': name})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 400


@app.route('/api/mkdirp', methods=['POST'])
@login_required
def api_mkdirp():
    """Create a directory if it doesn't already exist (mkdir -p style).
    Returns the folder's id whether it was just created or already existed."""
    data = request.get_json(silent=True) or {}
    name = data.get('name', '').strip()
    parent_id = data.get('parent_id')

    if not name:
        return jsonify({'error': 'Name is required'}), 400
    if '/' in name or '\\' in name:
        return jsonify({'error': 'Name cannot contain slashes'}), 400

    mk = _get_master_key()
    # Check if folder already exists
    existing = get_file_by_name(current_user.id, parent_id, name, key=mk)
    if existing and existing['is_directory']:
        return jsonify({'id': existing['id'], 'name': name})

    try:
        fid = create_file_record(current_user.id, parent_id, name, True, key=mk)
        return jsonify({'id': fid, 'name': name})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 400


@app.route('/api/upload', methods=['POST'])
@login_required
def api_upload():
    enc = _get_encryptor()
    if enc is None:
        return jsonify({'error': 'Vault is locked'}), 403

    parent_id = request.form.get('parent_id', None, type=int)
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    uploaded = request.files['file']
    if not uploaded.filename:
        return jsonify({'error': 'Empty filename'}), 400

    # Strip any folder path the browser may include (e.g. folder uploads)
    filename = os.path.basename(uploaded.filename)
    mime = (uploaded.content_type
            or mimetypes.guess_type(filename)[0]
            or 'application/octet-stream')

    # Actual file size (werkzeug stores large files on disk, seek is fine)
    uploaded.seek(0, 2)
    file_size = uploaded.tell()
    uploaded.seek(0)

    # Auto-rename on conflict: file.mp4 → file (1).mp4
    base_name = filename
    base, ext = os.path.splitext(filename)
    counter = 1
    mk = _get_master_key()
    while get_file_by_name(current_user.id, parent_id, filename, key=mk):
        filename = f'{base} ({counter}){ext}'
        counter += 1

    vault_name = str(uuid.uuid4()) + '.enc'
    vault_path = os.path.join(config.VAULT_DIR, vault_name)

    try:
        enc.encrypt_stream(uploaded, vault_path, file_size)
        fid = create_file_record(current_user.id, parent_id, filename, False,
                                 vault_name, file_size, mime, key=mk)
        return jsonify({'id': fid, 'name': filename,
                        'size': file_size, 'mime_type': mime})
    except Exception as exc:
        if os.path.exists(vault_path):
            os.remove(vault_path)
        return jsonify({'error': str(exc)}), 500


@app.route('/api/rename', methods=['POST'])
@login_required
def api_rename():
    data = request.get_json(silent=True) or {}
    fid = data.get('id')
    new_name = data.get('name', '').strip()
    if not fid or not new_name:
        return jsonify({'error': 'ID and name required'}), 400
    if '/' in new_name or '\\' in new_name:
        return jsonify({'error': 'Name cannot contain slashes'}), 400
    # Verify ownership
    f = get_file(fid, current_user.id, key=_get_master_key())
    if not f:
        return jsonify({'error': 'Not found'}), 404
    try:
        rename_file(fid, new_name, key=_get_master_key())
        return jsonify({'success': True})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 400


@app.route('/api/move', methods=['POST'])
@login_required
def api_move():
    data = request.get_json(silent=True) or {}
    fid = data.get('id')
    new_parent = data.get('parent_id')      # None ⇒ root
    if fid is None:
        return jsonify({'error': 'File ID required'}), 400
    # Verify ownership
    f = get_file(fid, current_user.id, key=_get_master_key())
    if not f:
        return jsonify({'error': 'Not found'}), 404
    try:
        move_file(fid, new_parent, key=_get_master_key())
        return jsonify({'success': True})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 400


@app.route('/api/delete', methods=['POST'])
@login_required
def api_delete():
    data = request.get_json(silent=True) or {}
    fid = data.get('id')
    if fid is None:
        return jsonify({'error': 'File ID required'}), 400

    vault_files = delete_file_record(fid, current_user.id)
    destroy_session(fid)          # kill any active HLS session
    for vf in vault_files:
        p = os.path.join(config.VAULT_DIR, vf)
        if os.path.exists(p):
            os.remove(p)
    return jsonify({'success': True})


@app.route('/api/bulk-delete', methods=['POST'])
@login_required
def api_bulk_delete():
    data = request.get_json(silent=True) or {}
    ids = data.get('ids', [])
    if not ids or not isinstance(ids, list):
        return jsonify({'error': 'ids array required'}), 400
    deleted = 0
    for fid in ids:
        try:
            vault_files = delete_file_record(fid, current_user.id)
            destroy_session(fid)
            for vf in vault_files:
                p = os.path.join(config.VAULT_DIR, vf)
                if os.path.exists(p):
                    os.remove(p)
            deleted += 1
        except Exception:
            pass
    return jsonify({'success': True, 'deleted': deleted})


@app.route('/api/bulk-move', methods=['POST'])
@login_required
def api_bulk_move():
    data = request.get_json(silent=True) or {}
    ids = data.get('ids', [])
    new_parent = data.get('parent_id')      # None ⇒ root
    if not ids or not isinstance(ids, list):
        return jsonify({'error': 'ids array required'}), 400
    mk = _get_master_key()
    moved = 0
    for fid in ids:
        f = get_file(fid, current_user.id, key=mk)
        if not f:
            continue
        try:
            move_file(fid, new_parent, key=mk)
            moved += 1
        except Exception:
            pass
    return jsonify({'success': True, 'moved': moved})


@app.route('/api/file/<int:file_id>/info')
@login_required
def api_file_info(file_id):
    f = get_file(file_id, current_user.id, key=_get_master_key())
    if not f:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(dict(f))


# ── streaming / download ────────────────────────────────────────────
@app.route('/stream/<int:file_id>')
@login_required
def stream_file(file_id):
    """Stream a decrypted file.  Supports HTTP Range for video seeking."""
    enc = _get_encryptor()
    if enc is None:
        abort(403)

    f = get_file(file_id, current_user.id, key=_get_master_key())
    if not f or f['is_directory']:
        abort(404)

    vault_path = os.path.join(config.VAULT_DIR, f['vault_filename'])
    if not os.path.exists(vault_path):
        abort(404)

    file_size = f['size']
    mime = f['mime_type'] or 'application/octet-stream'
    range_header = request.headers.get('Range')

    logger.debug('Stream file %d (%s, %d B), Range: %s',
                 file_id, mime, file_size, range_header)

    if range_header:
        # Parse "bytes=START-END" or "bytes=START-"
        rng = range_header.replace('bytes=', '').strip()
        parts = rng.split('-', 1)
        byte_start = int(parts[0]) if parts[0] else 0
        byte_end = int(parts[1]) if parts[1] else file_size - 1
        byte_end = min(byte_end, file_size - 1)
        length = byte_end - byte_start + 1

        resp = Response(
            enc.decrypt_range(vault_path, byte_start, byte_end),
            status=206,
            mimetype=mime,
            direct_passthrough=True,
        )
        resp.headers['Content-Range'] = f'bytes {byte_start}-{byte_end}/{file_size}'
        resp.headers['Content-Length'] = length
        resp.headers['Accept-Ranges'] = 'bytes'
        resp.headers['Cache-Control'] = 'no-cache'
        return resp

    # No Range → stream entire file
    resp = Response(
        enc.decrypt_full(vault_path),
        status=200,
        mimetype=mime,
        direct_passthrough=True,
    )
    resp.headers['Content-Length'] = file_size
    resp.headers['Accept-Ranges'] = 'bytes'
    resp.headers['Cache-Control'] = 'no-cache'
    return resp


@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    """Like stream but forces a download via Content-Disposition."""
    enc = _get_encryptor()
    if enc is None:
        abort(403)

    f = get_file(file_id, current_user.id, key=_get_master_key())
    if not f or f['is_directory']:
        abort(404)

    vault_path = os.path.join(config.VAULT_DIR, f['vault_filename'])
    if not os.path.exists(vault_path):
        abort(404)

    resp = Response(
        enc.decrypt_full(vault_path),
        mimetype=f['mime_type'] or 'application/octet-stream',
        direct_passthrough=True,
    )
    safe_name = f['name'].replace('"', '\\"')
    resp.headers['Content-Disposition'] = f'attachment; filename="{safe_name}"'
    resp.headers['Content-Length'] = f['size']
    return resp


@app.route('/download-folder/<int:folder_id>')
@login_required
def download_folder(folder_id):
    """Download an entire folder as a streamed ZIP archive."""
    enc = _get_encryptor()
    if enc is None:
        abort(403)

    mk = _get_master_key()
    owner_id = current_user.id
    folder = get_file(folder_id, owner_id, key=mk)
    if not folder or not folder['is_directory']:
        abort(404)

    def _collect_files(parent_id, prefix):
        """Recursively collect (zip_path, file_record) tuples."""
        items = list_files(owner_id, parent_id, key=mk)
        for item in items:
            path = prefix + item['name']
            if item['is_directory']:
                yield from _collect_files(item['id'], path + '/')
            else:
                yield (path, item)

    def _generate_zip():
        """Stream a ZIP file, writing decrypted files on the fly."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            for zip_path, item in _collect_files(folder_id, ''):
                vault_path = os.path.join(config.VAULT_DIR, item['vault_filename'])
                if not os.path.exists(vault_path):
                    continue
                # Decrypt the entire file into memory and add to zip
                data = b''.join(enc.decrypt_full(vault_path))
                zf.writestr(zip_path, data)
        buf.seek(0)
        while True:
            chunk = buf.read(65536)
            if not chunk:
                break
            yield chunk

    safe_name = folder['name'].replace('"', '\\"')
    resp = Response(
        _generate_zip(),
        mimetype='application/zip',
        direct_passthrough=True,
    )
    resp.headers['Content-Disposition'] = f'attachment; filename="{safe_name}.zip"'
    return resp


import random as _random


# ── media player page ────────────────────────────────────────────────
@app.route('/player/<int:file_id>')
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
    """Return prev/next file IDs and recursive total for same-type files.

    Accepts optional ?root=<parent_id> (or 'null' for vault root) to
    compute the recursive total from a specific ancestor directory
    instead of the file's immediate parent.
    """
    uid = current_user.id
    mk = _get_master_key()
    f = get_file(file_id, uid, key=mk)
    if not f:
        return jsonify({'error': 'Not found'}), 404

    cat = _media_category(f.get('mime_type'))

    # Sequential prev/next among direct siblings in the same folder
    siblings = list_files(uid, f['parent_id'], key=mk)
    typed = [s for s in siblings if not s['is_directory'] and _media_category(s.get('mime_type')) == cat]
    typed.sort(key=lambda d: (d.get('name') or '').lower())

    ids = [s['id'] for s in typed]
    try:
        idx = ids.index(file_id)
    except ValueError:
        idx = -1

    prev_id = ids[idx - 1] if idx > 0 else None
    next_id = ids[idx + 1] if idx >= 0 and idx < len(ids) - 1 else None

    # Use explicit root if provided, otherwise file's parent
    root_raw = request.args.get('root', None)
    if root_raw is not None:
        root_id = None if root_raw in ('null', '') else int(root_raw)
    else:
        root_id = f['parent_id']

    # Recursive total from the root directory
    all_recursive = _collect_recursive(uid, root_id, cat, mk)
    all_recursive.sort(key=lambda d: (d.get('name') or '').lower())
    rec_ids = [s['id'] for s in all_recursive]
    try:
        rec_idx = rec_ids.index(file_id)
    except ValueError:
        rec_idx = -1

    return jsonify({
        'prev_id': prev_id,
        'next_id': next_id,
        'total': len(rec_ids),
        'position': rec_idx + 1 if rec_idx >= 0 else 0,
        'root_parent_id': root_id,
    })


@app.route('/api/random-sibling/<int:file_id>')
@login_required
def api_random_sibling(file_id):
    """Return a random file of the same type from a directory tree.

    Accepts optional ?root=<parent_id> to anchor the search to the
    original browsing directory, not the current file's parent.
    """
    uid = current_user.id
    mk = _get_master_key()
    f = get_file(file_id, uid, key=mk)
    if not f:
        return jsonify({'error': 'Not found'}), 404

    cat = _media_category(f.get('mime_type'))

    # Use explicit root if provided, otherwise fall back to file's parent
    root_raw = request.args.get('root', None)
    if root_raw is not None:
        root_id = None if root_raw in ('null', '') else int(root_raw)
    else:
        root_id = f['parent_id']

    candidates = _collect_recursive(uid, root_id, cat, mk, exclude_id=file_id)
    if not candidates:
        return jsonify({'file_id': None})

    chosen = _random.choice(candidates)
    return jsonify({'file_id': chosen['id']})


# ── text editor ──────────────────────────────────────────────────────

# MIME types and extensions considered "text-editable"
_TEXT_MIMES = {
    'application/json', 'application/xml', 'application/javascript',
    'application/x-yaml', 'application/yaml', 'application/toml',
    'application/x-sh', 'application/x-shellscript',
    'application/sql', 'application/xhtml+xml',
    'application/x-httpd-php',
}
_TEXT_EXTS = {
    '.txt', '.md', '.markdown', '.json', '.yaml', '.yml', '.toml',
    '.xml', '.html', '.htm', '.css', '.js', '.ts', '.jsx', '.tsx',
    '.py', '.rb', '.rs', '.go', '.java', '.c', '.cpp', '.h', '.hpp',
    '.cs', '.sh', '.bash', '.zsh', '.fish', '.bat', '.ps1',
    '.sql', '.ini', '.cfg', '.conf', '.env', '.gitignore',
    '.dockerfile', '.makefile', '.cmake', '.gradle',
    '.lua', '.pl', '.php', '.r', '.swift', '.kt', '.scala',
    '.log', '.csv', '.tsv', '.rst', '.tex', '.srt', '.vtt', '.sub',
    '.svg',
}


def _is_text_editable(f):
    """Return True if the file should open in the text editor."""
    mime = (f.get('mime_type') or f.get('mime') or '').lower()
    if mime.startswith('text/'):
        return True
    if mime in _TEXT_MIMES:
        return True
    name = (f.get('name') or '').lower()
    _, ext = os.path.splitext(name)
    if ext in _TEXT_EXTS:
        return True
    # Dockerfile, Makefile etc. (no extension)
    base = os.path.basename(name)
    if base in ('dockerfile', 'makefile', 'cmakelists.txt', 'vagrantfile',
                'gemfile', 'rakefile', 'procfile'):
        return True
    return False


@app.route('/editor/<int:file_id>')
@login_required
def editor(file_id):
    f = get_file(file_id, current_user.id, key=_get_master_key())
    if not f or f['is_directory']:
        abort(404)
    # Touch last_accessed
    set_video_preferences(current_user.id, file_id, key=_get_master_key())
    return render_template('editor.html', file=dict(f))


@app.route('/api/file/<int:file_id>/text')
@login_required
def api_read_text(file_id):
    """Return the full decrypted text content of a file."""
    enc = _get_encryptor()
    if enc is None:
        return jsonify({'error': 'Vault is locked'}), 403
    f = get_file(file_id, current_user.id, key=_get_master_key())
    if not f or f['is_directory']:
        return jsonify({'error': 'Not found'}), 404
    vault_path = os.path.join(config.VAULT_DIR, f['vault_filename'])
    if not os.path.exists(vault_path):
        return jsonify({'error': 'File missing from vault'}), 404
    try:
        chunks = []
        for chunk in enc.decrypt_full(vault_path):
            chunks.append(chunk)
        content = b''.join(chunks).decode('utf-8', errors='replace')
        return jsonify({'content': content})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


@app.route('/api/file/<int:file_id>/text', methods=['POST'])
@login_required
def api_write_text(file_id):
    """Save new text content back to the vault (re-encrypt)."""
    enc = _get_encryptor()
    if enc is None:
        return jsonify({'error': 'Vault is locked'}), 403
    f = get_file(file_id, current_user.id, key=_get_master_key())
    if not f or f['is_directory']:
        return jsonify({'error': 'Not found'}), 404

    data = request.get_json(silent=True) or {}
    content = data.get('content', '')
    content_bytes = content.encode('utf-8')
    file_size = len(content_bytes)

    # Write to a new vault file, then swap
    new_vault_name = str(uuid.uuid4()) + '.enc'
    new_vault_path = os.path.join(config.VAULT_DIR, new_vault_name)
    old_vault_path = os.path.join(config.VAULT_DIR, f['vault_filename'])

    try:
        enc.encrypt_stream(io.BytesIO(content_bytes), new_vault_path, file_size)
        # Update DB record with new vault filename and size
        from models import get_db
        db = get_db()
        db.execute(
            'UPDATE files SET vault_filename = ?, size = ?, modified_at = datetime("now") WHERE id = ? AND owner_id = ?',
            (new_vault_name, file_size, file_id, current_user.id),
        )
        db.commit()
        db.close()
        # Remove old vault file
        if os.path.exists(old_vault_path):
            os.remove(old_vault_path)
        return jsonify({'success': True, 'size': file_size})
    except Exception as exc:
        if os.path.exists(new_vault_path):
            os.remove(new_vault_path)
        return jsonify({'error': str(exc)}), 500


@app.route('/api/create-text', methods=['POST'])
@login_required
def api_create_text():
    """Create a new empty text file."""
    enc = _get_encryptor()
    if enc is None:
        return jsonify({'error': 'Vault is locked'}), 403

    data = request.get_json(silent=True) or {}
    name = data.get('name', '').strip()
    parent_id = data.get('parent_id')

    if not name:
        return jsonify({'error': 'Name is required'}), 400
    if '/' in name or '\\' in name:
        return jsonify({'error': 'Name cannot contain slashes'}), 400

    # Ensure it has an extension, default to .txt
    _, ext = os.path.splitext(name)
    if not ext:
        name += '.txt'

    mk = _get_master_key()
    # Auto-rename on conflict
    base_name = name
    base, ext = os.path.splitext(name)
    counter = 1
    while get_file_by_name(current_user.id, parent_id, name, key=mk):
        name = f'{base} ({counter}){ext}'
        counter += 1

    mime = mimetypes.guess_type(name)[0] or 'text/plain'
    content_bytes = b''
    file_size = 0

    vault_name = str(uuid.uuid4()) + '.enc'
    vault_path = os.path.join(config.VAULT_DIR, vault_name)

    try:
        enc.encrypt_stream(io.BytesIO(content_bytes), vault_path, file_size)
        fid = create_file_record(current_user.id, parent_id, name, False,
                                 vault_name, file_size, mime, key=mk)
        return jsonify({'id': fid, 'name': name, 'size': file_size, 'mime_type': mime})
    except Exception as exc:
        if os.path.exists(vault_path):
            os.remove(vault_path)
        return jsonify({'error': str(exc)}), 500


@app.route('/api/file/<int:file_id>/editable')
@login_required
def api_is_editable(file_id):
    """Check if a file should open in the text editor."""
    f = get_file(file_id, current_user.id, key=_get_master_key())
    if not f:
        return jsonify({'editable': False})
    return jsonify({'editable': _is_text_editable(dict(f))})


# ── user settings / preferences ──────────────────────────────────────
@app.route('/settings')
@login_required
def settings_page():
    prefs = get_user_preferences(current_user.id, key=_get_master_key())
    return render_template('settings.html', prefs=prefs)


@app.route('/api/preferences', methods=['GET'])
@login_required
def api_get_preferences():
    mk = _get_master_key()
    return jsonify(get_user_preferences(current_user.id, key=mk))


@app.route('/api/preferences', methods=['POST'])
@login_required
def api_set_preferences():
    mk = _get_master_key()
    data = request.get_json(silent=True) or {}
    current = get_user_preferences(current_user.id, key=mk)
    audio_lang = data.get('default_audio_lang', current['default_audio_lang']).strip()
    sub_lang = data.get('default_subtitle_lang', current['default_subtitle_lang']).strip()
    sub_offset = float(data.get('default_subtitle_offset', current['default_subtitle_offset']))
    skip_amt = int(data.get('skip_amount', current['skip_amount']))
    sort_pref = data.get('sort_preference', current['sort_preference']).strip()
    if sort_pref not in ('name', 'recent', 'added', 'size'):
        sort_pref = 'name'
    cache_mode = data.get('audio_cache_mode', current.get('audio_cache_mode', 'keep')).strip().lower()
    if cache_mode not in ('keep', 'save', 'overwrite'):
        cache_mode = 'keep'
    set_user_preferences(current_user.id, audio_lang, sub_lang, sub_offset,
                         skip_amt, sort_pref, cache_mode, key=mk)
    return jsonify({'success': True})


@app.route('/api/video/<int:file_id>/prefs', methods=['GET'])
@login_required
def api_get_video_prefs(file_id):
    f = get_file(file_id, current_user.id, key=_get_master_key())
    if not f:
        abort(404)
    mk = _get_master_key()
    return jsonify(get_video_preferences(current_user.id, file_id, key=mk))


@app.route('/api/video/<int:file_id>/prefs', methods=['POST'])
@login_required
def api_set_video_prefs(file_id):
    mk = _get_master_key()
    f = get_file(file_id, current_user.id, key=mk)
    if not f:
        abort(404)
    data = request.get_json(silent=True) or {}
    allowed = {}
    if 'position' in data:  allowed['position']  = float(data['position'])
    if 'sub_offset' in data: allowed['sub_offset'] = float(data['sub_offset'])
    if allowed:
        set_video_preferences(current_user.id, file_id, key=mk, **allowed)
    return jsonify({'success': True})


@app.route('/api/video/prefs/clear', methods=['POST'])
@login_required
def api_clear_video_prefs():
    count = clear_all_video_preferences(current_user.id)
    return jsonify({'success': True, 'cleared': count})


# ── CBZ reader ───────────────────────────────────────────────────────

@app.route('/cbz/<int:file_id>')
@login_required
def cbz_reader(file_id):
    """CBZ reader page."""
    mk = _get_master_key()
    f = get_file(file_id, current_user.id, key=mk)
    if not f or f['is_directory']:
        abort(404)
    # Touch last_accessed (video_preferences tracks last_accessed used by "recent" sort)
    set_video_preferences(current_user.id, file_id, key=mk)
    cbz_prefs = get_cbz_preferences(current_user.id, file_id, key=mk)
    return render_template('cbz.html', file=dict(f), cbz_prefs=cbz_prefs)


@app.route('/api/cbz/<int:file_id>/image')
@login_required
def api_cbz_image(file_id):
    """Extract and serve a single page image from a CBZ file.
    The image is decrypted on-the-fly from the vault."""
    enc = _get_encryptor()
    if enc is None:
        return jsonify({'error': 'Vault is locked'}), 403

    f = get_file(file_id, current_user.id, key=_get_master_key())
    if not f or f['is_directory']:
        return jsonify({'error': 'Not found'}), 404

    vault_path = os.path.join(config.VAULT_DIR, f['vault_filename'])
    if not os.path.exists(vault_path):
        return jsonify({'error': 'File missing from vault'}), 404

    page = request.args.get('page', 0, type=int)
    if page < 0:
        return jsonify({'error': 'Invalid page'}), 400

    import zipfile
    import io

    # Decrypt entire CBZ into RAM, then extract the requested page
    decrypted = io.BytesIO()
    for chunk in enc.decrypt_full(vault_path):
        decrypted.write(chunk)
    decrypted.seek(0)

    with zipfile.ZipFile(decrypted, 'r') as zf:
        all_files = zf.namelist()
        image_exts = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tiff'}
        image_files = sorted(
            [n for n in all_files if os.path.splitext(n)[1].lower() in image_exts],
            key=lambda n: n.lower()
        )

        if page >= len(image_files):
            return jsonify({'error': 'Page not found'}), 404

        image_data = zf.read(image_files[page])
        ext = os.path.splitext(image_files[page])[1].lower()
        mime_map = {
            '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
            '.png': 'image/png', '.gif': 'image/gif',
            '.webp': 'image/webp', '.bmp': 'image/bmp',
            '.tiff': 'image/tiff', '.tif': 'image/tiff',
        }
        mime = mime_map.get(ext, 'image/jpeg')

    return Response(image_data, mimetype=mime)


@app.route('/api/cbz/<int:file_id>/pages')
@login_required
def api_cbz_pages(file_id):
    """Return total number of pages in a CBZ file."""
    enc = _get_encryptor()
    if enc is None:
        return jsonify({'error': 'Vault is locked'}), 403

    f = get_file(file_id, current_user.id, key=_get_master_key())
    if not f or f['is_directory']:
        return jsonify({'error': 'Not found'}), 404

    vault_path = os.path.join(config.VAULT_DIR, f['vault_filename'])
    if not os.path.exists(vault_path):
        return jsonify({'error': 'File missing from vault'}), 404

    import zipfile
    import io

    # Decrypt entire CBZ into RAM
    decrypted = io.BytesIO()
    for chunk in enc.decrypt_full(vault_path):
        decrypted.write(chunk)
    decrypted.seek(0)

    with zipfile.ZipFile(decrypted, 'r') as zf:
        image_exts = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tiff'}
        image_files = sorted(
            [n for n in zf.namelist() if os.path.splitext(n)[1].lower() in image_exts],
            key=lambda n: n.lower()
        )

    return jsonify({'pages': len(image_files)})


@app.route('/api/cbz/<int:file_id>/prefs', methods=['GET'])
@login_required
def api_get_cbz_prefs(file_id):
    f = get_file(file_id, current_user.id, key=_get_master_key())
    if not f:
        abort(404)
    mk = _get_master_key()
    return jsonify(get_cbz_preferences(current_user.id, file_id, key=mk))


@app.route('/api/cbz/<int:file_id>/prefs', methods=['POST'])
@login_required
def api_set_cbz_prefs(file_id):
    mk = _get_master_key()
    f = get_file(file_id, current_user.id, key=mk)
    if not f:
        abort(404)
    data = request.get_json(silent=True) or {}
    allowed = {}
    if 'page' in data:
        allowed['page'] = int(data['page'])
    if allowed:
        set_cbz_preferences(current_user.id, file_id, key=mk, **allowed)
    return jsonify({'success': True})


# ── audio cache management ───────────────────────────────────────────

@app.route('/api/audio-cache/<int:file_id>', methods=['GET'])
@login_required
def api_get_audio_cache(file_id):
    """Return whether this file has cached audio tracks."""
    f = get_file(file_id, current_user.id, key=_get_master_key())
    if not f:
        abort(404)
    cached = get_audio_cache_info(file_id)
    return jsonify({'has_cache': bool(cached),
                    'cached_tracks': list(cached.keys())})


@app.route('/api/audio-cache/<int:file_id>/clear', methods=['POST'])
@login_required
def api_clear_audio_cache(file_id):
    """Delete all cached audio for a specific file."""
    f = get_file(file_id, current_user.id, key=_get_master_key())
    if not f:
        abort(404)
    vault_files = clear_audio_cache(file_id)
    # Delete the encrypted cache files from disk
    for vf in vault_files:
        try:
            p = os.path.join(config.VAULT_DIR, vf)
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass
    return jsonify({'success': True, 'cleared': len(vault_files)})


@app.route('/api/audio-cache/clear-all', methods=['POST'])
@login_required
def api_clear_all_audio_cache():
    """Delete all cached audio for all files owned by the current user."""
    from models import get_db
    db = get_db()
    rows = db.execute(
        'SELECT ac.id, ac.vault_filename FROM audio_cache ac '
        'JOIN files f ON ac.file_id = f.id '
        'WHERE f.owner_id = ?', (current_user.id,)
    ).fetchall()
    vault_files = [r['vault_filename'] for r in rows]
    ids = [r['id'] for r in rows]
    if ids:
        db.execute(
            f'DELETE FROM audio_cache WHERE id IN ({",".join("?" * len(ids))})',
            ids)
        db.commit()
    db.close()
    for vf in vault_files:
        try:
            p = os.path.join(config.VAULT_DIR, vf)
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass
    return jsonify({'success': True, 'cleared': len(vault_files)})


@app.route('/api/overwrite-audio/<int:file_id>', methods=['POST'])
@login_required
def api_overwrite_audio(file_id):
    """Re-encode a video to H.264 8-bit + AAC stereo for browser playback."""
    enc = _get_encryptor()
    if enc is None:
        return jsonify({'success': False, 'error': 'Vault locked'}), 403
    mk = _get_master_key()
    f = get_file(file_id, current_user.id, key=mk)
    if not f or f['is_directory']:
        return jsonify({'success': False, 'error': 'File not found'}), 404
    if not (f['mime_type'] or '').startswith('video/'):
        return jsonify({'success': False, 'error': 'Not a video file'}), 400

    uid = current_user.id
    fid = file_id
    vault_fname = f['vault_filename']

    def update_size(new_size):
        from models import get_db, _encrypt_value, encrypt_field
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        db = get_db()
        db.execute(
            'UPDATE files SET size = ?, modified_at = ? '
            'WHERE id = ? AND owner_id = ?',
            (_encrypt_value(mk, new_size), encrypt_field(mk, now), fid, uid))
        db.commit()
        db.close()

    from transcoder import submit_reencode
    result = submit_reencode(enc, vault_fname, fid,
                             size_callback=update_size,
                             file_name=f.get('name', ''))
    if not result['accepted']:
        return jsonify({'success': False,
                        'error': result['reason']}), 409

    return jsonify({'success': True,
                    'message': 'Re-encode queued (H.264 + AAC). '
                               'You will be notified when it finishes.'})


@app.route('/api/reencode-dir/<int:dir_id>', methods=['POST'])
@login_required
def api_reencode_dir(dir_id):
    """Re-encode all video files in a directory (recursively) for browser playback."""
    enc = _get_encryptor()
    if enc is None:
        return jsonify({'success': False, 'error': 'Vault locked'}), 403
    mk = _get_master_key()
    f = get_file(dir_id, current_user.id, key=mk)
    if not f or not f['is_directory']:
        return jsonify({'success': False, 'error': 'Directory not found'}), 404

    uid = current_user.id
    # Collect all video files recursively
    videos = _collect_recursive(uid, dir_id, 'video', mk)
    if not videos:
        return jsonify({'success': False, 'error': 'No video files found in this directory'}), 400

    from transcoder import submit_reencode
    accepted = 0
    skipped = 0
    for v in videos:
        fid = v['id']
        vault_fname = v['vault_filename']
        file_name = v.get('name', '')

        def make_size_cb(fid_inner):
            def update_size(new_size):
                from models import get_db, _encrypt_value, encrypt_field
                from datetime import datetime, timezone
                now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                db = get_db()
                db.execute(
                    'UPDATE files SET size = ?, modified_at = ? '
                    'WHERE id = ? AND owner_id = ?',
                    (_encrypt_value(mk, new_size),
                     encrypt_field(mk, now),
                     fid_inner, uid))
                db.commit()
                db.close()
            return update_size

        result = submit_reencode(enc, vault_fname, fid,
                                size_callback=make_size_cb(fid),
                                file_name=file_name)
        if result['accepted']:
            accepted += 1
        else:
            skipped += 1

    if accepted == 0:
        return jsonify({'success': False,
                        'error': f'All {skipped} video(s) are already queued or processing'}), 409

    msg = f'Queued {accepted} video file(s) for re-encode.'
    if skipped:
        msg += f' ({skipped} already queued — skipped)'
    return jsonify({
        'success': True,
        'count': accepted,
        'skipped': skipped,
        'message': msg
    })


@app.route('/api/reencode-status')
@login_required
def api_reencode_status():
    """Return and clear finished re-encode jobs (for toast notifications)."""
    from transcoder import pop_finished_jobs, get_reencode_status, get_queue_size
    finished = pop_finished_jobs()
    all_jobs = get_reencode_status()
    running = sum(1 for j in all_jobs if j['status'] == 'running')
    queued = sum(1 for j in all_jobs if j['status'] == 'queued')
    return jsonify({'jobs': finished, 'running': running,
                    'queued': queued, 'queue_size': get_queue_size()})


@app.route('/api/reencode-jobs')
@login_required
def api_reencode_jobs():
    """Return all re-encode jobs (for the queue panel)."""
    from transcoder import get_reencode_status
    return jsonify({'jobs': get_reencode_status()})


@app.route('/api/reencode-clear', methods=['POST'])
@login_required
def api_reencode_clear():
    """Clear all finished re-encode jobs."""
    from transcoder import clear_finished_jobs
    cleared = clear_finished_jobs()
    return jsonify({'success': True, 'cleared': cleared})



# ── encryption key export ────────────────────────────────────────────
@app.route('/api/export-keys')
@login_required
def api_export_keys():
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


# ── user management (admin only) ────────────────────────────────────
@app.route('/users')
@admin_required
def users_page():
    return render_template('users.html', users=list_users())


@app.route('/api/users')
@admin_required
def api_list_users():
    return jsonify({'users': list_users()})


@app.route('/api/users/create', methods=['POST'])
@admin_required
def api_create_user():
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
    if user_id == current_user.id:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    row = get_user_by_id(user_id)
    if not row:
        return jsonify({'error': 'User not found'}), 404
    vault_files = delete_user(user_id)
    for vf in vault_files:
        p = os.path.join(config.VAULT_DIR, vf)
        if os.path.exists(p):
            os.remove(p)
    _user_keys.pop(user_id, None)
    return jsonify({'success': True})


@app.route('/api/users/<int:user_id>/reset-password', methods=['POST'])
@admin_required
def api_reset_password(user_id):
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
    if user_id == current_user.id:
        return jsonify({'error': 'Cannot change your own admin status'}), 400
    row = get_user_by_id(user_id)
    if not row:
        return jsonify({'error': 'User not found'}), 404
    new_val = not bool(row['is_admin'])
    set_user_admin(user_id, new_val)
    return jsonify({'success': True, 'is_admin': new_val})


# ── change own password ──────────────────────────────────────────────
@app.route('/api/change-password', methods=['POST'])
@login_required
def api_change_password():
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
    """Return session readiness and progress (for the loading overlay)."""
    sess = _get_or_start_session(file_id)
    if sess.get_error():
        return jsonify({'status': 'error', 'error_msg': sess.get_error()})
    if sess.is_ready():
        return jsonify({'status': 'ready', 'stage': 'ready'})
    return jsonify({
        'status': 'initializing',
        'stage': sess.init_stage,
        'decrypt_progress': round(sess.decrypt_progress, 3),
        'file_size': sess.file_size,
        'bytes_decrypted': sess.bytes_decrypted,
    })


@app.route('/api/hls/<int:file_id>/master.m3u8')
@login_required
def api_hls_master(file_id):
    """Generate and serve the HLS master playlist (blocks until probe done)."""
    sess = _get_or_start_session(file_id)
    try:
        sess.wait_ready(timeout=120)
    except RuntimeError as e:
        return Response(f'# Transcoder error: {e}\n', status=503,
                        mimetype='text/plain')

    audio_tracks = sess.audio_info()
    subtitle_tracks = sess.subtitle_info()

    lines = ['#EXTM3U']

    # Audio renditions
    for t in audio_tracks:
        default = 'YES' if t['is_default'] else 'NO'
        lang = t['language'] or 'und'
        name = t['label'] or t['language'] or f"Track {t['track_index']}"
        uri = url_for('api_hls_audio_playlist', file_id=file_id,
                       track=t['track_index'])
        lines.append(
            f'#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="audio",'
            f'NAME="{name}",LANGUAGE="{lang}",'
            f'DEFAULT={default},AUTOSELECT=YES,URI="{uri}"'
        )

    # Subtitle renditions
    for t in subtitle_tracks:
        lang = t['language'] or 'und'
        name = t['label'] or t['language'] or f"Subtitle {t['track_index']}"
        uri = url_for('api_hls_subtitle_playlist', file_id=file_id,
                       track=t['track_index'])
        lines.append(
            f'#EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID="subs",'
            f'NAME="{name}",LANGUAGE="{lang}",'
            f'DEFAULT=NO,AUTOSELECT=NO,URI="{uri}"'
        )

    # Stream inf
    attrs = 'BANDWIDTH=5000000'
    if audio_tracks:
        attrs += ',AUDIO="audio"'
    if subtitle_tracks:
        attrs += ',SUBTITLES="subs"'
    lines.append(f'#EXT-X-STREAM-INF:{attrs}')
    lines.append(url_for('api_hls_video_playlist', file_id=file_id))

    body = '\n'.join(lines) + '\n'
    return Response(body, mimetype='application/vnd.apple.mpegurl',
                    headers={'Cache-Control': 'no-cache'})


@app.route('/api/hls/<int:file_id>/video/playlist.m3u8')
@login_required
def api_hls_video_playlist(file_id):
    """Generate the video-only HLS media playlist."""
    sess = _get_or_start_session(file_id)
    if not sess.is_ready():
        sess.wait_ready(timeout=120)

    durations = sess.get_segment_durations('video', 0)
    max_dur = max(durations) if durations else 10
    lines = [
        '#EXTM3U',
        '#EXT-X-VERSION:3',
        f'#EXT-X-TARGETDURATION:{math.ceil(max_dur)}',
        '#EXT-X-PLAYLIST-TYPE:VOD',
    ]
    for i, dur in enumerate(durations):
        lines.append(f'#EXTINF:{dur:.6f},')
        lines.append(url_for('api_hls_segment', file_id=file_id,
                             stream='video', track=0, seg_index=i))
    lines.append('#EXT-X-ENDLIST')

    body = '\n'.join(lines) + '\n'
    return Response(body, mimetype='application/vnd.apple.mpegurl',
                    headers={'Cache-Control': 'no-cache'})


@app.route('/api/hls/<int:file_id>/audio/<int:track>/playlist.m3u8')
@login_required
def api_hls_audio_playlist(file_id, track):
    """Generate an audio-track HLS media playlist."""
    sess = _get_or_start_session(file_id)
    if not sess.is_ready():
        sess.wait_ready(timeout=120)

    durations = sess.get_segment_durations('audio', track)
    max_dur = max(durations) if durations else 10
    lines = [
        '#EXTM3U',
        '#EXT-X-VERSION:3',
        f'#EXT-X-TARGETDURATION:{math.ceil(max_dur)}',
        '#EXT-X-PLAYLIST-TYPE:VOD',
    ]
    for i, dur in enumerate(durations):
        lines.append(f'#EXTINF:{dur:.6f},')
        lines.append(url_for('api_hls_segment', file_id=file_id,
                             stream='audio', track=track, seg_index=i))
    lines.append('#EXT-X-ENDLIST')

    body = '\n'.join(lines) + '\n'
    return Response(body, mimetype='application/vnd.apple.mpegurl',
                    headers={'Cache-Control': 'no-cache'})


@app.route('/api/hls/<int:file_id>/subtitle/<int:track>/playlist.m3u8')
@login_required
def api_hls_subtitle_playlist(file_id, track):
    """Generate a subtitle HLS playlist (single VTT file)."""
    sess = _get_or_start_session(file_id)
    if not sess.is_ready():
        sess.wait_ready(timeout=120)

    duration = sess.duration or 99999
    lines = [
        '#EXTM3U',
        '#EXT-X-VERSION:3',
        f'#EXT-X-TARGETDURATION:{math.ceil(duration)}',
        '#EXT-X-PLAYLIST-TYPE:VOD',
        f'#EXTINF:{duration:.6f},',
        url_for('api_hls_subtitle_file', file_id=file_id, track=track),
        '#EXT-X-ENDLIST',
    ]

    body = '\n'.join(lines) + '\n'
    return Response(body, mimetype='application/vnd.apple.mpegurl',
                    headers={'Cache-Control': 'no-cache'})


@app.route('/api/hls/<int:file_id>/<stream>/<int:track>/segment/<int:seg_index>.ts')
@login_required
def api_hls_segment(file_id, stream, track, seg_index):
    """Serve a single HLS segment (blocks until FFmpeg writes it)."""
    sess = _get_or_start_session(file_id)
    if not sess.is_ready():
        sess.wait_ready(timeout=120)

    data = sess.get_segment(stream, track, seg_index, timeout=60)
    if data is None:
        abort(404)

    mime = 'video/mp2t' if stream == 'video' else 'audio/mp2t'
    return Response(data, mimetype=mime,
                    headers={'Cache-Control': 'no-cache'})


@app.route('/api/hls/<int:file_id>/subtitle/<int:track>/file.vtt')
@login_required
def api_hls_subtitle_file(file_id, track):
    """Serve a WebVTT subtitle file from the session cache."""
    sess = _get_or_start_session(file_id)
    if not sess.is_ready():
        sess.wait_ready(timeout=120)

    vtt = sess.get_subtitle(track)
    if vtt is None:
        abort(404)
    return Response(vtt, mimetype='text/vtt',
                    headers={'Cache-Control': 'no-cache'})


@app.route('/api/hls/<int:file_id>/tracks')
@login_required
def api_hls_tracks(file_id):
    """Return audio/subtitle track metadata for the UI."""
    sess = _get_or_start_session(file_id)
    try:
        sess.wait_ready(timeout=120)
    except RuntimeError:
        return jsonify({'audio': [], 'subtitles': []})
    return jsonify({
        'audio': sess.audio_info(),
        'subtitles': sess.subtitle_info(),
    })


# ── app factory ──────────────────────────────────────────────────────
def create_app():
    os.makedirs(config.DATA_DIR, exist_ok=True)
    os.makedirs(config.VAULT_DIR, exist_ok=True)
    init_db()

    secret = get_config('flask_secret')
    app.secret_key = secret if secret else os.urandom(32)
    logger.info('Vault server starting on %s:%s', config.HOST, config.PORT)
    return app
