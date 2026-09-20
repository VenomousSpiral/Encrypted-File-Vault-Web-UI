"""Text editor helpers extracted from app.py.

Route handlers for:
  - /editor/<id> (page)
  - /api/file/<id>/text GET/POST (read/write content) 
  - /api/create-text POST (create new text file)
  - /api/file/<id>/editable GET (check if editable)

Plus constants: _TEXT_MIMES, _TEXT_EXTS, _is_text_editable().
"""

import io as _io  # noqa: E402
import os as _os  # noqa: F401
import uuid as _uuid  # noqa: F401 — used in route handlers via lazy import below

# ── Text-editable MIME types (no "text/" prefix) ────────────────

# ── Text-editable MIME types (no "text/" prefix) ────────────────
_TEXT_MIMES = frozenset({
    'application/json', 'application/xml', 'application/javascript',
    'application/x-yaml', 'application/yaml', 'application/toml',
    'application/x-sh', 'application/x-shellscript',
    'application/sql', 'application/xhtml+xml',
    'application/x-httpd-php',
})

# ── Text-editable file extensions ────────────────────────────────
_TEXT_EXTS = frozenset({
    '.txt', '.md', '.markdown', '.json', '.yaml', '.yml', '.toml',
    '.xml', '.html', '.htm', '.css', '.js', '.ts', '.jsx', '.tsx',
    '.py', '.rb', '.rs', '.go', '.java', '.c', '.cpp', '.h', '.hpp',
    '.cs', '.sh', '.bash', '.zsh', '.fish', '.bat', '.ps1',
    '.sql', '.ini', '.cfg', '.conf', '.env', '.gitignore',
    '.dockerfile', '.makefile', '.cmake', '.gradle',
    '.lua', '.pl', '.php', '.r', '.swift', '.kt', '.scala',
    '.log', '.csv', '.tsv', '.rst', '.tex', '.srt', '.vtt', '.sub',
    '.svg',
})

# ── Extensionless filenames considered text-editable ─────────────
_TEXT_BASENAMES = frozenset({
    'dockerfile', 'makefile', 'cmakelists.txt', 'vagrantfile',
    'gemfile', 'rakefile', 'procfile',
})


def _is_text_editable(f: dict) -> bool:
    """Return True if the file should open in the text editor."""
    mime = (f.get('mime_type') or f.get('mime') or '').lower()
    if mime.startswith('text/'):
        return True
    if mime in _TEXT_MIMES:
        return True
    name = (f.get('name') or '').lower()
    _, ext = _os.path.splitext(name)
    if ext in _TEXT_EXTS:
        return True
    # Dockerfile, Makefile etc. (no extension)
    base = _os.path.basename(name)
    if base in _TEXT_BASENAMES:
        return True
    return False


def editor(file_id):
    """Render the text editor page."""
    from models import get_file, set_video_preferences  # noqa: F811
    from flask_login import current_user as _current_user  # noqa: F811
    from helpers.app_helpers_auth import _get_master_key  # noqa: F811

    f = get_file(file_id, _current_user.id, key=_get_master_key())
    if not f or f['is_directory']:
        return abort(404)
    set_video_preferences(_current_user.id, file_id, key=_get_master_key())  # noqa: F821
    return render_template('editor.html', file=dict(f))


def api_read_text(file_id):
    """Return the full decrypted text content of a file."""
    from models import get_file  # noqa: F811
    from flask_login import current_user as _current_user  # noqa: F811
    from helpers.app_helpers_auth import _get_master_key, _get_encryptor  # noqa: F811

    enc = _get_encryptor()
    if enc is None:
        return jsonify({'error': 'Vault is locked'}), 403
    f = get_file(file_id, _current_user.id, key=_get_master_key())
    if not f or f['is_directory']:
        return jsonify({'error': 'Not found'}), 404
    vault_path = _os.path.join(_config.VAULT_DIR, f['vault_filename'])  # noqa: F821
    if not _os.path.exists(vault_path):
        return jsonify({'error': 'File missing from vault'}), 404
    try:
        chunks = []
        for chunk in enc.decrypt_full(vault_path):
            chunks.append(chunk)
        content = b''.join(chunks).decode('utf-8', errors='replace')
        return jsonify({'content': content})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


def api_write_text(file_id):
    """Save new text content back to the vault (re-encrypt)."""
    from models import get_file, get_db  # noqa: F811
    from flask_login import current_user as _current_user  # noqa: F811
    from helpers.app_helpers_auth import _get_master_key, _get_encryptor  # noqa: F811

    enc = _get_encryptor()
    if enc is None:
        return jsonify({'error': 'Vault is locked'}), 403
    f = get_file(file_id, _current_user.id, key=_get_master_key())
    if not f or f['is_directory']:
        return jsonify({'error': 'Not found'}), 404

    data = request.get_json(silent=True) or {}  # noqa: F821
    content = data.get('content', '')
    content_bytes = content.encode('utf-8')
    file_size = len(content_bytes)

    new_vault_name = str(uuid.uuid4()) + '.enc'  # noqa: F821 — imported below
    new_vault_path = _os.path.join(_config.VAULT_DIR, new_vault_name)  # noqa: F821
    old_vault_path = _os.path.join(_config.VAULT_DIR, f['vault_filename'])  # noqa: F821

    try:
        enc.encrypt_stream(_io.BytesIO(content_bytes), new_vault_path, file_size)
        db = get_db()
        db.execute(
            'UPDATE files SET vault_filename = ?, size = ?, modified_at = datetime("now") WHERE id = ? AND owner_id = ?',
            (new_vault_name, file_size, file_id, _current_user.id),  # noqa: F821
        )
        db.commit()
        db.close()
        if _os.path.exists(old_vault_path):
            _os.remove(old_vault_path)
        return jsonify({'success': True, 'size': file_size})
    except Exception as exc:
        if _os.path.exists(new_vault_path):
            _os.remove(new_vault_path)
        return jsonify({'error': str(exc)}), 500


def api_create_text():
    """Create a new empty text file."""
    from models import get_file_by_name, create_file_record  # noqa: F811
    import mimetypes as _mimetypes  # noqa: F811
    from flask_login import current_user as _current_user  # noqa: F811
    from helpers.app_helpers_auth import _get_master_key, _get_encryptor  # noqa: F811

    enc = _get_encryptor()
    if enc is None:
        return jsonify({'error': 'Vault is locked'}), 403

    data = request.get_json(silent=True) or {}  # noqa: F821
    name = data.get('name', '').strip()
    parent_id = data.get('parent_id')

    if not name:
        return jsonify({'error': 'Name is required'}), 400
    if '/' in name or '\\' in name:
        return jsonify({'error': 'Name cannot contain slashes'}), 400

    _, ext = _os.path.splitext(name)
    if not ext:
        name += '.txt'

    mk = _get_master_key()
    base_name = name
    base, ext2 = _os.path.splitext(name)
    counter = 1
    while get_file_by_name(_current_user.id, parent_id, name, key=mk):  # noqa: F821
        name = f'{base} ({counter}){ext2}'
        counter += 1

    mime_type = _mimetypes.guess_type(name)[0] or 'text/plain'
    content_bytes = b''
    file_size = 0

    vault_name = str(uuid.uuid4()) + '.enc'  # noqa: F821
    vault_path = _os.path.join(_config.VAULT_DIR, vault_name)  # noqa: F821

    try:
        enc.encrypt_stream(_io.BytesIO(content_bytes), vault_path, file_size)
        fid = create_file_record(_current_user.id, parent_id, name, False,
                                 vault_name, file_size, mime_type, key=mk)  # noqa: F821
        return jsonify({'id': fid, 'name': name, 'size': file_size, 'mime_type': mime_type})
    except Exception as exc:
        if _os.path.exists(vault_path):
            _os.remove(vault_path)
        return jsonify({'error': str(exc)}), 500


def api_is_editable(file_id):
    """Check if a file should open in the text editor."""
    from models import get_file  # noqa: F811
    from flask_login import current_user as _current_user  # noqa: F811
    from helpers.app_helpers_auth import _get_master_key  # noqa: F811

    f = get_file(file_id, _current_user.id, key=_get_master_key())
    if not f:
        return jsonify({'editable': False})
    return jsonify({'editable': _is_text_editable(dict(f))})

# ── Lazy imports (resolved at runtime inside request handlers) ───────
import config as _config  # noqa: E402, F811
uuid = _uuid  # noqa: E402, F811
from flask import abort as _abort  # noqa: E402, F811
from flask import request as _request  # noqa: E402, F811
from flask import jsonify as _jsonify  # noqa: E402, F811
def abort(code): return _abort(code)
def jsonify(d): return _jsonify(d)
def render_template(tmpl, **kw):
    """Lazy import wrapper for Flask's render_template."""
    from flask import render_template as _rt  # noqa: E402
    return _rt(tmpl, **kw)
request = _request
