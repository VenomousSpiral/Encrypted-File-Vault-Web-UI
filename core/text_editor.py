"""Text editor feature — self-contained in one module.

Consolidated from: helpers/app_helpers_text.py (editor + read/write/create/editable text endpoints).
Plus constants for determining which files are editable as text.
"""

import io  # noqa: F401
import os  # noqa: F401 — standard lib, needed for path ops & extensions  
import uuid


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
    _, ext = os.path.splitext(name)
    if ext in _TEXT_EXTS:
        return True
    # Dockerfile, Makefile etc. (no extension)
    base = os.path.basename(name)
    if base in _TEXT_BASENAMES:
        return True
    return False


def editor(file_id):
    """Render the text editor page."""
    from models import get_file, set_video_preferences  # noqa: F811
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key

    f = get_file(file_id, cu.id, key=_get_master_key())
    if not f or f['is_directory']:
        return abort(404)
    set_video_preferences(cu.id, file_id, key=_get_master_key())  # noqa: F821
    return render_template('editor.html', file=dict(f))


def api_read_text(file_id):
    """Return the full decrypted text content of a file."""
    from models import get_file  # noqa: F811
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key, _get_encryptor

    enc = _get_encryptor()
    if enc is None:
        return jsonify({'error': 'Vault is locked'}), 403
    f = get_file(file_id, cu.id, key=_get_master_key())
    if not f or f['is_directory']:
        return jsonify({'error': 'Not found'}), 404
    vault_path = os.path.join(_config.VAULT_DIR, f['vault_filename'])
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


def api_write_text(file_id):
    """Save new text content back to the vault (re-encrypt)."""
    from models import get_file, get_db  # noqa: F811
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key, _get_encryptor

    enc = _get_encryptor()
    if enc is None:
        return jsonify({'error': 'Vault is locked'}), 403
    f = get_file(file_id, cu.id, key=_get_master_key())
    if not f or f['is_directory']:
        return jsonify({'error': 'Not found'}), 404

    data = _request.get_json(silent=True) or {}
    content = data.get('content', '')
    content_bytes = content.encode('utf-8')
    file_size = len(content_bytes)

    new_vault_name = str(uuid.uuid4()) + '.enc'
    new_vault_path = os.path.join(_config.VAULT_DIR, new_vault_name)
    old_vault_path = os.path.join(_config.VAULT_DIR, f['vault_filename'])

    try:
        enc.encrypt_stream(io.BytesIO(content_bytes), new_vault_path, file_size)
        db = get_db()
        db.execute(
            'UPDATE files SET vault_filename = ?, size = ?, modified_at = datetime("now") WHERE id = ? AND owner_id = ?',
            (new_vault_name, file_size, file_id, cu.id),
        )
        db.commit()
        db.close()
        if os.path.exists(old_vault_path):
            os.remove(old_vault_path)
        return jsonify({'success': True, 'size': file_size})
    except Exception as exc:
        if os.path.exists(new_vault_path):
            os.remove(new_vault_path)
        return jsonify({'error': str(exc)}), 500


def api_create_text():
    """Create a new empty text file."""
    from flask_login import current_user as cu  # noqa: F811
    from models import get_file_by_name, create_file_record  # noqa: F811
    from .auth import _get_master_key as gmk, _get_encryptor as gen
    import mimetypes as _mimetypes  # noqa: F821

    enc = gen()
    if enc is None:
        return jsonify({'error': 'Vault is locked'}), 403

    data = _request.get_json(silent=True) or {}
    name = data.get('name', '').strip()
    parent_id = data.get('parent_id')

    if not name:
        return jsonify({'error': 'Name is required'}), 400
    if '/' in name or '\\' in name:
        return jsonify({'error': 'Name cannot contain slashes'}), 400

    _, ext = os.path.splitext(name)
    if not ext:
        name += '.txt'

    mk = gmk()
    base_name = name
    base, ext2 = os.path.splitext(name)
    counter = 1
    while get_file_by_name(cu.id, parent_id, name, key=mk):
        name = f'{base} ({counter}){ext2}'
        counter += 1

    mime_type = _mimetypes.guess_type(name)[0] or 'text/plain'
    content_bytes = b''
    file_size = 0

    vault_name = str(uuid.uuid4()) + '.enc'
    vault_path = os.path.join(_config.VAULT_DIR, vault_name)

    try:
        enc.encrypt_stream(io.BytesIO(content_bytes), vault_path, file_size)
        fid = create_file_record(cu.id, parent_id, name, False,
                                 vault_name, file_size, mime_type, key=mk)  # noqa: F821
        return jsonify({'id': fid, 'name': name, 'size': file_size, 'mime_type': mime_type})
    except Exception as exc:
        if os.path.exists(vault_path):
            os.remove(vault_path)
        return jsonify({'error': str(exc)}), 500


def api_is_editable(file_id):
    """Check if a file should open in the text editor."""
    from models import get_file  # noqa: F811
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key

    f = get_file(file_id, cu.id, key=_get_master_key())
    if not f:
        return jsonify({'editable': False})
    return jsonify({'editable': _is_text_editable(dict(f))})


# ── Lazy imports (resolved at runtime inside request handlers) ───────

import config as _config  # noqa: E402, F811 — module-level reference
def config(): return _config  # noqa: E402, F811

from flask import abort as _abort  # noqa: E402, F811
def abort(code): return _abort(code)

from flask import request as _request  # noqa: E402, F811 — module-level reference  

from flask import jsonify as _jsonify  # noqa: E402, F811
def jsonify(d): return _jsonify(d)
