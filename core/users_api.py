"""User management self-contained in one module.

Consolidated from: helpers/app_helpers_users.py (export keys, user CRUD, 
password reset/toggle-admin, change password).

Admin-only endpoints for user lifecycle and the export-keys endpoint.
Kept separate because it has its own concerns from file operations.
"""


def api_export_keys():
    """Download a .txt file containing encryption info needed to restore/transfer the vault."""
    from datetime import datetime  # noqa: F811  
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key as gmk

    mk = gmk()
    mk_hex = mk.hex() if mk else '(vault locked — log out and back in)'

    lines = [
        '═══════════════════════════════════════════════════════',
        '  Encrypted Vault — Key Backup',
        f'  Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
        f'  User:      {cu.username}',
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
    return _Response(
        content,
        mimetype='text/plain',
        headers={
            'Content-Disposition': f'attachment; filename="vault-keys-{cu.username}.txt"',
            'Cache-Control': 'no-store',
        },
    )


def api_list_users():
    """List all users (admin only)."""
    from models import list_users as _list_users  # noqa: F811  
    return jsonify({'users': _list_users()})


def users_page():
    from models import list_users as _list_users  # noqa: F811  
    return render_template('users.html', users=_list_users())


def api_create_user():
    """Admin creates a new user. Each gets their own independent encryption key."""
    from models import get_user, create_user  # noqa: F811 — imported in function to avoid top-level side effects  
    from crypto import generate_master_key, encrypt_master_key
    from werkzeug.security import generate_password_hash

    data = _request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    is_admin = bool(data.get('is_admin', False))

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    if get_user(username):
        return jsonify({'error': 'Username already exists'}), 409

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


def api_delete_user(user_id):
    """Delete a user and all their files (admin only)."""
    from flask_login import current_user as cu  # noqa: F811  
    from models import get_user_by_id as _gui, delete_user

    if user_id == cu.id:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    row = _gui(user_id)
    if not row:
        return jsonify({'error': 'User not found'}), 404
    vault_files = delete_user(user_id)
    for vf in vault_files:
        p = os.path.join(_config.VAULT_DIR, vf)
        if os.path.exists(p):
            os.remove(p)
    
    # Clear user key from RAM using core.auth's lazy accessor
    state = _get_app_state()
    uk = state['_user_keys'] or {}  # noqa: F811 — app-level name resolved at runtime  
    uk.pop(user_id, None)
    return jsonify({'success': True})


def api_reset_password(user_id):
    """Admin resets a user's password; re-wraps that user's own key."""
    from models import get_user_by_id as _gui, update_user_password

    data = _request.get_json(silent=True) or {}
    password = data.get('password', '')
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    row = _gui(user_id)
    if not row:
        return jsonify({'error': 'User not found'}), 404

    # We need the user's key in RAM to re-wrap it.
    state = _get_app_state()
    uk = state['_user_keys'] or {}  # noqa: F811 — app-level name resolved at runtime  
    entry = uk.get(user_id)
    if entry is None:
        return jsonify({
            'error': 'That user must be logged in (key in RAM) to reset their password. '
                     'Ask them to log in first, or they can change their own password.'}), 409

    mk = entry[0]
    salt, nonce, enc_key = encrypt_master_key(mk, password)
    update_user_password(user_id, generate_password_hash(password),
                         salt, nonce, enc_key)
    uk.pop(user_id, None)
    return jsonify({'success': True})


def api_toggle_admin(user_id):
    """Toggle a user's admin status (admin only)."""
    from flask_login import current_user as cu  # noqa: F811  
    from models import get_user_by_id as _gui, set_user_admin

    if user_id == cu.id:
        return jsonify({'error': 'Cannot change your own admin status'}), 400
    row = _gui(user_id)
    if not row:
        return jsonify({'error': 'User not found'}), 404
    new_val = not bool(row['is_admin'])
    set_user_admin(user_id, new_val)
    return jsonify({'success': True, 'is_admin': new_val})


def api_change_password():
    """Change the current user's password; re-wraps their own key."""
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key as gmk, _get_app_state
    from models import get_user_by_id as _gui, update_user_password
    from crypto import encrypt_master_key
    from werkzeug.security import check_password_hash, generate_password_hash

    data = _request.get_json(silent=True) or {}
    current_pw = data.get('current_password', '')
    new_pw = data.get('new_password', '')

    if len(new_pw) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    row = _gui(cu.id)
    if not row or not check_password_hash(row['password_hash'], current_pw):
        return jsonify({'error': 'Current password is incorrect'}), 403

    mk = gmk()
    if mk is None:
        return jsonify({'error': 'Vault is locked'}), 403

    salt, nonce, enc_key = encrypt_master_key(mk, new_pw)
    update_user_password(cu.id, generate_password_hash(new_pw),
                         salt, nonce, enc_key)
    
    # Re-set the user's key in RAM using core.auth's lazy accessor  
    state = _get_app_state()
    uk = state['_user_keys'] or {}  # noqa: F811 — app-level name resolved at runtime  
    from crypto import ChunkEncryptor as _ChunkEncryptor  # noqa: F811  

    mk_entry = (mk, _ChunkEncryptor(mk, _config.CHUNK_SIZE))
    uk[cu.id] = mk_entry
    
    return jsonify({'success': True})


# ── Lazy imports (resolved at runtime inside request handlers) ───────

import config as _config  # noqa: E402, F811 — for VAULT_DIR path resolution  
def config(): return _config  # noqa: E402, F811

from flask import jsonify as _jsonify, Response as _Response  # noqa: E402, F811 — module-level reference
from flask import request as _request  # noqa: E402, F811
def abort(code): return __import__('flask').abort(code)  # noqa: F821 — module-level reference  
def jsonify(d): return _jsonify(d)


from flask import render_template as _render_template  # noqa: E402, F811
def render_template(tmpl, **kw): return _render_template(tmpl, **kw)
from .auth import _get_app_state
