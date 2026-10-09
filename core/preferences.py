"""All preference storage + CBZ reader consolidated in one module.

Consolidated from: helpers/_prefs_settings.py (user prefs, video prefs route handlers)
+ helpers/_cbz_reader.py (CBZ page, image serving, pages count, CBZ prefs).

Both share the same get_user_preferences/set_user_preferences DB call patterns
and use _get_master_key for decryption operations.
"""

import os  # noqa: F401 — standard lib, needed for path ops & extensions
from models import (  # noqa: E402, F811
    get_file as _get_file, set_cbz_preferences, get_cbz_preferences,
    set_video_preferences,
)


# ── Settings page + user preferences API (from helpers/_prefs_settings.py) ───

def settings_page():
    """Render the user preferences/settings page."""
    from models import get_user_preferences  # noqa: F811
    from .auth import _get_master_key
    from flask_login import current_user as cu

    mk = _get_master_key()
    prefs = get_user_preferences(cu.id, key=mk)
    return render_template('settings.html', prefs=prefs)


def api_get_preferences():
    """Get current user's stored preferences."""
    from models import get_user_preferences  # noqa: F811
    from .auth import _get_master_key as gmk
    from flask_login import current_user as cu

    mk = gmk()
    return jsonify(get_user_preferences(cu.id, key=mk))


def api_set_preferences():
    """Update user's stored preferences."""
    from models import get_user_preferences, set_user_preferences  # noqa: F811
    from .auth import _get_master_key as gmk
    from flask_login import current_user as cu

    mk = gmk()
    data = _request.get_json(silent=True) or {}
    cur = get_user_preferences(cu.id, key=mk)

    audio_lang = data.get('default_audio_lang', cur['default_audio_lang']).strip()
    sub_lang = data.get('default_subtitle_lang', cur['default_subtitle_lang']).strip()
    sub_offset = float(data.get('default_subtitle_offset', cur['default_subtitle_offset']))
    skip_amt = int(data.get('skip_amount', cur['skip_amount']))

    sort_pref = data.get('sort_preference', cur['sort_preference']).strip()
    if sort_pref not in ('name', 'recent', 'added', 'size'):
        sort_pref = 'name'

    cache_mode = data.get('audio_cache_mode', cur.get('audio_cache_mode', 'keep')).strip().lower()
    if cache_mode not in ('keep', 'save', 'overwrite'):
        cache_mode = 'keep'

    show_dir_size = bool(data.get('show_dir_size', cur.get('show_dir_size', False)))

    set_user_preferences(
        cu.id, audio_lang, sub_lang, sub_offset,
        skip_amt, sort_pref, cache_mode, show_dir_size, key=mk,
    )
    return jsonify({'success': True})


def api_get_video_prefs(file_id):
    """Get per-file video playback position & subtitle offset."""
    from models import get_file as _gf, get_video_preferences  # noqa: F811
    from .auth import _get_master_key as gmk
    from flask_login import current_user as cu

    f = _gf(file_id, cu.id, key=gmk())
    if not f:
        return abort(404)

    mk = gmk()
    return jsonify(get_video_preferences(cu.id, file_id, key=mk))


def api_set_video_prefs(file_id):
    """Update per-file video playback position & subtitle offset."""
    from models import get_file as _gf, set_video_preferences  # noqa: F811
    from .auth import _get_master_key as gmk
    from flask_login import current_user as cu

    mk = gmk()
    f = _gf(file_id, cu.id, key=mk)
    if not f:
        return abort(404)

    data = _request.get_json(silent=True) or {}
    allowed = {}
    if 'position' in data:
        allowed['position'] = float(data['position'])
    if 'sub_offset' in data:
        allowed['sub_offset'] = float(data['sub_offset'])

    if allowed:
        set_video_preferences(cu.id, file_id, key=mk, **allowed)

    return jsonify({'success': True})


def api_clear_video_prefs():
    """Clear all per-file video preferences for the current user."""
    from models import clear_all_video_preferences  # noqa: F811
    from flask_login import current_user as cu

    count = clear_all_video_preferences(cu.id)
    return jsonify({'success': True, 'cleared': count})


# ── CBZ Reader (from helpers/_cbz_reader.py) ────────────────────────

IMAGE_EXTS = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tiff'}
MIME_MAP = {
    '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
    '.png': 'image/png', '.gif': 'image/gif',
    '.webp': 'image/webp', '.bmp': 'image/bmp',
    '.tiff': 'image/tiff', '.tif': 'image/tiff',
}


def _decrypt_to_bytes(enc, vault_path):
    """Decrypt a vault file into an in-memory BytesIO buffer."""
    import io  # noqa: F811
    from cryptography.exceptions import InvalidTag as _InvalidTag
    try:
        decrypted = io.BytesIO()
        for chunk in enc.decrypt_full(vault_path):
            decrypted.write(chunk)
        return decrypted
    except _InvalidTag:
        raise ValueError("Decryption failed - wrong encryption context")


def _read_cbz_images(enc, vault_path):
    """Decrypt a CBZ file and return sorted list of image filenames."""
    import io  # noqa: F811 — re-define inside function to avoid top-level side effects
    import zipfile

    try:
        decrypted = io.BytesIO()
        for chunk in enc.decrypt_full(vault_path):
            decrypted.write(chunk)
        decrypted.seek(0)

        with zipfile.ZipFile(decrypted, 'r') as zf:
            all_files = zf.namelist()
            image_files = sorted(
                [n for n in all_files if os.path.splitext(n)[1].lower() in IMAGE_EXTS],
                key=lambda name: name.lower(),
            )

        return image_files
    except zipfile.BadZipFile:
        # Decryption returned invalid data — likely wrong encryption context
        return []
    except Exception:
        # InvalidTag, etc. from cryptography when keys don't match
        return []


def cbz_reader(file_id):
    """CBZ reader page."""
    from .auth import _get_master_key as gmk  # noqa: F811
    from flask_login import current_user as cu  # noqa: F811
    from cryptography.exceptions import InvalidTag as _InvalidTag

    try:
        mk = gmk()
        f = _get_file(file_id, cu.id, key=mk)
        if not f or f['is_directory']:
            return jsonify({'error': 'Not found'}), 404

        set_video_preferences(cu.id, file_id, key=mk)
        cbz_prefs = get_cbz_preferences(cu.id, file_id, key=mk)
        return render_template('cbz.html', file=dict(f), cbz_prefs=cbz_prefs)
    except _InvalidTag:
        return jsonify({'error': 'Not found'}), 403


def api_cbz_image(file_id):
    """Extract and serve a single page image from a CBZ file."""
    from flask_login import current_user as cu  # noqa: F811
    from cryptography.exceptions import InvalidTag as _InvalidTag
    import zipfile

    enc = _get_encryptor()
    if enc is None:
        return jsonify({'error': 'Vault is locked'}), 403

    try:
        f = _get_file(file_id, cu.id, key=_get_master_key())
        if not f or f['is_directory']:
            return jsonify({'error': 'Not found'}), 404

        vault_path = os.path.join(_config.VAULT_DIR, f['vault_filename'])
        if not os.path.exists(vault_path):
            return jsonify({'error': 'File missing from vault'}), 404

        page = _request.args.get('page', 0, type=int)
        if page < 0:
            return jsonify({'error': 'Invalid page'}), 400

        image_files = _read_cbz_images(enc, vault_path)
        if not image_files or page >= len(image_files):
            return jsonify({'error': 'Page not found'}), 404

        # Re-decrypt to get the full archive bytes for reading individual pages
        try:
            decrypted = _decrypt_to_bytes(enc, vault_path)
        except ValueError:
            return jsonify({'error': 'Decryption failed'}), 403

        with zipfile.ZipFile(decrypted, 'r') as zf:
            image_data = zf.read(image_files[page])

        ext = os.path.splitext(image_files[page])[1].lower()
        mime = MIME_MAP.get(ext, 'image/jpeg')

        return _Response(image_data, mimetype=mime)
    except _InvalidTag:
        return jsonify({'error': 'Decryption failed'}), 403


def api_cbz_pages(file_id):
    """Return total number of pages in a CBZ file."""
    from flask_login import current_user as cu  # noqa: F811
    from cryptography.exceptions import InvalidTag as _InvalidTag

    enc = _get_encryptor()
    if enc is None:
        return jsonify({'error': 'Vault is locked'}), 403

    try:
        f = _get_file(file_id, cu.id, key=_get_master_key())
        if not f or f['is_directory']:
            return jsonify({'error': 'Not found'}), 404

        vault_path = os.path.join(_config.VAULT_DIR, f['vault_filename'])
        if not os.path.exists(vault_path):
            return jsonify({'error': 'File missing from vault'}), 404

        image_files = _read_cbz_images(enc, vault_path)
        return jsonify({'pages': len(image_files)})
    except _InvalidTag:
        return jsonify({'error': 'Decryption failed'}), 403


def api_get_cbz_prefs(file_id):
    from .auth import _get_master_key as gmk  # noqa: F811
    from flask_login import current_user as cu  # noqa: F811

    try:
        f = _get_file(file_id, cu.id, key=gmk())
        if not f:
            return jsonify({'error': 'Not found'}), 404

        mk = gmk()
        return jsonify(get_cbz_preferences(cu.id, file_id, key=mk))
    except Exception as _e:
        from cryptography.exceptions import InvalidTag as _InvalidTag  # noqa: F811
        if isinstance(_e, _InvalidTag):
            return abort(403)
        raise


def api_set_cbz_prefs(file_id):
    from .auth import _get_master_key as gmk  # noqa: F811
    from flask_login import current_user as cu  # noqa: F811

    mk = gmk()
    f = _get_file(file_id, cu.id, key=mk)
    if not f:
        return jsonify({'error': 'Not found'}), 404

    data = _request.get_json(silent=True) or {}
    allowed = {}
    if 'page' in data:
        allowed['page'] = int(data['page'])

    if allowed:
        set_cbz_preferences(cu.id, file_id, key=mk, **allowed)

    return jsonify({'success': True})


# ── Lazy imports (resolved at runtime inside request handlers) ───────

import config as _config  # noqa: E402, F811 — for VAULT_DIR path resolution

from flask import jsonify as _jsonify  # noqa: E402, F811 — module-level reference
from .auth import _get_master_key, _get_encryptor  # noqa: E402, F811

def abort(code): return __import__('flask').abort(code)  # noqa: F821 — module-level reference  
def jsonify(d): return _jsonify(d)


from flask import Response as _Response, render_template as _render_template  # noqa: E402, F811
from flask import request as _request  # noqa: E402, F811

def render_template(tmpl, **kw):
    """Lazy import wrapper for Flask's render_template."""
    return _render_template(tmpl, **kw)
