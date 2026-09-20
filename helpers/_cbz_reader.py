"""CBZ (comic book) reader helpers.

Extracted from ``app_helpers_prefs.py`` — these functions use lazy internal imports
for names like ``_get_master_key`` that exist in the main app module at runtime.
"""

import os  # noqa: F401 — standard lib, needed for path ops & extensions
from models import get_file as _get_file, set_cbz_preferences, get_cbz_preferences, set_video_preferences  # noqa: E402, F811
from flask import request, jsonify, Response
# ── Lazy Flask global wrappers for request handlers ────────────────
from helpers.app_helpers_auth import _get_master_key, _get_encryptor as _ge  # noqa: F821
import config as _config  # noqa: E402 — for VAULT_DIR path resolution
from flask import abort as _abort  # noqa: E402, F811
from flask import render_template as _render_template  # noqa: E402, F811


def render_template(tmpl, **kw):
    """Lazy import wrapper for Flask's render_template."""
    return _render_template(tmpl, **kw)


# ── CBZ reader page ────────────────────────────────────────────────

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
    """Decrypt a CBZ file and return sorted list of image filenames.

    Reads the entire decrypted archive into RAM — fine for typical comic books (<50 MB).
    Returns an empty list if decryption fails or no images are found.
    """
    import io  # noqa: F811, re-define inside function to avoid top-level side effects
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
    from helpers.app_helpers_auth import _get_master_key as gmk  # noqa: F811
    from flask_login import current_user as cu  # noqa: F811
    from cryptography.exceptions import InvalidTag as _InvalidTag

    try:
        mk = gmk()
        f = _get_file(file_id, cu.id, key=mk)
        if not f or f['is_directory']:
            from flask import abort as _flask_abort
            return jsonify({'error': 'Not found'}), 404

        set_video_preferences(cu.id, file_id, key=mk)
        cbz_prefs = get_cbz_preferences(cu.id, file_id, key=mk)
        return render_template('cbz.html', file=dict(f), cbz_prefs=cbz_prefs)
    except _InvalidTag:
        return _abort(403)


def api_cbz_image(file_id):
    """Extract and serve a single page image from a CBZ file.

    The image is decrypted on-the-fly from the vault.
    """
    from flask_login import current_user as cu  # noqa: F811
    from cryptography.exceptions import InvalidTag as _InvalidTag
    import zipfile
    enc = _ge()
    if enc is None:
        return jsonify({'error': 'Vault is locked'}), 403

    try:
        f = _get_file(file_id, cu.id, key=_get_master_key())
        if not f or f['is_directory']:
            return jsonify({'error': 'Not found'}), 404

        vault_path = os.path.join(_config.VAULT_DIR, f['vault_filename'])
        if not os.path.exists(vault_path):
            return jsonify({'error': 'File missing from vault'}), 404

        page = request.args.get('page', 0, type=int)
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

        return Response(image_data, mimetype=mime)
    except _InvalidTag:
        return jsonify({'error': 'Decryption failed'}), 403


def api_cbz_pages(file_id):
    """Return total number of pages in a CBZ file."""
    from flask_login import current_user as cu  # noqa: F811
    from cryptography.exceptions import InvalidTag as _InvalidTag
    enc = _ge()
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


# ── CBZ preferences ────────────────────────────────────────────────

def api_get_cbz_prefs(file_id):
    from helpers.app_helpers_auth import _get_master_key as gmk  # noqa: F811
    from flask_login import current_user as cu  # noqa: F811
    from cryptography.exceptions import InvalidTag as _InvalidTag

    try:
        f = _get_file(file_id, cu.id, key=gmk())
        if not f:
            return jsonify({'error': 'Not found'}), 404

        mk = gmk()
        return jsonify(get_cbz_preferences(cu.id, file_id, key=mk))
    except _InvalidTag:
        return _abort(403)


def api_set_cbz_prefs(file_id):
    from helpers.app_helpers_auth import _get_master_key as gmk  # noqa: F811
    from flask_login import current_user as cu  # noqa: F811

    mk = gmk()
    f = _get_file(file_id, cu.id, key=mk)
    if not f:
        return jsonify({'error': 'Not found'}), 404

    data = request.get_json(silent=True) or {}
    allowed = {}
    if 'page' in data:
        allowed['page'] = int(data['page'])

    if allowed:
        set_cbz_preferences(cu.id, file_id, key=mk, **allowed)

    return jsonify({'success': True})
