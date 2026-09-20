"""Audio cache management helpers.

Extracted from ``app_helpers_prefs.py`` — these functions use lazy internal imports
for names like ``_get_master_key`` that exist in the main app module at runtime.
"""

import config as _config
import os as _os  # noqa: F401
from models import get_file, clear_audio_cache, has_audio_cache, get_audio_cache_info  # noqa: E402, F811
from flask import request, jsonify
from flask import abort as _abort  # noqa: E402, F811
def abort(code): return _abort(code)


def api_get_audio_cache(file_id):
    """Return whether this file has cached audio tracks."""
    from flask_login import current_user as cu  # noqa: F811
    from helpers.app_helpers_auth import _get_master_key as gmk  # noqa: F811

    f = get_file(file_id, cu.id, key=gmk())
    if not f:
        return abort(404)

    cached = get_audio_cache_info(file_id)
    return jsonify({'has_cache': bool(cached), 'cached_tracks': list(cached.keys())})


def api_clear_audio_cache(file_id):
    """Delete all cached audio for a specific file."""
    from flask_login import current_user as cu  # noqa: F811
    from helpers.app_helpers_auth import _get_master_key as gmk  # noqa: F811

    f = get_file(file_id, cu.id, key=gmk())
    if not f:
        return abort(404)

    vault_files = clear_audio_cache(file_id)
    for vf in vault_files:
        try:
            p = __os.path.join(_config.VAULT_DIR, vf)
            if _os.path.exists(p):
                os.remove(p)
        except Exception:  # noqa: S110 — best-effort cleanup
            pass

    return jsonify({'success': True, 'cleared': len(vault_files)})


def api_clear_all_audio_cache():
    """Delete all cached audio for all files owned by the current user."""
    from flask_login import current_user as cu  # noqa: F811
    from models import get_db

    db = get_db()
    rows = db.execute(
        'SELECT ac.id, ac.vault_filename FROM audio_cache ac '
        'JOIN files f ON ac.file_id = f.id '
        'WHERE f.owner_id = ?', (current_user.id,),
    ).fetchall()

    vault_files = [r['vault_filename'] for r in rows]
    ids = [r['id'] for r in rows]
    if ids:
        db.execute(
            f'DELETE FROM audio_cache WHERE id IN ({",".join("?" * len(ids))})',
            ids,
        )
        db.commit()

    db.close()

    for vf in vault_files:
        try:
            p = __os.path.join(_config.VAULT_DIR, vf)
            if _os.path.exists(p):
                os.remove(p)
        except Exception:  # noqa: S110 — best-effort cleanup
            pass

    return jsonify({'success': True, 'cleared': len(vault_files)})
