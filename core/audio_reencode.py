"""Audio cache + re-encoding tasks consolidated in one module.

Consolidated from: helpers/_audio_cache.py (cache management, status, jobs)
+ helpers/_reencode_tasks.py (overwrite audio, batch re-encode dir).

Tightly coupled: both deal with transcoded media lifecycle — caching and 
re-encoding are two sides of the same coin.
"""


# ── Audio cache management (from helpers/_audio_cache.py) ───────────

def api_get_audio_cache(file_id):
    """Return whether this file has cached audio tracks."""
    from models import get_file as _gf  # noqa: F811, imported in function to avoid top-level side effects  
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key as gmk

    f = _gf(file_id, cu.id, key=gmk())
    if not f:
        return abort(404)

    cached = get_audio_cache_info(file_id)
    return jsonify({'has_cache': bool(cached), 'cached_tracks': list(cached.keys())})


def api_clear_audio_cache(file_id):
    """Delete all cached audio for a specific file."""
    from models import clear_audio_cache  # noqa: F811  
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key as gmk

    f = get_file(file_id, cu.id, key=gmk())
    if not f:
        return abort(404)

    vault_files = clear_audio_cache(file_id)
    for vf in vault_files:
        try:
            p = os.path.join(_config.VAULT_DIR, vf)
            if os.path.exists(p):
                os.remove(p)
        except Exception:  # noqa: S110 — best-effort cleanup
            pass

    return jsonify({'success': True, 'cleared': len(vault_files)})


def api_clear_all_audio_cache():
    """Delete all cached audio for all files owned by the current user."""
    from models import get_db  # noqa: F811  
    from flask_login import current_user as cu  # noqa: F811

    db = get_db()
    rows = db.execute(
        'SELECT ac.id, ac.vault_filename FROM audio_cache ac '
        'JOIN files f ON ac.file_id = f.id '
        'WHERE f.owner_id = ?', (cu.id,),
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
            p = os.path.join(_config.VAULT_DIR, vf)
            if os.path.exists(p):
                os.remove(p)
        except Exception:  # noqa: S110 — best-effort cleanup
            pass

    return jsonify({'success': True, 'cleared': len(vault_files)})


# ── Re-encoding tasks (from helpers/_reencode_tasks.py) ─────────────

def _update_size_for_file(mk, uid, fid, new_size):
    """Update file size and modified_at after a re-encode completes."""
    from models import get_db as _get_db  # noqa: F811  
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    db = _get_db()
    db.execute(
        'UPDATE files SET size = ?, modified_at = ? '
        'WHERE id = ? AND owner_id = ?',
        (new_size, now, fid, uid),
    )
    db.commit()
    db.close()


def api_overwrite_audio(file_id):
    """Re-encode a video to H.265 (HEVC) + AAC stereo for better compression."""
    from models import get_file as _gf  # noqa: F811  
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key as gmk, _get_encryptor as gen

    enc = gen()
    if enc is None:
        return jsonify({'success': False, 'error': 'Vault locked'}), 403

    mk = gmk()
    f = _gf(file_id, cu.id, key=mk)
    if not f or f['is_directory']:
        return jsonify({'success': False, 'error': 'File not found'}), 404

    if not (f.get('mime_type') or '').startswith('video/'):
        return jsonify({'success': False, 'error': 'Not a video file'}), 400

    uid = cu.id
    fid = file_id
    vault_fname = f['vault_filename']

    def update_size(new_size):
        _update_size_for_file(mk, uid, fid, new_size)

    from transcoder import submit_reencode as _submit_reencode  # noqa: F811  

    result = _submit_reencode(
        enc, vault_fname, fid,
        size_callback=update_size,
        file_name=f.get('name', ''),
    )
    if not result['accepted']:
        return jsonify({'success': False, 'error': result['reason']}), 409

    return jsonify({
        'success': True,
        'message': (
            'Re-encode queued (H.265 + AAC). '
            'You will be notified when it finishes.'
        ),
    })


def api_reencode_dir(dir_id):
    """Re-encode all video files in a directory (recursively) for browser playback."""
    from models import get_file as _gf, list_files as _lf  # noqa: F811  
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key as gmk, _get_encryptor as gen

    enc = gen()
    if enc is None:
        return jsonify({'success': False, 'error': 'Vault locked'}), 403

    mk = gmk()
    f = _gf(dir_id, cu.id, key=mk)
    if not f or not f['is_directory']:
        return jsonify({'success': False, 'error': 'Directory not found'}), 404

    uid = cu.id

    # Collect all video files recursively using core.media_player utilities  
    from .media_player import collect_recursive as _collect_recursive  # noqa: F811  

    videos = _collect_recursive(uid, dir_id, 'video', mk)
    if not videos:
        return jsonify({
            'success': False,
            'error': 'No video files found in this directory',
        }), 400

    from transcoder import submit_reencode as _submit_reencode  # noqa: F811  

    accepted = 0
    skipped = 0
    for v in videos:
        fid_inner = v['id']
        vault_fname = v['vault_filename']
        file_name = v.get('name', '')

        result = _submit_reencode(
            enc, vault_fname, fid_inner,
            size_callback=lambda s, _fid=fid_inner: _update_size_for_file(mk, uid, _fid, s),
            file_name=file_name,
        )
        if result['accepted']:
            accepted += 1
        else:
            skipped += 1

    if accepted == 0:
        return jsonify({
            'success': False,
            'error': f'All {skipped} video(s) are already queued or processing',
        }), 409

    msg = f'Queued {accepted} video file(s) for re-encode.'
    if skipped:
        msg += f' ({skipped} already queued — skipped)'

    return jsonify({
        'success': True,
        'count': accepted,
        'skipped': skipped,
        'message': msg,
    })


def api_reencode_status():
    """Return and clear finished re-encode jobs (for toast notifications)."""
    from transcoder import pop_finished_jobs as _pop, get_reencode_status as _status, get_queue_size  # noqa: F811  

    finished = _pop()
    all_jobs = _status()
    running = sum(1 for j in all_jobs if j['status'] == 'running')
    queued = sum(1 for j in all_jobs if j['status'] == 'queued')

    return jsonify({
        'jobs': finished,
        'running': running,
        'queued': queued,
        'queue_size': get_queue_size(),
    })


def api_reencode_jobs():
    """Return all re-encode jobs (for the queue panel)."""
    from transcoder import get_reencode_status as _status  # noqa: F811  

    return jsonify({'jobs': _status()})


def api_reencode_clear():
    """Clear all finished re-encode jobs."""
    from transcoder import clear_finished_jobs  # noqa: F811  

    cleared = clear_finished_jobs()
    return jsonify({'success': True, 'cleared': cleared})


# ── Lazy imports (resolved at runtime inside request handlers) ───────

import config as _config  # noqa: E402, F811 — for VAULT_DIR path resolution  
def config(): return _config  # noqa: E402, F811

from flask import jsonify as _jsonify  # noqa: E402, F811 — module-level reference
from .auth import _get_master_key, _get_encryptor as _ge  # noqa: E402, F811

def abort(code): return __import__('flask').abort(code)  # noqa: F821 — module-level reference  
def jsonify(d): return _jsonify(d)


from models import get_file as _get_file  # noqa: E402, F811
from models import clear_audio_cache, has_audio_cache, get_audio_cache_info  # noqa: E402, F811
