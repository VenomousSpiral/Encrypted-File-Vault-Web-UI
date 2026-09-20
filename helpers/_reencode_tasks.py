"""Re-encoding task helpers.

Extracted from ``app_helpers_prefs.py`` — these functions use lazy internal imports
for names like ``_get_master_key`` that exist in the main app module at runtime.
"""
from flask import jsonify as _jsonify  # noqa: F401

def _update_size_for_file(mk, uid, fid, new_size):
    """Update file size and modified_at after a re-encode completes."""
    from models import get_db, _encrypt_value, encrypt_field
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    db = get_db()
    db.execute(
        'UPDATE files SET size = ?, modified_at = ? '
        'WHERE id = ? AND owner_id = ?',
        (_encrypt_value(mk, new_size), encrypt_field(mk, now), fid, uid),
    )
    db.commit()
    db.close()


def api_overwrite_audio(file_id):
    """Re-encode a video to H.265 (HEVC) + AAC stereo for better compression."""
    from flask import jsonify as _jsonify  # noqa: F811
    from models import get_file  # noqa: F811
    from flask_login import current_user as cu  # noqa: F811
    from helpers.app_helpers_auth import _get_master_key as gmk, _get_encryptor as gen  # noqa: F811

    enc = gen()
    if enc is None:
        return _jsonify({'success': False, 'error': 'Vault locked'}), 403

    mk = gmk()
    f = get_file(file_id, cu.id, key=mk)
    if not f or f['is_directory']:
        return _jsonify({'success': False, 'error': 'File not found'}), 404

    if not (f.get('mime_type') or '').startswith('video/'):
        return _jsonify({'success': False, 'error': 'Not a video file'}), 400

    uid = cu.id
    fid = file_id
    vault_fname = f['vault_filename']

    def update_size(new_size):
        _update_size_for_file(mk, uid, fid, new_size)

    from transcoder import submit_reencode

    result = submit_reencode(
        enc, vault_fname, fid,
        size_callback=update_size,
        file_name=f.get('name', ''),
    )
    if not result['accepted']:
        return _jsonify({'success': False, 'error': result['reason']}), 409

    return _jsonify({
        'success': True,
        'message': (
            'Re-encode queued (H.265 + AAC). '
            'You will be notified when it finishes.'
        ),
    })


def api_reencode_dir(dir_id):
    """Re-encode all video files in a directory (recursively) for browser playback."""
    from flask import jsonify as _jsonify  # noqa: F811
    from models import get_file, list_files  # noqa: F811
    from flask_login import current_user as cu  # noqa: F811
    from helpers.app_helpers_auth import _get_master_key as gmk, _get_encryptor as gen  # noqa: F811

    enc = gen()
    if enc is None:
        return _jsonify({'success': False, 'error': 'Vault locked'}), 403

    mk = gmk()
    f = get_file(dir_id, cu.id, key=mk)
    if not f or not f['is_directory']:
        return _jsonify({'success': False, 'error': 'Directory not found'}), 404

    uid = cu.id

    # Collect all video files recursively
    from helpers.app_helpers_media import _collect_recursive, _media_category as _cat
    videos = _collect_recursive(uid, dir_id, 'video', mk)
    if not videos:
        return _jsonify({
            'success': False,
            'error': 'No video files found in this directory',
        }), 400

    from transcoder import submit_reencode

    accepted = 0
    skipped = 0
    for v in videos:
        fid_inner = v['id']
        vault_fname = v['vault_filename']
        file_name = v.get('name', '')

        result = submit_reencode(
            enc, vault_fname, fid_inner,
            size_callback=lambda s, _fid=fid_inner: _update_size_for_file(mk, uid, _fid, s),
            file_name=file_name,
        )
        if result['accepted']:
            accepted += 1
        else:
            skipped += 1

    if accepted == 0:
        return _jsonify({
            'success': False,
            'error': f'All {skipped} video(s) are already queued or processing',
        }), 409

    msg = f'Queued {accepted} video file(s) for re-encode.'
    if skipped:
        msg += f' ({skipped} already queued — skipped)'

    return _jsonify({
        'success': True,
        'count': accepted,
        'skipped': skipped,
        'message': msg,
    })


def api_reencode_status():
    """Return and clear finished re-encode jobs (for toast notifications)."""
    from transcoder import pop_finished_jobs, get_reencode_status, get_queue_size

    finished = pop_finished_jobs()
    all_jobs = get_reencode_status()
    running = sum(1 for j in all_jobs if j['status'] == 'running')
    queued = sum(1 for j in all_jobs if j['status'] == 'queued')

    return _jsonify({
        'jobs': finished,
        'running': running,
        'queued': queued,
        'queue_size': get_queue_size(),
    })


def api_reencode_jobs():
    """Return all re-encode jobs (for the queue panel)."""
    from transcoder import get_reencode_status

    return _jsonify({'jobs': get_reencode_status()})


def api_reencode_clear():
    """Clear all finished re-encode jobs."""
    from transcoder import clear_finished_jobs

    cleared = clear_finished_jobs()
    return _jsonify({'success': True, 'cleared': cleared})
