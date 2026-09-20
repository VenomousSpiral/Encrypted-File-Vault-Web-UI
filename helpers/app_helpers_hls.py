"""HLS streaming helpers extracted from app.py.

Contains:
  - _get_or_start_session() — shared session factory used by all HLS endpoints
  - api_hls_status, api_hls_master, api_hls_video_playlist, etc. — playlist generation & segments

All route handlers use lazy imports for Flask objects and app-level auth helpers.
"""

import logging as _logging

logger = _logging.getLogger('vault')

from flask import abort


def _get_or_start_session(file_id):
    """Helper: get/create an HLS session for file_id, or abort.

    Called from within a Flask request context where app-level helpers
    (_get_encryptor, _get_master_key) and current_user are available.
    
    Uses lazy imports at runtime to avoid circular dependency issues
    between this module and app.py during import-time loading.
    """
    # Lazy imports — resolved when called inside a request handler,
    # by which point all modules have finished importing.
    from models import get_file, get_user_preferences, get_audio_cache_info
    from helpers.app_helpers_auth import _get_encryptor, _get_master_key  # noqa: F821
    from flask_login import current_user
    from transcoder import get_session as get_hls_session

    enc = _get_encryptor()  # defined in app.py — available at runtime
    if enc is None:
        abort(403)
    f = get_file(file_id, current_user.id, key=_get_master_key())
    if not f or f['is_directory']:
        abort(404)
    if not (f['mime_type'] or '').startswith('video/'):
        abort(400)
    mk = _get_master_key()  # defined in app.py — available at runtime
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

        def _do_overwrite(new_size):
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

        overwrite_cb = _do_overwrite

    sess = get_hls_session(file_id, encryptor=enc,
                           vault_filename=f['vault_filename'],
                           preferred_audio_lang=audio_lang,
                           cache_mode=cache_mode,
                           cached_tracks=cached_tracks,
                           overwrite_callback=overwrite_cb)
    if sess is None:
        return _abort(500)
    return sess


def api_hls_status(file_id):
    """Return session readiness and progress (for the loading overlay)."""
    import math as _math  # noqa: F811
    from helpers.app_helpers_auth import _get_master_key  # noqa: F811

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


def api_hls_master(file_id):
    """Generate and serve the HLS master playlist (blocks until probe done)."""
    from flask import url_for as _url_for  # noqa: F811

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
        uri = _url_for('api_hls_audio_playlist', file_id=file_id,
                       track=t['track_index'])
        lines.append(
            f'#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="audio",'
            f'NAME="{name}",LANGUAGE="{lang}",'
            f'DEFAULT={default},AUTOSELECT=YES,URI="{uri}"')

    # Subtitle renditions
    for t in subtitle_tracks:
        lang = t['language'] or 'und'
        name = t['label'] or t['language'] or f"Subtitle {t['track_index']}"
        uri = _url_for('api_hls_subtitle_playlist', file_id=file_id,
                       track=t['track_index'])
        lines.append(
            f'#EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID="subs",'
            f'NAME="{name}",LANGUAGE="{lang}",'
            f'DEFAULT=NO,AUTOSELECT=NO,URI="{uri}"')

    # Stream inf
    attrs = 'BANDWIDTH=5000000'
    if audio_tracks:
        attrs += ',AUDIO="audio"'
    if subtitle_tracks:
        attrs += ',SUBTITLES="subs"'
    lines.append(f'#EXT-X-STREAM-INF:{attrs}')
    lines.append(_url_for('api_hls_video_playlist', file_id=file_id))

    body = '\n'.join(lines) + '\n'
    return Response(body, mimetype='application/vnd.apple.mpegurl',
                    headers={'Cache-Control': 'no-cache'})


def api_hls_video_playlist(file_id):
    """Generate the video-only HLS media playlist."""
    import math as _math  # noqa: F811
    from flask import url_for as _url_for  # noqa: F811

    sess = _get_or_start_session(file_id)
    if not sess.is_ready():
        sess.wait_ready(timeout=120)

    durations = sess.get_segment_durations('video', 0)
    max_dur = max(durations) if durations else 10
    lines = [
        '#EXTM3U',
        '#EXT-X-VERSION:3',
        f'#EXT-X-TARGETDURATION:{_math.ceil(max_dur)}',
        '#EXT-X-PLAYLIST-TYPE:VOD',
    ]
    for i, dur in enumerate(durations):
        lines.append(f'#EXTINF:{dur:.6f},')
        lines.append(_url_for('api_hls_segment', file_id=file_id,
                             stream='video', track=0, seg_index=i))
    lines.append('#EXT-X-ENDLIST')

    body = '\n'.join(lines) + '\n'
    return Response(body, mimetype='application/vnd.apple.mpegurl',
                    headers={'Cache-Control': 'no-cache'})


def api_hls_audio_playlist(file_id, track):
    """Generate an audio-track HLS media playlist."""
    import math as _math  # noqa: F811
    from flask import url_for as _url_for  # noqa: F811

    sess = _get_or_start_session(file_id)
    if not sess.is_ready():
        sess.wait_ready(timeout=120)

    durations = sess.get_segment_durations('audio', track)
    max_dur = max(durations) if durations else 10
    lines = [
        '#EXTM3U',
        '#EXT-X-VERSION:3',
        f'#EXT-X-TARGETDURATION:{_math.ceil(max_dur)}',
        '#EXT-X-PLAYLIST-TYPE:VOD',
    ]
    for i, dur in enumerate(durations):
        lines.append(f'#EXTINF:{dur:.6f},')
        lines.append(_url_for('api_hls_segment', file_id=file_id,
                             stream='audio', track=track, seg_index=i))
    lines.append('#EXT-X-ENDLIST')

    body = '\n'.join(lines) + '\n'
    return Response(body, mimetype='application/vnd.apple.mpegurl',
                    headers={'Cache-Control': 'no-cache'})


def api_hls_subtitle_playlist(file_id, track):
    """Generate a subtitle HLS playlist (single VTT file)."""
    from flask import url_for as _url_for  # noqa: F811

    sess = _get_or_start_session(file_id)
    if not sess.is_ready():
        sess.wait_ready(timeout=120)

    duration = sess.duration or 99999
    lines = [
        '#EXTM3U',
        '#EXT-X-VERSION:3',
        f'#EXT-X-TARGETDURATION:{_math.ceil(duration)}',
        '#EXT-X-PLAYLIST-TYPE:VOD',
        f'#EXTINF:{duration:.6f},',
        _url_for('api_hls_subtitle_file', file_id=file_id, track=track),
        '#EXT-X-ENDLIST',
    ]

    body = '\n'.join(lines) + '\n'
    return Response(body, mimetype='application/vnd.apple.mpegurl',
                    headers={'Cache-Control': 'no-cache'})


def api_hls_segment(file_id, stream, track, seg_index):
    """Serve a single HLS segment (blocks until FFmpeg writes it)."""
    sess = _get_or_start_session(file_id)
    if not sess.is_ready():
        sess.wait_ready(timeout=120)

    data = sess.get_segment(stream, track, seg_index, timeout=60)
    if data is None:
        return abort(404)

    mime_type = 'video/mp2t' if stream == 'video' else 'audio/mp2t'
    return Response(data, mimetype=mime_type,
                    headers={'Cache-Control': 'no-cache'})


def api_hls_subtitle_file(file_id, track):
    """Serve a WebVTT subtitle file from the session cache."""
    sess = _get_or_start_session(file_id)
    if not sess.is_ready():
        sess.wait_ready(timeout=120)

    vtt = sess.get_subtitle(track)
    if vtt is None:
        return abort(404)
    return Response(vtt, mimetype='text/vtt',
                    headers={'Cache-Control': 'no-cache'})


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


# ── Lazy imports (resolved at runtime inside request handlers) ───────
from flask import abort as _abort  # noqa: E402, F811
from flask import Response  # noqa: E402, F811
from flask import jsonify as _jsonify  # noqa: E402, F811
def abort(code): return _abort(code)
def jsonify(d): return _jsonify(d)

# Import app-level auth helpers for use in functions.
from helpers.app_helpers_auth import (  # noqa: E402, F811
    _get_master_key as gmk,
    _get_encryptor as gen,
)
