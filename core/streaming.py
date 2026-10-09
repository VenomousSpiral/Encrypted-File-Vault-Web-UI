"""Stream + HLS logic consolidated into one module.

Consolidated from: helpers/app_helpers_streaming.py (stream_file, download_file, download_folder)
+ helpers/app_helpers_hls.py (_get_or_start_session, all HLS endpoints).

Single responsibility: serving files to client — both regular streaming and HLS are file-serving.
"""

import logging as _logging
import math as _math
import os as _os

logger = _logging.getLogger('vault')


# ── Streaming & download (from helpers/app_helpers_streaming) ────────────────

def stream_file(file_id):
    """Stream a decrypted file. Supports HTTP Range for video seeking."""
    from models import get_file  # noqa: F811
    from flask_login import current_user as _current_user  # noqa: F811
    from .auth import _get_master_key, _get_encryptor

    enc = _get_encryptor()
    if enc is None:
        return abort(403)

    f = get_file(file_id, _current_user.id, key=_get_master_key())
    if not f or f['is_directory']:
        return abort(404)

    vault_path = _os.path.join(_config.VAULT_DIR, f['vault_filename'])
    if not _os.path.exists(vault_path):
        return abort(404)

    file_size = f['size']
    mime_type = f.get('mime_type') or 'application/octet-stream'
    range_header = _request.headers.get('Range')

    logger.debug(
        'Stream file %d (%s, %d B), Range: %s',
        file_id, mime_type, file_size, range_header)

    if range_header:
        rng = range_header.replace('bytes=', '').strip()
        parts = rng.split('-', 1)
        byte_start = int(parts[0]) if parts[0] else 0
        byte_end = int(parts[1]) if parts[1] else file_size - 1
        byte_end = min(byte_end, file_size - 1)
        length = byte_end - byte_start + 1

        resp = Response(
            enc.decrypt_range(vault_path, byte_start, byte_end),
            status=206, mimetype=mime_type, direct_passthrough=True,
        )
        resp.headers['Content-Range'] = f'bytes {byte_start}-{byte_end}/{file_size}'
        resp.headers['Content-Length'] = length
        resp.headers['Accept-Ranges'] = 'bytes'
        resp.headers['Cache-Control'] = 'no-cache'
        return resp

    resp = Response(
        enc.decrypt_full(vault_path), status=200, mimetype=mime_type, direct_passthrough=True,
    )
    resp.headers['Content-Length'] = file_size
    resp.headers['Accept-Ranges'] = 'bytes'
    resp.headers['Cache-Control'] = 'no-cache'
    return resp


def download_file(file_id):
    """Like stream but forces a download via Content-Disposition."""
    from models import get_file  # noqa: F811
    from flask_login import current_user as _current_user  # noqa: F811
    from .auth import _get_master_key, _get_encryptor

    enc = _get_encryptor()
    if enc is None:
        return abort(403)

    f = get_file(file_id, _current_user.id, key=_get_master_key())
    if not f or f['is_directory']:
        return abort(404)

    vault_path = _os.path.join(_config.VAULT_DIR, f['vault_filename'])
    if not _os.path.exists(vault_path):
        return abort(404)

    resp = Response(
        enc.decrypt_full(vault_path), mimetype=f.get('mime_type') or 'application/octet-stream', direct_passthrough=True,
    )
    disp_header = _encode_content_disposition(f['name'])
    resp.headers['Content-Disposition'] = disp_header
    resp.headers['Content-Length'] = f['size']
    return resp


def download_folder(folder_id):
    """Download an entire folder as a streamed ZIP archive."""
    from models import get_file, list_files  # noqa: F811
    from flask_login import current_user as _current_user  # noqa: F811
    from .auth import _get_master_key, _get_encryptor

    enc = _get_encryptor()
    if enc is None:
        return abort(403)

    mk = _get_master_key()
    owner_id = _current_user.id
    folder = get_file(folder_id, owner_id, key=mk)
    if not folder or not folder['is_directory']:
        return abort(404)

    def _collect_files(parent_id, prefix):
        items = list_files(owner_id, parent_id, key=mk)
        for item in items:
            path = prefix + item['name']
            if item['is_directory']:
                yield from _collect_files(item['id'], path + '/')
            else:
                yield (path, item)

    def _decrypted_stream(vault_path):
        for chunk in enc.decrypt_full(vault_path):
            yield chunk

    zs = ZipStream(compress_type=ZIP_DEFLATED)
    for zip_path, item in _collect_files(folder_id, ''):
        vault_path = _os.path.join(_config.VAULT_DIR, item['vault_filename'])
        if not _os.path.exists(vault_path):
            continue
        zs.add(_decrypted_stream(vault_path), zip_path)

    disp_header = _encode_content_disposition(f'{folder["name"]}.zip')
    resp = Response(zs, mimetype='application/zip', direct_passthrough=True)
    resp.headers['Content-Disposition'] = disp_header
    return resp


# ── HLS streaming (from helpers/app_helpers_hls.py) ───────────────────────

def _get_or_start_session(file_id):
    """Helper: get/create an HLS session for file_id, or abort."""
    from models import get_file, get_user_preferences, get_audio_cache_info
    from .auth import _get_encryptor as _ge, _get_master_key  # noqa: F821
    from flask_login import current_user
    from transcoder import get_session as get_hls_session

    enc = _ge()
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
    from flask import url_for as _url_for

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
    cors_headers = {
        'Access-Control-Allow-Origin': '*',
        'Vary': 'Origin',
    }
    return Response(body, mimetype='application/vnd.apple.mpegurl',
                    headers={**cors_headers, **{'Cache-Control': 'no-cache'}})


def api_hls_video_playlist(file_id):
    """Generate the video-only HLS media playlist."""
    from flask import url_for as _url_for

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
    cors_headers = {
        'Access-Control-Allow-Origin': '*',
        'Vary': 'Origin',
    }
    return Response(body, mimetype='application/vnd.apple.mpegurl',
                    headers={**cors_headers, **{'Cache-Control': 'no-cache'}})


def api_hls_audio_playlist(file_id, track):
    """Generate an audio-track HLS media playlist."""
    from flask import url_for as _url_for

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
    cors_headers = {
        'Access-Control-Allow-Origin': '*',
        'Vary': 'Origin',
    }
    return Response(body, mimetype='application/vnd.apple.mpegurl',
                    headers={**cors_headers, **{'Cache-Control': 'no-cache'}})


def api_hls_subtitle_playlist(file_id, track):
    """Generate a subtitle HLS playlist (single VTT file)."""
    from flask import url_for as _url_for

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

    cors_headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Expose-Headers': 'Content-Length',
        'Vary': 'Origin',
    }
    mime_type = 'video/mp2t' if stream == 'video' else 'audio/mp2t'
    return Response(data, mimetype=mime_type,
                    headers={**cors_headers, **{'Cache-Control': 'no-cache'}})


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


# ── Helpers (shared between streaming and HLS) ───────────────────────

def _encode_content_disposition(name: str) -> str:
    """Encode filename for HTTP Content-Disposition header (RFC 5987)."""
    import urllib.parse as _urllib_parse  # noqa: E402, F811
    
    safe = name.replace('\\', '/').replace('"', '\\"') 
    try:
        safe.encode('latin-1')
        return f'attachment; filename="{safe}"'
    except UnicodeEncodeError:
        utf8_name = _urllib_parse.quote(name)
        return f'attachment; filename=""; filename*=UTF-8\'{utf8_name}'


# ── Lazy imports (resolved at runtime inside request handlers) ───────

from flask import request as _request  # noqa: E402, F811 — module-level reference

import config as _config  # noqa: E402, F811
from zipstream import ZipStream, ZIP_DEFLATED  # noqa: E402, F811 — lazy third-party lib for streaming + HLS

from flask import abort as _abort  # noqa: E402, F811
def abort(code): return _abort(code)

from flask import Response  # noqa: E402, F811
from flask import jsonify as _jsonify  # noqa: E402, F811
def jsonify(d): return _jsonify(d)
