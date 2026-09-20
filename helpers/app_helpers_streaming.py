"""Streaming & download route handlers extracted from app.py.

Handles encrypted file streaming (with Range support) and ZIP folder downloads.
Uses lazy imports for _get_master_key, _get_encryptor which exist in the main
app module at runtime via helpers.app_helpers_auth.
"""

import logging as _logging
import os as _os

import config  # VAULT_DIR used throughout


def stream_file(file_id):
    """Stream a decrypted file. Supports HTTP Range for video seeking."""
    from models import get_file  # noqa: F811
    from flask_login import current_user as _current_user  # noqa: F811
    from helpers.app_helpers_auth import _get_master_key, _get_encryptor  # noqa: F811

    enc = _get_encryptor()
    if enc is None:
        return _abort(403)

    f = get_file(file_id, _current_user.id, key=_get_master_key())
    if not f or f['is_directory']:
        return _abort(404)

    vault_path = _os.path.join(config.VAULT_DIR, f['vault_filename'])
    if not _os.path.exists(vault_path):
        return _abort(404)

    file_size = f['size']
    mime_type = f.get('mime_type') or 'application/octet-stream'
    range_header = _request.headers.get('Range')

    _logging.getLogger('vault').debug(
        'Stream file %d (%s, %d B), Range: %s',
        file_id, mime_type, file_size, range_header)

    if range_header:
        rng = range_header.replace('bytes=', '').strip()
        parts = rng.split('-', 1)
        byte_start = int(parts[0]) if parts[0] else 0
        byte_end = int(parts[1]) if parts[1] else file_size - 1
        byte_end = min(byte_end, file_size - 1)
        length = byte_end - byte_start + 1

        resp = _Response(
            enc.decrypt_range(vault_path, byte_start, byte_end),
            status=206, mimetype=mime_type, direct_passthrough=True,
        )
        resp.headers['Content-Range'] = f'bytes {byte_start}-{byte_end}/{file_size}'
        resp.headers['Content-Length'] = length
        resp.headers['Accept-Ranges'] = 'bytes'
        resp.headers['Cache-Control'] = 'no-cache'
        return resp

    resp = _Response(
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
    from helpers.app_helpers_auth import _get_master_key, _get_encryptor  # noqa: F811

    enc = _get_encryptor()
    if enc is None:
        return _abort(403)

    f = get_file(file_id, _current_user.id, key=_get_master_key())
    if not f or f['is_directory']:
        return _abort(404)

    vault_path = _os.path.join(config.VAULT_DIR, f['vault_filename'])
    if not _os.path.exists(vault_path):
        return _abort(404)

    resp = _Response(
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
    from helpers.app_helpers_auth import _get_master_key, _get_encryptor  # noqa: F811

    enc = _get_encryptor()
    if enc is None:
        return _abort(403)

    mk = _get_master_key()
    owner_id = _current_user.id
    folder = get_file(folder_id, owner_id, key=mk)
    if not folder or not folder['is_directory']:
        return _abort(404)

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
        vault_path = _os.path.join(config.VAULT_DIR, item['vault_filename'])
        if not _os.path.exists(vault_path):
            continue
        zs.add(_decrypted_stream(vault_path), zip_path)

    disp_header = _encode_content_disposition(f'{folder["name"]}.zip')
    resp = _Response(zs, mimetype='application/zip', direct_passthrough=True)
    resp.headers['Content-Disposition'] = disp_header
    return resp


# Lazy imports for Flask objects — resolved at runtime inside request handlers.
from flask import request as _request  # noqa: E402, F811
from flask import Response as _Response  # noqa: E402, F811
from flask import abort as _abort  # noqa: E402, F811
# Lazy imports for third-party libraries used in route handlers.
from zipstream import ZipStream, ZIP_DEFLATED
import urllib.parse as _urllib_parse  # noqa: E402

def _encode_content_disposition(name: str) -> str:
    """Encode filename for HTTP Content-Disposition header (RFC 5987)."""
    safe = name.replace('\\', '/').replace('"', '\\"') 
    try:
        safe.encode('latin-1')
        return f'attachment; filename="{safe}"'
    except UnicodeEncodeError:
        utf8_name = _urllib_parse.quote(name)
        return f'attachment; filename=""; filename*=UTF-8\'{utf8_name}'
