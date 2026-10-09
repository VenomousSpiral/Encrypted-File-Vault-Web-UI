"""All file/vfs operations consolidated in one place.

Consolidated from: helpers/app_helpers_files.py (mkdir, upload, rename, move, delete, bulk ops, search, breadcrumbs).
Every function uses top-level imports for Flask objects and lazy internal imports 
for shared auth via core.auth._get_master_key / _get_encryptor.
"""

import config as _config  # noqa: E402, F811 — for VAULT_DIR path resolution
import os  # noqa: F401 — standard lib, available in all functions  
from flask import request, jsonify


# ── JSON API ─────────────────────────────────────────────────────────
def api_list_files():
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key
    from models import get_user_preferences, list_files, get_all_video_last_accessed, get_breadcrumbs, _compute_recursive_sizes

    parent_id = request.args.get('parent_id', None, type=int)
    uid = cu.id
    mk = _get_master_key()

    # Only compute recursive sizes if user has enabled this feature
    prefs = get_user_preferences(uid, key=mk)
    show_dir_size = bool(prefs.get('show_dir_size', False))
    size_map: dict[int, int] = {}
    if show_dir_size:
        size_map = _compute_recursive_sizes(uid, parent_id, key=mk)

    rows = list_files(uid, parent_id, key=mk)

    # Attach last_accessed from video_preferences for sort support
    accessed_map = get_all_video_last_accessed(uid, key=mk)

    file_list = []
    for r in rows:
        d = dict(r)
        d['last_accessed'] = accessed_map.get(d['id'], '')
        if show_dir_size and d['is_directory']:
            d['recursive_size'] = size_map.get(d['id'], 0)
        file_list.append(d)

    crumbs = get_breadcrumbs(uid, parent_id, key=mk)
    return jsonify({
        'files': file_list,
        'breadcrumbs': crumbs,
        'parent_id': parent_id,
    })


def api_search_files():
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key
    from models import search_files, get_all_video_last_accessed

    query = request.args.get('q', '').strip()
    if not query or len(query) < 1:
        return jsonify({'files': []})
    uid = cu.id
    mk = _get_master_key()
    # parent_id scopes search to a specific folder; None = root; 'all' = global
    raw_pid = request.args.get('parent_id', None)
    if raw_pid is None:
        parent_id = None          # root
    elif raw_pid == 'all':
        parent_id = 'all'         # global search (not currently used by UI)
    else:
        try:
            parent_id = int(raw_pid)
        except ValueError:
            parent_id = None
    results = search_files(uid, query, parent_id=parent_id, key=mk)

    # Attach last_accessed from encrypted video_preferences
    accessed_map = get_all_video_last_accessed(uid, key=mk)

    file_list = []
    for r in results:
        d = dict(r) if not isinstance(r, dict) else r
        d['last_accessed'] = accessed_map.get(d['id'], '')
        file_list.append(d)

    return jsonify({'files': file_list})


def api_list_folders():
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key
    from models import get_folders

    parent_id = request.args.get('parent_id', None, type=int)
    return jsonify({'folders': get_folders(cu.id, parent_id, key=_get_master_key()), 'parent_id': parent_id})


def api_folder_breadcrumbs(folder_id):
    """Get breadcrumb path to a folder (all ancestors including it)."""
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key
    from models import get_breadcrumbs

    try:
        breadcrumbs = get_breadcrumbs(cu.id, folder_id, key=_get_master_key())
        return jsonify({'breadcrumbs': breadcrumbs})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 400


def api_get_folder_parent(folder_id):
    """Get parent folder ID for a given folder (for 'up' navigation)."""
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key
    from models import get_folder_info

    info = get_folder_info(folder_id, cu.id, key=_get_master_key())
    if not info:
        return jsonify({'error': 'Folder not found'}), 404
    return jsonify({'parent_id': info['parent_id']})


def api_mkdir():
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key
    from models import create_file_record

    data = request.get_json(silent=True) or {}
    name = data.get('name', '').strip()
    parent_id = data.get('parent_id')

    if not name:
        return jsonify({'error': 'Name is required'}), 400
    if '/' in name or '\\' in name:
        return jsonify({'error': 'Name cannot contain slashes'}), 400
    try:
        fid = create_file_record(cu.id, parent_id, name, True, key=_get_master_key())
        return jsonify({'id': fid, 'name': name})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 400


def api_mkdirp():
    """Create a directory if it doesn't already exist (mkdir -p style)."""
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key
    from models import get_file_by_name, create_file_record

    data = request.get_json(silent=True) or {}
    name = data.get('name', '').strip()
    parent_id = data.get('parent_id')

    if not name:
        return jsonify({'error': 'Name is required'}), 400
    if '/' in name or '\\' in name:
        return jsonify({'error': 'Name cannot contain slashes'}), 400

    mk = _get_master_key()
    # Check if folder already exists
    existing = get_file_by_name(cu.id, parent_id, name, key=mk)
    if existing and existing['is_directory']:
        return jsonify({'id': existing['id'], 'name': name})

    try:
        fid = create_file_record(cu.id, parent_id, name, True, key=mk)
        return jsonify({'id': fid, 'name': name})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 400


def api_upload():
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key, _get_encryptor
    from models import get_file_by_name, create_file_record
    import uuid


    enc = _get_encryptor()
    if enc is None:
        return jsonify({'error': 'Vault is locked'}), 403

    parent_id = request.form.get('parent_id', None, type=int)
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    uploaded = request.files['file']
    if not uploaded.filename:
        return jsonify({'error': 'Empty filename'}), 400

    # Strip any folder path the browser may include (e.g. folder uploads)
    filename = os.path.basename(uploaded.filename)
    mime = (uploaded.content_type
            or mimetypes.guess_type(filename)[0]
            or 'application/octet-stream')

    # Actual file size (werkzeug stores large files on disk, seek is fine)
    uploaded.seek(0, 2)
    file_size = uploaded.tell()
    uploaded.seek(0)

    # Auto-rename on conflict: file.mp4 → file (1).mp4
    base_name = filename
    base, ext = os.path.splitext(filename)
    counter = 1
    mk = _get_master_key()
    while get_file_by_name(cu.id, parent_id, filename, key=mk):
        filename = f'{base} ({counter}){ext}'
        counter += 1

    vault_name = str(uuid.uuid4()) + '.enc'
    vault_path = os.path.join(_config.VAULT_DIR, vault_name)

    try:
        enc.encrypt_stream(uploaded, vault_path, file_size)
        fid = create_file_record(cu.id, parent_id, filename, False,
                                 vault_name, file_size, mime, key=mk)
        return jsonify({'id': fid, 'name': filename,
                        'size': file_size, 'mime_type': mime})
    except Exception as exc:
        if os.path.exists(vault_path):
            os.remove(vault_path)
        return jsonify({'error': str(exc)}), 500


def api_rename():
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key
    from models import rename_file, get_file

    data = request.get_json(silent=True) or {}
    fid = data.get('id')
    new_name = data.get('name', '').strip()
    if not fid or not new_name:
        return jsonify({'error': 'ID and name required'}), 400
    if '/' in new_name or '\\' in new_name:
        return jsonify({'error': 'Name cannot contain slashes'}), 400
    # Verify ownership
    f = get_file(fid, cu.id, key=_get_master_key())
    if not f:
        return jsonify({'error': 'Not found'}), 404
    try:
        rename_file(fid, new_name, key=_get_master_key())
        return jsonify({'success': True})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 400


def api_move():
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key
    from models import move_file, get_file

    data = request.get_json(silent=True) or {}
    fid = data.get('id')
    new_parent = data.get('parent_id')      # None ⇒ root
    if fid is None:
        return jsonify({'error': 'File ID required'}), 400
    # Verify ownership
    f = get_file(fid, cu.id, key=_get_master_key())
    if not f:
        return jsonify({'error': 'Not found'}), 404
    try:
        move_file(fid, new_parent, key=_get_master_key())
        return jsonify({'success': True})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 400


def api_delete():
    from flask_login import current_user as cu  # noqa: F811
    from models import delete_file_record
    from transcoder import destroy_session

    data = request.get_json(silent=True) or {}
    fid = data.get('id')
    if fid is None:
        return jsonify({'error': 'File ID required'}), 400

    vault_files = delete_file_record(fid, cu.id)
    destroy_session(fid)          # kill any active HLS session
    for vf in vault_files:
        p = os.path.join(_config.VAULT_DIR, vf)
        if os.path.exists(p):
            os.remove(p)
    return jsonify({'success': True})


def api_bulk_delete():
    from transcoder import destroy_session
    from flask_login import current_user as cu  # noqa: F811
    from models import delete_file_record

    data = request.get_json(silent=True) or {}
    ids = data.get('ids', [])
    if not ids or not isinstance(ids, list):
        return jsonify({'error': 'ids array required'}), 400
    deleted = 0
    for fid in ids:
        try:
            vault_files = delete_file_record(fid, cu.id)
            destroy_session(fid)
            for vf in vault_files:
                p = os.path.join(_config.VAULT_DIR, vf)
                if os.path.exists(p):
                    os.remove(p)
            deleted += 1
        except Exception:
            pass
    return jsonify({'success': True, 'deleted': deleted})


def api_bulk_move():
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key
    from models import get_file, move_file

    data = request.get_json(silent=True) or {}
    ids = data.get('ids', [])
    new_parent = data.get('parent_id')      # None ⇒ root
    if not ids or not isinstance(ids, list):
        return jsonify({'error': 'ids array required'}), 400
    mk = _get_master_key()
    moved = 0
    for fid in ids:
        f = get_file(fid, cu.id, key=mk)
        if not f:
            continue
        try:
            move_file(fid, new_parent, key=mk)
            moved += 1
        except Exception:
            pass
    return jsonify({'success': True, 'moved': moved})


def api_file_info(file_id):
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key
    from models import get_file

    f = get_file(file_id, cu.id, key=_get_master_key())
    if not f:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(dict(f))
