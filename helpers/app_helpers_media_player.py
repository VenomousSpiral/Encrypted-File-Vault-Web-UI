"""Media player and sibling navigation helpers."""


def _media_category(mime: str) -> str:
    """Return a broad category string for grouping sibling navigation."""
    mime = (mime or '').lower()
    if mime.startswith('video/'):
        return 'video'
    if mime.startswith('audio/'):
        return 'audio'
    if mime.startswith('image/'):
        return 'image'
    if mime.startswith('text/') or mime in {
        'application/json', 'application/xml', 'application/javascript',
        'application/x-yaml', 'application/yaml', 'application/toml',
        'application/x-sh', 'application/x-shellscript',
        'application/sql', 'application/xhtml+xml', 'application/x-httpd-php',
    }:
        return 'text'
    if mime == 'application/pdf':
        return 'document'
    return 'other'


def _sort_files(files, sort_by='name'):
    """Sort a list of file dicts by the given preference."""
    import random as _random  # noqa: F401

    if sort_by == 'name':
        files.sort(key=lambda d: (d.get('name') or '').lower())
    elif sort_by in ('recent', 'added', 'size'):
        if sort_by == 'recent':
            files.sort(key=lambda d: (d.get('last_accessed') or ''), reverse=True)
        elif sort_by == 'added':
            files.sort(key=lambda d: (d.get('created_at') or ''), reverse=True)
        else:
            files.sort(key=lambda d: int(d.get('size') or 0), reverse=True)
    return files


def _collect_recursive(uid, parent_id, cat, mk, exclude_id=None):
    """Collect all non-directory files of a given category recursively."""
    from models import list_files as _list_files

    items = _list_files(uid, parent_id, key=mk)
    result = []
    for item in items:
        if item['is_directory']:
            result.extend(_collect_recursive(uid, item['id'], cat, mk, exclude_id))
        elif _media_category(item.get('mime_type')) == cat:
            if exclude_id is None or item['id'] != exclude_id:
                result.append(item)
    return result


def api_siblings(file_id):
    """Return prev/next file IDs and recursive total for same-type files."""
    import flask_login as _fl  # noqa: F401

    from models import get_file as _gf, list_files as _lf  # noqa: F821
    from helpers.app_helpers_auth import _get_master_key  # noqa: F821
    from models import get_user_preferences as _gup  # noqa: F401
    
    cu = _fl.current_user
    uid = cu.id
    mk = _get_master_key()
    f = _gf(file_id, uid, key=mk)

    if not f:
        return jsonify({'error': 'Not found'}), 404

    cat = _media_category(f.get('mime_type'))

    raw_sort = request().args.get('sort_by', '').strip().lower()
    if raw_sort in ('name', 'recent', 'added', 'size'):
        sort_by = raw_sort
    else:
        prefs = _gup(uid, key=mk)
        sort_by = (prefs.get('sort_preference') or 'name').strip().lower()
        if sort_by not in ('name', 'recent', 'added', 'size'):
            sort_by = 'name'

    raw_recurse = request().args.get('recurse', '').strip()
    do_recurse = False if raw_recurse in ('0', 'no', 'false') else True

    root_raw = request().args.get('root', None)
    root_id = f['parent_id']
    if root_raw is not None:
        root_id = None if root_raw in ('null', '') else int(root_raw)

    if do_recurse:
        all_recursive = _collect_recursive(uid, root_id, cat, mk)
        typed_collection = _sort_files(all_recursive, sort_by)
    else:
        direct_siblings = _lf(uid, f['parent_id'], key=mk)
        typed_collection = [s for s in direct_siblings if not s['is_directory'] and _media_category(s.get('mime_type')) == cat]
        typed_collection = _sort_files(typed_collection, sort_by)

    ids_in_order = [s['id'] for s in typed_collection]
    try:
        idx = ids_in_order.index(file_id)
    except ValueError:
        idx = -1

    prev_id = ids_in_order[idx - 1] if idx > 0 else None
    next_id = ids_in_order[idx + 1] if idx >= 0 and idx < len(ids_in_order) - 1 else None

    total_count = len(typed_collection)
    current_position = idx + 1 if idx >= 0 else 0

    return jsonify({
        'prev_id': prev_id,
        'next_id': next_id,
        'total': total_count,
        'position': current_position,
        'root_parent_id': root_id,
        'sort_by': sort_by,
        'recurse': do_recurse,
    })


def api_random_sibling(file_id):
    """Return a random file of the same type."""
    import flask_login as _fl  # noqa: F401

    from models import get_file as _gf, list_files as _lf  # noqa: F821
    from helpers.app_helpers_auth import _get_master_key  # noqa: F821
    
    cu = _fl.current_user
    uid = cu.id
    mk = _get_master_key()
    f = _gf(file_id, uid, key=mk)

    if not f:
        return jsonify({'error': 'Not found'}), 404

    cat = _media_category(f.get('mime_type'))

    raw_recurse = request().args.get('recurse', '').strip()
    do_recurse = True if raw_recurse not in ('0', 'no', 'false') else False

    root_raw = request().args.get('root', None)
    root_id = f['parent_id']
    if root_raw is not None:
        root_id = None if root_raw in ('null', '') else int(root_raw)

    if do_recurse:
        candidates = _collect_recursive(uid, root_id, cat, mk, exclude_id=file_id)
    else:
        direct_siblings = _lf(uid, f['parent_id'], key=mk)
        candidates = [s for s in direct_siblings 
                      if not s['is_directory'] and _media_category(s.get('mime_type')) == cat]

    candidates = [c for c in candidates if c['id'] != file_id]

    if not candidates:
        return jsonify({'file_id': None})

    import random as _random  # noqa: F401
    chosen = _random.choice(candidates)
    return jsonify({'file_id': chosen['id']})


# ── Lazy Flask global wrappers for request handlers ────────────────
from flask import jsonify as _jsonify, request as _request

def abort(code): return __import__('flask').abort(code)  # noqa: F821 — module-level reference
def jsonify(d): return _jsonify(d)




def explorer_page():
    """Render the file explorer HTML page."""
    from flask import render_template as _rt  # noqa: F821
    
    from helpers.app_helpers_auth import _get_master_key  # noqa: F821
    mk = _get_master_key()
    
    prefs = get_user_preferences(_cu.id, key=mk) if 'current_user' in dir() else {}

    return _rt('explorer.html', 
               sort_preference=prefs.get('sort_preference', 'name'),
               show_dir_size=bool(prefs.get('show_dir_size', False)))


def player_page(file_id):
    """Render the media player HTML page."""
    from flask import render_template as _rt  # noqa: F821
    
    from helpers.app_helpers_auth import _get_master_key  # noqa: F821
    mk = _get_master_key()
    
    from models import get_file as _gf  # noqa: F821
    f = _gf(file_id, _cu.id, key=mk)

    from models import get_user_preferences as _gup  # noqa: F401
    prefs = _gup(_cu.id, key=mk)
    from models import get_video_preferences as _gvp  # noqa: F401
    vprefs = _gvp(_cu.id, file_id, key=mk)
    
    return _rt('player.html', file=dict(f), prefs=prefs, vprefs=vprefs)


def request(): return __import__('flask').request
