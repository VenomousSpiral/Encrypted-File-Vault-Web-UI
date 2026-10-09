"""Media browsing and navigation utilities consolidated in one place.

Consolidated from: helpers/app_helpers_media_player.py (sibling nav, player/explorer pages)
+ helpers/app_helpers_media.py (media_category, sort_files, collect_recursive).

All media-related operations together — sibling navigation, random sibling, 
player page, explorer page, recursive collection, and file categorization.
"""


# ── Media category/sort utilities (from helpers/app_helpers_media) ────────────

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


def _sort_files(files: list, sort_by: str = 'name') -> list:
    """Sort a list of file dicts by the given preference."""
    from models import list_files  # noqa: F811
    
    if sort_by == 'name':
        files.sort(key=lambda d: (d.get('name') or '').lower())
    elif sort_by in ('recent', 'added', 'size'):
        if sort_by == 'recent':
            files.sort(key=lambda d: (d.get('last_accessed') or ''), reverse=True)
        elif sort_by == 'added':
            files.sort(key=lambda d: (d.get('created_at') or ''), reverse=True)
        else:
            # size descending
            files.sort(key=lambda d: int(d.get('size') or 0), reverse=True)
    return files


def _collect_recursive(
    uid: int,
    parent_id: int | None,
    cat: str,
    mk,  # master key — opaque bytes
    *,
    exclude_id: int | None = None,
) -> list[dict]:
    """Collect all non-directory files of a given category recursively."""
    from models import list_files as _list_files

    items = _list_files(uid, parent_id, key=mk)
    result: list[dict] = []
    for item in items:
        if item['is_directory']:
            result.extend(_collect_recursive(
                uid, item['id'], cat, mk, exclude_id=exclude_id,
            ))
        elif _media_category(item.get('mime_type')) == cat:
            if exclude_id is None or item['id'] != exclude_id:
                result.append(item)
    return result


# Public aliases (for new callers; internal code keeps using _prefixed)
media_category = _media_category
sort_files = _sort_files
collect_recursive = _collect_recursive


# ── Media player routes (from helpers/app_helpers_media_player.py) ───────────

def api_siblings(file_id):
    """Return prev/next file IDs and recursive total for same-type files."""
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key
    from models import get_file, list_files, get_user_preferences

    uid = cu.id
    mk = _get_master_key()
    f = get_file(file_id, uid, key=mk)

    if not f:
        return jsonify({'error': 'Not found'}), 404

    cat = media_category(f.get('mime_type'))

    raw_sort = request().args.get('sort_by', '').strip()
    if raw_sort in ('name', 'recent', 'added', 'size'):
        sort_by = raw_sort
    else:
        prefs = get_user_preferences(uid, key=mk)
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
        all_recursive = collect_recursive(uid, root_id, cat, mk)
        typed_collection = sort_files(all_recursive, sort_by)
    else:
        direct_siblings = list_files(uid, f['parent_id'], key=mk)
        typed_collection = [s for s in direct_siblings if not s['is_directory'] and media_category(s.get('mime_type')) == cat]
        typed_collection = sort_files(typed_collection, sort_by)

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
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key
    from models import get_file, list_files

    uid = cu.id
    mk = _get_master_key()
    f = get_file(file_id, uid, key=mk)

    if not f:
        return jsonify({'error': 'Not found'}), 404

    cat = media_category(f.get('mime_type'))

    raw_recurse = request().args.get('recurse', '').strip()
    do_recurse = True if raw_recurse not in ('0', 'no', 'false') else False

    root_raw = request().args.get('root', None)
    root_id = f['parent_id']
    if root_raw is not None:
        root_id = None if root_raw in ('null', '') else int(root_raw)

    if do_recurse:
        candidates = collect_recursive(uid, root_id, cat, mk, exclude_id=file_id)
    else:
        direct_siblings = list_files(uid, f['parent_id'], key=mk)
        candidates = [s for s in direct_siblings 
                      if not s['is_directory'] and media_category(s.get('mime_type')) == cat]

    candidates = [c for c in candidates if c['id'] != file_id]

    if not candidates:
        return jsonify({'file_id': None})

    import random  # noqa: F811
    chosen = random.choice(candidates)
    return jsonify({'file_id': chosen['id']})


def explorer_page():
    """Render the file explorer HTML page."""
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key
    from models import get_user_preferences

    mk = _get_master_key()
    uid = cu.id
    prefs = get_user_preferences(uid, key=mk)

    return render_template('explorer.html', 
                           sort_preference=prefs.get('sort_preference', 'name'),
                           show_dir_size=bool(prefs.get('show_dir_size', False)))


def player_page(file_id):
    """Render the media player HTML page."""
    from flask_login import current_user as cu  # noqa: F811
    from .auth import _get_master_key
    from models import get_file, get_user_preferences, get_video_preferences

    mk = _get_master_key()
    uid = cu.id
    
    f = get_file(file_id, uid, key=mk)
    if not f:
        return abort(404)

    prefs = get_user_preferences(uid, key=mk)
    vprefs = get_video_preferences(uid, file_id, key=mk)
    
    return render_template('player.html', file=dict(f), prefs=prefs, vprefs=vprefs)


# ── Lazy Flask global wrappers for request handlers ────────────────

from flask import jsonify as _jsonify, render_template as _render_template  # noqa: E402, F811 — module-level reference
def abort(code): return __import__('flask').abort(code)  # noqa: F821 — module-level reference  
def jsonify(d): return _jsonify(d)
request = lambda: __import__('flask').request
def render_template(tmpl, **kw):
    """Lazy import wrapper for Flask's render_template."""
    return _render_template(tmpl, **kw)
