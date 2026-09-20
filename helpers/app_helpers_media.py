"""Media player helpers extracted from app.py.

Pure functions used by the media player, siblings navigation, and random sibling features.
No Flask context required — they call models directly like the rest of app.py does.
"""

from models import list_files


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
    """Sort a list of file dicts by the given preference.

    Returns files sorted in ascending order so prev/next indices work correctly.
    For 'recent' and 'added', descending means newest first (reverse=True).
    For 'size', largest first (descending).
    """
    if sort_by == 'name':
        # Ascending alphabetical
        files.sort(key=lambda d: (d.get('name') or '').lower())
    elif sort_by in ('recent', 'added', 'size'):
        # Descending = newest/largest first, so we reverse for ascending prev/next logic
        if sort_by == 'recent':
            files.sort(key=lambda d: (d.get('last_accessed') or ''), reverse=True)
        elif sort_by == 'added':
            files.sort(key=lambda d: (d.get('created_at') or ''), reverse=True)
        else:
            # size descending
            files.sort(key=lambda d: int(d.get('size') or 0), reverse=True)
    return files


def _collect_recursive(uid, parent_id, cat, mk, exclude_id=None):
    """Collect all non-directory files of a given category recursively."""
    items = list_files(uid, parent_id, key=mk)
    result: list[dict] = []
    for item in items:
        if item['is_directory']:
            result.extend(_collect_recursive(uid, item['id'], cat, mk, exclude_id))
        elif _media_category(item.get('mime_type')) == cat:
            if exclude_id is None or item['id'] != exclude_id:
                result.append(item)
    return result
