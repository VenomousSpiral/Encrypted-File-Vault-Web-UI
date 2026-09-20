"""User preferences & video settings helpers extracted from app.py.

Route handlers for:
  - /settings (page)
  - /api/preferences GET/POST
  - /api/video/<id>/prefs GET/POST  
  - /api/video/prefs/clear POST

Uses lazy imports for _get_master_key which accesses app-level state at runtime.
"""

import config as _config


# ── settings page (template rendering) ───────────────────────

def settings_page():
    """Render the user preferences/settings page."""
    from models import get_user_preferences  # noqa: F811
    from helpers.app_helpers_auth import _get_master_key  # noqa: F811
    from flask_login import current_user as cu  # noqa: F811

    mk = _get_master_key()
    prefs = get_user_preferences(cu.id, key=mk)
    return render_template('settings.html', prefs=prefs)


# ── user preferences API ────────────────────────────────────────

def api_get_preferences():
    """Get current user's stored preferences."""
    from models import get_user_preferences  # noqa: F811
    from helpers.app_helpers_auth import _get_master_key as gmk  # noqa: F811
    from flask_login import current_user as cu  # noqa: F811

    mk = gmk()
    return jsonify(get_user_preferences(cu.id, key=mk))


def api_set_preferences():
    """Update user's stored preferences."""
    from models import get_user_preferences, set_user_preferences  # noqa: F811
    from helpers.app_helpers_auth import _get_master_key as gmk  # noqa: F811
    from flask_login import current_user as cu  # noqa: F811

    mk = gmk()
    data = request().get_json(silent=True) or {}
    cur = get_user_preferences(cu.id, key=mk)

    audio_lang = data.get('default_audio_lang', cur['default_audio_lang']).strip()
    sub_lang = data.get('default_subtitle_lang', cur['default_subtitle_lang']).strip()
    sub_offset = float(data.get('default_subtitle_offset', cur['default_subtitle_offset']))
    skip_amt = int(data.get('skip_amount', cur['skip_amount']))

    sort_pref = data.get('sort_preference', cur['sort_preference']).strip()
    if sort_pref not in ('name', 'recent', 'added', 'size'):
        sort_pref = 'name'

    cache_mode = data.get('audio_cache_mode', cur.get('audio_cache_mode', 'keep')).strip().lower()
    if cache_mode not in ('keep', 'save', 'overwrite'):
        cache_mode = 'keep'

    show_dir_size = bool(data.get('show_dir_size', cur.get('show_dir_size', False)))

    set_user_preferences(
        cu.id, audio_lang, sub_lang, sub_offset,
        skip_amt, sort_pref, cache_mode, show_dir_size, key=mk,
    )
    return jsonify({'success': True})


# ── video preferences API ───────────────────────────────────────

def api_get_video_prefs(file_id):
    """Get per-file video playback position & subtitle offset."""
    from models import get_file, get_video_preferences  # noqa: F811
    from helpers.app_helpers_auth import _get_master_key as gmk  # noqa: F811
    from flask_login import current_user as cu  # noqa: F811

    f = get_file(file_id, cu.id, key=gmk())
    if not f:
        return abort(404)

    mk = gmk()
    return jsonify(get_video_preferences(cu.id, file_id, key=mk))


def api_set_video_prefs(file_id):
    """Update per-file video playback position & subtitle offset."""
    from models import get_file, set_video_preferences  # noqa: F811
    from helpers.app_helpers_auth import _get_master_key as gmk  # noqa: F811
    from flask_login import current_user as cu  # noqa: F811

    mk = gmk()
    f = get_file(file_id, cu.id, key=mk)
    if not f:
        return abort(404)

    data = request().get_json(silent=True) or {}
    allowed = {}
    if 'position' in data:
        allowed['position'] = float(data['position'])
    if 'sub_offset' in data:
        allowed['sub_offset'] = float(data['sub_offset'])

    if allowed:
        set_video_preferences(cu.id, file_id, key=mk, **allowed)

    return jsonify({'success': True})


def api_clear_video_prefs():
    """Clear all per-file video preferences for the current user."""
    from models import clear_all_video_preferences  # noqa: F811
    from flask_login import current_user as cu  # noqa: F811

    count = clear_all_video_preferences(cu.id)
    return jsonify({'success': True, 'cleared': count})


# ── Lazy imports (resolved at runtime inside request handlers) ───────
from helpers.app_helpers_auth import _get_master_key as _gmk  # noqa: E402, F811 — needed by api_get_video_prefs

import io as _io  # noqa: E402
uuid = __import__('uuid')  # noqa: E402, F811

from flask import request as _request  # noqa: E402, F811
from flask import jsonify as _jsonify  # noqa: E402, F811
from flask import abort as _abort  # noqa: E402, F811
from flask import render_template as _render_template  # noqa: E402, F811

def request(): return _request  # noqa: E402, F811 — module-level reference
def jsonify(d): return _jsonify(d)  # noqa: E402, F811
def abort(code): return _abort(code)  # noqa: E402, F811
render_template = _render_template  # noqa: E402, F811
