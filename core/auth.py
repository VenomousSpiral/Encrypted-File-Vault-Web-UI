"""Auth infrastructure — shared by every route.

Consolidated from: app.py (User class, _get_master_key/_encryptor) + helpers/app_helpers_auth.py (admin_required).

Provides the universal auth primitives that any module can import without
worrying about circular dependencies or importing from app.py's global scope.
"""

from functools import wraps as _wraps


# ── admin_required decorator (moved from helpers/app_helpers_auth) ────────────────

def admin_required(f):
    """Decorator: require logged-in admin user."""
    @_wraps(f)
    def wrapped(*args, **kwargs):
        from flask_login import current_user as _cu  # noqa: F811
        if not _cu.is_authenticated or not _cu.is_admin:
            from flask import abort
            abort(403)
        return f(*args, **kwargs)
    return wrapped


# ── Lazy accessors for app-level state (avoids circular imports) ─────────────────

def _get_app_state():
    """Return the app-level state dict (lazy lookup at runtime)."""
    try:
        import app as _app_mod  # type: ignore
        return {
            '_user_keys': getattr(_app_mod, '_user_keys', {}),
            'app': _app_mod.app if hasattr(_app_mod, 'app') else None,
        }
    except Exception:
        return {'_user_keys': {}, 'app': None}


def _get_encryptor():
    """Return the ChunkEncryptor for the currently logged-in user, or None."""
    from flask_login import current_user as _cu  # noqa: F811

    if not _cu.is_authenticated:
        return None
    state = _get_app_state()
    entry = state['_user_keys'].get(_cu.id)
    return entry[1] if entry else None


def _get_master_key():
    """Return the raw master key for the currently logged-in user."""
    from flask_login import current_user as _cu  # noqa: F811

    if not _cu.is_authenticated:
        return None
    state = _get_app_state()
    entry = state['_user_keys'].get(_cu.id)
    return entry[0] if entry else None
