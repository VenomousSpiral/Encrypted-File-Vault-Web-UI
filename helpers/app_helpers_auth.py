"""Auth helpers extracted from app.py.

Shared utility functions for authentication and cross-module state access:
  - admin_required decorator  
  - _get_encryptor() / _get_master_key() helper functions
  - app_state() — unified lazy accessor for all app-level mutable state
  
The actual `_user_keys` dict is defined in app.py and accessed via lazy import 
of the main module to avoid circular dependency at load time. All helpers use
app_state() or direct accessors from this module when they need app-level data.
"""

from functools import wraps as _wraps
from flask_login import login_required as _login_required, current_user


def admin_required(f):
    """Decorator: require logged-in admin user."""
    @_wraps(f)
    @_login_required  
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            from flask import abort
            abort(403)
        return f(*args, **kwargs)
    return wrapped


def _get_app_state():
    """Return the app-level state dict (lazy lookup).

    Returns a mapping with keys: '_user_keys' and 'app'.
    Resolved at runtime inside request handlers to avoid circular imports.
    """
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
    if not current_user.is_authenticated:
        return None
    state = _get_app_state()
    entry = state['_user_keys'].get(current_user.id)
    return entry[1] if entry else None


def _get_master_key():
    """Return the raw master key for the currently logged-in user."""
    if not current_user.is_authenticated:
        return None
    state = _get_app_state()
    entry = state['_user_keys'].get(current_user.id)
    return entry[0] if entry else None
