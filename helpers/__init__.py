"""Encrypted File Vault helper modules.

Public API — route handlers extracted from app.py, grouped by feature area.
For new code (CBZ reader, etc.), add your functions to the appropriate module
and export them here so tests and other code can import cleanly.
"""

from .app_helpers_auth import _get_encryptor, _get_master_key, admin_required  # noqa: F401
from .app_helpers_files import (  # noqa: F401
    api_list_files, api_search_files, api_mkdir, api_upload,
    api_rename, api_move, api_delete, api_bulk_delete,
)
from .app_helpers_hls import _get_or_start_session  # noqa: F401
from .app_helpers_media_player import (  # noqa: F401
    api_siblings, api_random_sibling, explorer_page as media_explorer,
)
from .app_helpers_text import (  # noqa: F401
    editor, api_read_text, api_write_text, api_create_text, api_is_editable,
)
from .app_helpers_users import (  # noqa: F401
    api_export_keys, api_list_users, api_create_user,
    api_delete_user, api_reset_password, api_toggle_admin,
    api_change_password,
)
from .app_helpers_streaming import download_file, download_folder  # noqa: F401
from ._prefs_settings import (  # noqa: F401
    api_get_preferences, api_set_preferences,
    api_get_video_prefs, api_set_video_prefs, api_clear_video_prefs,
)
from .app_helpers_media import media_category, sort_files, collect_recursive  # noqa: F401

__all__ = [
    '_get_encryptor', '_get_master_key', 'admin_required',
    'api_export_keys',
    'api_list_files', 'api_search_files', 'api_mkdir', 'api_upload',
    'api_rename', 'api_move', 'api_delete', 'api_bulk_delete',
    '_get_or_start_session',
    'media_category', 'sort_files', 'collect_recursive',
    'api_siblings', 'api_random_sibling', 'media_explorer',
    'editor', 'api_read_text', 'api_write_text', 'api_create_text',
    'api_is_editable',
    'api_list_users', 'api_create_user', 'api_delete_user',
    'api_reset_password', 'api_toggle_admin', 'api_change_password',
    'api_get_preferences', 'api_set_preferences',
    'api_get_video_prefs', 'api_set_video_prefs', 'api_clear_video_prefs',
]
