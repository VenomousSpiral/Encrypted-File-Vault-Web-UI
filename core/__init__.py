"""Core modules — consolidated from helpers/.

Public API re-exported for backward compatibility during transition.
New code should import directly from core.{module} instead of helpers.*

Module organization:
  - auth.py          : _get_master_key, _get_encryptor, admin_required (shared by EVERY route)
  - files_api.py     : All file/vfs operations (mkdir, upload, rename, move, delete, search...)
  - streaming.py     : File streaming + HLS endpoints (both serve files to client)
  - media_player.py  : Media browsing, sibling navigation, player/explorer pages
  - text_editor.py   : Text editing feature (editor, read/write/create/editable)
  - preferences.py   : User prefs, video prefs + CBZ reader/prefs
  - audio_reencode.py: Audio cache management + re-encoding tasks
  - users_api.py     : User CRUD and admin endpoints

Backward compat aliases — old helpers/ names still work during transition.
"""

# ── Auth (moved from app.py global scope → core/auth) ───────────────
from .auth import _get_master_key, _get_encryptor, admin_required  # noqa: F401

# ── File operations (consolidated into files_api) ───────────────────
from .files_api import (  # noqa: F401
    api_list_files, api_search_files, api_mkdir, api_upload,
    api_rename, api_move, api_delete, api_bulk_delete,
    api_folder_breadcrumbs, api_get_folder_parent,
    api_file_info,
)

# ── Streaming + HLS (consolidated into streaming) ───────────────────
from .streaming import download_file, download_folder  # noqa: F401

# ── Media player utilities (moved from media_player/media) ──────────
from .media_player import media_category, sort_files, collect_recursive  # noqa: F401

# ── Text editor (consolidated into text_editor) ─────────────────────
from .text_editor import editor as _ed, api_read_text as _artx, api_write_text as _awtx  # noqa: F401

# ── Audio re-encode (consolidated from audio_cache + reencode_tasks) ─
from .audio_reencode import get_audio_cache_info as _gaci  # noqa: F401

__all__ = [
    '_get_master_key', '_get_encryptor', 'admin_required',
    'api_list_files', 'media_category', 'sort_files', 'collect_recursive',
]
