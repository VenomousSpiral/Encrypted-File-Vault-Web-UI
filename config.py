"""Configuration for the Encrypted Vault server."""

import os

# Load .env file (simple parser — no extra dependency)
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
if os.path.exists(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if not _line or _line.startswith('#') or '=' not in _line:
                continue
            _k, _v = _line.split('=', 1)
            os.environ.setdefault(_k.strip(), _v.strip())

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Resolve path-based env vars relative to BASE_DIR so they are always absolute.
# This fixes the bug where a value like "./data/" in .env would resolve against
# the process CWD instead of the project root (causing vault files to appear
# wherever Flask was started from, e.g. ~ when run via `python app.py` there).
def _resolve_path(key):
    val = os.environ.get(key, '')
    if not val:
        return ''
    # If it is already absolute leave as-is; otherwise make relative to BASE_DIR
    path = val if os.path.isabs(val) else os.path.join(BASE_DIR, val)
    return os.path.normpath(path)

# DATA_DIR holds the vault and database — defaults to ./data (resolved relative to BASE_DIR)
DATA_DIR = _resolve_path('DATA_DIR') or os.path.join(BASE_DIR, 'data')
VAULT_DIR = os.path.join(DATA_DIR, 'vault')
DB_PATH = os.path.join(DATA_DIR, 'vault.db')

# Server
HOST = os.environ.get('HOST', '0.0.0.0')
PORT = int(os.environ.get('PORT', '5575'))
DEBUG = os.environ.get('DEBUG', 'false').lower() in ('true', '1', 'yes')

# 1 MB encryption chunks — good balance between seek granularity and throughput
CHUNK_SIZE = int(os.environ.get('CHUNK_SIZE_MB', '1')) * 1024 * 1024

# Allow uploads up to 100 GB
MAX_CONTENT_LENGTH = int(os.environ.get('MAX_UPLOAD_GB', '100')) * 1024 * 1024 * 1024

# Temp directory for HLS transcoding (set to /dev/shm for RAM-only)
TEMP_DIR = _resolve_path('TEMP_DIR')

# FFmpeg / ffprobe paths (leave blank to use system PATH)
FFMPEG_PATH = os.environ.get('FFMPEG_PATH', '') or 'ffmpeg'
FFPROBE_PATH = os.environ.get('FFPROBE_PATH', '') or 'ffprobe'
