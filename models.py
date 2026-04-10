"""
SQLite-backed metadata store for the Encrypted Vault.

Tables
──────
config   – key/value pairs (flask secret, etc.)
users    – multiple users, each with their own independent encryption key
files    – virtual filesystem tree, per-user (owner_id isolation)

Sensitive fields (file names, mime types, sizes, timestamps, user
preferences, video playback state) are AES-256-GCM encrypted at the
application level using each user's per-user master key.
No separate database key is needed — your login password is the key.
"""

import hashlib
import hmac
import json
import os
import sqlite3

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import DB_PATH

_NONCE_SIZE = 12


# ── field-level encryption helpers ──────────────────────────────────
def encrypt_field(key: bytes, plaintext: str) -> bytes:
    """Encrypt a string → nonce(12) + ciphertext + tag(16)."""
    nonce = os.urandom(_NONCE_SIZE)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode('utf-8'), None)
    return nonce + ct


def decrypt_field(key: bytes, blob: bytes) -> str:
    """Decrypt nonce+ciphertext+tag → original string."""
    nonce = blob[:_NONCE_SIZE]
    ct = blob[_NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ct, None).decode('utf-8')


def _encrypt_value(key: bytes, value) -> bytes:
    """Encrypt any JSON-serialisable value."""
    return encrypt_field(key, json.dumps(value))


def _decrypt_value(key: bytes, blob: bytes):
    """Decrypt a blob back to the original Python value."""
    return json.loads(decrypt_field(key, blob))


def name_hash(key: bytes, name: str) -> str:
    """Deterministic HMAC-SHA256 of a filename for indexed lookups."""
    return hmac.new(key, name.encode('utf-8'), hashlib.sha256).hexdigest()


def _is_encrypted_blob(val) -> bool:
    """Return True if a value looks like an encrypted blob (bytes > nonce)."""
    return isinstance(val, bytes) and len(val) > _NONCE_SIZE


def _dec_row(key: bytes | None, row: sqlite3.Row | None) -> dict | None:
    """Convert a file row to dict, decrypting encrypted fields if key given."""
    if row is None:
        return None
    d = dict(row)
    if key:
        # name
        if isinstance(d.get('name'), bytes):
            d['name'] = decrypt_field(key, d['name'])
        # mime_type
        if _is_encrypted_blob(d.get('mime_type')):
            d['mime_type'] = decrypt_field(key, d['mime_type'])
        elif isinstance(d.get('mime_type'), bytes):
            d['mime_type'] = ''
        # size
        if _is_encrypted_blob(d.get('size')):
            d['size'] = _decrypt_value(key, d['size'])
        # created_at
        if _is_encrypted_blob(d.get('created_at')):
            d['created_at'] = decrypt_field(key, d['created_at'])
        # modified_at
        if _is_encrypted_blob(d.get('modified_at')):
            d['modified_at'] = decrypt_field(key, d['modified_at'])
    else:
        # No key — handle raw bytes gracefully
        if isinstance(d.get('mime_type'), bytes):
            d['mime_type'] = ''
    return d


def _dec_rows(key: bytes | None, rows: list) -> list[dict]:
    """Decrypt a list of file rows and sort directories-first, name asc."""
    result = [_dec_row(key, r) for r in rows]
    result.sort(key=lambda d: (0 if d['is_directory'] else 1,
                               (d['name'] or '').lower()))
    return result


# ── connection helper ────────────────────────────────────────────────
def get_db() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA foreign_keys=ON')
    return db


# ── schema bootstrap ────────────────────────────────────────────────
def init_db():
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS config (
            key   TEXT PRIMARY KEY,
            value BLOB
        );

        CREATE TABLE IF NOT EXISTS users (
            id               INTEGER PRIMARY KEY,
            username         TEXT UNIQUE NOT NULL,
            password_hash    TEXT NOT NULL,
            is_admin         INTEGER DEFAULT 0,
            key_salt         BLOB,
            key_nonce        BLOB,
            key_encrypted    BLOB
        );

        CREATE TABLE IF NOT EXISTS files (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id      INTEGER NOT NULL,
            parent_id     INTEGER,
            name          BLOB    NOT NULL,
            name_hash     TEXT    DEFAULT '',
            is_directory  INTEGER DEFAULT 0,
            vault_filename TEXT,
            size          BLOB    DEFAULT x'',
            mime_type     BLOB    DEFAULT x'',
            created_at    BLOB    DEFAULT x'',
            modified_at   BLOB    DEFAULT x'',
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (parent_id) REFERENCES files(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_files_parent
            ON files(parent_id);
        CREATE INDEX IF NOT EXISTS idx_files_owner
            ON files(owner_id);

        -- Per-user playback preferences (values encrypted per-user)
        CREATE TABLE IF NOT EXISTS user_preferences (
            user_id          INTEGER PRIMARY KEY,
            prefs_blob       BLOB DEFAULT x'',
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        -- Per-user per-video playback state (values encrypted per-user)
        CREATE TABLE IF NOT EXISTS video_preferences (
            user_id   INTEGER NOT NULL,
            file_id   INTEGER NOT NULL,
            data_blob BLOB    DEFAULT x'',
            PRIMARY KEY (user_id, file_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
        );

        -- Cached transcoded audio tracks (AAC versions of non-AAC originals)
        CREATE TABLE IF NOT EXISTS audio_cache (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id        INTEGER NOT NULL,
            track_index    INTEGER NOT NULL,
            codec_name     TEXT    NOT NULL DEFAULT '',
            vault_filename TEXT    NOT NULL,
            created_at     TEXT    NOT NULL,
            UNIQUE(file_id, track_index),
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
        );
    ''')

    # ── migrations for pre-existing databases ────────────────────────

    # files table: ensure name_hash column exists
    file_cols = {r[1] for r in db.execute('PRAGMA table_info(files)').fetchall()}
    if 'name_hash' not in file_cols:
        db.execute("ALTER TABLE files ADD COLUMN name_hash TEXT DEFAULT ''")

    # Create the name_hash unique index (safe now that column exists)
    db.execute('''CREATE UNIQUE INDEX IF NOT EXISTS idx_files_name_hash
                  ON files(owner_id, parent_id, name_hash)''')

    # user_preferences: migrate old multi-column schema → single prefs_blob
    up_cols = {r[1] for r in db.execute('PRAGMA table_info(user_preferences)').fetchall()}
    if 'prefs_blob' not in up_cols:
        db.execute("ALTER TABLE user_preferences ADD COLUMN prefs_blob BLOB DEFAULT x''")

    # video_preferences: migrate old multi-column schema → single data_blob
    vp_cols = {r[1] for r in db.execute('PRAGMA table_info(video_preferences)').fetchall()}
    if 'data_blob' not in vp_cols:
        db.execute("ALTER TABLE video_preferences ADD COLUMN data_blob BLOB DEFAULT x''")

    db.commit()
    db.close()


def migrate_user_fields(user_id: int, key: bytes):
    """One-time migration: encrypt all plaintext fields for a user.

    Runs on first login after encryption upgrades.  Detects plaintext
    by checking column types (str vs bytes).  Handles:
    - file names, mime types (v1)
    - file sizes, created_at, modified_at (v2)
    - user_preferences → prefs_blob (v2)
    - video_preferences → data_blob (v2)
    """
    flag = f'field_enc_v2_user_{user_id}'
    if get_config(flag):
        return  # already migrated v2

    db = get_db()

    # ── files: encrypt name, mime, size, timestamps ──────────────────
    rows = db.execute('SELECT * FROM files WHERE owner_id = ?',
                      (user_id,)).fetchall()

    for r in rows:
        updates = {}
        params = []

        # name
        raw_name = r['name']
        if isinstance(raw_name, str):
            updates['name'] = '?'
            params.append(encrypt_field(key, raw_name))
            updates['name_hash'] = '?'
            params.append(name_hash(key, raw_name))
        # mime_type
        raw_mime = r['mime_type']
        if isinstance(raw_mime, str):
            updates['mime_type'] = '?'
            params.append(encrypt_field(key, raw_mime) if raw_mime else b'')
        # size — encrypt if still an integer
        raw_size = r['size']
        if isinstance(raw_size, (int, float)):
            updates['size'] = '?'
            params.append(_encrypt_value(key, int(raw_size)))
        # created_at — encrypt if still plaintext string
        raw_created = r['created_at']
        if isinstance(raw_created, str):
            updates['created_at'] = '?'
            params.append(encrypt_field(key, raw_created or ''))
        # modified_at
        raw_modified = r['modified_at']
        if isinstance(raw_modified, str):
            updates['modified_at'] = '?'
            params.append(encrypt_field(key, raw_modified or ''))

        if updates:
            set_clause = ', '.join(f'{col} = {ph}' for col, ph in updates.items())
            params.append(r['id'])
            db.execute(f'UPDATE files SET {set_clause} WHERE id = ?', params)

    # ── user_preferences: migrate columns → encrypted blob ───────────
    up_row = db.execute('SELECT * FROM user_preferences WHERE user_id = ?',
                        (user_id,)).fetchone()
    if up_row:
        up_cols = {r[1] for r in db.execute('PRAGMA table_info(user_preferences)').fetchall()}
        # Only migrate if old columns still exist (haven't been cleaned)
        blob_val = up_row['prefs_blob'] if 'prefs_blob' in up_cols else b''
        if not _is_encrypted_blob(blob_val):
            prefs = {
                'default_audio_lang': up_row['default_audio_lang'] if 'default_audio_lang' in up_cols else '',
                'default_subtitle_lang': up_row['default_subtitle_lang'] if 'default_subtitle_lang' in up_cols else '',
                'default_subtitle_offset': float(up_row['default_subtitle_offset'] or 0) if 'default_subtitle_offset' in up_cols else 0.0,
                'skip_amount': int(up_row['skip_amount'] or 15) if 'skip_amount' in up_cols else 15,
                'sort_preference': (up_row['sort_preference'] or 'name') if 'sort_preference' in up_cols else 'name',
            }
            enc_blob = _encrypt_value(key, prefs)
            db.execute('UPDATE user_preferences SET prefs_blob = ? WHERE user_id = ?',
                       (enc_blob, user_id))

    # ── video_preferences: migrate columns → encrypted blob ──────────
    vp_rows = db.execute('SELECT * FROM video_preferences WHERE user_id = ?',
                         (user_id,)).fetchall()
    vp_cols = {r[1] for r in db.execute('PRAGMA table_info(video_preferences)').fetchall()}
    for vr in vp_rows:
        blob_val = vr['data_blob'] if 'data_blob' in vp_cols else b''
        if not _is_encrypted_blob(blob_val):
            vdata = {
                'position': float(vr['position'] or 0) if 'position' in vp_cols else 0,
                'audio_idx': int(vr['audio_idx'] if vr['audio_idx'] is not None else -1) if 'audio_idx' in vp_cols else -1,
                'sub_idx': int(vr['sub_idx'] if vr['sub_idx'] is not None else -1) if 'sub_idx' in vp_cols else -1,
                'sub_offset': float(vr['sub_offset'] or 0) if 'sub_offset' in vp_cols else 0.0,
                'last_accessed': (vr['last_accessed'] or '') if 'last_accessed' in vp_cols else '',
            }
            enc_blob = _encrypt_value(key, vdata)
            db.execute('UPDATE video_preferences SET data_blob = ? WHERE user_id = ? AND file_id = ?',
                       (enc_blob, user_id, vr['file_id']))

    db.commit()
    db.close()

    set_config(flag, b'done')
    print(f'[vault] Encrypted all fields (v2) for user {user_id} ({len(rows)} files).')


# ── config table ─────────────────────────────────────────────────────
def get_config(key: str):
    db = get_db()
    row = db.execute('SELECT value FROM config WHERE key = ?', (key,)).fetchone()
    db.close()
    return row['value'] if row else None


def set_config(key: str, value):
    db = get_db()
    db.execute('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', (key, value))
    db.commit()
    db.close()


def is_setup_done() -> bool:
    """True if at least one admin user exists."""
    db = get_db()
    row = db.execute('SELECT 1 FROM users WHERE is_admin = 1').fetchone()
    db.close()
    return row is not None


# ── user table ───────────────────────────────────────────────────────
def create_user(username: str, password_hash: str, is_admin: bool = False,
                key_salt: bytes = b'', key_nonce: bytes = b'',
                key_encrypted: bytes = b'') -> int:
    db = get_db()
    cur = db.execute(
        'INSERT INTO users (username, password_hash, is_admin, '
        'key_salt, key_nonce, key_encrypted) VALUES (?, ?, ?, ?, ?, ?)',
        (username, password_hash, int(is_admin),
         key_salt, key_nonce, key_encrypted)
    )
    uid = cur.lastrowid
    db.commit()
    db.close()
    return uid


def get_user(username: str):
    db = get_db()
    row = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    db.close()
    return row


def get_user_by_id(user_id: int):
    db = get_db()
    row = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    db.close()
    return row


def list_users() -> list[dict]:
    db = get_db()
    rows = db.execute(
        'SELECT id, username, is_admin FROM users ORDER BY id'
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]


def delete_user(user_id: int) -> list[str]:
    """Delete a user and all their files.  Returns vault filenames to remove."""
    db = get_db()
    # Regular file vault files
    rows = db.execute(
        'SELECT vault_filename FROM files WHERE owner_id = ? AND vault_filename IS NOT NULL',
        (user_id,)
    ).fetchall()
    vault_files = [r['vault_filename'] for r in rows]
    # Audio cache vault files
    cache_rows = db.execute(
        'SELECT ac.vault_filename FROM audio_cache ac '
        'JOIN files f ON ac.file_id = f.id '
        'WHERE f.owner_id = ?',
        (user_id,)
    ).fetchall()
    vault_files.extend(r['vault_filename'] for r in cache_rows)
    db.execute('DELETE FROM files WHERE owner_id = ?', (user_id,))
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    db.close()
    return vault_files


def update_user_password(user_id: int, password_hash: str,
                         key_salt: bytes, key_nonce: bytes,
                         key_encrypted: bytes):
    db = get_db()
    db.execute(
        'UPDATE users SET password_hash = ?, key_salt = ?, '
        'key_nonce = ?, key_encrypted = ? WHERE id = ?',
        (password_hash, key_salt, key_nonce, key_encrypted, user_id)
    )
    db.commit()
    db.close()


def set_user_admin(user_id: int, is_admin: bool):
    db = get_db()
    db.execute('UPDATE users SET is_admin = ? WHERE id = ?',
               (int(is_admin), user_id))
    db.commit()
    db.close()


# ── virtual filesystem (per-user) ────────────────────────────────────
def list_files(owner_id: int, parent_id=None, *, key: bytes | None = None):
    db = get_db()
    if parent_id is None:
        rows = db.execute(
            'SELECT * FROM files WHERE owner_id = ? AND parent_id IS NULL',
            (owner_id,)
        ).fetchall()
    else:
        rows = db.execute(
            'SELECT * FROM files WHERE owner_id = ? AND parent_id = ?',
            (owner_id, parent_id)
        ).fetchall()
    db.close()
    return _dec_rows(key, rows)


def get_file(file_id: int, owner_id: int, *, key: bytes | None = None):
    db = get_db()
    row = db.execute(
        'SELECT * FROM files WHERE id = ? AND owner_id = ?',
        (file_id, owner_id)
    ).fetchone()
    db.close()
    return _dec_row(key, row)


def get_file_by_name(owner_id: int, parent_id, name: str,
                     *, key: bytes | None = None):
    """Look up a file/folder by exact name inside *parent_id* for a specific owner."""
    db = get_db()
    if key:
        # Use name_hash for indexed lookup
        nh = name_hash(key, name)
        if parent_id is None:
            row = db.execute(
                'SELECT * FROM files WHERE owner_id = ? AND parent_id IS NULL AND name_hash = ?',
                (owner_id, nh)
            ).fetchone()
        else:
            row = db.execute(
                'SELECT * FROM files WHERE owner_id = ? AND parent_id = ? AND name_hash = ?',
                (owner_id, parent_id, nh)
            ).fetchone()
    else:
        # Fallback: plaintext name comparison
        if parent_id is None:
            row = db.execute(
                'SELECT * FROM files WHERE owner_id = ? AND parent_id IS NULL AND name = ?',
                (owner_id, name)
            ).fetchone()
        else:
            row = db.execute(
                'SELECT * FROM files WHERE owner_id = ? AND parent_id = ? AND name = ?',
                (owner_id, parent_id, name)
            ).fetchone()
    db.close()
    return _dec_row(key, row)


def search_files(owner_id: int, query: str, *, parent_id=None, key: bytes | None = None) -> list[dict]:
    """Search files for *owner_id* whose decrypted name contains *query*.

    Because file names are encrypted, we must decrypt every file and filter
    in Python.  Returns a flat list (ignores folder hierarchy) with a
    'path' field showing the breadcrumb trail to each result.

    If *parent_id* is provided (including None treated as "root"), search is
    scoped to only files/folders whose parent_id matches.
    """
    if not query:
        return []

    db = get_db()
    rows = db.execute(
        'SELECT * FROM files WHERE owner_id = ?', (owner_id,)
    ).fetchall()
    db.close()

    # Decrypt all rows
    all_files = [_dec_row(key, r) for r in rows]
    # Build id → file map for breadcrumbs
    by_id = {f['id']: f for f in all_files}

    q = query.lower()
    results = []
    for f in all_files:
        name = (f.get('name') or '')
        if q in name.lower():
            # Filter to the requested directory
            if parent_id != 'all' and f.get('parent_id') != parent_id:
                continue
            # Build path
            parts = []
            pid = f['parent_id']
            while pid and pid in by_id:
                parts.insert(0, by_id[pid]['name'])
                pid = by_id[pid]['parent_id']
            f['path'] = '/'.join(parts) + ('/' if parts else '') + name
            results.append(f)

    results.sort(key=lambda d: (0 if d['is_directory'] else 1,
                                (d['name'] or '').lower()))
    return results


def create_file_record(owner_id: int, parent_id, name: str, is_directory: bool,
                       vault_filename: str | None = None,
                       size: int = 0, mime_type: str = '',
                       *, key: bytes | None = None) -> int:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    if key:
        enc_name = encrypt_field(key, name)
        nh = name_hash(key, name)
        enc_mime = encrypt_field(key, mime_type) if mime_type else b''
        enc_size = _encrypt_value(key, size)
        enc_created = encrypt_field(key, now)
        enc_modified = encrypt_field(key, now)
    else:
        enc_name = name
        nh = ''
        enc_mime = mime_type
        enc_size = size
        enc_created = now
        enc_modified = now
    db = get_db()
    cur = db.execute(
        'INSERT INTO files (owner_id, parent_id, name, name_hash, is_directory, '
        'vault_filename, size, mime_type, created_at, modified_at) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        (owner_id, parent_id, enc_name, nh, int(is_directory),
         vault_filename, enc_size, enc_mime, enc_created, enc_modified)
    )
    fid = cur.lastrowid
    db.commit()
    db.close()
    return fid


def rename_file(file_id: int, new_name: str, *, key: bytes | None = None):
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    if key:
        enc_name = encrypt_field(key, new_name)
        nh = name_hash(key, new_name)
        enc_modified = encrypt_field(key, now)
    else:
        enc_name = new_name
        nh = ''
        enc_modified = now
    db = get_db()
    db.execute(
        "UPDATE files SET name = ?, name_hash = ?, modified_at = ? WHERE id = ?",
        (enc_name, nh, enc_modified, file_id)
    )
    db.commit()
    db.close()


def move_file(file_id: int, new_parent_id, *, key: bytes | None = None):
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    enc_modified = encrypt_field(key, now) if key else now
    db = get_db()
    db.execute("UPDATE files SET parent_id = ?, modified_at = ? WHERE id = ?",
               (new_parent_id, enc_modified, file_id))
    db.commit()
    db.close()


def clear_file_vault(file_id: int):
    """Clear vault_filename for a file record."""
    db = get_db()
    db.execute("UPDATE files SET vault_filename = NULL WHERE id = ?", (file_id,))
    db.commit()
    db.close()


def delete_file_record(file_id: int, owner_id: int) -> list[str]:
    """Delete a file/folder (cascading) and return vault filenames to remove.
    Only deletes if owned by *owner_id*."""
    db = get_db()
    vault_files: list[str] = []
    row = db.execute('SELECT * FROM files WHERE id = ? AND owner_id = ?',
                     (file_id, owner_id)).fetchone()
    if not row:
        db.close()
        return []
    _collect_vault_files(db, file_id, vault_files)
    db.execute('DELETE FROM files WHERE id = ?', (file_id,))
    db.commit()
    db.close()
    return vault_files


def _collect_vault_files(db, file_id: int, result: list[str]):
    row = db.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
    if not row:
        return
    if row['vault_filename']:
        result.append(row['vault_filename'])
    # Also collect audio cache vault files
    cache_rows = db.execute(
        'SELECT vault_filename FROM audio_cache WHERE file_id = ?',
        (file_id,)
    ).fetchall()
    for cr in cache_rows:
        result.append(cr['vault_filename'])
    if row['is_directory']:
        children = db.execute('SELECT id FROM files WHERE parent_id = ?',
                              (file_id,)).fetchall()
        for child in children:
            _collect_vault_files(db, child['id'], result)


def get_breadcrumbs(owner_id: int, parent_id, *, key: bytes | None = None) -> list[dict]:
    """Return a breadcrumb list [{id, name}, …] from root to *parent_id*."""
    crumbs: list[dict] = [{'id': None, 'name': 'Root'}]
    if parent_id is None:
        return crumbs
    parts: list[dict] = []
    db = get_db()
    cid = parent_id
    while cid is not None:
        row = db.execute('SELECT * FROM files WHERE id = ? AND owner_id = ?',
                         (cid, owner_id)).fetchone()
        if not row:
            break
        d = _dec_row(key, row)
        parts.append({'id': d['id'], 'name': d['name']})
        cid = row['parent_id']
    db.close()
    parts.reverse()
    return crumbs + parts


def get_folders(owner_id: int, parent_id=None, *, key: bytes | None = None):
    """Return only directories inside *parent_id* for a specific owner."""
    db = get_db()
    if parent_id is None:
        rows = db.execute(
            "SELECT * FROM files WHERE owner_id = ? AND parent_id IS NULL AND is_directory = 1",
            (owner_id,)
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM files WHERE owner_id = ? AND parent_id = ? AND is_directory = 1",
            (owner_id, parent_id)
        ).fetchall()
    db.close()
    decrypted = [_dec_row(key, r) for r in rows]
    decrypted.sort(key=lambda d: (d['name'] or '').lower())
    return [{'id': d['id'], 'name': d['name']} for d in decrypted]


def get_folder_info(folder_id: int, owner_id: int, *, key: bytes | None = None):
    """Get folder info including parent_id for navigation."""
    db = get_db()
    row = db.execute(
        "SELECT id, parent_id, name FROM files WHERE id = ? AND owner_id = ? AND is_directory = 1",
        (folder_id, owner_id)
    ).fetchone()
    db.close()
    if not row:
        return None
    d = _dec_row(key, row)
    return {'id': d['id'], 'parent_id': row['parent_id'], 'name': d['name']}


# ── user preferences ─────────────────────────────────────────────────
_USER_PREF_DEFAULTS = {
    'default_audio_lang': '',
    'default_subtitle_lang': '',
    'default_subtitle_offset': 0.0,
    'skip_amount': 15,
    'sort_preference': 'name',
    'audio_cache_mode': 'keep',
}


def get_user_preferences(user_id: int, *, key: bytes | None = None) -> dict:
    """Return preferences for a user, with defaults if none saved yet."""
    db = get_db()
    row = db.execute('SELECT * FROM user_preferences WHERE user_id = ?',
                     (user_id,)).fetchone()
    db.close()
    if not row:
        return dict(_USER_PREF_DEFAULTS)

    d = dict(row)
    blob = d.get('prefs_blob')
    if key and _is_encrypted_blob(blob):
        prefs = _decrypt_value(key, blob)
        # Merge with defaults in case new pref keys are added later
        result = dict(_USER_PREF_DEFAULTS)
        result.update(prefs)
        return result

    # Fallback: try old plaintext columns (pre-migration)
    cols = set(d.keys())
    if 'default_audio_lang' in cols:
        return {
            'default_audio_lang': d.get('default_audio_lang') or '',
            'default_subtitle_lang': d.get('default_subtitle_lang') or '',
            'default_subtitle_offset': float(d.get('default_subtitle_offset') or 0),
            'skip_amount': int(d.get('skip_amount') or 15),
            'sort_preference': d.get('sort_preference') or 'name',
        }

    return dict(_USER_PREF_DEFAULTS)


def set_user_preferences(user_id: int, audio_lang: str = '',
                         subtitle_lang: str = '',
                         subtitle_offset: float = 0.0,
                         skip_amount: int = 15,
                         sort_preference: str = 'name',
                         audio_cache_mode: str = 'keep',
                         *, key: bytes | None = None):
    prefs = {
        'default_audio_lang': audio_lang,
        'default_subtitle_lang': subtitle_lang,
        'default_subtitle_offset': subtitle_offset,
        'skip_amount': skip_amount,
        'sort_preference': sort_preference,
        'audio_cache_mode': audio_cache_mode,
    }
    if key:
        enc_blob = _encrypt_value(key, prefs)
    else:
        enc_blob = json.dumps(prefs).encode('utf-8')
    db = get_db()
    db.execute(
        'INSERT OR REPLACE INTO user_preferences (user_id, prefs_blob) VALUES (?, ?)',
        (user_id, enc_blob)
    )
    db.commit()
    db.close()


# ── per-video preferences ────────────────────────────────────────────
_VIDEO_PREF_DEFAULTS = {
    'position': 0,
    'audio_idx': -1,
    'sub_idx': -1,
    'sub_offset': 0.0,
    'last_accessed': '',
}


def get_video_preferences(user_id: int, file_id: int, *, key: bytes | None = None) -> dict:
    """Return saved per-video playback state, or defaults."""
    db = get_db()
    row = db.execute(
        'SELECT * FROM video_preferences WHERE user_id = ? AND file_id = ?',
        (user_id, file_id)).fetchone()
    db.close()
    if not row:
        return dict(_VIDEO_PREF_DEFAULTS)

    d = dict(row)
    blob = d.get('data_blob')
    if key and _is_encrypted_blob(blob):
        vdata = _decrypt_value(key, blob)
        result = dict(_VIDEO_PREF_DEFAULTS)
        result.update(vdata)
        return result

    # Fallback: try old plaintext columns (pre-migration)
    cols = set(d.keys())
    if 'position' in cols:
        return {
            'position': float(d.get('position') or 0),
            'audio_idx': int(d['audio_idx'] if d.get('audio_idx') is not None else -1),
            'sub_idx': int(d['sub_idx'] if d.get('sub_idx') is not None else -1),
            'sub_offset': float(d.get('sub_offset') or 0),
            'last_accessed': d.get('last_accessed') or '',
        }

    return dict(_VIDEO_PREF_DEFAULTS)


def set_video_preferences(user_id: int, file_id: int, *, key: bytes | None = None, **kwargs):
    """Upsert per-video preferences.  Only updates keys present in kwargs.
    All values are stored encrypted in a single data_blob column."""
    from datetime import datetime, timezone
    allowed_keys = {'position', 'audio_idx', 'sub_idx', 'sub_offset'}
    filtered = {k: v for k, v in kwargs.items() if k in allowed_keys}

    db = get_db()
    existing = db.execute(
        'SELECT data_blob FROM video_preferences WHERE user_id = ? AND file_id = ?',
        (user_id, file_id)).fetchone()

    if existing and key and _is_encrypted_blob(existing['data_blob']):
        # Decrypt current state, merge updates
        current = _decrypt_value(key, existing['data_blob'])
    else:
        current = dict(_VIDEO_PREF_DEFAULTS)

    current.update(filtered)
    current['last_accessed'] = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

    if key:
        enc_blob = _encrypt_value(key, current)
    else:
        enc_blob = json.dumps(current).encode('utf-8')

    if existing:
        db.execute('UPDATE video_preferences SET data_blob = ? WHERE user_id = ? AND file_id = ?',
                   (enc_blob, user_id, file_id))
    else:
        db.execute('INSERT INTO video_preferences (user_id, file_id, data_blob) VALUES (?, ?, ?)',
                   (user_id, file_id, enc_blob))

    db.commit()
    db.close()


def get_all_video_last_accessed(user_id: int, *, key: bytes | None = None) -> dict[int, str]:
    """Return {file_id: last_accessed} for all videos of a user."""
    db = get_db()
    rows = db.execute(
        'SELECT file_id, data_blob FROM video_preferences WHERE user_id = ?',
        (user_id,)).fetchall()
    db.close()

    result = {}
    for r in rows:
        blob = r['data_blob']
        if key and _is_encrypted_blob(blob):
            try:
                vdata = _decrypt_value(key, blob)
                result[r['file_id']] = vdata.get('last_accessed', '')
            except Exception:
                result[r['file_id']] = ''
        else:
            # Fallback for old rows with last_accessed column
            d = dict(r)
            result[r['file_id']] = d.get('last_accessed', '')
    return result


def clear_all_video_preferences(user_id: int) -> int:
    """Delete all per-video preferences for a user. Returns count deleted."""
    db = get_db()
    cur = db.execute('DELETE FROM video_preferences WHERE user_id = ?',
                     (user_id,))
    count = cur.rowcount
    db.commit()
    db.close()
    return count


# ── audio cache ──────────────────────────────────────────────────────

def get_audio_cache_info(file_id: int) -> dict[int, str]:
    """Return {track_index: vault_filename} for cached audio tracks."""
    db = get_db()
    rows = db.execute(
        'SELECT track_index, vault_filename FROM audio_cache WHERE file_id = ?',
        (file_id,)
    ).fetchall()
    db.close()
    return {r['track_index']: r['vault_filename'] for r in rows}


def add_audio_cache(file_id: int, track_index: int, codec_name: str,
                    vault_filename: str):
    """Record a cached (transcoded AAC) audio track."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    db = get_db()
    db.execute(
        'INSERT OR REPLACE INTO audio_cache '
        '(file_id, track_index, codec_name, vault_filename, created_at) '
        'VALUES (?, ?, ?, ?, ?)',
        (file_id, track_index, codec_name, vault_filename, now)
    )
    db.commit()
    db.close()


def clear_audio_cache(file_id: int) -> list[str]:
    """Delete all cached audio for a file.  Returns vault filenames to remove."""
    db = get_db()
    rows = db.execute(
        'SELECT vault_filename FROM audio_cache WHERE file_id = ?',
        (file_id,)
    ).fetchall()
    vault_files = [r['vault_filename'] for r in rows]
    db.execute('DELETE FROM audio_cache WHERE file_id = ?', (file_id,))
    db.commit()
    db.close()
    return vault_files


def has_audio_cache(file_id: int) -> bool:
    """Return True if the file has any cached audio tracks."""
    db = get_db()
    row = db.execute(
        'SELECT 1 FROM audio_cache WHERE file_id = ? LIMIT 1',
        (file_id,)
    ).fetchone()
    db.close()
    return row is not None
