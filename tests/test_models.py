"""Tests for models.py — field-level encryption helpers and name hashing."""

import os as _os  # noqa: A001
from pathlib import Path

import pytest

# Import the functions we need from models (no DB setup required)
sys_path = str(Path(__file__).resolve().parent.parent)
if sys_path not in __import__('sys').path:
    __import__('sys').path.insert(0, sys_path)

from crypto import generate_master_key  # noqa: E402


# ── name_hash Tests ───────────────────────────────────────────────────

class TestNameHash:
    """Tests for HMAC-SHA256 filename hashing (used for indexed lookups)."""

    def test_returns_hex_string(self):
        key = generate_master_key()
        result = self._import_name_hash()(key, "test.txt")
        assert isinstance(result, str)
        # SHA-256 hex digest is exactly 64 characters
        assert len(result) == 64

    def test_deterministic_same_key(self):
        key = generate_master_key()
        h1 = self._import_name_hash()(key, "same name")
        h2 = self._import_name_hash()(key, "same name")
        # Same key + same filename → always the same hash (deterministic)
        assert h1 == h2

    def test_different_keys_same_filename(self):
        k1, k2 = generate_master_key(), generate_master_key()
        from models import name_hash  # noqa: F811
        h1 = name_hash(k1, "same name")
        h2 = name_hash(k2, "same name")
        assert h1 != h2

    def test_different_filenames_same_key(self):
        key = generate_master_key()
        h1 = self._import_name_hash()(key, "file_a.txt")
        h2 = self._import_name_hash()(key, "file_b.txt")
        assert h1 != h2

    def _import_name_hash(self):
        """Lazy import to avoid DB setup."""
        from models import name_hash  # noqa: F811
        return name_hash


# ── config.py Tests ───────────────────────────────────────────────────

class TestConfigDefaults:
    """Tests for default configuration values.

    NOTE: These rely on the current process state. If PORT/DEBUG env vars are set
    in the environment, these tests may fail — that's expected (env overrides win).
    They serve as a sanity check of documented defaults when no override is active.
    """

    def test_port_default(self):
        import os  # noqa: A001
        if 'PORT' not in os.environ:
            import config as cfg  # noqa: F811
            assert cfg.PORT == 6660

    def test_host_default(self):
        import os  # noqa: A001
        if 'HOST' not in os.environ:
            import config as cfg  # noqa: F811
            assert cfg.HOST == '0.0.0.0'

    def test_debug_defaults_to_false(self):
        """DEBUG defaults to False unless explicitly set."""
        import os  # noqa: A001
        if 'DEBUG' not in os.environ:
            import config as cfg  # noqa: F811
            assert cfg.DEBUG is False





# ── _is_encrypted_blob Edge Case Tests ───────────────────────────────

class TestIsEncryptedBlob:
    """Tests for the helper that detects encrypted blobs vs raw bytes."""

    def test_long_bytes_is_encrypted(self):
        from models import _is_encrypted_blob  # noqa: F811
        assert _is_encrypted_blob(_os.urandom(20)) is True  # nonce (12) + ciphertext + tag = >12

    def test_short_bytes_not_encrypted(self):
        from models import _is_encrypted_blob  # noqa: F811
        assert _is_encrypted_blob(b'\x00' * 5) is False  # too short (nonce=12)

    def test_none_is_false(self):
        from models import _is_encrypted_blob  # noqa: F811
        assert _is_encrypted_blob(None) is False

    def test_empty_bytes_not_encrypted(self):
        from models import _is_encrypted_blob  # noqa: F811
        assert _is_encrypted_blob(b'') is False


class TestEncryptDecryptValueRoundtrip:
    """Tests for JSON-serializable value encryption round-trip."""

    def test_integer_value(self):
        from models import _encrypt_value, _decrypt_value  # noqa: F811
        
        key = generate_master_key()
        original = 42
        encrypted = _encrypt_value(key, original)
        decrypted = _decrypt_value(key, encrypted)
        assert decrypted == original

    def test_string_value(self):
        from models import _encrypt_value, _decrypt_value  # noqa: F811
        
        key = generate_master_key()
        original = "hello world"
        encrypted = _encrypt_value(key, original)
        decrypted = _decrypt_value(key, encrypted)
        assert decrypted == original

    def test_dict_value(self):
        from models import _encrypt_value, _decrypt_value  # noqa: F811
        
        key = generate_master_key()
        original = {"position": 0.5, "audio_idx": -1}
        encrypted = _encrypt_value(key, original)
        decrypted = _decrypt_value(key, encrypted)
        assert decrypted == original

    def test_list_value(self):
        from models import _encrypt_value, _decrypt_value  # noqa: F811
        
        key = generate_master_key()
        original = [1, "two", 3.0]
        encrypted = _encrypt_value(key, original)
        decrypted = _decrypt_value(key, encrypted)
        assert decrypted == original
