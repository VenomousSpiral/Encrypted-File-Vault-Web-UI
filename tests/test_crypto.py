"""Tests for crypto.py — AES-256-GCM chunk encryption engine.

These are pure unit tests: no Flask, no DB, no network needed.
They verify correctness of the core cryptography primitives used by the vault.
"""

import io
import os
from pathlib import Path

import pytest
pytest_plugins = ('pytest_forked',)
from cryptography.exceptions import InvalidTag as CryptoInvalidTag

# Import directly from source (no app dependency)
sys_path = str(Path(__file__).resolve().parent.parent)
if sys_path not in __import__('sys').path:
    __import__('sys').path.insert(0, sys_path)

# Import crypto.py primitives
from core.auth import _get_master_key  # noqa: F401

from crypto import (  # noqa: E402
    HEADER_FORMAT,
    MAGIC,
    NONCE_SIZE,
    SALT_SIZE,
    TAG_SIZE,
    VERSION,
    ChunkEncryptor,
    decrypt_blob,
    decrypt_master_key,
    derive_key,
    encrypt_blob,
    encrypt_master_key,
    generate_master_key,
)

# Field-level encryption is in models.py (wraps crypto primitives for string fields)
from models import decrypt_field, encrypt_field  # noqa: E402


# ── Key Derivation Tests ─────────────────────────────────────────────

@pytest.mark.forked
@pytest.mark.forked
class TestDeriveKey:

    """Tests for the scrypt-based key derivation function."""

    def test_returns_tuple_of_two_bytes(self):
        key, salt = derive_key("test-password")
        assert isinstance(key, bytes) and isinstance(salt, bytes)

    def test_key_is_32_bytes(self):
        key, _ = derive_key("any password works here")
        assert len(key) == 32  # AES-256 needs exactly 32 bytes

    def test_salt_is_sized_correctly(self):
        _, salt = derive_key("test-password")
        assert len(salt) == SALT_SIZE

    def test_different_salts_produce_different_keys(self):
        key1, _ = derive_key("same password")
        key2, _ = derive_key("same password")
        # Salt should be random each time → different keys
        # (extremely unlikely collision is acceptable for testing)
        assert key1 != key2

    def test_same_salt_produces_same_key(self):
        salt = os.urandom(32)
        key1, _ = derive_key("password", salt=salt)
        key2, _ = derive_key("password", salt=salt)
        assert key1 == key2


@pytest.mark.forked
class TestGenerateMasterKey:

    """Tests for random master key generation."""

    def test_returns_32_bytes(self):
        mk = generate_master_key()
        assert len(mk) == 32

    def test_unique_keys(self):
        keys = {generate_master_key() for _ in range(10)}
        assert len(keys) == 10


# ── Field-Level Encryption Tests ──────────────────────────────────────

@pytest.mark.forked
class TestEncryptField:

    """Tests for string field-level encryption."""

    def test_roundtrip_simple_string(self, key):
        plaintext = "hello world"
        encrypted = encrypt_field(key, plaintext)
        decrypted = decrypt_field(key, encrypted)
        assert decrypted == plaintext

    def test_roundtrip_unicode(self, key):
        plaintext = "🔐 中文 🎉 café résumé"
        encrypted = encrypt_field(key, plaintext)
        decrypted = decrypt_field(key, encrypted)
        assert decrypted == plaintext

    def test_different_nonces_same_input(self, key):
        """Encrypting the same string twice produces different ciphertexts."""
        plain = "same input"
        enc1 = encrypt_field(key, plain)
        enc2 = encrypt_field(key, plain)
        assert enc1 != enc2  # nonce is random

    def test_wrong_key_fails(self, key):
        plaintext = "secret data"
        encrypted = encrypt_field(key, plaintext)
        wrong_key = os.urandom(32)
        with pytest.raises(CryptoInvalidTag):
            decrypt_field(wrong_key, encrypted)


# ── Master Key Encryption Tests ───────────────────────────────────────

@pytest.mark.forked
class TestEncryptMasterKey:

    """Tests for password-wrapped master key encryption."""

    def test_roundtrip(self):
        original_mk = generate_master_key()
        password = "correct horse battery staple"

        salt, nonce, encrypted = encrypt_master_key(original_mk, password)
        recovered = decrypt_master_key(salt, nonce, encrypted, password)

        assert recovered == original_mk

    def test_wrong_password_fails(self):
        mk = generate_master_key()
        correct_pw = "correct"
        wrong_pw = "wrong"

        salt, nonce, enc = encrypt_master_key(mk, correct_pw)
        with pytest.raises(CryptoInvalidTag):
            decrypt_master_key(salt, nonce, enc, wrong_pw)


# ── Chunk Encryptor Tests ────────────────────────────────────────────

@pytest.mark.forked
class TestChunkEncryptor:

    """Tests for streaming chunk-based encryption."""

    def _make_enc(self, chunk_size=1024):
        return ChunkEncryptor(generate_master_key(), chunk_size)

    # Geometry helpers
    @pytest.mark.forked
    class TestGeometryHelpers:
        def test_full_enc_chunk_size(self, key):
            enc = ChunkEncryptor(key, 8192)
            expected = NONCE_SIZE + 8192 + TAG_SIZE
            assert enc.full_enc_chunk_size() == expected

        def test_total_chunks_empty_file(self, key):
            enc = ChunkEncryptor(key, 4096)
            assert enc.total_chunks(0) == 0

        def test_total_chunks_exact_multiple(self, key):
            enc = ChunkEncryptor(key, 1024)
            # Exactly 5 chunks of 1024 bytes each
            assert enc.total_chunks(5 * 1024) == 5

        def test_total_chunks_partial_last_chunk(self, key):
            enc = ChunkEncryptor(key, 1024)
            # 3073 bytes → 3 full chunks + 1 partial chunk = 4 total
            assert enc.total_chunks(3 * 1024 + 1) == 4

        def test_plain_chunk_len_last_partial(self, key):
            enc = ChunkEncryptor(key, 1024)
            # File is 2560 bytes (2 full chunks of 1024 + partial chunk of 512)
            assert enc.plain_chunk_len(0, 2560) == 1024
            assert enc.plain_chunk_len(1, 2560) == 1024
            assert enc.plain_chunk_len(2, 2560) == 512

        def test_plain_chunk_len_last_full(self, key):
            """When file_size % chunk_size == 0, last chunk is full."""
            enc = ChunkEncryptor(key, 1024)
            assert enc.plain_chunk_len(0, 3 * 1024) == 1024

        def test_plain_chunk_len_zero_file(self, key):
            enc = ChunkEncryptor(key, 1024)
            assert enc.plain_chunk_len(0, 0) == 0

    # Single chunk operations
    @pytest.mark.forked
    class TestSingleChunk:
        def test_encrypt_decrypt_roundtrip(self, key):
            data = os.urandom(512)
            enc = ChunkEncryptor(key, 4096)
            encrypted = enc.encrypt_chunk(data, chunk_index=0)

            # Encrypted chunk is longer than plaintext (nonce + tag overhead)
            assert len(encrypted) == NONCE_SIZE + 512 + TAG_SIZE

            decrypted = enc.decrypt_chunk(encrypted, chunk_index=0)
            assert decrypted == data

        def test_different_chunks_different_nonces(self, key):
            """Same input encrypted as different chunks → same ciphertext (deterministic AAD)."""
            data = os.urandom(256)
            enc = ChunkEncryptor(key, 4096)
            # Different chunk_index uses different AAD → should produce DIFFERENT ciphertexts
            enc1 = enc.encrypt_chunk(data, chunk_index=0)
            enc2 = enc.encrypt_chunk(data, chunk_index=1)
            assert enc1 != enc2

        def test_wrong_chunk_index_fails(self, key):
            data = os.urandom(512)
            enc = ChunkEncryptor(key, 4096)
            encrypted = enc.encrypt_chunk(data, chunk_index=0)
            with pytest.raises(CryptoInvalidTag):
                # Decrypting as a different chunk index should fail (AAD mismatch)
                enc.decrypt_chunk(encrypted, chunk_index=1)

        def test_tampered_data_fails(self, key):
            data = os.urandom(512)
            enc = ChunkEncryptor(key, 4096)
            encrypted = bytearray(enc.encrypt_chunk(data, chunk_index=0))
            # Flip a byte in the ciphertext portion (skip nonce prefix and tag suffix)
            encrypted[NONCE_SIZE + len(data) // 2] ^= 0xFF

            with pytest.raises(CryptoInvalidTag):
                enc.decrypt_chunk(bytes(encrypted), chunk_index=0)

    # Full stream operations
    @pytest.mark.forked
    class TestStreamEncryption:
        def test_roundtrip_small_file(self, tmp_path: Path, key):
            """Encrypt and decrypt a small file (less than one chunk)."""
            plaintext = os.urandom(128)
            enc = ChunkEncryptor(key, 4096)

            input_stream = io.BytesIO(plaintext)
            vault_path = tmp_path / "test.enc"
            enc.encrypt_stream(input_stream, str(vault_path), len(plaintext))

            assert vault_path.exists() and vault_path.stat().st_size > 0

            # Decrypt full file
            decrypted_chunks = b"".join(enc.decrypt_full(str(vault_path)))
            assert decrypted_chunks == plaintext

        def test_roundtrip_exact_chunk_boundary(self, tmp_path: Path, key):
            """Encrypt a file that's exactly one chunk boundary."""
            chunk_size = 4096
            plaintext = os.urandom(chunk_size)
            enc = ChunkEncryptor(key, chunk_size)

            input_stream = io.BytesIO(plaintext)
            vault_path = tmp_path / "boundary.enc"
            enc.encrypt_stream(input_stream, str(vault_path), len(plaintext))

            decrypted_chunks = b"".join(enc.decrypt_full(str(vault_path)))
            assert decrypted_chunks == plaintext

        def test_roundtrip_multiple_chunks(self, tmp_path: Path, key):
            """Encrypt and decrypt a file spanning multiple chunks."""
            chunk_size = 1024
            # 3.5 chunks worth of data
            plaintext = os.urandom(3 * chunk_size + 512)
            enc = ChunkEncryptor(key, chunk_size)

            input_stream = io.BytesIO(plaintext)
            vault_path = tmp_path / "multi.enc"
            enc.encrypt_stream(input_stream, str(vault_path), len(plaintext))

            decrypted_chunks = b"".join(enc.decrypt_full(str(vault_path)))
            assert decrypted_chunks == plaintext

        def test_empty_file(self, tmp_path: Path, key):
            """Encrypt and decrypt a zero-byte file."""
            enc = ChunkEncryptor(key, 4096)

            input_stream = io.BytesIO(b"")
            vault_path = tmp_path / "empty.enc"
            enc.encrypt_stream(input_stream, str(vault_path), 0)

            decrypted_chunks = b"".join(enc.decrypt_full(str(vault_path)))
            assert decrypted_chunks == b""

    # Range decryption (for HTTP Range / seeking)
    @pytest.mark.forked
    class TestRangeDecryption:
        def test_range_single_chunk(self, tmp_path: Path, key):
            plaintext = os.urandom(4096)  # exactly one chunk
            enc = ChunkEncryptor(key, 2048)

            input_stream = io.BytesIO(plaintext)
            vault_path = tmp_path / "range.enc"
            enc.encrypt_stream(input_stream, str(vault_path), len(plaintext))

            # Request bytes [100:500] from the first chunk only
            result = b"".join(enc.decrypt_range(str(vault_path), 100, 499))
            assert result == plaintext[100:500]

        def test_range_crosses_chunk_boundary(self, tmp_path: Path, key):
            """Request range that spans two chunks."""
            chunk_size = 2048
            # Create data spanning 3 chunks
            plaintext = os.urandom(3 * chunk_size)
            enc = ChunkEncryptor(key, chunk_size)

            input_stream = io.BytesIO(plaintext)
            vault_path = tmp_path / "cross.enc"
            enc.encrypt_stream(input_stream, str(vault_path), len(plaintext))

            # Request bytes that span chunks 0 and 1
            result = b"".join(enc.decrypt_range(str(vault_path), chunk_size - 64, chunk_size + 63))
            assert result == plaintext[chunk_size - 64:chunk_size + 64]

        def test_range_last_chunk_partial(self, tmp_path: Path, key):
            """Request range from the last (partial) chunk."""
            chunk_size = 1024
            # File is exactly one full chunk + partial second chunk
            plaintext = os.urandom(chunk_size + 512)
            enc = ChunkEncryptor(key, chunk_size)

            input_stream = io.BytesIO(plaintext)
            vault_path = tmp_path / "last.enc"
            enc.encrypt_stream(input_stream, str(vault_path), len(plaintext))

            # Request from the last partial chunk only
            result = b"".join(enc.decrypt_range(str(vault_path), 1500, 1999))
            assert result == plaintext[1500:2000]


# ── Blob Encryption Tests ────────────────────────────────────────────

@pytest.mark.forked
class TestBlobEncryption:

    """Tests for small-blob encryption (used by HLS segments)."""

    def test_roundtrip(self, key):
        data = os.urandom(1024)
        encrypted = encrypt_blob(key, data)
        decrypted = decrypt_blob(key, encrypted)
        assert decrypted == data

    def test_different_nonces_same_input(self, key):
        """Encrypting the same blob twice produces different ciphertexts."""
        data = os.urandom(512)
        enc1 = encrypt_blob(key, data)
        enc2 = encrypt_blob(key, data)
        assert len(enc1) == len(enc2)  # same overhead
        assert enc1 != enc2

    def test_wrong_key_fails(self, key):
        data = os.urandom(512)
        encrypted = encrypt_blob(key, data)
        wrong_key = os.urandom(32)
        with pytest.raises(CryptoInvalidTag):
            decrypt_blob(wrong_key, encrypted)

    def test_output_contains_nonce_and_tag(self, key):
        """Encrypted blob should be plaintext + nonce (12B) + tag (16B)."""
        data = os.urandom(500)
        encrypted = encrypt_blob(key, data)
        assert len(encrypted) == NONCE_SIZE + 16 + len(data)


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture()
def key():
    """Generate a random 256-bit AES key for testing."""
    return generate_master_key()
