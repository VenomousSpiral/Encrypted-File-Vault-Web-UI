"""
AES-256-GCM chunk encryption engine for the Encrypted Vault.

File format on disk
───────────────────
Header (20 bytes):
    4 B  magic   b'EVLT'
    4 B  version uint32-LE  (currently 1)
    4 B  chunk   uint32-LE  plaintext chunk size in bytes
    8 B  size    uint64-LE  original file size

Chunks (sequential, no length prefix):
    12 B  nonce
     N B  ciphertext   (N = plaintext chunk length)
    16 B  GCM tag

All chunks except the last have plaintext length == chunk_size.
Last chunk length = file_size mod chunk_size (or chunk_size if even).

Because every full encrypted chunk is a fixed size we can seek to any
chunk in O(1) — critical for HTTP Range / video seeking.
"""

import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ── constants ────────────────────────────────────────────────────────
NONCE_SIZE = 12
TAG_SIZE = 16
SALT_SIZE = 32

HEADER_FORMAT = '<4sIIQ'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)          # 20 bytes
MAGIC = b'EVLT'
VERSION = 1


# ── key derivation helpers ───────────────────────────────────────────
def derive_key(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Derive a 256-bit key from *password* via scrypt (n=2^17, r=8, p=1)."""
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
    key = kdf.derive(password.encode('utf-8'))
    return key, salt


def generate_master_key() -> bytes:
    """Return a random 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_master_key(master_key: bytes, password: str) -> tuple[bytes, bytes, bytes]:
    """Encrypt *master_key* with a password-derived wrapping key.

    Returns (salt, nonce, ciphertext_with_tag).
    """
    key, salt = derive_key(password)
    nonce = os.urandom(NONCE_SIZE)
    encrypted = AESGCM(key).encrypt(nonce, master_key, None)
    return salt, nonce, encrypted


def decrypt_master_key(salt: bytes, nonce: bytes, encrypted: bytes, password: str) -> bytes:
    """Decrypt the master key using the user's password."""
    key, _ = derive_key(password, salt)
    return AESGCM(key).decrypt(nonce, encrypted, None)


# ── chunk encryptor ──────────────────────────────────────────────────
class ChunkEncryptor:
    """Streaming AES-256-GCM file encryption with random-access decryption."""

    def __init__(self, key: bytes, chunk_size: int):
        self.key = key
        self.aesgcm = AESGCM(key)
        self.chunk_size = chunk_size

    # ── single-chunk ops ─────────────────────────────────────────────
    def encrypt_chunk(self, data: bytes, chunk_index: int) -> bytes:
        """Return *nonce || ciphertext || tag* for one chunk."""
        nonce = os.urandom(NONCE_SIZE)
        aad = struct.pack('<Q', chunk_index)
        return nonce + self.aesgcm.encrypt(nonce, data, aad)

    def decrypt_chunk(self, data: bytes, chunk_index: int) -> bytes:
        """Decrypt *nonce || ciphertext || tag* for one chunk."""
        nonce = data[:NONCE_SIZE]
        aad = struct.pack('<Q', chunk_index)
        return self.aesgcm.decrypt(nonce, data[NONCE_SIZE:], aad)

    # ── geometry helpers ─────────────────────────────────────────────
    def full_enc_chunk_size(self) -> int:
        """On-disk size of every full encrypted chunk."""
        return NONCE_SIZE + self.chunk_size + TAG_SIZE

    def total_chunks(self, original_size: int) -> int:
        if original_size == 0:
            return 0
        return (original_size + self.chunk_size - 1) // self.chunk_size

    def plain_chunk_len(self, chunk_idx: int, original_size: int) -> int:
        total = self.total_chunks(original_size)
        if total == 0:
            return 0
        if chunk_idx < total - 1:
            return self.chunk_size
        rem = original_size % self.chunk_size
        return rem if rem else self.chunk_size

    def chunk_offset(self, chunk_idx: int) -> int:
        """Byte offset of *chunk_idx* inside the encrypted file."""
        return HEADER_SIZE + chunk_idx * self.full_enc_chunk_size()

    # ── header I/O ───────────────────────────────────────────────────
    @staticmethod
    def read_header(f) -> tuple[int, int]:
        """Read and validate the file header.  Returns (chunk_size, original_size)."""
        raw = f.read(HEADER_SIZE)
        if len(raw) < HEADER_SIZE:
            raise ValueError('Encrypted file header too short')
        magic, version, chunk_size, original_size = struct.unpack(HEADER_FORMAT, raw)
        if magic != MAGIC:
            raise ValueError('Not an EVLT encrypted file')
        if version != VERSION:
            raise ValueError(f'Unsupported EVLT version {version}')
        return chunk_size, original_size

    # ── encrypt a stream into a vault file ───────────────────────────
    def encrypt_stream(self, input_stream, output_path: str, file_size: int):
        """Read plaintext from *input_stream*, write encrypted to *output_path*.

        Memory usage is bounded to ~2 × chunk_size regardless of file size.
        """
        with open(output_path, 'wb') as out:
            out.write(struct.pack(HEADER_FORMAT, MAGIC, VERSION, self.chunk_size, file_size))
            remaining = file_size
            idx = 0
            while remaining > 0:
                want = min(self.chunk_size, remaining)
                data = input_stream.read(want)
                if not data:
                    break
                out.write(self.encrypt_chunk(data, idx))
                remaining -= len(data)
                idx += 1

    # ── streaming decryption (full file) ─────────────────────────────
    def decrypt_full(self, vault_path: str):
        """Yield all decrypted chunks of *vault_path* sequentially."""
        with open(vault_path, 'rb') as f:
            _, original_size = self.read_header(f)
            n = self.total_chunks(original_size)
            for i in range(n):
                plen = self.plain_chunk_len(i, original_size)
                enc_len = NONCE_SIZE + plen + TAG_SIZE
                raw = f.read(enc_len)
                if len(raw) < enc_len:
                    raise ValueError(f'Truncated chunk {i}')
                yield self.decrypt_chunk(raw, i)

    # ── decrypt to file (for HLS transcoding) ──────────────────────
    def decrypt_to_file(self, vault_path: str, output_path: str):
        """Decrypt an entire vault file to a plaintext file on disk."""
        with open(output_path, 'wb') as out:
            for chunk in self.decrypt_full(vault_path):
                out.write(chunk)

    # ── range decryption (for HTTP Range / seeking) ──────────────────
    def decrypt_range(self, vault_path: str, byte_start: int, byte_end: int):
        """Yield decrypted bytes covering [byte_start, byte_end] of the
        original plaintext.  Only the necessary chunks are read & decrypted.
        """
        with open(vault_path, 'rb') as f:
            _, original_size = self.read_header(f)
            if byte_end >= original_size:
                byte_end = original_size - 1
            if byte_start > byte_end:
                return

            first = byte_start // self.chunk_size
            last = byte_end // self.chunk_size

            for ci in range(first, last + 1):
                f.seek(self.chunk_offset(ci))
                plen = self.plain_chunk_len(ci, original_size)
                enc_len = NONCE_SIZE + plen + TAG_SIZE
                raw = f.read(enc_len)
                if len(raw) < enc_len:
                    raise ValueError(f'Truncated chunk {ci}')
                plain = self.decrypt_chunk(raw, ci)

                cstart = ci * self.chunk_size
                lo = max(byte_start - cstart, 0)
                hi = min(byte_end - cstart + 1, len(plain))
                yield plain[lo:hi]


# ── simple blob encryption (for small HLS segments) ──────────────────
def encrypt_blob(key: bytes, data: bytes) -> bytes:
    """Encrypt a small blob (<~100 MB) in one AES-GCM operation.

    Returns ``nonce (12 B) || ciphertext || tag (16 B)``.
    """
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def decrypt_blob(key: bytes, data: bytes) -> bytes:
    """Decrypt a blob produced by :func:`encrypt_blob`."""
    return AESGCM(key).decrypt(data[:NONCE_SIZE], data[NONCE_SIZE:], None)
