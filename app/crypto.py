"""Layered symmetric encryption core for the legal-aid vault.

Pipeline (encrypt order): AES-256-GCM -> PKCS#7 -> DES-CBC -> RC4; decryption
runs in reverse with MACs verified before any layer is stripped.

DES is retained ONLY because this is a course assignment: its effective
strength is 56 bits and the cipher is obsolete. RC4 is also obsolete -- a
stream cipher with no block mode, no IV, and keystream-reuse pitfalls. Stacking
these three layers does NOT provide 3x security; the layers are redundancy,
not multiplication. Assignment-only, never for real data.

This module is request-independent: every function takes ``master`` bytes
explicitly (the Flask layer passes ``app.config["MASTER_KEY"]`` hex-decoded).
Every failure raises the single generic :class:`CryptoError` and never leaks
internal detail (correctness, not diagnosis, is the requirement here).

Envelope format v1::

    b"LVLT" | u16 version (LE) | salt16 |
    META (AES_NONCE12 | AES_TAG16 | u32le len | ct, AD = MAGIC|VER|SALT) |
    AES_NONCE12 | AES_TAG16 | u32le len | AES_CT |
    DES_IV8 | DES_MAC32 | RC4_MAC32 | u32le len | RC4_CT
"""

import hashlib
import hmac
import json
import struct

from Crypto.Cipher import AES, ARC4, DES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

__all__ = ["CryptoError", "derive_keys", "encrypt_file", "decrypt_file"]


class CryptoError(Exception):
    """Uniform failure signal for every cryptographic error path.

    Messages stay generic ("decryption failed", "integrity check failed"):
    internal detail must never reach callers or logs.
    """


_MAGIC = b"LVLT"
_VERSION = 1
_SALT_LEN = 16

# key length per label for HKDF; DES gets 8 bytes because that is all it takes,
# RC4 accepts variable 5-256, 16 chosen here. Kept in one place on purpose:
# Task 3+ code must never choose these.
_KEY_LEN = {
    "aes": 32,
    "rc4": 16,
    "hmac-des": 32,
    "hmac-rc4": 32,
    "des": 8,
}

# DES weak and semi-weak keys (FIPS 74, RFC variants). Compared after odd-arity
# parity adjustment so a key derived from random bytes (any parity bit pattern)
# is recognised against one canonical entry. 4 weak + 12 semi-weak keys.
_DES_WEAK_KEYS = frozenset({
    0x0101010101010101, 0xFEFEFEFEFEFEFEFE,
    0xE0E0E0E0E0E0E0E0, 0x1F1F1F1F1F1F1F1F,
    0x01FE01FE01FE01FE, 0xFE01FE01FE01FE01,
    0x1FE01FE00EF10EF1, 0xE01FE01FF10EF10E,
    0x01E001E001F101F1, 0xE001E001F101F101,
    0x1FFE1FFE0EFE0EFE, 0xFE1FFE1FFE0EFE0E,
    0x011F011F010E010E, 0x1F011F010E010E01,
    0xE0FEE0FEF1FEF1FE, 0xFEE0FEE0FEF1FEF1,
})


def _parity_adjust(key: bytes) -> bytes:
    """Fold each byte onto its odd-parity form (DES ignores the parity bit)."""
    out = bytearray()
    for b in key:
        b &= 0xFE
        if bin(b).count("1") % 2 == 0:
            b |= 1
        out.append(b)
    return bytes(out)


def _is_des_key_weak(key: bytes) -> bool:
    """True if key (any DES parity) reduces to a known weak/semi-weak key."""
    return int.from_bytes(_parity_adjust(key), "big") in _DES_WEAK_KEYS


def derive_keys(master: bytes, salt: bytes) -> dict[str, bytes]:
    """HKDF-SHA256 subkeys: aes(32) des(8) rc4(16) hmac-des(32) hmac-rc4(32).

    Deterministic: decryption of one envelope reproduces the exact same DES
    weak-key retry loop that encryption used (labels des -> des-2 -> des-3,
    CryptoError if still weak after all three).
    """
    # Trust boundary: reject empty/malformed master before HKDF, generic msg only.
    if not isinstance(master, bytes) or len(master) < 32:
        raise CryptoError("key derivation failed")
    keys = {
        label: HKDF(master, length, salt, SHA256, context=label.encode())
        for label, length in _KEY_LEN.items()
        if label != "des"
    }
    # DES is obsolete and only 56 effective bits; derived keys are random, so a
    # weak one is near-impossible in practice -- the loop exists for spec
    # compliance and stays deterministic on both sides.
    des_key = None
    for label in ("des", "des-2", "des-3"):
        candidate = HKDF(master, _KEY_LEN["des"], salt, SHA256, context=label.encode())
        if not _is_des_key_weak(candidate):
            des_key = candidate
            break
    if des_key is None:
        raise CryptoError("key derivation failed")
    keys["des"] = des_key
    return keys


def hash_plaintext(plaintext: bytes) -> str:
    """The one plaintext-digest definition used by META and the DB row."""
    return hashlib.sha256(plaintext).hexdigest()


def _ad_meta(version: int, salt: bytes) -> bytes:
    """AES-GCM associated data for the META section: MAGIC | VER | SALT."""
    return _MAGIC + struct.pack("<H", version) + salt


def _ad_payload(version: int, salt: bytes, file_id: str, owner_id: int) -> bytes:
    """AES-GCM associated data for the payload section: VER | SALT | file_id | owner | b"payload"."""
    return (
        struct.pack("<H", version)
        + salt
        + file_id.encode("utf-8")
        + str(owner_id).encode("ascii")
        + b"payload"
    )


def _gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(aad)
    return cipher.encrypt_and_digest(plaintext)


def encrypt_file(
    plaintext: bytes,
    *,
    master: bytes,
    owner_id: int,
    file_id: str,
    filename: str,
    mime: str,
) -> bytes:
    """Encrypt plaintext into an envelope v1 under the layered pipeline."""
    salt = get_random_bytes(_SALT_LEN)
    keys = derive_keys(master, salt)

    meta_pt = json.dumps(
        {
            "filename": filename,
            "mime": mime,
            "size": len(plaintext),
            "owner_id": int(owner_id),
            "file_id": file_id,
            "sha256": hash_plaintext(plaintext),
        },
        sort_keys=True,
    ).encode("utf-8")

    meta_nonce = get_random_bytes(12)
    meta_ct, meta_tag = _gcm_encrypt(keys["aes"], meta_nonce, meta_pt, _ad_meta(_VERSION, salt))

    aes_nonce = get_random_bytes(12)
    aes_ct, aes_tag = _gcm_encrypt(
        keys["aes"], aes_nonce, plaintext, _ad_payload(_VERSION, salt, file_id, owner_id)
    )

    # PKCS#7 to the DES (8-byte) block, CBC, then RC4 stream over the result.
    aes_padded = pad(aes_ct, 8)
    des_iv = get_random_bytes(8)
    des_ct = DES.new(keys["des"], DES.MODE_CBC, iv=des_iv).encrypt(aes_padded)
    rc4_ct = ARC4.new(keys["rc4"]).encrypt(des_ct)

    des_mac = hmac.new(keys["hmac-des"], des_iv + des_ct, hashlib.sha256).digest()
    rc4_mac = hmac.new(keys["hmac-rc4"], rc4_ct, hashlib.sha256).digest()

    return b"".join([
        _MAGIC,
        struct.pack("<H", _VERSION),
        salt,
        meta_nonce, meta_tag, struct.pack("<I", len(meta_ct)), meta_ct,
        aes_nonce, aes_tag, struct.pack("<I", len(aes_ct)), aes_ct,
        des_iv, des_mac, rc4_mac, struct.pack("<I", len(rc4_ct)), rc4_ct,
    ])


def _take(blob: bytes, pos: int, n: int) -> tuple[bytes, int]:
    if pos + n > len(blob):
        raise CryptoError("decryption failed")
    return blob[pos:pos + n], pos + n


def _read_len(blob: bytes, pos: int) -> tuple[int, int]:
    chunk, pos = _take(blob, pos, 4)
    return struct.unpack("<I", chunk)[0], pos


def decrypt_file(
    blob: bytes,
    *,
    master: bytes,
    expect_owner: int,
    expect_file_id: str,
) -> tuple[bytes, dict]:
    """Decrypt an envelope v1; returns (plaintext, meta dict).

    Verify order (never release plaintext before every check passes):
    structure -> META GCM -> owner/file binding -> RC4_MAC -> strip RC4 ->
    DES_MAC -> DES-CBC -> strict PKCS#7 unpad -> AES tag -> size/sha256.
    """
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < 4 + 2 + _SALT_LEN:
        raise CryptoError("decryption failed")
    blob = bytes(blob)
    if blob[:4] != _MAGIC:
        raise CryptoError("decryption failed")
    (version,) = struct.unpack("<H", blob[4:6])
    if version != _VERSION:
        raise CryptoError("decryption failed")

    salt = blob[6:22]
    pos = 22

    meta_nonce, pos = _take(blob, pos, 12)
    meta_tag, pos = _take(blob, pos, 16)
    meta_ct_len, pos = _read_len(blob, pos)
    meta_ct, pos = _take(blob, pos, meta_ct_len)

    keys = derive_keys(master, salt)

    try:
        cipher = AES.new(keys["aes"], AES.MODE_GCM, nonce=meta_nonce, mac_len=16)
        cipher.update(_ad_meta(version, salt))
        meta_pt = cipher.decrypt_and_verify(meta_ct, meta_tag)
    except ValueError:
        raise CryptoError("integrity check failed") from None
    try:
        meta = json.loads(meta_pt.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise CryptoError("decryption failed") from None

    if (
        meta.get("owner_id") != expect_owner
        or str(meta.get("file_id")) != expect_file_id
        or set(meta.keys()) != {"filename", "mime", "size", "owner_id", "file_id", "sha256"}
    ):
        raise CryptoError("integrity check failed")

    aes_nonce, pos = _take(blob, pos, 12)
    aes_tag, pos = _take(blob, pos, 16)
    aes_ct_len, pos = _read_len(blob, pos)
    aes_ct, pos = _take(blob, pos, aes_ct_len)
    des_iv, pos = _take(blob, pos, 8)
    des_mac, pos = _take(blob, pos, 32)
    rc4_mac, pos = _take(blob, pos, 32)
    rc4_ct_len, pos = _read_len(blob, pos)
    rc4_ct, pos = _take(blob, pos, rc4_ct_len)
    if pos != len(blob):
        raise CryptoError("decryption failed")

    if not hmac.compare_digest(
        hmac.new(keys["hmac-rc4"], rc4_ct, hashlib.sha256).digest(), rc4_mac
    ):
        raise CryptoError("integrity check failed")

    # RC4 keystream is deterministic per key, so decrypt == encrypt.
    des_ct = ARC4.new(keys["rc4"]).decrypt(rc4_ct)
    if not hmac.compare_digest(
        hmac.new(keys["hmac-des"], des_iv + des_ct, hashlib.sha256).digest(), des_mac
    ):
        raise CryptoError("integrity check failed")

    try:
        aes_padded = DES.new(keys["des"], DES.MODE_CBC, iv=des_iv).decrypt(des_ct)
        aes_ct_inner = unpad(aes_padded, 8)
    except (ValueError, TypeError):
        raise CryptoError("decryption failed") from None

    # The envelope carries AES_CT both in its own field and inside the RC4
    # layer. Verify the tag against the field copy, and prove the recovered
    # inner copy is identical, before anything is released.
    try:
        cipher = AES.new(keys["aes"], AES.MODE_GCM, nonce=aes_nonce, mac_len=16)
        cipher.update(_ad_payload(version, salt, expect_file_id, expect_owner))
        plaintext = cipher.decrypt_and_verify(aes_ct, aes_tag)
    except ValueError:
        raise CryptoError("integrity check failed") from None
    if not hmac.compare_digest(aes_ct_inner, aes_ct):
        raise CryptoError("integrity check failed")

    if len(plaintext) != meta["size"] or hash_plaintext(plaintext) != meta["sha256"]:
        raise CryptoError("integrity check failed")

    return plaintext, meta
