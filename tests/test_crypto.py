"""Tests for the layered crypto core (app/crypto.py), TDD-first per task brief."""

import hashlib
import hmac
import json
import struct

import pytest

from app import crypto
from app.crypto import CryptoError

MASTER = bytes(range(32))
FID = "11111111-2222-3333-4444-555555555555"


def enc(pt, owner=7, fid=FID, master=MASTER, filename="a.txt", mime="text/plain"):
    return crypto.encrypt_file(
        pt, master=master, owner_id=owner, file_id=fid,
        filename=filename, mime=mime,
    )


def dec(blob, owner=7, fid=FID, master=MASTER):
    return crypto.decrypt_file(blob, master=master, expect_owner=owner, expect_file_id=fid)


# ---------------------------------------------------------------- derive_keys

def test_derive_keys_labels_and_lengths():
    keys = crypto.derive_keys(MASTER, b"\x00" * 16)
    assert sorted(keys) == ["aes", "des", "hmac-des", "hmac-rc4", "rc4"]
    for label, n in [("aes", 32), ("des", 8), ("rc4", 16), ("hmac-des", 32), ("hmac-rc4", 32)]:
        assert len(keys[label]) == n


def test_derive_keys_deterministic():
    k1 = crypto.derive_keys(MASTER, b"k" * 16)
    k2 = crypto.derive_keys(MASTER, b"k" * 16)
    assert k1 == k2


def test_derive_keys_des_weak_check_unit():
    # 0x0101010101010101 is the canonical weak key; parity-adjusted 0x0000... maps onto it.
    assert crypto._is_des_key_weak(b"\x01" * 8)
    assert crypto._is_des_key_weak(b"\x00" * 8)
    assert crypto._is_des_key_weak(b"\xfe" * 8)
    assert not crypto._is_des_key_weak(b"\x24" * 8)


# ------------------------------------------------------------------ round trip

def test_round_trip_empty():
    pt, meta = dec(enc(b""))
    assert pt == b""
    assert meta["size"] == 0


def test_round_trip_small_text():
    msg = b"legal aid case file: confidential"
    pt, meta = dec(enc(msg))
    assert pt == msg
    assert meta["filename"] == "a.txt"
    assert meta["mime"] == "text/plain"
    assert meta["owner_id"] == 7
    assert meta["file_id"] == FID


def test_round_trip_binary():
    msg = bytes(range(256)) * 40 + b"\x00\xff\x00"
    pt, meta = dec(enc(msg))
    assert pt == msg


def test_round_trip_1mib():
    msg = b"A" * (1 << 20)
    pt, meta = dec(enc(msg))
    assert pt == msg


def test_meta_sha256_and_size_verified():
    msg = b"payload for hash"
    blob = enc(msg)
    pt, meta = dec(blob)
    assert meta["sha256"] == hashlib.sha256(msg).hexdigest()
    assert meta["size"] == len(msg)
    keys = sorted(meta)
    assert keys == ["file_id", "filename", "mime", "owner_id", "sha256", "size"]


def test_two_encryptions_differ():
    b1 = enc(b"same")
    b2 = enc(b"same")
    assert b1 != b2


# --------------------------------------------------------------------- helpers

def region_offsets(blob, pt=b"same-text-for-tamper"):
    """Byte offsets of each tamperable region in a v1 envelope."""
    meta_ct_len = struct.unpack("<I", blob[50:54])[0]
    pos = 22 + 12 + 16 + 4 + meta_ct_len
    aes_ct_len = struct.unpack("<I", blob[pos + 12 + 16:pos + 12 + 16 + 4])[0]
    return {
        "version": 5,
        "salt": 6,
        "meta_ct": 54,  # first META ciphertext byte
        "aes_tag": pos + 12,
        "aes_ct": pos + 12 + 16 + 4,
        "des_iv": pos + 12 + 16 + 4 + aes_ct_len,
        "des_mac": pos + 12 + 16 + 4 + aes_ct_len + 8,
        "rc4_mac": pos + 12 + 16 + 4 + aes_ct_len + 8 + 32,
        "rc4_ct": pos + 12 + 16 + 4 + aes_ct_len + 8 + 32 + 32 + 4,
    }


# --------------------------------------------------------------------- tamper

@pytest.mark.parametrize(
    "region", ["version", "salt", "meta_ct", "aes_tag", "aes_ct",
               "des_iv", "des_mac", "rc4_mac", "rc4_ct"]
)
def test_single_byte_tamper_fails(region):
    blob = bytearray(enc(b"tamper-target-payload"))
    idx = region_offsets(bytes(blob))[region]
    blob[idx] ^= 0x01
    with pytest.raises(CryptoError):
        dec(bytes(blob))


def test_meta_tag_tamper_fails():
    blob = bytearray(enc(b"tamper-target-payload"))
    blob[34] ^= 0x01  # META AES tag
    with pytest.raises(CryptoError):
        dec(bytes(blob))


@pytest.mark.parametrize("frac", [1, 2, 3])
def test_truncation_fails(frac):
    blob = enc(b"truncate-this-envelope-payload")
    with pytest.raises(CryptoError):
        dec(blob[: max(1, len(blob) * frac // 4)])


def test_truncation_last_16_fails():
    blob = enc(b"truncate-this-envelope-payload")
    with pytest.raises(CryptoError):
        dec(blob[:-16])


# ------------------------------------------------------------ failure classes

def test_wrong_master_fails():
    blob = enc(b"protected")
    other = bytes(range(32, 64))
    with pytest.raises(CryptoError):
        crypto.decrypt_file(blob, master=other, expect_owner=7, expect_file_id=FID)


def test_unsupported_version_fails():
    blob = bytearray(enc(b"v2-only"))
    blob[5] = 2  # structured version bump, not a random flip
    with pytest.raises(CryptoError):
        dec(bytes(blob))


def test_owner_mismatch_fails():
    blob = enc(b"owner-bound")
    with pytest.raises(CryptoError):
        crypto.decrypt_file(blob, master=MASTER, expect_owner=8, expect_file_id=FID)


def test_file_id_mismatch_fails():
    blob = enc(b"file-bound")
    with pytest.raises(CryptoError):
        crypto.decrypt_file(blob, master=MASTER, expect_owner=7, expect_file_id="other")


def test_bad_pkcs7_padding_fails():
    # Craft an envelope whose MACs are valid but whose DES ciphertext decodes
    # to an invalid PKCS#7 pad: corrupt the final block, re-encrypt the RC4
    # layer (same keystream reproduces the stream), recompute both MACs.
    blob = bytearray(enc(b"pad-check-payload"))
    keys = crypto.derive_keys(MASTER, bytes(blob[6:22]))
    meta_ct_len = struct.unpack("<I", bytes(blob[50:54]))[0]
    pos = 22 + 12 + 16 + 4 + meta_ct_len
    aes_ct_len = struct.unpack("<I", bytes(blob[pos + 28:pos + 32]))[0]
    p = pos + 12 + 16 + 4 + aes_ct_len
    des_iv = bytes(blob[p:p + 8])
    des_mac = bytes(blob[p + 8:p + 40])
    rc4_mac = bytes(blob[p + 40:p + 72])
    rc4_ct = bytes(blob[p + 76:])

    des_ct = bytearray(crypto.ARC4.new(keys["rc4"]).decrypt(rc4_ct))
    des_ct[-1] ^= 0x01  # corrupt final block only
    des_ct = bytes(des_ct)
    new_rc4_ct = crypto.ARC4.new(keys["rc4"]).encrypt(des_ct)
    new_des_mac = hmac.new(keys["hmac-des"], des_iv + des_ct, hashlib.sha256).digest()
    new_rc4_mac = hmac.new(keys["hmac-rc4"], new_rc4_ct, hashlib.sha256).digest()

    crafted = b"".join([
        bytes(blob[:p]),           # everything up to payload section intact
        des_iv, new_des_mac, new_rc4_mac,
        struct.pack("<I", len(new_rc4_ct)), new_rc4_ct,
    ])
    with pytest.raises(CryptoError):
        dec(crafted)
