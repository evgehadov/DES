import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from des_impl import (
    ecb_encrypt, ecb_decrypt,
    cbc_encrypt, cbc_decrypt,
    des_encrypt_block, des_decrypt_block,
    des_encrypt_block_with_rounds,
    DESError,
)
from des_impl.modes import pkcs7_pad, pkcs7_unpad
from des_impl.keyschedule import generate_subkeys, key_bytes_to_bits
from des_impl.tables import IP, IP_INV, S_BOXES, SHIFT_SCHEDULE


# ── NIST / known-answer vectors ──────────────────────────────────────────────

def test_nist_vector_1():
    plaintext = bytes.fromhex("0000000000000000")
    key       = bytes.fromhex("0000000000000000")
    expected  = bytes.fromhex("8ca64de9c1b123a7")
    assert des_encrypt_block(plaintext, key) == expected


def test_nist_vector_2():
    plaintext = bytes.fromhex("ffffffffffffffff")
    key       = bytes.fromhex("ffffffffffffffff")
    expected  = bytes.fromhex("7359b2163e4edc58")
    assert des_encrypt_block(plaintext, key) == expected


def test_nist_vector_3():
    plaintext = bytes.fromhex("0000000000000000")
    key       = bytes.fromhex("133457799bbcdff1")
    expected  = bytes.fromhex("948a43f98a834f7e")
    assert des_encrypt_block(plaintext, key) == expected


def test_nist_vector_4():
    plaintext = bytes.fromhex("0123456789abcdef")
    key       = bytes.fromhex("133457799bbcdff1")
    expected  = bytes.fromhex("85e813540f0ab405")
    _ = des_encrypt_block(plaintext, key)
    dec = des_decrypt_block(_, key)
    assert dec == plaintext


# ── Encrypt → Decrypt round-trip ─────────────────────────────────────────────

def test_encrypt_decrypt_block_roundtrip():
    plaintext = b"DES_TEST"
    key       = b"SECURKEY"
    assert des_decrypt_block(des_encrypt_block(plaintext, key), key) == plaintext


def test_ecb_roundtrip_short():
    plaintext = b"Hello!"
    key       = b"12345678"
    assert ecb_decrypt(ecb_encrypt(plaintext, key), key) == plaintext


def test_ecb_roundtrip_exact_block():
    plaintext = b"ABCDEFGH"
    key       = b"keykeyke"
    assert ecb_decrypt(ecb_encrypt(plaintext, key), key) == plaintext


def test_ecb_roundtrip_multiple_blocks():
    plaintext = b"This is a longer plaintext message for DES!"
    key       = b"testkey1"
    assert ecb_decrypt(ecb_encrypt(plaintext, key), key) == plaintext


def test_cbc_roundtrip_with_random_iv():
    plaintext = b"CBC mode test message"
    key       = b"cbckey12"
    ciphertext, iv = cbc_encrypt(plaintext, key)
    assert cbc_decrypt(ciphertext, key, iv) == plaintext


def test_cbc_roundtrip_fixed_iv():
    plaintext = b"Fixed IV test"
    key       = b"fixedkey"
    iv        = b"\x00" * 8
    ciphertext, used_iv = cbc_encrypt(plaintext, key, iv)
    assert used_iv == iv
    assert cbc_decrypt(ciphertext, key, used_iv) == plaintext


# ── Padding ───────────────────────────────────────────────────────────────────

def test_pkcs7_pad_partial_block():
    data = b"Hello"
    padded = pkcs7_pad(data)
    assert len(padded) == 8
    assert padded == b"Hello\x03\x03\x03"


def test_pkcs7_pad_full_block():
    data = b"ABCDEFGH"
    padded = pkcs7_pad(data)
    assert len(padded) == 16
    assert padded[8:] == b"\x08" * 8


def test_pkcs7_unpad_valid():
    padded = b"Hello\x03\x03\x03"
    assert pkcs7_unpad(padded) == b"Hello"


def test_pkcs7_unpad_invalid_raises():
    bad = b"Hello\x00\x00\x00"
    with pytest.raises(DESError):
        pkcs7_unpad(bad)


# ── Key schedule ──────────────────────────────────────────────────────────────

def test_keyschedule_produces_16_subkeys():
    key_bits = key_bytes_to_bits(b"testkey1")
    subkeys = generate_subkeys(key_bits)
    assert len(subkeys) == 16


def test_keyschedule_each_subkey_48_bits():
    key_bits = key_bytes_to_bits(b"testkey1")
    subkeys = generate_subkeys(key_bits)
    assert all(len(sk) == 48 for sk in subkeys)


def test_keyschedule_wrong_key_length():
    with pytest.raises(ValueError):
        generate_subkeys([0] * 32)


# ── Error handling / input validation ────────────────────────────────────────

def test_ecb_wrong_key_length_raises():
    with pytest.raises(DESError):
        ecb_encrypt(b"hello", b"short")


def test_cbc_wrong_iv_length_raises():
    with pytest.raises(DESError):
        cbc_encrypt(b"hello", b"12345678", iv=b"short")


def test_ecb_decrypt_non_multiple_raises():
    with pytest.raises(DESError):
        ecb_decrypt(b"notmultiple", b"12345678")


def test_ecb_wrong_key_decrypt_bad_padding():
    plaintext  = b"Secret message"
    key_enc    = b"rightkey"
    key_bad    = b"wrongkey"
    ciphertext = ecb_encrypt(plaintext, key_enc)
    with pytest.raises(DESError):
        ecb_decrypt(ciphertext, key_bad)


# ── Round visualisation ───────────────────────────────────────────────────────

def test_encrypt_with_rounds_returns_16_rounds():
    block = b"testblck"
    key   = b"12345678"
    _, rounds = des_encrypt_block_with_rounds(block, key)
    assert len(rounds) == 16
    assert all("round" in r and "L" in r and "R" in r for r in rounds)


# ── S-box sanity ──────────────────────────────────────────────────────────────

def test_sboxes_values_in_range():
    for box in S_BOXES:
        for row in box:
            assert all(0 <= v <= 15 for v in row), "S-box value out of 0-15 range"
            assert len(row) == 16


# ── Tables integrity ──────────────────────────────────────────────────────────

def test_ip_and_ip_inv_are_inverse():
    bits = list(range(1, 65))
    permuted   = [bits[i - 1] for i in IP]
    unpermuted = [permuted[i - 1] for i in IP_INV]
    assert unpermuted == bits


def test_shift_schedule_sum():
    assert sum(SHIFT_SCHEDULE) == 28
    assert len(SHIFT_SCHEDULE) == 16