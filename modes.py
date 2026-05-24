import os
from .des_core import des_encrypt_block, des_decrypt_block


BLOCK_SIZE = 8


class DESError(Exception):
    pass


def pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise DESError("Данные для расшифровки пустые")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > BLOCK_SIZE:
        raise DESError("Неверный ключ — не удаётся расшифровать данные")
    if len(data) < pad_len:
        raise DESError("Неверный ключ — не удаётся расшифровать данные")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise DESError("Неверный ключ — не удаётся расшифровать данные")
    return data[:-pad_len]


def _split_blocks(data: bytes):
    return [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    _validate_key(key)
    padded = pkcs7_pad(plaintext)
    return b"".join(des_encrypt_block(block, key) for block in _split_blocks(padded))


def ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    _validate_key(key)
    _validate_ciphertext(ciphertext)
    decrypted = b"".join(des_decrypt_block(block, key) for block in _split_blocks(ciphertext))
    return pkcs7_unpad(decrypted)


def cbc_encrypt(plaintext: bytes, key: bytes, iv=None) -> tuple:
    _validate_key(key)
    if iv is None:
        iv = os.urandom(BLOCK_SIZE)
    _validate_iv(iv)
    padded = pkcs7_pad(plaintext)
    blocks = _split_blocks(padded)
    ciphertext = b""
    prev = iv
    for block in blocks:
        xored = bytes(a ^ b for a, b in zip(block, prev))
        encrypted = des_encrypt_block(xored, key)
        ciphertext += encrypted
        prev = encrypted
    return ciphertext, iv


def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    _validate_key(key)
    _validate_ciphertext(ciphertext)
    _validate_iv(iv)
    blocks = _split_blocks(ciphertext)
    plaintext = b""
    prev = iv
    for block in blocks:
        decrypted = des_decrypt_block(block, key)
        plaintext += bytes(a ^ b for a, b in zip(decrypted, prev))
        prev = block
    return pkcs7_unpad(plaintext)


def _validate_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)):
        raise DESError("Ключ должен быть байтовой строкой")
    if len(key) != 8:
        raise DESError(f"Ключ должен быть ровно 8 байт, получено {len(key)}")


def _validate_iv(iv: bytes) -> None:
    if not isinstance(iv, (bytes, bytearray)):
        raise DESError("Вектор инициализации должен быть байтовой строкой")
    if len(iv) != 8:
        raise DESError(f"Вектор инициализации должен быть ровно 8 байт, получено {len(iv)}")


def _validate_ciphertext(ciphertext: bytes) -> None:
    if not ciphertext:
        raise DESError("Зашифрованные данные пустые")
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise DESError(f"Зашифрованные данные повреждены — длина должна быть кратна 8 байтам")