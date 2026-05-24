from .tables import IP, IP_INV
from .keyschedule import generate_subkeys, key_bytes_to_bits
from .feistel import feistel


def _permute(block: list[int], table: list[int]) -> list[int]:
    return [block[i - 1] for i in table]


def _xor(a: list[int], b: list[int]) -> list[int]:
    return [x ^ y for x, y in zip(a, b)]


def _block_to_bits(block: bytes) -> list[int]:
    if len(block) != 8:
        raise ValueError(f"Block must be 8 bytes, got {len(block)}")
    bits = []
    for byte in block:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_block(bits: list[int]) -> bytes:
    if len(bits) != 64:
        raise ValueError(f"Expected 64 bits, got {len(bits)}")
    result = bytearray()
    for i in range(8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i * 8 + j]
        result.append(byte)
    return bytes(result)


def _des_block(block: bytes, subkeys: list[list[int]]) -> bytes:
    bits = _block_to_bits(block)
    permuted = _permute(bits, IP)
    l, r = permuted[:32], permuted[32:]

    for subkey in subkeys:
        l, r = r, _xor(l, feistel(r, subkey))

    combined = _permute(r + l, IP_INV)
    return _bits_to_block(combined)


def des_encrypt_block(block: bytes, key: bytes) -> bytes:
    key_bits = key_bytes_to_bits(key)
    subkeys = generate_subkeys(key_bits)
    return _des_block(block, subkeys)


def des_decrypt_block(block: bytes, key: bytes) -> bytes:
    key_bits = key_bytes_to_bits(key)
    subkeys = generate_subkeys(key_bits)
    return _des_block(block, list(reversed(subkeys)))


def des_encrypt_block_with_rounds(block: bytes, key: bytes) -> tuple[bytes, list[dict]]:
    key_bits = key_bytes_to_bits(key)
    subkeys = generate_subkeys(key_bits)

    bits = _block_to_bits(block)
    permuted = _permute(bits, IP)
    l, r = permuted[:32], permuted[32:]

    rounds = []
    for i, subkey in enumerate(subkeys):
        new_r = _xor(l, feistel(r, subkey))
        rounds.append({
            "round": i + 1,
            "L": _bits_to_block(l + [0] * 32).hex()[:8],
            "R": _bits_to_block(r + [0] * 32).hex()[:8],
            "subkey": _bits_to_block(subkey + [0] * 16).hex()[:12],
        })
        l, r = r, new_r

    combined = _permute(r + l, IP_INV)
    return _bits_to_block(combined), rounds