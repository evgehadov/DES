from .tables import PC1, PC2, SHIFT_SCHEDULE


def _permute(block: list[int], table: list[int]) -> list[int]:
    return [block[i - 1] for i in table]


def _rotate_left(bits: list[int], n: int) -> list[int]:
    return bits[n:] + bits[:n]


def generate_subkeys(key_bits: list[int]) -> list[list[int]]:
    if len(key_bits) != 64:
        raise ValueError(f"Key must be 64 bits, got {len(key_bits)}")

    key_56 = _permute(key_bits, PC1)
    c, d = key_56[:28], key_56[28:]

    subkeys = []
    for shift in SHIFT_SCHEDULE:
        c = _rotate_left(c, shift)
        d = _rotate_left(d, shift)
        cd = c + d
        subkeys.append(_permute(cd, PC2))

    return subkeys


def key_bytes_to_bits(key: bytes) -> list[int]:
    if len(key) != 8:
        raise ValueError(f"DES key must be exactly 8 bytes, got {len(key)}")
    bits = []
    for byte in key:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits