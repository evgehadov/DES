from .tables import E, P, S_BOXES


def _permute(block: list[int], table: list[int]) -> list[int]:
    return [block[i - 1] for i in table]


def _xor(a: list[int], b: list[int]) -> list[int]:
    return [x ^ y for x, y in zip(a, b)]


def _apply_sboxes(bits_48: list[int]) -> list[int]:
    result = []
    for i in range(8):
        chunk = bits_48[i * 6:(i + 1) * 6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        val = S_BOXES[i][row][col]
        for j in range(3, -1, -1):
            result.append((val >> j) & 1)
    return result


def feistel(r: list[int], subkey: list[int]) -> list[int]:
    expanded = _permute(r, E)
    xored = _xor(expanded, subkey)
    substituted = _apply_sboxes(xored)
    return _permute(substituted, P)