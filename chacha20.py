import struct


def rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff


def quarter_round(st, a, b, c, d):
    st[a] = (st[a] + st[b]) & 0xffffffff
    st[d] ^= st[a]
    st[d] = rotl32(st[d], 16)

    st[c] = (st[c] + st[d]) & 0xffffffff
    st[b] ^= st[c]
    st[b] = rotl32(st[b], 12)

    st[a] = (st[a] + st[b]) & 0xffffffff
    st[d] ^= st[a]
    st[d] = rotl32(st[d], 8)

    st[c] = (st[c] + st[d]) & 0xffffffff
    st[b] ^= st[c]
    st[b] = rotl32(st[b], 7)


def chacha20_block(key, counter, nonce):

    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")

    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be 12 bytes")

    state = [
        0x61707865, 0x3320646e,
        0x79622d32, 0x6b206574,
    ]

    state += [
        int.from_bytes(key[i:i + 4], "little")
        for i in range(0, 32, 4)
    ]

    state.append(counter & 0xffffffff)

    state += [
        int.from_bytes(nonce[i:i + 4], "little")
        for i in range(0, 12, 4)
    ]

    working = state.copy()

    for _ in range(10):
        # column rounds
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)

        # diagonal rounds
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)

    out = [
        (working[i] + state[i]) & 0xffffffff
        for i in range(16)
    ]

    return struct.pack("<16I", *out)


def chacha20_xor(key, nonce, data, counter=1):
    result = bytearray()

    for i in range(0, len(data), 64):
        block = data[i:i + 64]

        keystream = chacha20_block(key, counter, nonce)
        counter += 1

        result.extend(
            b ^ k for b, k in zip(block, keystream)
        )

    return bytes(result)

