
def clamp_r(r_bytes):
    r = bytearray(r_bytes)

    r[3]  &= 15
    r[7]  &= 15
    r[11] &= 15
    r[15] &= 15

    r[4]  &= 252
    r[8]  &= 252
    r[12] &= 252

    return bytes(r)


def poly1305_mac(msg, key):
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")

    r = clamp_r(key[:16])
    s = key[16:]

    r_num = int.from_bytes(r, "little")
    s_num = int.from_bytes(s, "little")

    p = (1 << 130) - 5

    acc = 0

    for i in range(0, len(msg), 16):
        block = msg[i:i+16]

        n = int.from_bytes(block + b"\x01", "little")

        acc = (acc + n) % p
        acc = (acc * r_num) % p

    acc = (acc + s_num) % (1 << 128)

    return acc.to_bytes(16, "little")

