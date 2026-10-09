
from sha256 import sha256

# =====================================================
# HMAC-SHA-256 — RFC 2104
# =====================================================

BLOCK = 64

def xor_bytes(data, byte):
    return bytes([b ^ byte for b in data])

def hmacsha256(key: bytes, message: bytes):
    if len(key) > BLOCK:
        key = sha256(key)
    key = key.ljust(BLOCK, b'\x00')
    inner = sha256(xor_bytes(key, 0x36) + message)
    outer = sha256(xor_bytes(key, 0x5c) + inner)
    return outer