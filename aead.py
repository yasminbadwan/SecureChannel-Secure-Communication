import struct
from chacha20 import chacha20_block, chacha20_xor
from Poly1305 import poly1305_mac


# =====================================================
# HELPER: PAD TO 16 BYTES (Poly1305 requirement)
# =====================================================
def pad16(data):
    """
    Poly1305 requires inputs to be multiple of 16 bytes.
    If not aligned, we pad with zero bytes.
    """

    if len(data) % 16 == 0:
        return b""

    return b"\x00" * (16 - (len(data) % 16))


# =====================================================
# HELPER: 64-bit little-endian encoding
# =====================================================
def le64(n):
    """
    Encodes integer as 8-byte little-endian value.
    Used in Poly1305 AAD and ciphertext length encoding.
    """
    return struct.pack("<Q", n)


# =====================================================
# AEAD ENCRYPTION (ChaCha20-Poly1305)
# =====================================================
def aead_encrypt(key, nonce, plaintext, aad=b""):

    # Validate key size (ChaCha20 requires 256-bit key)
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")

    # Validate nonce size (RFC 8439 uses 96-bit nonce)
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")

    # -------------------------------------------------
    # 1. Generate Poly1305 one-time key (OTK)
    # -------------------------------------------------
    # Derived by encrypting all-zero block with counter = 0
    otk = chacha20_block(key, 0, nonce)[:32]

    # -------------------------------------------------
    # 2. Encrypt plaintext using ChaCha20
    # -------------------------------------------------
    # Counter starts at 1 (counter=0 reserved for OTK)
    ciphertext = chacha20_xor(key, nonce, plaintext, counter=1)

    # -------------------------------------------------
    # 3. Build Poly1305 MAC input (RFC 8439 AAD format)
    # -------------------------------------------------
    mac_data = (
        aad + pad16(aad) +                    # authenticated but not encrypted data
        ciphertext + pad16(ciphertext) +      # encrypted data
        le64(len(aad)) +                      # length of AAD
        le64(len(ciphertext))                 # length of ciphertext
    )

    # -------------------------------------------------
    # 4. Compute authentication tag (Poly1305)
    # -------------------------------------------------
    tag = poly1305_mac(mac_data, otk)

    return ciphertext, tag


# =====================================================
# AEAD DECRYPTION
# =====================================================
def aead_decrypt(key, nonce, ciphertext, tag, aad=b""):

    # Validate key size
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")

    # Validate nonce size
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")

    # -------------------------------------------------
    # 1. Recompute Poly1305 one-time key
    # -------------------------------------------------
    otk = chacha20_block(key, 0, nonce)[:32]

    # -------------------------------------------------
    # 2. Rebuild MAC input (must match encryption exactly)
    # -------------------------------------------------
    mac_data = (
        aad + pad16(aad) +
        ciphertext + pad16(ciphertext) +
        le64(len(aad)) +
        le64(len(ciphertext))
    )

    # -------------------------------------------------
    # 3. Verify authentication tag (integrity check first)
    # -------------------------------------------------
    expected_tag = poly1305_mac(mac_data, otk)

    # Constant-time comparison is recommended (note: not implemented here)
    if expected_tag != tag:
        raise ValueError("TAG INVALID (message tampered or corrupted)")

    # -------------------------------------------------
    # 4. Decrypt ciphertext
    # -------------------------------------------------
    plaintext = chacha20_xor(key, nonce, ciphertext, counter=1)

    return plaintext
