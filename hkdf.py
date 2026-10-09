from hmaac import hmacsha256

# =========================
# HKDF - RFC 5869
# Key Derivation Function based on HMAC-SHA256
# =========================

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """
    Extract step of HKDF.

    Input:
        salt: optional random value used for randomness
        ikm: input key material (initial secret)

    Output:
        PRK: pseudorandom key
    """

    # If salt is empty, replace it with a zero-filled string
    if salt is None or len(salt) == 0:
        salt = b'\x00' * 32  # SHA-256 output size

    # Apply HMAC to extract pseudorandom key
    return hmacsha256(salt, ikm)


# ----------------------------

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """
    Expand step of HKDF.

    Input:
        prk: pseudorandom key from extract step
        info: optional context/application-specific information
        length: required output key length

    Output:
        OKM: output keying material
    """

    hash_len = 32  # SHA-256 output size

    # Ensure requested length is within allowed limit
    if length > 255 * hash_len:
        raise ValueError("Requested key too long")

    # Calculate number of blocks needed
    n_blocks = (length + hash_len - 1) // hash_len

    okm = b""
    previous_block = b""

    # Generate each block iteratively
    for i in range(1, n_blocks + 1):
        data = previous_block + info + bytes([i])
        previous_block = hmacsha256(prk, data)
        okm += previous_block

    # Trim output to requested length
    return okm[:length]


# ----------------------------

def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """
    Full HKDF construction (Extract + Expand).

    This function derives cryptographic keys from input material.
    """

    # Step 1: Extract pseudorandom key
    prk = hkdf_extract(salt, ikm)

    # Step 2: Expand into final key material
    return hkdf_expand(prk, info, length)