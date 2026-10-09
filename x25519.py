import os

# =====================================================
# X25519 PARAMETERS (RFC 7748)
# =====================================================

# Prime field: 2^255 - 19 (finite field for Curve25519)
P_X25519 = 2**255 - 19

# Base point (generator) in little-endian format
G_X25519 = (9).to_bytes(32, "little")


# =====================================================
# SCALAR CLAMPING (RFC 7748 §5)
# =====================================================
def clamp_scalar(k_bytes: bytes) -> int:
    """
    Clamps private key as required by X25519:
    - Clears lowest 3 bits (multiple of 8)
    - Clears highest bit
    - Sets second highest bit
    """

    k = bytearray(k_bytes)

    # Clear lowest 3 bits (makes scalar a multiple of 8)
    k[0] &= 248

    # Clear most significant bit (bit 255)
    k[31] &= 127

    # Set bit 254 (required by RFC)
    k[31] |= 64

    # Convert to integer for scalar multiplication
    return int.from_bytes(k, "little")


# =====================================================
# X25519 SCALAR MULTIPLICATION (Montgomery Ladder)
# =====================================================
def scalar_mult(k_bytes: bytes, u_bytes: bytes) -> bytes:
    """
    Performs scalar multiplication on Curve25519.
    Implements Montgomery ladder for constant-time security.
    """

    p = P_X25519

    # Clamp private key (security requirement)
    k = clamp_scalar(k_bytes)

    # Clamp public u-coordinate (clear MSB)
    u = bytearray(u_bytes)
    u[31] &= 127
    u = int.from_bytes(u, "little")

    # Initialize Montgomery ladder variables
    x_1 = u
    x_2, z_2 = 1, 0
    x_3, z_3 = u, 1

    swap = 0

    # Iterate over 255 bits (from MSB → LSB)
    for t in range(254, -1, -1):

        # Extract bit t from scalar
        k_t = (k >> t) & 1

        # Conditional swap logic (constant-time style)
        swap ^= k_t
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2

        swap = k_t

        # Montgomery ladder step
        A = (x_2 + z_2) % p
        AA = (A * A) % p

        B = (x_2 - z_2) % p
        BB = (B * B) % p

        E = (AA - BB) % p

        C = (x_3 + z_3) % p
        D = (x_3 - z_3) % p

        DA = (D * A) % p
        CB = (C * B) % p

        # Update point (projective coordinates)
        x_3 = (DA + CB) ** 2 % p
        z_3 = (x_1 * (DA - CB) ** 2) % p

        x_2 = AA * BB % p
        z_2 = E * (AA + 121665 * E) % p

    # Final conditional swap
    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2

    # Convert from projective to affine coordinates
    result = x_2 * pow(z_2, p - 2, p) % p

    # Return 32-byte little-endian public key
    return result.to_bytes(32, "little")


# =====================================================
# KEY GENERATION
# =====================================================
def generate_private_key():
    """
    Generates 32-byte random private key.
    NOTE: should ideally be from cryptographically secure RNG (os.urandom is OK)
    """
    return os.urandom(32)


def generate_public_key(private_key):
    """
    Computes public key = private * base_point
    """
    return scalar_mult(private_key, G_X25519)


def compute_shared_secret(private_key, peer_public):
    """
    Computes shared secret using ECDH:
    secret = private_key * peer_public
    """
    return scalar_mult(private_key, peer_public)
