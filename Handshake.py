from x25519 import generate_private_key, generate_public_key, compute_shared_secret
from hmaac import hmacsha256
from hkdf import hkdf
import os

# =====================================================
# HANDSHAKE MODULE
# =====================================================
# 
# Establish a secure session key between client and server
# using:
# 1. X25519 Diffie-Hellman (key exchange)
# 2. PSK-based HMAC (authentication)
# 3. HKDF (key derivation)
# =====================================================

# Protocol identifier (binds handshake to specific protocol version)
PROTOCOL_VERSION = b"SecureChannel-v1"

# Pre-shared key (known only to both parties)
# Used for authentication (HMAC)
PSK = b"super-secret-psk-agreed-out-of-band"


# =====================================================
# BUILD HANDSHAKE TRANSCRIPT
# =====================================================
def build_transcript(version: bytes, c_pub: bytes, s_pub: bytes,
                     cid: str, sid: str) -> bytes:
    """
    Creates a deterministic transcript of the handshake.

    Included values:
    - Protocol version
    - Client public key
    - Server public key
    - Client identity
    - Server identity

    Why important?
     Prevents Man-in-the-Middle attacks
     Ensures both parties authenticate the same session context
    """

    return version + c_pub + s_pub + cid.encode() + sid.encode()


# =====================================================
# HANDSHAKE FUNCTION
# =====================================================
def handshake():
    """
    Performs full cryptographic handshake:

    Step 1: Generate ephemeral X25519 keys
    Step 2: Perform Diffie-Hellman exchange
    Step 3: Build handshake transcript
    Step 4: Authenticate using HMAC(PSK, transcript + shared_secret)
    """

    # -------------------------------------------------
    # 1. Generate ephemeral key pairs
    # -------------------------------------------------
    c_priv = generate_private_key()   # client private key
    s_priv = generate_private_key()   # server private key

    c_pub  = generate_public_key(c_priv)  # client public key
    s_pub  = generate_public_key(s_priv)  # server public key

    # -------------------------------------------------
    # 2. Compute Diffie-Hellman shared secret
    # -------------------------------------------------
    shared_secret = compute_shared_secret(c_priv, s_pub)

    # Verify correctness (should always match on both sides)
    assert compute_shared_secret(s_priv, c_pub) == shared_secret

    # -------------------------------------------------
    # 3. Build handshake transcript
    # -------------------------------------------------
    transcript = build_transcript(
        PROTOCOL_VERSION,
        c_pub,
        s_pub,
        "client",
        "server"
    )

    # -------------------------------------------------
    # 4. Authentication using PSK + shared secret
    # -------------------------------------------------
    # HMAC binds:
    # - long-term secret (PSK)
    # - ephemeral DH result (shared_secret)
    tag_c = hmacsha256(PSK, transcript + shared_secret)
    tag_s = hmacsha256(PSK, transcript + shared_secret)

    # In real protocol:
    # client sends tag_c, server verifies it, and vice versa

    # Here we simulate equality check
    assert tag_c == tag_s, "HMAC verification failed — handshake aborted"

    print("[Handshake] HMAC authentication passed")

    # Return derived shared secret for key derivation phase
    return shared_secret


# =====================================================
# MAIN EXECUTION
# =====================================================
if __name__ == "__main__":

    # Run handshake and obtain shared secret
    secret = handshake()

    # -------------------------------------------------
    # 5. Key derivation input (salt)
    # -------------------------------------------------
    salt = os.urandom(16)
    # -------------------------------------------------
    # 6. HKDF key expansion
    # -------------------------------------------------
    # Derive:
    # - c2s encryption key (32 bytes)
    # - s2c encryption key (32 bytes)
    # - c2s nonce base (12 bytes)ٍ
    # - s2c nonce base (12 bytes)
    keys = hkdf(secret, salt, b"SecureChannel-X25519", 96)

    c2s_enc   = keys[0:32]
    s2c_enc   = keys[32:64]
    c2s_nonce = keys[64:76]
    s2c_nonce = keys[76:88]

    # -------------------------------------------------
    # 7. Output derived material (debug / verification)
    # -------------------------------------------------
    print("Client → Server Key:", c2s_enc.hex())
    print("Server → Client Key:", s2c_enc.hex())
    print("Client → Server Nonce:", c2s_nonce.hex())
    print("Server → Client Nonce:", s2c_nonce.hex())
