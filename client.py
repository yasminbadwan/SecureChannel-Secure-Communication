import socket
import os
from x25519 import generate_private_key, generate_public_key, compute_shared_secret
from hmaac import hmacsha256
from hkdf import hkdf
from aead import aead_encrypt, aead_decrypt
from replay_protection import ReplayProtection
from protocol_frames import Frame


# =====================================================
# NETWORK CONFIGURATION
# =====================================================
HOST = "127.0.0.1"
PORT = 5555

# Pre-Shared Key used for authentication (PSK model)
PSK  = b"super-secret-psk-agreed-out-of-band"

# Protocol identifier (prevents cross-protocol attacks)
PROTOCOL_VERSION = b"SecureChannel-v1"

# Sender identifiers
CLIENT_ID = 1
SERVER_ID = 2

# Message types
MSG_CHAT = 1
MSG_BYE  = 2


# =====================================================
# CLIENT MAIN FUNCTION
# =====================================================
def run_client():

    print("[Client] Connecting to server...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

        # Connect to server
        sock.connect((HOST, PORT))
        print(f"[Client] Connected to {HOST}:{PORT}")

        # -------------------------------------------------
        # 1. Generate ephemeral X25519 key pair
        # -------------------------------------------------
        c_priv = generate_private_key()
        c_pub  = generate_public_key(c_priv)

        # Send client public key to server
        sock.sendall(c_pub)
        print(f"[Client] Sent client pub: {c_pub.hex()[:16]}...")

        # Receive server public key
        s_pub = recv_exact(sock, 32)
        print(f"[Client] Got server pub: {s_pub.hex()[:16]}...")

        # -------------------------------------------------
        # 2. Compute shared secret (ECDH)
        # -------------------------------------------------
        shared = compute_shared_secret(c_priv, s_pub)

        # -------------------------------------------------
        # 3. Build handshake transcript
        # -------------------------------------------------
        # Includes all handshake parameters to prevent MITM
        transcript = PROTOCOL_VERSION + c_pub + s_pub + b"client" + b"server"

        # -------------------------------------------------
        # 4. Authenticate handshake using HMAC
        # -------------------------------------------------
        # Binds:
        # - PSK (long-term secret)
        # - DH shared secret (ephemeral secret)
        c_tag = hmacsha256(PSK, transcript + shared)

        # Send authentication tag to server
        sock.sendall(c_tag)

        # Receive server authentication tag
        s_tag = recv_exact(sock, 32)

        # Verify server authenticity
        if s_tag != hmacsha256(PSK, transcript + shared):
            print("[Client] Server HMAC verification failed — aborting")
            return

        print("[Client] Handshake complete")

        # -------------------------------------------------
        # 5. Key derivation (HKDF)
        # ------------------------------------------------- 
        ## Derive multiple keys from shared secret
        keys = hkdf(shared, PSK, b"SecureChannel-X25519", 88)

       
      

        c2s_enc   = keys[0:32]   # client → server encryption key
        s2c_enc   = keys[32:64]  # server → client encryption key
        c2s_nonce = keys[64:76]  # nonce base for client → server
        s2c_nonce = keys[76:88]  # nonce base for server → client

        # -------------------------------------------------
        # 6. Replay protection setup
        # -------------------------------------------------
        replay = ReplayProtection()

        # Expect first message from server to have seq = 0
        replay.register(SERVER_ID)

        seq_send = 0
        seq_recv = 0

        print("[Client] Ready — type messages ('bye' to quit)\n")

        # =================================================
        # MAIN MESSAGE LOOP
        # =================================================
        while True:

            msg_text = input("[You]: ").encode()

            # Determine message type
            msg_type = MSG_BYE if msg_text.lower() == b"bye" else MSG_CHAT

            # Create structured frame
            frame = Frame(sender_id=CLIENT_ID, seq=seq_send,
                          msg_type=msg_type, payload=msg_text)

            raw = frame.encode()

            # AAD = authenticated but not encrypted metadata
            aad = raw[:9]

            # Encrypt + send
            send_aead(sock, c2s_enc, c2s_nonce, seq_send, msg_text, aad)

            seq_send += 1

            # If user exits
            if msg_type == MSG_BYE:
                print("[Client] Goodbye!")
                break

            # -------------------------------------------------
            # Receive response
            # -------------------------------------------------
            result = receive_aead(sock, s2c_enc, s2c_nonce, seq_recv)

            if result is None:
                break

            reply_payload, reply_aad = result

            reply_frame = Frame.decode(reply_aad + reply_payload)

            # -------------------------------------------------
            # Replay protection check
            # -------------------------------------------------
            if not replay.is_valid(reply_frame.sender_id, reply_frame.seq):
                print(f"[Client] Replayed/out-of-order (seq={reply_frame.seq}) — dropping")
                seq_recv += 1
                continue

            # Server requested termination
            if reply_frame.msg_type == MSG_BYE:
                print("[Client] Server closed the session.")
                break

            print(f"[Server]: {reply_payload.decode()}")
            seq_recv += 1


# =====================================================
# RECEIVE EXACT BYTES FROM SOCKET
# =====================================================
def recv_exact(sock, n):
    """
    Ensures full reception of n bytes (TCP is stream-based).
    """
    buf = b""

    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf += chunk

    return buf


# =====================================================
# AEAD SEND (encrypt + authenticate)
# =====================================================
def send_aead(sock, key, nonce_base, seq, plaintext, aad):

    # Generate unique nonce per message
    nonce = xor_nonce(nonce_base, seq + 1)

    ciphertext, tag = aead_encrypt(key, nonce, plaintext, aad)

    # Wire format:
    # [aad_len][aad][ct_len][ciphertext][tag]
    wire = (
        len(aad).to_bytes(2, "little") +
        aad +
        len(ciphertext).to_bytes(8, "little") +
        ciphertext +
        tag
    )

    sock.sendall(wire)


# =====================================================
# AEAD RECEIVE (decrypt + verify)
# =====================================================
def receive_aead(sock, key, nonce_base, seq):

    try:
        aad_len    = int.from_bytes(recv_exact(sock, 2), "little")
        aad        = recv_exact(sock, aad_len)

        ct_len     = int.from_bytes(recv_exact(sock, 8), "little")
        ciphertext = recv_exact(sock, ct_len)

        tag        = recv_exact(sock, 16)

        # Reconstruct nonce
        nonce = xor_nonce(nonce_base, seq + 1)

        plaintext = aead_decrypt(key, nonce, ciphertext, tag, aad)

        return plaintext, aad

    except Exception as e:
        print(f"[Client] Receive error: {e}")
        return None


# =====================================================
# NONCE CONSTRUCTION
# =====================================================
def xor_nonce(base, counter):
    """
    XOR-based nonce derivation using 12-byte counter.
    Ensures uniqueness per message.
    """
    counter_bytes = counter.to_bytes(12, "little")
    return bytes(a ^ b for a, b in zip(base, counter_bytes))


# =====================================================
# ENTRY POINT
# =====================================================
if __name__ == "__main__":
    run_client()
