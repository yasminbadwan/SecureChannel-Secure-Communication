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

# Pre-shared secret used for authentication (out-of-band agreement)
PSK  = b"super-secret-psk-agreed-out-of-band"

# Protocol identifier (prevents cross-protocol attacks)
PROTOCOL_VERSION = b"SecureChannel-v1"

# Entity identifiers
CLIENT_ID = 1
SERVER_ID = 2

# Message types
MSG_CHAT = 1
MSG_BYE  = 2


# =====================================================
# SERVER MAIN FUNCTION
# =====================================================
def run_server():

    print("[Server] Starting...")

    # Create TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:

        # Allow reuse of port after restart
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind to address
        srv.bind((HOST, PORT))

        # Listen for incoming connections
        srv.listen(1)

        print(f"[Server] Listening on {HOST}:{PORT}")

        # Accept client connection
        conn, addr = srv.accept()

        with conn:
            print(f"[Server] Connected by {addr}")

            # -------------------------------------------------
            # 1. Generate ephemeral X25519 key pair
            # -------------------------------------------------
            s_priv = generate_private_key()
            s_pub  = generate_public_key(s_priv)

            # Receive client public key
            c_pub = recv_exact(conn, 32)
            print(f"[Server] Got client pub: {c_pub.hex()[:16]}...")

            # Send server public key
            conn.sendall(s_pub)
            print(f"[Server] Sent server pub: {s_pub.hex()[:16]}...")

            # -------------------------------------------------
            # 2. Compute shared secret (ECDH)
            # -------------------------------------------------
            shared = compute_shared_secret(s_priv, c_pub)

            # -------------------------------------------------
            # 3. Build handshake transcript
            # -------------------------------------------------
            transcript = (
                PROTOCOL_VERSION +
                c_pub +
                s_pub +
                b"client" +
                b"server"
            )

            # -------------------------------------------------
            # 4. Authenticate client using HMAC
            # -------------------------------------------------
            c_tag = recv_exact(conn, 32)

            # Verify PSK + DH binding
            if c_tag != hmacsha256(PSK, transcript + shared):
                print("[Server] Client HMAC verification failed — aborting")
                return

            # Generate server authentication tag
            s_tag = hmacsha256(PSK, transcript + shared)

            # Send it to client
            conn.sendall(s_tag)

            print("[Server] Handshake complete")

            # -------------------------------------------------
            # 5. Key derivation (HKDF)
            # -------------------------------------------------
            keys = hkdf(shared, PSK, b"SecureChannel-X25519", 88)

            # Split derived key material
            c2s_enc   = keys[0:32]   # client → server encryption key
            s2c_enc   = keys[32:64]  # server → client encryption key
            c2s_nonce = keys[64:76]  # nonce base (client → server)
            s2c_nonce = keys[76:88]  # nonce base (server → client)

            # -------------------------------------------------
            # 6. Replay protection setup
            # -------------------------------------------------
            replay = ReplayProtection()

            # Expect messages from client starting at seq=0
            replay.register(CLIENT_ID)

            seq_recv = 0
            seq_send = 0

            print("[Server] Ready — waiting for messages\n")

            # =================================================
            # MAIN MESSAGE LOOP
            # =================================================
            while True:

                # Receive encrypted message
                result = receive_aead(conn, c2s_enc, c2s_nonce, seq_recv)

                if result is None:
                    break

                msg_payload, msg_aad = result

                # Decode structured frame
                msg_frame = Frame.decode(msg_aad + msg_payload)

                # -------------------------------------------------
                # Replay attack check
                # -------------------------------------------------
                if not replay.is_valid(msg_frame.sender_id, msg_frame.seq):
                    print(f"[Server] Replayed/out-of-order (seq={msg_frame.seq}) — dropping")
                    seq_recv += 1
                    continue

                seq_recv += 1

                # Client requested session termination
                if msg_frame.msg_type == MSG_BYE:
                    print("[Server] Client closed the session.")
                    break

                # Print decrypted message
                print(f"[Client]: {msg_payload.decode()}")

                # -------------------------------------------------
                # Server response
                # -------------------------------------------------
                reply_text = input("[You]: ").encode()

                msg_type = MSG_BYE if reply_text.lower() == b"bye" else MSG_CHAT

                reply_frame = Frame(
                    sender_id=SERVER_ID,
                    seq=seq_send,
                    msg_type=msg_type,
                    payload=reply_text
                )

                raw = reply_frame.encode()

                # AAD = authenticated metadata (not encrypted)
                aad = raw[:9]

                # Send encrypted response
                send_aead(conn, s2c_enc, s2c_nonce, seq_send, reply_text, aad)

                seq_send += 1

                if msg_type == MSG_BYE:
                    print("[Server] Goodbye!")
                    break


# =====================================================
# RECEIVE EXACT BYTES (TCP helper)
# =====================================================
def recv_exact(conn, n):
    """
    Ensures full reception of exactly n bytes.
    TCP is stream-based, so reads may be partial.
    """
    buf = b""

    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf += chunk

    return buf


# =====================================================
# AEAD SEND
# =====================================================
def send_aead(conn, key, nonce_base, seq, plaintext, aad):

    # Generate unique nonce per message
    nonce = xor_nonce(nonce_base, seq + 1)

    # Encrypt + authenticate
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

    conn.sendall(wire)


# =====================================================
# AEAD RECEIVE
# =====================================================
def receive_aead(conn, key, nonce_base, seq):

    try:
        aad_len    = int.from_bytes(recv_exact(conn, 2), "little")
        aad        = recv_exact(conn, aad_len)

        ct_len     = int.from_bytes(recv_exact(conn, 8), "little")
        ciphertext = recv_exact(conn, ct_len)

        tag        = recv_exact(conn, 16)

        # Reconstruct nonce
        nonce = xor_nonce(nonce_base, seq + 1)

        # Decrypt + verify integrity
        plaintext = aead_decrypt(key, nonce, ciphertext, tag, aad)

        return plaintext, aad

    except Exception as e:
        print(f"[Server] Receive error: {e}")
        return None


# =====================================================
# NONCE DERIVATION
# =====================================================
def xor_nonce(base, counter):

    counter_bytes = counter.to_bytes(12, "little")

    # XOR-based nonce binding with sequence counter
    return bytes(a ^ b for a, b in zip(base, counter_bytes))


# =====================================================
# ENTRY POINT
# =====================================================
if __name__ == "__main__":
    run_server()
