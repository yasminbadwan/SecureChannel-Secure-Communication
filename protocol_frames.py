import struct
import json

# =====================================================
# PROTOCOL FRAME STRUCTURE
# =====================================================
"""
This module defines a simple binary message format
used for secure communication between client and server.

Frame layout:

| sender_id (4 bytes) |  -> identifies sender (client/server)
| seq       (4 bytes) |  -> sequence number (replay protection)
| msg_type  (1 byte)  |  -> message type (chat / bye / etc.)
| payload   (variable) |  -> actual message data
"""

class Frame:
    def __init__(self, sender_id: int, seq: int, msg_type: int, payload: bytes):
        """
        Initialize a protocol frame.
        """

        self.sender_id = sender_id
        self.seq = seq
        self.msg_type = msg_type
        self.payload = payload

    # =====================================================
    # ENCODE FRAME → BYTES (for transmission)
    # =====================================================
    def encode(self) -> bytes:
        """
        Converts structured frame into raw bytes
        suitable for sending over a network.
        """

        # Pack fixed-size header in big-endian format
        header = struct.pack(
            ">I I B",
            self.sender_id,  # 4 bytes
            self.seq,        # 4 bytes
            self.msg_type    # 1 byte
        )

        # Append payload (not fixed size)
        return header + self.payload

    # =====================================================
    # DECODE BYTES → FRAME (on receiver side)
    # =====================================================
    @staticmethod
    def decode(data: bytes):
        """
        Parses raw bytes back into a Frame object.
        """

        # Extract fixed header (first 9 bytes)
        sender_id, seq, msg_type = struct.unpack(">I I B", data[:9])

        # Remaining bytes are payload
        payload = data[9:]

        return Frame(sender_id, seq, msg_type, payload)


# =====================================================
# HELPER FUNCTIONS
# =====================================================

def create_message(sender_id: int, seq: int, msg_type: int, payload_str: str) -> bytes:
    """
    Convenience function:
    Builds a frame from a string message and encodes it.
    """

    payload = payload_str.encode()  # convert string → bytes
    frame = Frame(sender_id, seq, msg_type, payload)

    return frame.encode()


def parse_message(data: bytes):
    """
    Decodes a frame and returns a human-readable dictionary.
    Useful for debugging or logging.
    """

    frame = Frame.decode(data)

    return {
        "sender_id": frame.sender_id,
        "seq": frame.seq,
        "msg_type": frame.msg_type,
        "payload": frame.payload.decode()
    }
