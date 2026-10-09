# =========================
# Replay Protection Module
# =========================
# Purpose:
# Prevent replay attacks by enforcing
# strictly increasing sequence numbers per sender.
# =========================

class ReplayProtection:

    def __init__(self):
        """
        Stores the last accepted sequence number for each sender.
        
        Structure:
        - key: sender_id
        - value: last accepted sequence number
        """

        # -1 means: no message received yet (expecting seq = 0)
        self.last_seq = {}

    # =====================================================
    # Register sender after handshake
    # =====================================================
    def register(self, sender_id: int):
        """
        Initialize tracking for a sender.
        Must be called after handshake completion.
        """

        # Start at -1 so first valid sequence is 0
        self.last_seq[sender_id] = -1

    # =====================================================
    # Validate incoming message
    # =====================================================
    def is_valid(self, sender_id: int, seq: int) -> bool:
        """
        Checks whether a message is valid or replayed.
        
        Rules:
        - Sender must be registered
        - First message must have seq = 0
        - Every next seq must be strictly greater than last accepted
        """

        # Reject messages from unknown senders
        if sender_id not in self.last_seq:
            return False

        last = self.last_seq[sender_id]

        # Reject replayed or duplicate messages
        if seq <= last:
            return False

        # Accept message and update state
        self.last_seq[sender_id] = seq
        return True

    # =====================================================
    # Reset sender state
    # =====================================================
    def reset(self, sender_id: int):
        """
        Resets sequence tracking for a sender.
        Useful for restarting a session or debugging.
        """

        if sender_id in self.last_seq:
            self.last_seq[sender_id] = -1
