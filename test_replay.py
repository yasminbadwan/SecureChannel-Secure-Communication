from replay_protection import ReplayProtection
from protocol_frames import create_message, parse_message

# =========================
# Initialize system
# =========================
rp = ReplayProtection()
sender_id = 1
rp.register(sender_id) 

# =========================
# Simulate messages
# =========================

print("=== TEST 1: Normal flow ===")

msg1 = create_message(sender_id, 0, 1, "Hello 1") 
msg2 = create_message(sender_id, 1, 1, "Hello 2")
msg3 = create_message(sender_id, 2, 1, "Hello 3")

for msg in [msg1, msg2, msg3]:
    frame = parse_message(msg)
    valid = rp.is_valid(frame["sender_id"], frame["seq"])
    print(frame, "=>", valid)

# =========================
# Replay attack simulation
# =========================

print("\n=== TEST 2: Replay attack ===")

replay_msg = create_message(sender_id, 1, 1, "REPLAY ATTACK")

frame = parse_message(replay_msg)
valid = rp.is_valid(frame["sender_id"], frame["seq"])
print(frame, "=>", valid)

# =========================
# Old message test
# =========================

print("\n=== TEST 3: Old message ===")

old_msg = create_message(sender_id, 0, 1, "OLD MESSAGE")

frame = parse_message(old_msg)
valid = rp.is_valid(frame["sender_id"], frame["seq"])
print(frame, "=>", valid)
