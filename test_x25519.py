# test_x25519.py
import os
from x25519 import scalar_mult  

passed = 0
failed = 0

def check(label, got, expected):
    global passed, failed
    if got == expected:
        print(f" {label}")
        passed += 1
    else:
        print(f" {label}")
        print(f"       got:      {got.hex()}")
        print(f"       expected: {expected.hex()}")
        failed += 1

def section(title):
    print("\n" + "="*65)
    print(f"  {title}")
    print("="*65)

# =====================================================
# 5.2 fixed input/output
# =====================================================
section("RFC 7748 §5.2 — fixed input/output")

k1 = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
u1 = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
check("5.2 vector 1",
      scalar_mult(k1, u1),
      bytes.fromhex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"))

k2 = bytes.fromhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
u2 = bytes.fromhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
check("5.2 vector 2",
      scalar_mult(k2, u2),
      bytes.fromhex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"))

# =====================================================
# 5.2 iterative
# =====================================================
section("RFC 7748 5.2 — iterative")

G = bytes.fromhex("0900000000000000000000000000000000000000000000000000000000000000")
k = G[:]
u = G[:]

# After 1 iteration
k_new = scalar_mult(k, u)
check("Iterative 1 iteration",
      k_new,
      bytes.fromhex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"))

# After 1,000 iterations
k = G[:]
u = G[:]
for _ in range(1000):
    k_new = scalar_mult(k, u)
    u = k
    k = k_new
check("Iterative 1,000 iterations",
      k,
      bytes.fromhex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"))

# =====================================================
# 6.1 ECDH Diffie-Hellman
# =====================================================
section("RFC 7748 6.1 — ECDH Diffie-Hellman")

alice_priv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
bob_priv   = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
G_base     = bytes.fromhex("0900000000000000000000000000000000000000000000000000000000000000")


alice_pub = scalar_mult(alice_priv, G_base)
bob_pub   = scalar_mult(bob_priv, G_base)

check("Alice public key",
      alice_pub,
      bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))

check("Bob public key",
      bob_pub,
      bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))

check("Shared secret Alice",
      scalar_mult(alice_priv, bob_pub),
      bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"))

check("Shared secret Bob",
      scalar_mult(bob_priv, alice_pub),
      bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"))

# =====================================================
# Results
# =====================================================
print()
total = passed + failed
print(f"RESULTS: {passed}/{total} passed, {failed} failed")