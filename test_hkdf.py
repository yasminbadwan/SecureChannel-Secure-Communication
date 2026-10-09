from hkdf import hkdf_extract, hkdf_expand

# =========================
# RFC 5869 - Test Case 1 (SHA-256)
# =========================

ikm = bytes.fromhex(
    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
)

salt = bytes.fromhex(
    "000102030405060708090a0b0c"
)

info = bytes.fromhex(
    "f0f1f2f3f4f5f6f7f8f9"
)

L = 42

# Expected values from RFC
prk_expected = bytes.fromhex(
    "077709362c2e32df0ddc3f0dc47bba63"
    "90b6c73bb50f9c3122ec844ad7c2b3e5"
)

okm_expected = bytes.fromhex(
    "3cb25f25faacd57a90434f64d0362f2a"
    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865"
)

# =========================
# Run HKDF
# =========================

prk = hkdf_extract(salt, ikm)
okm = hkdf_expand(prk, info, L)

# =========================
# Results
# =========================

print("PRK OK:", prk == prk_expected)
print("OKM OK:", okm == okm_expected)

# Debug output
print("\n--- DEBUG ---")
print("PRK actual :", prk.hex())
print("PRK expect :", prk_expected.hex())
print("OKM actual :", okm.hex())
print("OKM expect :", okm_expected.hex())

# Final check
if prk == prk_expected and okm == okm_expected:
    print("\nSTATUS: PASS")
else:
    print("\nSTATUS: FAIL")