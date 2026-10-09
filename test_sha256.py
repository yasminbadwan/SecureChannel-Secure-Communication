# test_sha256.py
# =====================================================
# SHA-256 Test Vectors — based on NIST FIPS 180-4 §5–6
# =====================================================

from sha256 import sha256

def test_sha256_vectors():
    print("Running SHA-256 Test Vectors...")

    # Test vector 1: empty string
    msg1 = b""
    expected1 = bytes.fromhex(
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    )
    assert sha256(msg1) == expected1
    print("Test 1 passed")

    # Test vector 2: "abc"
    msg2 = b"abc"
    expected2 = bytes.fromhex(
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )
    assert sha256(msg2) == expected2
    print("Test 2 passed")

    # Test vector 3: longer message
    msg3 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    expected3 = bytes.fromhex(
        "248d6a61d20638b8e5c026930c3e6039"
        "a33ce45964ff2167f6ecedd419db06c1"
    )
    assert sha256(msg3) == expected3
    print("Test 3 passed")

    print("\nAll SHA-256 test vectors passed")

if __name__ == "__main__":
    test_sha256_vectors()