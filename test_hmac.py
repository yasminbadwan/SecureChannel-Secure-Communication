# test_hmac.py
# =====================================================
# HMAC-SHA256 Test Vectors — based on RFC 4231
# =====================================================

from hmaac import hmacsha256  

def test_hmac_vectors():
    print("Running HMAC-SHA256 Test Vectors...")

    # Test vector 1 — Key shorter than block size
    key1 = bytes.fromhex("0b" * 20)
    msg1 = b"Hi There"
    expected1 = bytes.fromhex(
        "b0344c61d8db38535ca8afceaf0bf12b"
        "881dc200c9833da726e9376c2e32cff7"
    )
    assert hmacsha256(key1, msg1) == expected1, "HMAC test 1 failed"
    print("  Test 1 passed")

    # Test vector 2 — Key same as block size
    key2 = b"Jefe" + b"\x00" * 60
    msg2 = b"what do ya want for nothing?"
    expected2 = bytes.fromhex(
        "5bdcc146bf60754e6a042426089575c7"
        "5a003f089d2739839dec58b964ec3843"
    )
    assert hmacsha256(key2, msg2) == expected2, "HMAC test 2 failed"
    print("  Test 2 passed")

    # Test vector 3 — Key longer than block size
    key3 = bytes.fromhex("aa" * 131)
    msg3 = b"Test Using Larger Than Block-Size Key - Hash Key First"
    expected3 = bytes.fromhex(
        "60e431591ee0b67f0d8a26aacbf5b77f"
        "8e0bc6213728c5140546040f0ee37f54"
    )
    assert hmacsha256(key3, msg3) == expected3, "HMAC test 3 failed"
    print("  Test 3 passed")

    print("\nAll HMAC-SHA256 test vectors passed")

if __name__ == "__main__":
    test_hmac_vectors()