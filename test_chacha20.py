from chacha20 import chacha20_block, chacha20_xor


def get_test_key():
    return bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    )


def get_test_nonce():
    return bytes.fromhex("000000090000004a00000000")


def test_chacha20_block_rfc():
    """
    RFC 8439 test vector - Section 2.3.2
    """

    key = get_test_key()
    nonce = get_test_nonce()
    counter = 1

    expected = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )

    result = chacha20_block(key, counter, nonce)

    print("=== ChaCha20 Block Test (RFC 8439) ===")
    print("Result  :", result.hex())
    print("Expected:", expected.hex())

    assert result == expected, "ChaCha20 block test FAILED"

    print("ChaCha20 block test PASSED")


def test_chacha20_encrypt_decrypt():
    """
    Encryption and decryption consistency test
    """

    key = get_test_key()
    nonce = get_test_nonce()

    plaintext = b"Hello ChaCha20 test message for encryption!"

    ciphertext = chacha20_xor(key, nonce, plaintext, counter=1)
    decrypted = chacha20_xor(key, nonce, ciphertext, counter=1)

    print("\n=== Encrypt/Decrypt Test ===")
    print("Plaintext :", plaintext)
    print("Ciphertext:", ciphertext.hex())
    print("Decrypted :", decrypted)

    assert decrypted == plaintext, "Encrypt/Decrypt FAILED"

    print("Encrypt/Decrypt test PASSED")


def test_multi_block():
    """
    Test messages longer than 64 bytes
    """

    key = get_test_key()
    nonce = get_test_nonce()

    plaintext = b"A" * 200

    ciphertext = chacha20_xor(key, nonce, plaintext, counter=1)
    decrypted = chacha20_xor(key, nonce, ciphertext, counter=1)

    print("\n=== Multi-block Test ===")
    print("Ciphertext:", ciphertext[:64].hex(), "...")

    assert decrypted == plaintext, "Multi-block FAILED"

    print("Multi-block test PASSED")


if __name__ == "__main__":
    test_chacha20_block_rfc()
    test_chacha20_encrypt_decrypt()
    test_multi_block()

    print("\nALL CHACHA20 TESTS PASSED")

