from aead import aead_encrypt, aead_decrypt


def test():
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    )

    nonce = bytes.fromhex("000000000000004a00000000")

    plaintext = b"Hello AEAD ChaCha20-Poly1305!"
    aad = b"header-data"

    ciphertext, tag = aead_encrypt(key, nonce, plaintext, aad)

    print("Ciphertext:", ciphertext.hex())
    print("Tag       :", tag.hex())

    decrypted = aead_decrypt(key, nonce, ciphertext, tag, aad)

    print("Decrypted :", decrypted)

    assert decrypted == plaintext
    print("AEAD PASSED ")


test()