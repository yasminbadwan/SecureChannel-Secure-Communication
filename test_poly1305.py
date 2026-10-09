from Poly1305 import poly1305_mac


def test_poly1305():
    key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b"
    )

    msg = b"Cryptographic Forum Research Group"

    expected = bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9")

    result = poly1305_mac(msg, key)

    print("Result  :", result.hex())
    print("Expected:", expected.hex())

    assert result == expected

    print("Poly1305 PASSED")


if __name__ == "__main__":
    test_poly1305()