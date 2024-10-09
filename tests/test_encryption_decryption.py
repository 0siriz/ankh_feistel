import pytest
from ankh import Ankh
from Crypto.Random import get_random_bytes


# Fixture for the plaintext
@pytest.fixture
def plaintext():
    return b"Test message for encryption"


# Test encryption/decryption for different modes
@pytest.mark.parametrize("mode", [
    Ankh.Mode.ECB, Ankh.Mode.CBC, Ankh.Mode.PCBC, Ankh.Mode.CFB, Ankh.Mode.OFB, Ankh.Mode.CTR
])
def test_encryption_decryption(key, plaintext, mode):
    cipher = Ankh(key, mode)
    ciphertext = cipher.encrypt(plaintext)
    assert ciphertext != plaintext, "Ciphertext should differ from plaintext"

    decrypted_text = cipher.decrypt(ciphertext)
    assert decrypted_text == plaintext, f"Decrypted text should match original for mode {mode}"


# Test decryption failure when using a wrong key
@pytest.mark.parametrize("mode", [
    Ankh.Mode.ECB, Ankh.Mode.CBC, Ankh.Mode.PCBC, Ankh.Mode.CFB, Ankh.Mode.OFB, Ankh.Mode.CTR
])
def test_decryption_with_wrong_key(key, wrong_key, plaintext, mode):
    cipher = Ankh(key, mode)
    wrong_cipher = Ankh(wrong_key, mode)

    # Encrypt with the correct key
    ciphertext = cipher.encrypt(plaintext)

    # Attempt to decrypt with the wrong key
    with pytest.raises(ValueError, match="Padding is incorrect."):
        wrong_cipher.decrypt(ciphertext)


# Fixture to ensure the wrong key is different from the correct key
@pytest.fixture
def key():
    return get_random_bytes(16)  # Default: 128-bit key


@pytest.fixture
def wrong_key(key):
    wrong_key = get_random_bytes(16)
    while wrong_key == key:
        wrong_key = get_random_bytes(16)
    return wrong_key


# Test different key lengths, including small keys
@pytest.mark.parametrize("key_length", [1, 2, 4, 8, 16, 24, 32])  # Small keys + 128-bit, 192-bit, 256-bit
@pytest.mark.parametrize("mode", [
    Ankh.Mode.ECB, Ankh.Mode.CBC, Ankh.Mode.PCBC, Ankh.Mode.CFB, Ankh.Mode.OFB, Ankh.Mode.CTR
])
def test_different_key_lengths(key_length, plaintext, mode):
    key = get_random_bytes(key_length)
    cipher = Ankh(key, mode)

    # Encrypt and decrypt
    ciphertext = cipher.encrypt(plaintext)
    decrypted_text = cipher.decrypt(ciphertext)

    # Ensure the decrypted text matches the original plaintext
    assert decrypted_text == plaintext, (
        f"Decrypted text should match original for key length {key_length*8} bits and mode {mode}"
    )
