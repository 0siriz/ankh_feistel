import pytest
from ankh import Ankh
from Crypto.Random import get_random_bytes


# Fixture for the plaintext, dynamically generating plaintext based on number of blocks
@pytest.fixture
def plaintext(request):
    blocks = request.param
    block_size = Ankh.BLOCKSIZE
    return get_random_bytes(blocks * block_size)


# Fixture to ensure the wrong key is different from the correct key
@pytest.fixture
def key():
    return get_random_bytes(16)  # Default: 128-bit key (16 bytes)


@pytest.fixture
def wrong_key(key):
    wrong_key = get_random_bytes(16)
    while wrong_key == key:
        wrong_key = get_random_bytes(16)
    return wrong_key


# Test encryption/decryption for different modes with dynamic plaintext lengths (in blocks)
@pytest.mark.parametrize("plaintext", [1, 2, 4, 8, 16], indirect=True)  # Number of blocks
@pytest.mark.parametrize("mode", [
    Ankh.Mode.ECB, Ankh.Mode.CBC, Ankh.Mode.PCBC, Ankh.Mode.CFB, Ankh.Mode.OFB, Ankh.Mode.CTR
])
def test_encryption_decryption(mode, key, plaintext):
    cipher = Ankh(key, mode)
    ciphertext = cipher.encrypt(plaintext)
    assert ciphertext != plaintext, "Ciphertext should differ from plaintext"

    decrypted_text = cipher.decrypt(ciphertext)
    assert decrypted_text == plaintext, f"Decrypted text should match original for mode {mode} and plaintext length {len(plaintext)} bytes"


# Test decryption failure when using a wrong key with dynamic plaintext lengths (in blocks)
@pytest.mark.parametrize("plaintext", [1, 2, 4, 8, 16], indirect=True)  # Number of blocks
@pytest.mark.parametrize("mode", [
    Ankh.Mode.ECB, Ankh.Mode.CBC, Ankh.Mode.PCBC, Ankh.Mode.CFB, Ankh.Mode.OFB, Ankh.Mode.CTR
])
def test_decryption_with_wrong_key(mode, key, wrong_key, plaintext):
    cipher = Ankh(key, mode)
    wrong_cipher = Ankh(wrong_key, mode)

    # Encrypt with the correct key
    ciphertext = cipher.encrypt(plaintext)

    # Attempt to decrypt with the wrong key
    with pytest.raises(ValueError, match="[Pp]adding is incorrect."):
        wrong_cipher.decrypt(ciphertext)


# Test different key lengths specified in bits, with dynamic plaintext lengths (in blocks)
@pytest.mark.parametrize("plaintext", [1, 2, 4, 8, 16], indirect=True)  # Number of blocks
@pytest.mark.parametrize("key_length_bits", [8, 16, 32, 64, 128, 192, 256])  # Key sizes in bits
@pytest.mark.parametrize("mode", [
    Ankh.Mode.ECB, Ankh.Mode.CBC, Ankh.Mode.PCBC, Ankh.Mode.CFB, Ankh.Mode.OFB, Ankh.Mode.CTR
])
def test_different_key_lengths(mode, key_length_bits, plaintext):
    key_length_bytes = key_length_bits // 8  # Convert bits to bytes
    key = get_random_bytes(key_length_bytes)
    cipher = Ankh(key, mode)

    # Encrypt and decrypt
    ciphertext = cipher.encrypt(plaintext)
    decrypted_text = cipher.decrypt(ciphertext)

    # Ensure the decrypted text matches the original plaintext
    assert decrypted_text == plaintext, (
        f"Decrypted text should match original for key length {key_length_bits} bits, mode {mode}, and plaintext length {len(plaintext)} bytes"
    )
