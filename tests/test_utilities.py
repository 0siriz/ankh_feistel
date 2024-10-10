import pytest
from ankh import Ankh
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


# Fixture to dynamically generate keys of a given length
@pytest.fixture
def key(request):
    length = request.param
    return get_random_bytes(length)


# Test subkey generation for different key lengths
@pytest.mark.parametrize("key", [1, 2, 4, 8, 16, 24, 32], indirect=True)  # Small keys + 128-bit, 192-bit, 256-bit
def test_subkey_generation(key):
    cipher = Ankh(key, Ankh.Mode.ECB)

    # Ensure correct number of subkeys and correct size
    assert len(cipher.subkeys) == cipher.NUMBEROFROUNDS
    assert all(isinstance(subkey, bytes) for subkey in cipher.subkeys)
    assert all(len(subkey) == cipher.BLOCKSIZE // 2 for subkey in cipher.subkeys)


# Test block splitting with different key lengths
@pytest.mark.parametrize("key", [1, 2, 4, 8, 16, 24, 32], indirect=True)  # Small keys + 128-bit, 192-bit, 256-bit
def test_block_splitting(key):
    cipher = Ankh(key, Ankh.Mode.ECB)

    # Generate some test data with padding
    data_length = 64  # Fixed data length
    data = pad(get_random_bytes(data_length), cipher.BLOCKSIZE)  # Padded data to match block size

    blocks = cipher._split_into_blocks(data)

    # Ensure the correct number of blocks and that each block has the correct size
    assert len(blocks) == len(data) // cipher.BLOCKSIZE
    assert all(len(block) == cipher.BLOCKSIZE for block in blocks)
