import pytest
from ankh import Ankh
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


@pytest.fixture
def key():
    return get_random_bytes(16)


def test_subkey_generation(key):
    cipher = Ankh(key, Ankh.Mode.ECB)
    assert len(cipher.subkeys) == cipher.NUMBEROFROUNDS
    assert all(isinstance(subkey, bytes) for subkey in cipher.subkeys)
    assert all(len(subkey) == cipher.BLOCKSIZE // 2 for subkey in cipher.subkeys)


def test_block_splitting(key):
    cipher = Ankh(key, Ankh.Mode.ECB)
    data = pad(b"1234567890123456", cipher.BLOCKSIZE)  # 16 bytes data + padding
    blocks = cipher._split_into_blocks(data)
    assert len(blocks) == len(data) // cipher.BLOCKSIZE
    assert all(len(block) == cipher.BLOCKSIZE for block in blocks)
