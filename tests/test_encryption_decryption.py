from ankh import Ankh
import pytest


def test_simple_block():
    message: bytes = b''.join(i.to_bytes(1, 'little') for i in range(16))
    key: bytes = b''.join(i.to_bytes(1, 'little') for i in range(8))
    ankh: Ankh = Ankh(key)
    ciphertext: bytes = ankh.encrypt(message)
    assert ankh.decrypt(ciphertext) == message


def test_multiple_blocks():
    message: bytes = b''.join(i.to_bytes(1, 'little') for i in range(64))
    key: bytes = b''.join(i.to_bytes(1, 'little') for i in range(8))
    ankh: Ankh = Ankh(key)
    ciphertext: bytes = ankh.encrypt(message)
    assert ankh.decrypt(ciphertext) == message


def test_wrong_key_single_block():
    message: bytes = b''.join(i.to_bytes(1, 'little') for i in range(16))
    key1: bytes = b'key'
    key2: bytes = b'kei'
    ankh1: Ankh = Ankh(key1)
    ankh2: Ankh = Ankh(key2)
    ciphertext: bytes = ankh1.encrypt(message)
    with pytest.raises(ValueError):
        ankh2.decrypt(ciphertext)


def test_wrong_key_multiple_blocks():
    message: bytes = b''.join(i.to_bytes(1, 'little') for i in range(64))
    key1: bytes = b'key'
    key2: bytes = b'kei'
    ankh1: Ankh = Ankh(key1)
    ankh2: Ankh = Ankh(key2)
    ciphertext: bytes = ankh1.encrypt(message)
    with pytest.raises(ValueError):
        ankh2.decrypt(ciphertext)
