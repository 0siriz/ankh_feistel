from ankh import Ankh


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
