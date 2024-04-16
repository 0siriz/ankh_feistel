from Crypto.Hash import SHA3_256, HMAC
from Crypto.Util.number import bytes_to_long
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import numpy as np


class Ankh:
    BLOCKSIZE: int = 16
    NUMBEROFROUNDS: int = 20
    subkeys: list[bytes] = []

    def __init__(self, key: bytes):
        self.key = key
        self._generate_subkeys()

    def _xor(self, data: bytes, key: bytes) -> bytes:
        assert len(data) == len(key)

        return bytes(a ^ b for a, b in zip(data, key))

    def _generate_subkeys(self):
        rng: np.random.Generator = np.random.default_rng(
            bytes_to_long(self.key))
        for i in range(self.NUMBEROFROUNDS):
            self.subkeys.append(rng.bytes(int(self.BLOCKSIZE/2)))

    def _split_into_blocks(self, data: bytes) -> list[bytes]:
        assert len(data) % self.BLOCKSIZE == 0

        blocks: list[bytes] = []
        for i in range(0, len(data), self.BLOCKSIZE):
            blocks.append(data[i:i+self.BLOCKSIZE])

        return blocks

    def _feistel_network(self, block: bytes, decryption: bool) -> bytes:
        left = block[:int(self.BLOCKSIZE/2)]
        right = block[int(self.BLOCKSIZE/2):]
        for i, subkey in enumerate(self.subkeys[::-1 if decryption else 1]):
            fright = HMAC.new(subkey, right, digestmod=SHA3_256).digest()
            left = self._xor(left, fright[:int(self.BLOCKSIZE/2)])
            left, right = right, left

        return right+left

    def encrypt(self, cleartext: bytes) -> bytes:
        cleartext: bytes = pad(cleartext, self.BLOCKSIZE)
        iv: bytes = get_random_bytes(self.BLOCKSIZE)
        blocks: list[bytes] = self._split_into_blocks(cleartext)
        ciphertext: bytes = b''

        xorkey: bytes = iv
        for clearblock in blocks:
            block: bytes = self._xor(clearblock, xorkey)
            cipherblock: bytes = self._feistel_network(block, False)
            ciphertext += cipherblock
            xorkey: bytes = self._xor(clearblock, cipherblock)

        return iv+ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        iv: bytes = ciphertext[:self.BLOCKSIZE]
        ciphertext: bytes = ciphertext[self.BLOCKSIZE:]
        blocks: list[bytes] = self._split_into_blocks(ciphertext)
        cleartext: bytes = b''

        xorkey: bytes = iv
        for cipherblock in blocks:
            block: bytes = self._feistel_network(cipherblock, True)
            clearblock: bytes = self._xor(block, xorkey)
            cleartext += clearblock
            xorkey: bytes = self._xor(clearblock, cipherblock)

        cleartext: bytes = unpad(cleartext, self.BLOCKSIZE)

        return cleartext
