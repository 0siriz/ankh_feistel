from Crypto.Hash import SHA3_256, HMAC
from Crypto.Util.number import bytes_to_long
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from enum import Enum
import numpy as np


class Ankh:
    BLOCKSIZE: int = 16
    NUMBEROFROUNDS: int = 2000

    class Mode(Enum):
        ECB = 1
        CBC = 2
        PCBC = 3
        CFB = 4
        OFB = 5
        CTR = 6

    subkeys: list[bytes] = []

    def __init__(self, key: bytes, mode: Mode):
        self.key = key
        self.subkeys: list[bytes] = self._generate_subkeys()
        self.mode = mode

    def _xor(self, data: bytes, key: bytes) -> bytes:
        assert len(data) == len(key)

        return bytes(a ^ b for a, b in zip(data, key))

    def _generate_subkeys(self) -> list[bytes]:
        rng: np.random.Generator = np.random.default_rng(
            bytes_to_long(SHA3_256.new(self.key).digest())
        )
        subkeys: list[bytes] = []
        for i in range(self.NUMBEROFROUNDS):
            subkeys.append(rng.bytes(self.BLOCKSIZE//2))

        return subkeys

    def _split_into_blocks(self, data: bytes) -> list[bytes]:
        assert len(data) % self.BLOCKSIZE == 0

        blocks: list[bytes] = []
        for i in range(0, len(data), self.BLOCKSIZE):
            blocks.append(data[i:i+self.BLOCKSIZE])

        return blocks

    def _feistel_network(self, block: bytes, decryption: bool) -> bytes:
        left = block[:self.BLOCKSIZE//2]
        right = block[self.BLOCKSIZE//2:]
        for i, subkey in enumerate(self.subkeys[::-1 if decryption else 1]):
            fright = HMAC.new(subkey, right, digestmod=SHA3_256).digest()
            left = self._xor(left, fright[:self.BLOCKSIZE//2])
            left, right = right, left

        return right+left

    def encrypt(self, cleartext: bytes) -> bytes:
        cleartext: bytes = pad(cleartext, self.BLOCKSIZE)
        blocks: list[bytes] = self._split_into_blocks(cleartext)
        ciphertext: bytes = b''

        if self.mode != self.Mode.ECB:
            iv: bytes = get_random_bytes(self.BLOCKSIZE)
            vector: bytes = iv

        if self.mode == self.Mode.CTR:
            counter: int = 0

        for clearblock in blocks:
            if self.mode in (self.Mode.ECB, self.Mode.CBC, self.Mode.PCBC):
                if self.mode == self.Mode.ECB:
                    block: bytes = clearblock

                else:
                    block: bytes = self._xor(clearblock, vector)

                cipherblock: bytes = self._feistel_network(block, False)

                if self.mode in (self.Mode.CBC, self.Mode.PCBC):
                    vector: bytes = cipherblock
                    if self.mode == self.Mode.PCBC:
                        vector: bytes = self._xor(vector, clearblock)

            else:
                if self.mode == self.Mode.CTR:
                    vector: bytes = self._xor(
                        vector, counter.to_bytes(self.BLOCKSIZE, 'big'))
                    counter += 1

                cipherblock: bytes = self._feistel_network(vector, False)

                if self.mode == self.Mode.OFB:
                    vector: bytes = cipherblock

                cipherblock: bytes = self._xor(clearblock, cipherblock)

                if self.mode == self.Mode.CFB:
                    vector: bytes = cipherblock

            ciphertext += cipherblock

        if self.mode != self.Mode.ECB:
            return iv+ciphertext
        else:
            return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        if self.mode != self.Mode.ECB:
            iv: bytes = ciphertext[:self.BLOCKSIZE]
            ciphertext: bytes = ciphertext[self.BLOCKSIZE:]
            vector: bytes = iv

        if self.mode == self.Mode.CTR:
            counter: int = 0

        blocks: list[bytes] = self._split_into_blocks(ciphertext)
        cleartext: bytes = b''

        for cipherblock in blocks:
            if self.mode in (self.Mode.ECB, self.Mode.CBC, self.Mode.PCBC):
                clearblock: bytes = self._feistel_network(cipherblock, True)

                if self.mode in (self.Mode.CBC, self.Mode.PCBC):
                    clearblock = self._xor(clearblock, vector)
                    vector: bytes = cipherblock
                    if self.mode == self.Mode.PCBC:
                        vector: bytes = self._xor(vector, clearblock)

            else:
                if self.mode == self.Mode.CTR:
                    vector: bytes = self._xor(
                        vector, counter.to_bytes(self.BLOCKSIZE, 'big'))
                    counter += 1

                clearblock: bytes = self._feistel_network(vector, False)

                if self.mode == self.Mode.OFB:
                    vector: bytes = clearblock

                clearblock: bytes = self._xor(clearblock, cipherblock)

                if self.mode == self.Mode.CFB:
                    vector: bytes = cipherblock

            cleartext += clearblock

        cleartext: bytes = unpad(cleartext, self.BLOCKSIZE)

        return cleartext
