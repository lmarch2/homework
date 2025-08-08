import math
import hashlib
from typing import Iterable, List

class BloomFilter:
    def __init__(self, m_bits: int, k: int):
        assert m_bits > 0 and k > 0
        self.m_bits = m_bits
        self.k = k
        self.bitarray = bytearray((m_bits + 7) // 8)
        self.n_items = 0

    @staticmethod
    def optimal_m_k(n: int, p: float, min_m_bits: int = 1024) -> "tuple[int, int]":
        # n items, target false positive p
        if n <= 0:
            n = 1
        if p <= 0 or p >= 1:
            p = 1e-6
        m = - (n * math.log(p)) / (math.log(2) ** 2)
        m_bits = max(int(math.ceil(m)), min_m_bits)
        k = max(1, int(round((m_bits / n) * math.log(2))))
        return m_bits, k

    def _hashes(self, data: bytes) -> List[int]:
        # double hashing trick
        h1 = int.from_bytes(hashlib.sha256(data).digest(), 'big')
        h2 = int.from_bytes(hashlib.blake2b(data, digest_size=32).digest(), 'big')
        return [ (h1 + i * h2) % self.m_bits for i in range(self.k) ]

    def add(self, data: bytes):
        for idx in self._hashes(data):
            byte_i = idx // 8
            bit_i = idx % 8
            self.bitarray[byte_i] |= (1 << bit_i)
        self.n_items += 1

    def contains(self, data: bytes) -> bool:
        for idx in self._hashes(data):
            byte_i = idx // 8
            bit_i = idx % 8
            if not (self.bitarray[byte_i] & (1 << bit_i)):
                return False
        return True

    def to_bytes(self) -> bytes:
        header = self.m_bits.to_bytes(4, 'big') + self.k.to_bytes(2, 'big') + self.n_items.to_bytes(4, 'big')
        return header + bytes(self.bitarray)

    @staticmethod
    def from_bytes(buf: bytes) -> 'BloomFilter':
        m_bits = int.from_bytes(buf[0:4], 'big')
        k = int.from_bytes(buf[4:6], 'big')
        n_items = int.from_bytes(buf[6:10], 'big')
        bf = BloomFilter(m_bits, k)
        bf.bitarray[:] = buf[10:]
        bf.n_items = n_items
        return bf
