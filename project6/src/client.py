from dataclasses import dataclass
from typing import Tuple

from .oprf_group import OPRFKey, prefix_bits
from .bloom import BloomFilter


@dataclass
class Client:
    b_bits: int

    def prepare(self, password: bytes, server_pk_hint: int | None = None) -> Tuple[int, int, int]:
        # Blind
        dummy_key = OPRFKey.generate()  # only to reuse blind() helper; k is irrelevant client-side
        M, r = dummy_key.blind(password)
        bucket_idx = prefix_bits(password, self.b_bits)
        return bucket_idx, M, r

    def finalize(self, password: bytes, N: int, r: int, bf_bytes: bytes) -> bool:
        # Recompute blind helper to reuse finalize()
        dummy_key = OPRFKey.generate()
        y = dummy_key.finalize(N, r)
        bf = BloomFilter.from_bytes(bf_bytes)
        return bf.contains(y)
