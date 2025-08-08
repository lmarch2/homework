import hashlib
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Tuple

from .oprf_group import OPRFKey, prefix_bits, sha256
from .bloom import BloomFilter


def bucket_prefix(x: bytes, b: int) -> int:
    return prefix_bits(x, b)


def derive_prf_output(oprf_key: OPRFKey, x: bytes) -> bytes:
    # For precomputation server-side: compute H1(x)^k and hash to y
    H = oprf_key  # just to highlight type
    # emulate client flow without blind: y = H2(H1(x)^k)
    Hx = hashlib.sha256(x).digest()
    # Use internal helpers
    from .oprf_group import hash_to_group, i2osp, P
    Z = pow(hash_to_group(x), oprf_key.k, P)
    return sha256(i2osp(Z, (P.bit_length() + 7) // 8))


@dataclass
class ServerDB:
    buckets: Dict[int, BloomFilter]
    b_bits: int
    oprf_key: OPRFKey

    @staticmethod
    def build(leaked_passwords: List[bytes], b_bits: int, target_fpr: float = 1e-4) -> "ServerDB":
        key = OPRFKey.generate()
        # partition by prefix
        buckets: Dict[int, List[bytes]] = defaultdict(list)
        for pw in leaked_passwords:
            buckets[bucket_prefix(pw, b_bits)].append(pw)
        # build bloom per bucket
        bf_buckets: Dict[int, BloomFilter] = {}
        for idx, arr in buckets.items():
            m_bits, k = BloomFilter.optimal_m_k(len(arr), target_fpr)
            bf = BloomFilter(m_bits, k)
            for pw in arr:
                y = derive_prf_output(key, pw)
                bf.add(y)
            bf_buckets[idx] = bf
        return ServerDB(buckets=bf_buckets, b_bits=b_bits, oprf_key=key)

    def respond(self, bucket_idx: int, M: int) -> Tuple[int, bytes]:
        N = self.oprf_key.evaluate(M)
        bf = self.buckets.get(bucket_idx)
        if bf is None:
            # empty bucket: return small empty bloom
            bf = BloomFilter(1024, 3)
        return N, bf.to_bytes()
