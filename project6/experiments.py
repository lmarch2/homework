#!/usr/bin/env python3
import os
import random
import string
import statistics
import time
import sys
from typing import List, Tuple

CUR = os.path.dirname(os.path.abspath(__file__))
if CUR not in sys.path:
    sys.path.insert(0, CUR)

from src.protocol import Protocol


def rand_pw(n: int) -> bytes:
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(n)).encode()


def make_dataset(N: int, include_common: bool = True) -> List[bytes]:
    data = set()
    while len(data) < N:
        data.add(rand_pw(random.randint(8, 12)))
    arr = list(data)
    if include_common:
        arr += [b"123456", b"password", b"qwerty", b"111111", b"abc123"]
    random.shuffle(arr)
    return arr


def run_experiment(N: int = 10000, b_bits: int = 12, fpr: float = 1e-4, q_pos: int = 500, q_neg: int = 500) -> Tuple[float, float, float, int]:
    leaked = make_dataset(N)
    proto = Protocol.setup(leaked_passwords=leaked, b_bits=b_bits, target_fpr=fpr)

    # positives from leaked
    pos_samples = random.sample(leaked, min(q_pos, len(leaked)))
    # negatives not in leaked
    neg_samples = []
    while len(neg_samples) < q_neg:
        x = rand_pw(random.randint(8, 12))
        if x not in leaked:
            neg_samples.append(x)

    def bench(samples: List[bytes]) -> Tuple[int, float, List[int]]:
        hits = 0
        times = []
        sizes = []
        for pw in samples:
            t0 = time.perf_counter()
            # extract bucket size by single query
            bucket_idx, M, r = proto.client.prepare(pw)
            N, bf_bytes = proto.server.respond(bucket_idx, M)
            sizes.append(len(bf_bytes))
            hit = proto.client.finalize(pw, N, r, bf_bytes)
            t1 = time.perf_counter()
            times.append(t1 - t0)
            hits += 1 if hit else 0
        avg_t = sum(times) / len(times)
        avg_size = int(sum(sizes) / len(sizes))
        return hits, avg_t, sizes

    pos_hits, pos_t, pos_sizes = bench(pos_samples)
    neg_hits, neg_t, neg_sizes = bench(neg_samples)

    tpr = pos_hits / len(pos_samples)
    fpr_obs = neg_hits / len(neg_samples)
    avg_t = (pos_t + neg_t) / 2
    avg_bucket_size = int((sum(pos_sizes) + sum(neg_sizes)) / (len(pos_sizes) + len(neg_sizes)))

    return tpr, fpr_obs, avg_t, avg_bucket_size


def main():
    random.seed(0)
    tpr, fpr_obs, avg_t, avg_bucket_size = run_experiment(N=8000, b_bits=12, fpr=1e-4, q_pos=300, q_neg=300)
    print("TPR:", tpr)
    print("FPR_obs:", fpr_obs)
    print("avg_query_time_sec:", avg_t)
    print("avg_bucket_bytes:", avg_bucket_size)


if __name__ == "__main__":
    main()
