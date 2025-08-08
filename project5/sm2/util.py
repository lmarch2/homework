from __future__ import annotations

import os
from typing import Tuple


def int_to_bytes(i: int, length: int) -> bytes:
    return i.to_bytes(length, 'big')


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')


def random_scalar(n: int) -> int:
    # simple rejection sampling for scalar in [1, n-1]
    while True:
        rb = os.urandom((n.bit_length() + 7) // 8)
        k = int.from_bytes(rb, 'big') % n
        if 1 <= k < n:
            return k
