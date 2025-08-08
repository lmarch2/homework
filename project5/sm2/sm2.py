from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple, Literal

from .curve import CURVE, G, Point, scalar_mul, point_add
from .util import random_scalar
from .sm3 import sm3_hash


@dataclass
class KeyPair:
    d: int
    Px: int
    Py: int


def keygen() -> KeyPair:
    d = random_scalar(CURVE.n)
    P = scalar_mul(d, G)
    return KeyPair(d, P.x, P.y)


def encode_ZA(ID: bytes, Px: int, Py: int) -> bytes:
    ENTL = (len(ID) * 8).to_bytes(2, 'big')
    a = CURVE.a.to_bytes(32, 'big')
    b = CURVE.b.to_bytes(32, 'big')
    gx = CURVE.gx.to_bytes(32, 'big')
    gy = CURVE.gy.to_bytes(32, 'big')
    px = Px.to_bytes(32, 'big')
    py = Py.to_bytes(32, 'big')
    return sm3_hash(ENTL + ID + a + b + gx + gy + px + py)


def _deterministic_k(d: int, e: int, n: int) -> int:
    # Simple SM3-based determinstic k: k = SM3(d||e||ctr) mod n, ctr from 1.. until valid
    d_bytes = d.to_bytes(32, 'big')
    e_bytes = e.to_bytes(32, 'big')
    ctr = 1
    while True:
        h = sm3_hash(d_bytes + e_bytes + ctr.to_bytes(4, 'big'))
        k = int.from_bytes(h, 'big') % n
        if 1 <= k < n:
            return k
        ctr += 1


def sm2_sign(
    msg: bytes,
    ID: bytes,
    kp: KeyPair,
    k_fixed: int | None = None,
    k_mode: Literal['random', 'deterministic'] = 'random',
) -> Tuple[int, int]:
    ZA = encode_ZA(ID, kp.Px, kp.Py)
    e = int.from_bytes(sm3_hash(ZA + msg), 'big')
    n = CURVE.n
    while True:
        if k_fixed is not None:
            k = k_fixed
        else:
            k = random_scalar(n) if k_mode == 'random' else _deterministic_k(kp.d, e, n)
        P1 = scalar_mul(k, G)
        r = (e + P1.x) % n
        if r == 0 or (r + k) % n == 0:
            if k_fixed is not None:
                raise ValueError("bad fixed k, leads to invalid r")
            continue
        s = ((pow(1 + kp.d, -1, n) * (k - r * kp.d)) % n)
        if s == 0:
            if k_fixed is not None:
                raise ValueError("bad fixed k, leads to s=0")
            continue
        return r, s


def sm2_verify(msg: bytes, ID: bytes, Px: int, Py: int, sig: Tuple[int, int]) -> bool:
    r, s = sig
    n = CURVE.n
    if not (1 <= r < n and 1 <= s < n):
        return False
    ZA = encode_ZA(ID, Px, Py)
    e = int.from_bytes(sm3_hash(ZA + msg), 'big')
    t = (r + s) % n
    if t == 0:
        return False
    SG = scalar_mul(s, G)
    tP = scalar_mul(t, Point(Px, Py))
    X1Y1 = point_add(SG, tP)
    if X1Y1.is_infinity:
        return False
    R = (e + X1Y1.x) % n
    return R == r


# variant without ZA (misuse intentionally for experiment)
def sm2_sign_without_ZA(
    msg: bytes,
    kp: KeyPair,
    k_fixed: int | None = None,
    k_mode: Literal['random', 'deterministic'] = 'random',
) -> Tuple[int, int]:
    e = int.from_bytes(sm3_hash(msg), 'big')
    n = CURVE.n
    while True:
        if k_fixed is not None:
            k = k_fixed
        else:
            k = random_scalar(n) if k_mode == 'random' else _deterministic_k(kp.d, e, n)
        P1 = scalar_mul(k, G)
        r = (e + P1.x) % n
        if r == 0 or (r + k) % n == 0:
            if k_fixed is not None:
                raise ValueError("bad fixed k, leads to invalid r")
            continue
        s = ((pow(1 + kp.d, -1, n) * (k - r * kp.d)) % n)
        if s == 0:
            if k_fixed is not None:
                raise ValueError("bad fixed k, leads to s=0")
            continue
        return r, s


def sm2_verify_without_ZA(msg: bytes, Px: int, Py: int, sig: Tuple[int, int]) -> bool:
    r, s = sig
    n = CURVE.n
    if not (1 <= r < n and 1 <= s < n):
        return False
    e = int.from_bytes(sm3_hash(msg), 'big')
    t = (r + s) % n
    if t == 0:
        return False
    SG = scalar_mul(s, G)
    tP = scalar_mul(t, Point(Px, Py))
    X1Y1 = point_add(SG, tP)
    if X1Y1.is_infinity:
        return False
    R = (e + X1Y1.x) % n
    return R == r
