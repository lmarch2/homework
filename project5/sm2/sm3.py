from __future__ import annotations

from typing import Iterable

# Minimal pure-Python SM3 implementation for course experiments.

IV = [
    0x7380166F,
    0x4914B2B9,
    0x172442D7,
    0xDA8A0600,
    0xA96F30BC,
    0x163138AA,
    0xE38DEE4D,
    0xB0FB0E4E,
]


def _rotl(x: int, n: int) -> int:
    n %= 32
    if n == 0:
        return x & 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _ff(x, y, z, j):
    if 0 <= j <= 15:
        return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)


def _gg(x, y, z, j):
    if 0 <= j <= 15:
        return x ^ y ^ z
    return (x & y) | (~x & z)


def _p0(x):
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _p1(x):
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def sm3_hash(data: bytes) -> bytes:
    # padding
    length = len(data) * 8
    m = bytearray(data)
    m.append(0x80)
    while ((len(m) * 8) % 512) != 448:
        m.append(0)
    m += length.to_bytes(8, 'big')

    V = IV[:]
    # process each block
    for b in range(0, len(m), 64):
        block = m[b:b+64]
        W = [int.from_bytes(block[i:i+4], 'big') for i in range(0, 64, 4)]
        for j in range(16, 68):
            x = _p1(W[j-16] ^ W[j-9] ^ _rotl(W[j-3], 15)) ^ _rotl(W[j-13], 7) ^ W[j-6]
            W.append(x & 0xFFFFFFFF)
        W_ = [(W[j] ^ W[j+4]) & 0xFFFFFFFF for j in range(64)]

        A,B,C,D,E,F,G,H = V
        for j in range(64):
            Tj = 0x79CC4519 if j <= 15 else 0x7A879D8A
            SS1 = _rotl((_rotl(A, 12) + E + _rotl(Tj, j)) & 0xFFFFFFFF, 7)
            SS2 = SS1 ^ _rotl(A, 12)
            TT1 = (_ff(A, B, C, j) + D + SS2 + W_[j]) & 0xFFFFFFFF
            TT2 = (_gg(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
            D = C
            C = _rotl(B, 9)
            B = A
            A = TT1
            H = G
            G = _rotl(F, 19)
            F = E
            E = _p0(TT2)
        V = [a ^ b for a,b in zip(V, [A,B,C,D,E,F,G,H])]
    out = b''.join(v.to_bytes(4, 'big') for v in V)
    return out
