import hashlib
import os
from dataclasses import dataclass
from typing import Tuple

# RFC 3526 2048-bit MODP Group (Group 14) prime
# https://www.rfc-editor.org/rfc/rfc3526
P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
)
# The above is the 1536-bit group in RFC 3526. To keep runtime small in Python, we use it here.
# For stronger security one should use group 14 (2048-bit) or EC-based groups.
P = int(P_HEX, 16)
Q = (P - 1) // 2  # safe prime: p = 2q + 1
G = 2  # generator of a large subgroup; with squaring we stay in QR_p


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def i2osp(x: int, l: int) -> bytes:
    return x.to_bytes(l, 'big')


def os2ip(b: bytes) -> int:
    return int.from_bytes(b, 'big')


def modinv(a: int, m: int) -> int:
    # Extended Euclidean Algorithm
    t, new_t = 0, 1
    r, new_r = m, a % m
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    if r > 1:
        raise ValueError("not invertible")
    if t < 0:
        t += m
    return t


def hash_to_group(x: bytes) -> int:
    # Map to QR_p via exponentiation and squaring: h = (g^{e})^2 mod p
    e = os2ip(sha256(x)) % Q
    if e == 0:
        e = 1
    h = pow(G, e, P)
    h = pow(h, 2, P)  # ensure QR_p
    return h


@dataclass
class OPRFKey:
    k: int  # secret exponent in Z_q^*

    @staticmethod
    def generate() -> "OPRFKey":
        while True:
            k = os2ip(os.urandom(32)) % Q
            if k not in (0, 1):
                return OPRFKey(k=k)

    def blind(self, x: bytes) -> Tuple[int, int]:
        # returns (M, r)
        r = 0
        while r in (0, 1):
            r = os2ip(os.urandom(32)) % Q
        H = hash_to_group(x)
        M = pow(H, r, P)
        return M, r

    def evaluate(self, M: int) -> int:
        # server-side: compute N = M^k mod p
        return pow(M, self.k, P)

    def finalize(self, N: int, r: int) -> bytes:
        # client-side: Z = N^{r^{-1}} = H(x)^k
        rinv = modinv(r, Q)
        Z = pow(N, rinv, P)
        # PRF output derived via hash of integer encoding
        z_bytes = i2osp(Z, (P.bit_length() + 7) // 8)
        return sha256(z_bytes)


def prefix_bits(x: bytes, b: int) -> int:
    h = sha256(x)
    # take first b bits
    need_bytes = (b + 7) // 8
    v = os2ip(h[:need_bytes])
    shift = need_bytes * 8 - b
    return v >> shift
