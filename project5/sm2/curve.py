from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class CurveParams:
    p: int
    a: int
    b: int
    gx: int
    gy: int
    n: int


SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
SM2_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
SM2_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
SM2_GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
SM2_GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

CURVE = CurveParams(
    p=SM2_P,
    a=SM2_A,
    b=SM2_B,
    gx=SM2_GX,
    gy=SM2_GY,
    n=SM2_N,
)


@dataclass
class Point:
    x: Optional[int]
    y: Optional[int]

    @property
    def is_infinity(self) -> bool:
        return self.x is None or self.y is None


O = Point(None, None)


def mod_inv(x: int, p: int) -> int:
    # Fermat's little theorem, as p is prime
    return pow(x, p - 2, p)


def is_on_curve(P: Point, c: CurveParams = CURVE) -> bool:
    if P.is_infinity:
        return True
    x, y = P.x, P.y
    return (y * y - (x * x * x + c.a * x + c.b)) % c.p == 0


def point_add(P: Point, Q: Point, c: CurveParams = CURVE) -> Point:
    if P.is_infinity:
        return Q
    if Q.is_infinity:
        return P
    if P.x == Q.x and (P.y + Q.y) % c.p == 0:
        return O
    if P.x == Q.x and P.y == Q.y:
        s = (3 * P.x * P.x + c.a) * mod_inv((2 * P.y) % c.p, c.p)
    else:
        s = (Q.y - P.y) * mod_inv((Q.x - P.x) % c.p, c.p)
    s %= c.p
    rx = (s * s - P.x - Q.x) % c.p
    ry = (s * (P.x - rx) - P.y) % c.p
    return Point(rx, ry)


def scalar_mul(k: int, P: Point, c: CurveParams = CURVE) -> Point:
    if k % c.n == 0 or P.is_infinity:
        return O
    if k < 0:
        return scalar_mul(-k, Point(P.x, (-P.y) % c.p), c)
    result = O
    addend = P
    while k:
        if k & 1:
            result = point_add(result, addend, c)
        addend = point_add(addend, addend, c)
        k >>= 1
    return result


G = Point(SM2_GX, SM2_GY)
