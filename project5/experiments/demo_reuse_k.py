from __future__ import annotations

from project5.sm2.sm2 import keygen, sm2_sign, sm2_verify
from project5.sm2.curve import CURVE

# Reuse-k attack PoC: recover d from two signatures that used the same k

def recover_d_from_reused_k(sig1, sig2):
    r1, s1 = sig1
    r2, s2 = sig2
    n = CURVE.n
    num = (s2 - s1) % n
    den = ( (s1 + r1) - (s2 + r2) ) % n
    d = (num * pow(den, -1, n)) % n
    return d


def main():
    ID = b"Alice"
    msg1 = b"message one"
    msg2 = b"message two"

    kp = keygen()

    # force same k for two signatures
    k_fixed = 0x123456789ABCDEF % CURVE.n
    sig1 = sm2_sign(msg1, ID, kp, k_fixed=k_fixed)
    sig2 = sm2_sign(msg2, ID, kp, k_fixed=k_fixed)

    d_rec = recover_d_from_reused_k(sig1, sig2)
    ok = (d_rec == kp.d)

    # with recovered d, we can sign anything (here we just verify against known d is recovered)
    print("reuse-k recovery success:", ok)
    print("original d:", hex(kp.d))
    print("recovered d:", hex(d_rec))

    # demonstrate forging a signature for Satoshi message by using the recovered d as our real key
    from project5.sm2.sm2 import KeyPair
    forged_kp = KeyPair(d_rec, kp.Px, kp.Py)  # public matches when d matches
    satoshi_msg = "我是中本聪".encode("utf-8")
    sig = sm2_sign(satoshi_msg, ID, forged_kp)  # normal sign with recovered key
    assert sm2_verify(satoshi_msg, ID, forged_kp.Px, forged_kp.Py, sig)
    print("forged signature for '我是中本聪' verified under recovered key.")


if __name__ == "__main__":
    main()
