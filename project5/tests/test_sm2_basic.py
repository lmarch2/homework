from __future__ import annotations

from project5.sm2.sm2 import keygen, sm2_sign, sm2_verify


def test_sm2_sign_verify_roundtrip():
    kp = keygen()
    ID = b"Alice"
    msg = b"test message"
    sig = sm2_sign(msg, ID, kp)
    assert sm2_verify(msg, ID, kp.Px, kp.Py, sig)
