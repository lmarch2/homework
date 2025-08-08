from __future__ import annotations

import os, sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from sm2.sm2 import keygen, sm2_sign, sm2_verify


def test_sm2_sign_verify_roundtrip():
    kp = keygen()
    ID = b"Alice"
    msg = b"test message"
    sig = sm2_sign(msg, ID, kp)
    assert sm2_verify(msg, ID, kp.Px, kp.Py, sig)
