from __future__ import annotations

import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from sm2.sm2 import keygen, sm2_sign, sm2_verify, sm2_sign_without_ZA, sm2_verify_without_ZA


def main():
    kp = keygen()
    ID1 = b"Alice"
    ID2 = b"Bob"
    msg = b"hello"

    # Correct implementation with ZA should fail when ID is changed
    sig = sm2_sign(msg, ID1, kp)
    ok_same = sm2_verify(msg, ID1, kp.Px, kp.Py, sig)
    ok_diff = sm2_verify(msg, ID2, kp.Px, kp.Py, sig)

    # Misused implementation without ZA may still verify under another ID
    sig_wo = sm2_sign_without_ZA(msg, kp)
    ok_same_wo = sm2_verify_without_ZA(msg, kp.Px, kp.Py, sig_wo)
    ok_diff_wo = sm2_verify_without_ZA(msg, kp.Px, kp.Py, sig_wo)

    print("with ZA, verify under same ID:", ok_same)
    print("with ZA, verify under different ID:", ok_diff)
    print("without ZA, verify under same ID:", ok_same_wo)
    print("without ZA, verify under different ID:", ok_diff_wo)


if __name__ == "__main__":
    main()
