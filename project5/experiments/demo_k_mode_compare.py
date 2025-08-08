from __future__ import annotations

import os, sys, time
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from sm2.sm2 import keygen, sm2_sign, sm2_verify


def main():
    kp = keygen()
    ID = b"Alice"
    N = 20
    msgs = [f"msg-{i}".encode() for i in range(N)]

    t0 = time.time()
    sigs_rnd = [sm2_sign(m, ID, kp, k_mode='random') for m in msgs]
    t1 = time.time()
    t2 = time.time()
    sigs_det = [sm2_sign(m, ID, kp, k_mode='deterministic') for m in msgs]
    t3 = time.time()

    ok_rnd = all(sm2_verify(m, ID, kp.Px, kp.Py, s) for m, s in zip(msgs, sigs_rnd))
    ok_det = all(sm2_verify(m, ID, kp.Px, kp.Py, s) for m, s in zip(msgs, sigs_det))

    print("random-k: ok=", ok_rnd, ", sign time=", f"{(t1-t0)*1000:.2f} ms")
    print("deterministic-k: ok=", ok_det, ", sign time=", f"{(t3-t2)*1000:.2f} ms")


if __name__ == "__main__":
    main()
