from __future__ import annotations

import time
import os
import sys

# allow running as: python3 project5/run_all.py
sys.path.append(os.path.dirname(__file__))

from sm2.sm2 import keygen, sm2_sign, sm2_verify
from experiments.demo_reuse_k import main as demo_reuse_k
from experiments.demo_omit_ZA import main as demo_omit_ZA
from experiments.demo_k_mode_compare import main as demo_k_mode


def basic_correctness_and_perf():
    kp = keygen()
    ID = b"Alice"
    N = 50
    msgs = [f"msg-{i}".encode() for i in range(N)]
    t0 = time.time()
    sigs = [sm2_sign(m, ID, kp) for m in msgs]
    t1 = time.time()
    ok = all(sm2_verify(m, ID, kp.Px, kp.Py, s) for m, s in zip(msgs, sigs))
    t2 = time.time()
    print("basic correctness:", ok)
    print(f"sign {N} msgs time: {(t1 - t0)*1000:.2f} ms, verify time: {(t2 - t1)*1000:.2f} ms")


def main():
    print("== Experiment A: correctness and perf ==")
    basic_correctness_and_perf()

    print("\n== Experiment B: reuse-k PoC ==")
    demo_reuse_k()

    print("\n== Experiment C: omit ZA ==")
    demo_omit_ZA()

    print("\n== Experiment D: deterministic k vs random k ==")
    demo_k_mode()


if __name__ == "__main__":
    main()
