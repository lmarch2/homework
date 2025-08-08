#!/usr/bin/env python3
import random

from project6.src.protocol import Protocol

COMMON = [
    b"123456", b"password", b"qwerty", b"111111", b"abc123",
    b"password1", b"iloveyou", b"admin", b"welcome", b"monkey",
]


def main():
    leaked = COMMON + [f"pass{random.randint(100000, 999999)}".encode() for _ in range(500)]
    proto = Protocol.setup(leaked_passwords=leaked, b_bits=12, target_fpr=1e-4)

    tests = [b"password", b"hello1234", b"admin", b"not_in_set_987654"]
    for pw in tests:
        hit = proto.query(pw)
        print(f"query={pw!r} -> leaked={hit}")


if __name__ == "__main__":
    main()
