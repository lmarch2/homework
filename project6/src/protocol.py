from dataclasses import dataclass
from typing import List

from .client import Client
from .server import ServerDB


@dataclass
class Protocol:
    server: ServerDB
    client: Client

    @staticmethod
    def setup(leaked_passwords: List[bytes], b_bits: int = 12, target_fpr: float = 1e-4) -> "Protocol":
        server = ServerDB.build(leaked_passwords, b_bits, target_fpr)
        client = Client(b_bits)
        return Protocol(server=server, client=client)

    def query(self, password: bytes) -> bool:
        bucket_idx, M, r = self.client.prepare(password)
        N, bf_bytes = self.server.respond(bucket_idx, M)
        return self.client.finalize(password, N, r, bf_bytes)
