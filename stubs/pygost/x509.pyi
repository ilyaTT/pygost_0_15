from typing import Tuple


def keypair_gen(seed: bytes) -> Tuple[bytes, bytes]: ...


def sign(private_key: bytes, data: bytes) -> bytes: ...


def verify(public_key: bytes, data: bytes, signature: bytes) -> bool: ...
