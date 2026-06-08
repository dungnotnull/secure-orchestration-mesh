"""
X25519 ECDH key exchange + AES-256-GCM encryption + HMAC-SHA256 integrity.

Provides the cryptographic foundation for all Orchestrator-Agent communication.
Every session gets a fresh ephemeral key pair (forward secrecy).

CRITICAL PROTOCOL ORDER (must be identical on both sides):
  1. Encrypt plaintext with AES-256-GCM using sequence_number-derived nonce
  2. Compute HMAC-SHA256 over CIPHERTEXT (not plaintext)
  3. Send {ciphertext, hmac, sequence_number} as SignedPacket
  4. Receiver: verify HMAC over ciphertext FIRST, then decrypt
"""

from __future__ import annotations

import os
import hashlib
import hmac
import struct
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


__all__ = [
    "generate_keypair",
    "derive_session_key",
    "compute_hmac",
    "verify_hmac",
    "encrypt_payload",
    "decrypt_payload",
    "CryptoSession",
]

AES_GCM_NONCE_LENGTH = 12
HMAC_OUTPUT_LENGTH = 32
X25519_KEY_LENGTH = 32

HKDF_INFO_CONTEXT_KEY = b"secure-orchestration-mesh-v1-session-key"
HKDF_HASH_ALGORITHM = hashes.SHA256()


def generate_keypair() -> Tuple[X25519PrivateKey, X25519PublicKey]:
    private = X25519PrivateKey.generate()
    return private, private.public_key()


def derive_session_key(
    own_private: X25519PrivateKey,
    peer_public: X25519PublicKey,
    shared_nonce: bytes,
) -> bytes:
    shared_secret = own_private.exchange(peer_public)
    derived = HKDF(
        algorithm=HKDF_HASH_ALGORITHM,
        length=32,
        salt=shared_nonce,
        info=HKDF_INFO_CONTEXT_KEY,
    ).derive(shared_secret)
    return derived


def compute_hmac(key: bytes, message: bytes) -> bytes:
    return hmac.digest(key, message, "sha256")


def verify_hmac(key: bytes, message: bytes, signature: bytes) -> bool:
    return hmac.compare_digest(compute_hmac(key, message), signature)


def encrypt_payload(session_key: bytes, nonce_base: bytes, plaintext: bytes, sequence_number: int) -> bytes:
    nonce = _derive_nonce(nonce_base, sequence_number)
    aesgcm = AESGCM(session_key)
    return aesgcm.encrypt(nonce, plaintext, None)


def decrypt_payload(
    session_key: bytes, nonce_base: bytes, ciphertext: bytes, sequence_number: int
) -> bytes:
    nonce = _derive_nonce(nonce_base, sequence_number)
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def _derive_nonce(nonce_base: bytes, counter: int) -> bytes:
    counter_bytes = struct.pack(">Q", counter)
    h = hashlib.sha256(nonce_base + counter_bytes).digest()
    return h[:AES_GCM_NONCE_LENGTH]


@dataclass
class CryptoSession:
    """Holds all cryptographic state for a single agent session."""

    agent_private: X25519PrivateKey
    agent_public: X25519PublicKey
    orchestrator_public: X25519PublicKey
    session_key: bytes
    nonce_base: bytes
    session_id: str
    sequence_counter: int = 0

    @classmethod
    def init_for_agent(
        cls,
        session_id: str,
        orchestrator_public_bytes: bytes,
    ) -> "CryptoSession":
        agent_private = X25519PrivateKey.generate()
        agent_public = agent_private.public_key()
        orchestrator_public = X25519PublicKey.from_public_bytes(orchestrator_public_bytes)
        nonce_base = os.urandom(16)
        session_key = derive_session_key(agent_private, orchestrator_public, nonce_base)
        return cls(
            agent_private=agent_private,
            agent_public=agent_public,
            orchestrator_public=orchestrator_public,
            session_key=session_key,
            nonce_base=nonce_base,
            session_id=session_id,
        )

    @classmethod
    def init_for_orchestrator(
        cls,
        session_id: str,
        agent_public_bytes: bytes,
    ) -> "CryptoSession":
        orch_private = X25519PrivateKey.generate()
        orch_public = orch_private.public_key()
        agent_public = X25519PublicKey.from_public_bytes(agent_public_bytes)
        nonce_base = os.urandom(16)
        session_key = derive_session_key(orch_private, agent_public, nonce_base)
        return cls(
            agent_private=orch_private,
            agent_public=orch_public,
            orchestrator_public=agent_public,
            session_key=session_key,
            nonce_base=nonce_base,
            session_id=session_id,
        )

    def encrypt(self, plaintext: bytes) -> bytes:
        self.sequence_counter += 1
        return encrypt_payload(self.session_key, self.nonce_base, plaintext, self.sequence_counter)

    def decrypt(self, ciphertext: bytes, sequence_number: int) -> bytes:
        return decrypt_payload(self.session_key, self.nonce_base, ciphertext, sequence_number)

    def sign(self, message: bytes) -> bytes:
        return compute_hmac(self.session_key, message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        return verify_hmac(self.session_key, message, signature)
