"""
JWT token issuer and ephemeral key manager for the Orchestrator.

Each agent session receives a short-lived JWT (RS256, 60s TTL) with scoped permissions.
Keys are auto-generated on first run if not found on disk.
"""

from __future__ import annotations

import os
import time
import uuid
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Set, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from jose import jwt, jws, JWTError

from agent_sdk.crypto import CryptoSession

logger = logging.getLogger(__name__)


@dataclass
class TokenPayload:
    agent_id: str
    task_id: str
    permissions: Set[str] = field(default_factory=set)
    expires_at: float = 0.0

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class TokenIssuer:
    """Generates and verifies short-lived JWT tokens for agent sessions."""

    ALGORITHM = "RS256"
    TTL_SECONDS = 60
    ISSUER = "secure-orchestration-mesh"

    def __init__(
        self,
        private_key_path: str = "config/jwt_private.pem",
        public_key_path: str = "config/jwt_public.pem",
        ttl_seconds: int = 60,
    ):
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self.TTL_SECONDS = ttl_seconds
        self._private_key = self._load_or_generate_private_key()
        self._public_key = self._load_or_generate_public_key()
        self._session_keys: Dict[str, CryptoSession] = {}

    def issue(self, agent_id: str, task_id: str, permissions: Set[str]) -> Tuple[str, str]:
        """
        Issue a new JWT for an agent task session.
        Returns (token_string, expires_at_iso8601).
        """
        now = time.time()
        expires_at = now + self.TTL_SECONDS
        claims = {
            "iss": self.ISSUER,
            "sub": agent_id,
            "task_id": task_id,
            "permissions": sorted(permissions),
            "iat": int(now),
            "exp": int(expires_at),
            "jti": str(uuid.uuid4()),
        }
        token = jwt.encode(claims, self._private_key, algorithm=self.ALGORITHM)
        expires_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_at))
        return token, expires_iso

    def verify(self, token: str) -> Optional[TokenPayload]:
        """
        Verify and decode a JWT token.
        Returns TokenPayload on success, None on failure.
        """
        try:
            claims = jwt.decode(
                token,
                self._public_key,
                algorithms=[self.ALGORITHM],
                options={
                    "verify_exp": True,
                    "verify_iss": True,
                    "verify_aud": False,
                },
            )
        except JWTError as e:
            logger.warning("JWT verification failed: %s", e)
            return None

        return TokenPayload(
            agent_id=claims["sub"],
            task_id=claims.get("task_id", ""),
            permissions=set(claims.get("permissions", [])),
            expires_at=claims["exp"],
        )

    def register_session(self, agent_id: str, crypto_session: CryptoSession):
        self._session_keys[agent_id] = crypto_session

    def get_session(self, agent_id: str) -> Optional[CryptoSession]:
        return self._session_keys.get(agent_id)

    def revoke_session(self, agent_id: str):
        self._session_keys.pop(agent_id, None)
        logger.info("Session revoked for agent_id=%s", agent_id)

    def _load_or_generate_private_key(self):
        if os.path.exists(self.private_key_path):
            with open(self.private_key_path, "rb") as f:
                return serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        os.makedirs(os.path.dirname(self.private_key_path), exist_ok=True)
        with open(self.private_key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        logger.info("Generated new JWT private key at %s", self.private_key_path)
        return key

    def _load_or_generate_public_key(self):
        if os.path.exists(self.public_key_path):
            with open(self.public_key_path, "rb") as f:
                return serialization.load_pem_public_key(
                    f.read(), backend=default_backend()
                )
        public_key = self._private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        os.makedirs(os.path.dirname(self.public_key_path), exist_ok=True)
        with open(self.public_key_path, "wb") as f:
            f.write(pem)
        logger.info("Generated new JWT public key at %s", self.public_key_path)
        return public_key
