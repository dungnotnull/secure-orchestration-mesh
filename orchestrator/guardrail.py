"""
Deterministic Guardrail Layer — pure-code validation, no LLM in the path.

All packets flowing through the Orchestrator pass through this layer.
Checks: HMAC integrity over CIPHERTEXT, decrypt, JWT expiry, sequence replay,
payload size limits, and permission boundary enforcement.
"""

from __future__ import annotations

import time
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple
from collections import defaultdict

from proto import mesh_pb2
from agent_sdk.crypto import CryptoSession

logger = logging.getLogger(__name__)

__all__ = ["GuardrailLayer", "GuardrailResult", "ValidationOutcome"]


class ValidationOutcome:
    PASS = "PASS"
    REJECT_EXPIRED_JWT = "REJECT_EXPIRED_JWT"
    REJECT_PERMISSION_OUT_OF_SCOPE = "REJECT_PERMISSION_OUT_OF_SCOPE"
    REJECT_HMAC_MISMATCH = "REJECT_HMAC_MISMATCH"
    REJECT_PAYLOAD_OVERSIZE = "REJECT_PAYLOAD_OVERSIZE"
    REJECT_REPLAY = "REJECT_REPLAY"
    REJECT_SCHEMA_VIOLATION = "REJECT_SCHEMA_VIOLATION"
    REJECT_MISSING_SESSION = "REJECT_MISSING_SESSION"


@dataclass
class GuardrailResult:
    outcome: str
    detail: str = ""
    task_id: str = ""
    agent_id: str = ""
    elapsed_microseconds: float = 0.0

    @property
    def passed(self) -> bool:
        return self.outcome == ValidationOutcome.PASS


class GuardrailLayer:
    """Deterministic validation firewall between transport and task processing."""

    MAX_PAYLOAD_BYTES = 10 * 1024 * 1024
    REPLAY_WINDOW_SECONDS = 30
    MAX_WINDOW_DRIFT = 100_000

    def __init__(
        self,
        token_issuer,
        max_payload_bytes: int = MAX_PAYLOAD_BYTES,
    ):
        self._token_issuer = token_issuer
        self.max_payload_bytes = max_payload_bytes
        self._seen_sequences: Dict[str, set] = defaultdict(set)
        self._sequence_high_water: Dict[str, int] = defaultdict(int)
        self._metrics_buffer: List[dict] = []

    def validate_inbound(
        self,
        signed_packet: mesh_pb2.SignedPacket,
        session: CryptoSession,
        access_token: str,
    ) -> GuardrailResult:
        start = time.perf_counter_ns()
        seq = signed_packet.sequence_number

        # 1. Verify HMAC over CIPHERTEXT first — fail fast on tampering
        if not session.verify(signed_packet.payload, signed_packet.hmac_signature):
            elapsed = (time.perf_counter_ns() - start) / 1000
            return GuardrailResult(
                outcome=ValidationOutcome.REJECT_HMAC_MISMATCH,
                detail=f"HMAC signature verification failed for seq={seq}",
                elapsed_microseconds=elapsed,
            )

        # 2. Sequence replay detection
        if not self._check_replay(session.session_id, signed_packet.sequence_number):
            elapsed = (time.perf_counter_ns() - start) / 1000
            return GuardrailResult(
                outcome=ValidationOutcome.REJECT_REPLAY,
                detail=f"Replay detected for sequence {seq}",
                elapsed_microseconds=elapsed,
            )

        # 3. Decrypt
        try:
            plaintext = session.decrypt(signed_packet.payload, seq)
        except Exception as e:
            elapsed = (time.perf_counter_ns() - start) / 1000
            return GuardrailResult(
                outcome=ValidationOutcome.REJECT_SCHEMA_VIOLATION,
                detail=f"Decryption failed: {e}",
                elapsed_microseconds=elapsed,
            )

        # 4. Payload size check
        payload_size = len(signed_packet.payload)
        if payload_size > self.max_payload_bytes:
            elapsed = (time.perf_counter_ns() - start) / 1000
            return GuardrailResult(
                outcome=ValidationOutcome.REJECT_PAYLOAD_OVERSIZE,
                detail=f"Payload {payload_size} bytes exceeds {self.max_payload_bytes}",
                elapsed_microseconds=elapsed,
            )

        # 5. Verify JWT
        token_payload = self._token_issuer.verify(access_token)
        if token_payload is None:
            elapsed = (time.perf_counter_ns() - start) / 1000
            return GuardrailResult(
                outcome=ValidationOutcome.REJECT_EXPIRED_JWT,
                detail="JWT verification failed or token expired",
                elapsed_microseconds=elapsed,
            )

        # 6. Schema validation — must parse as a valid message type
        try:
            inner = mesh_pb2.SignedPacket.FromString(plaintext) if False else None
            task_result = mesh_pb2.TaskResult()
            task_result.ParseFromString(plaintext)
        except Exception as e:
            elapsed = (time.perf_counter_ns() - start) / 1000
            return GuardrailResult(
                outcome=ValidationOutcome.REJECT_SCHEMA_VIOLATION,
                detail=f"Protobuf parse failed: {e}",
                elapsed_microseconds=elapsed,
            )

        # 7. Permission boundary check
        permissions = token_payload.permissions
        if task_result.payload and len(task_result.payload) > 0 and not permissions:
            elapsed = (time.perf_counter_ns() - start) / 1000
            return GuardrailResult(
                outcome=ValidationOutcome.REJECT_PERMISSION_OUT_OF_SCOPE,
                detail="Agent has no permissions but returned payload data",
                task_id=task_result.task_id,
                agent_id=token_payload.agent_id,
                elapsed_microseconds=elapsed,
            )

        elapsed = (time.perf_counter_ns() - start) / 1000
        self._record_metric(token_payload.agent_id, task_result.task_id, elapsed, payload_size)

        return GuardrailResult(
            outcome=ValidationOutcome.PASS,
            task_id=task_result.task_id,
            agent_id=token_payload.agent_id,
            elapsed_microseconds=elapsed,
        )

    def drain_metrics(self) -> List[dict]:
        metrics = list(self._metrics_buffer)
        self._metrics_buffer.clear()
        return metrics

    def _check_replay(self, session_id: str, seq: int) -> bool:
        seq_set = self._seen_sequences[session_id]
        high_water = self._sequence_high_water[session_id]

        if seq <= high_water - self.MAX_WINDOW_DRIFT:
            return False

        if seq in seq_set:
            return False

        if len(seq_set) > 10000:
            cutoff = seq - 5000
            seq_set = {s for s in seq_set if s > cutoff}
            self._seen_sequences[session_id] = seq_set

        seq_set.add(seq)
        self._sequence_high_water[session_id] = max(high_water, seq)
        return True

    def _record_metric(self, agent_id: str, task_id: str, latency_us: float, payload_bytes: int):
        self._metrics_buffer.append({
            "agent_id": agent_id,
            "task_id": task_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "payload_bytes": payload_bytes,
            "latency_us": latency_us,
            "error_code": "",
        })
