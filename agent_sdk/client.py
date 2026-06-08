"""
gRPC client stub for Worker Agents.

Handles registration, key exchange, task stream, heartbeat loop, and graceful shutdown.
CRITICAL PROTOCOL: HMAC-SHA256 is computed over CIPHERTEXT, not plaintext.
"""

from __future__ import annotations

import asyncio
import uuid
import time
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, AsyncIterator

import grpc

from proto import mesh_pb2
from proto import mesh_pb2_grpc
from agent_sdk.crypto import CryptoSession
from agent_sdk.executor import TaskExecutor, PermissionScope as ExecScope

logger = logging.getLogger(__name__)


@dataclass
class AgentConfig:
    agent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_label: str = "worker-agent-01"
    capabilities: list[str] = field(default_factory=lambda: ["web_search", "file_read"])
    sdk_version: str = "0.1.0"
    orchestrator_address: str = "localhost:50051"
    heartbeat_interval: float = 5.0
    heartbeat_timeout: float = 15.0
    tls_cert_path: str = ""
    tls_key_path: str = ""


class MeshAgent:
    """Worker Agent that connects to an Orchestrator over secure gRPC."""

    def __init__(self, config: AgentConfig = AgentConfig()):
        self.config = config
        self.crypto: Optional[CryptoSession] = None
        self.access_token: Optional[str] = None
        self.token_expires_at: Optional[str] = None
        self._channel: Optional[grpc.aio.Channel] = None
        self._stub: Optional[mesh_pb2_grpc.AgentMeshStub] = None
        self._executor = TaskExecutor()
        self._running: bool = False
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._pending_results: asyncio.Queue[mesh_pb2.SignedPacket] = asyncio.Queue(maxsize=256)

    async def connect(self) -> bool:
        options = [
            ("grpc.max_send_message_length", 100 * 1024 * 1024),
            ("grpc.max_receive_message_length", 100 * 1024 * 1024),
            ("grpc.keepalive_time_ms", 10000),
            ("grpc.keepalive_timeout_ms", 5000),
        ]
        self._channel = grpc.aio.insecure_channel(self.config.orchestrator_address, options=options)
        self._stub = mesh_pb2_grpc.AgentMeshStub(self._channel)

        pub_bytes = self._generate_ephemeral_keypair()

        reg_request = mesh_pb2.AgentRegistrationRequest(
            agent_id=self.config.agent_id,
            agent_label=self.config.agent_label,
            capabilities=self.config.capabilities,
            sdk_version=self.config.sdk_version,
            public_key=pub_bytes,
        )

        try:
            response: mesh_pb2.AgentRegistrationResponse = await self._stub.Register(reg_request, timeout=30)
        except grpc.RpcError as e:
            logger.error("Registration failed: %s", e)
            return False

        self.access_token = response.access_token
        self.token_expires_at = response.token_expires_at
        self.crypto = CryptoSession.init_for_agent(
            session_id=self.config.agent_id,
            orchestrator_public_bytes=response.orchestrator_public_key,
        )
        self.crypto.nonce_base = response.nonce

        logger.info("Registered with orchestrator. Token expires at %s", self.token_expires_at)
        return True

    async def run(self):
        self._running = True
        if not await self.connect():
            return
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        try:
            await self._task_stream_loop()
        finally:
            self._running = False
            if self._heartbeat_task:
                self._heartbeat_task.cancel()
            await self.disconnect()

    async def _task_stream_loop(self):
        async def request_iterator() -> AsyncIterator[mesh_pb2.SignedPacket]:
            while self._running:
                try:
                    packet = await asyncio.wait_for(self._pending_results.get(), timeout=0.5)
                    yield packet
                except asyncio.TimeoutError:
                    continue

        try:
            call = self._stub.TaskStream(request_iterator())
            async for signed_response in call:
                try:
                    await self._handle_inbound_packet(signed_response)
                except Exception as e:
                    logger.error("Error handling inbound packet: %s", e)
        except grpc.RpcError as e:
            logger.error("Task stream error: %s", e)

    async def _handle_inbound_packet(self, signed: mesh_pb2.SignedPacket):
        seq = signed.sequence_number

        if not self.crypto.verify(signed.payload, signed.hmac_signature):
            logger.warning("HMAC verification failed for sequence %d", seq)
            return

        try:
            plaintext = self.crypto.decrypt(signed.payload, seq)
        except Exception:
            logger.warning("Decryption failed for sequence %d", seq)
            return

        task_request = mesh_pb2.TaskRequest()
        task_request.ParseFromString(plaintext)

        if task_request.access_token:
            self.access_token = task_request.access_token

        scope = ExecScope(
            allowed_actions=list(task_request.permission_scope.allowed_actions),
            max_payload_bytes=task_request.permission_scope.max_payload_bytes,
            max_execution_ms=task_request.permission_scope.max_execution_ms,
            resource_allowlist=list(task_request.permission_scope.resource_allowlist),
        )

        result = await self._executor.execute(task_request.task, scope)

        result_msg = mesh_pb2.TaskResult(
            task_id=result.task_id,
            state=result.state,
            payload=result.payload,
            error_message=result.error_message,
            completed_at=result.completed_at,
            sequence_number=seq + 1,
            metrics=result.metrics,
        )

        signed_response = self._sign_and_encrypt(result_msg)
        await self._pending_results.put(signed_response)
        logger.info("Task %s completed: state=%s", result.task_id, mesh_pb2.TaskState.Name(result.state))

    def _sign_and_encrypt(self, message) -> mesh_pb2.SignedPacket:
        raw = message.SerializeToString()
        self.crypto.sequence_counter += 1
        ciphertext = self.crypto.encrypt(raw)
        hmac_sig = self.crypto.sign(ciphertext)
        return mesh_pb2.SignedPacket(
            payload=ciphertext,
            hmac_signature=hmac_sig,
            sequence_number=self.crypto.sequence_counter,
        )

    async def _heartbeat_loop(self):
        while self._running:
            try:
                heartbeat = mesh_pb2.HeartBeat(
                    agent_id=self.config.agent_id,
                    status=mesh_pb2.AGENT_STATUS_IDLE,
                    timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    current_task_id="",
                    tasks_completed=0,
                    tasks_failed=0,
                    sequence_number=self.crypto.sequence_counter if self.crypto else 0,
                )
                call = self._stub.HeartBeatStream(iter([heartbeat]))
                async for _ in call:
                    pass
            except grpc.RpcError:
                pass
            await asyncio.sleep(self.config.heartbeat_interval)

    async def report_error(self, error_code: str, summary: str, severity=mesh_pb2.LOG_SEVERITY_ERROR):
        report = mesh_pb2.ErrorReport(
            agent_id=self.config.agent_id,
            error_code=error_code,
            error_summary=summary,
            severity=severity,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        try:
            await self._stub.ReportError(report, timeout=10)
        except grpc.RpcError:
            pass

    async def disconnect(self):
        self._running = False
        if self._channel:
            await self._channel.close()

    def _generate_ephemeral_keypair(self) -> bytes:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        self._ephemeral_private = X25519PrivateKey.generate()
        return self._ephemeral_private.public_key().public_bytes_raw()
