"""
WebSocket fallback transport with identical security guarantees to gRPC path.

When gRPC/HTTP2 is unavailable (firewall restrictions, protocol downgrade attacks),
agents fall back to TLS-encrypted WebSocket with Protobuf framing and the same
AES-256-GCM + HMAC-SHA256 security model.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
import struct
from dataclasses import dataclass
from typing import Optional, Callable, Awaitable, Dict, AsyncIterator

import websockets
from websockets.asyncio.server import ServerConnection

from proto import mesh_pb2
from agent_sdk.crypto import CryptoSession

logger = logging.getLogger(__name__)

MAX_FRAME_SIZE = 10 * 1024 * 1024
WS_PROTOCOL_VERSION = 1


@dataclass
class WebsocketAuthContext:
    agent_id: str
    session: CryptoSession
    access_token: str
    connected_at: float


class WebsocketAgentHandler:
    """Handles a single agent connection over WebSocket."""

    def __init__(
        self,
        websocket: ServerConnection,
        auth: WebsocketAuthContext,
        on_task_complete: Callable[[mesh_pb2.TaskResult], Awaitable[None]],
    ):
        self._ws = websocket
        self._auth = auth
        self._on_task_complete = on_task_complete
        self._running = False

    async def run(self):
        self._running = True
        try:
            async for raw_message in self._ws:
                await self._handle_frame(raw_message)
        except websockets.exceptions.ConnectionClosed:
            logger.info("WebSocket connection closed for agent %s", self._auth.agent_id)
        finally:
            self._running = False

    async def send_task(self, task_request: mesh_pb2.TaskRequest) -> bool:
        signed = self._sign_and_encrypt(task_request)
        frame = signed.SerializeToString()
        framed = struct.pack("!I", len(frame)) + frame
        try:
            await self._ws.send(framed)
            return True
        except websockets.exceptions.ConnectionClosed:
            return False

    async def _handle_frame(self, raw: bytes):
        try:
            signed = mesh_pb2.SignedPacket()
            signed.ParseFromString(raw)
        except Exception:
            logger.warning("WebSocket: failed to parse SignedPacket from agent %s", self._auth.agent_id)
            return

        try:
            plaintext = self._auth.session.decrypt(signed.payload)
        except Exception:
            logger.warning("WebSocket: decryption failed for agent %s", self._auth.agent_id)
            return

        if not self._auth.session.verify(signed.payload, signed.hmac_signature):
            logger.warning("WebSocket: HMAC mismatch for agent %s", self._auth.agent_id)
            return

        task_result = mesh_pb2.TaskResult()
        task_result.ParseFromString(plaintext)

        if self._on_task_complete:
            await self._on_task_complete(task_result)

    def _sign_and_encrypt(self, message) -> mesh_pb2.SignedPacket:
        raw = message.SerializeToString()
        ciphertext = self._auth.session.encrypt(raw)
        hmac_sig = self._auth.session.sign(ciphertext)
        return mesh_pb2.SignedPacket(
            payload=ciphertext,
            hmac_signature=hmac_sig,
            sequence_number=self._auth.session.sequence_counter,
        )


class WebsocketServer:
    """WebSocket fallback server for agent communication."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8443,
        token_issuer=None,
        guardrail=None,
        scheduler=None,
        tls_cert_path: str = "",
        tls_key_path: str = "",
    ):
        self.host = host
        self.port = port
        self._token_issuer = token_issuer
        self._guardrail = guardrail
        self._scheduler = scheduler
        self._tls_cert_path = tls_cert_path
        self._tls_key_path = tls_key_path
        self._server = None
        self._handlers: Dict[str, WebsocketAgentHandler] = {}

    async def start(self):
        ssl_context = None
        if self._tls_cert_path and self._tls_key_path:
            import ssl
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(self._tls_cert_path, self._tls_key_path)

        self._server = await websockets.serve(
            self._handle_connection,
            self.host,
            self.port,
            ssl=ssl_context,
            max_size=MAX_FRAME_SIZE,
            ping_interval=10,
            ping_timeout=5,
        )
        logger.info("WebSocket fallback server listening on wss://%s:%d", self.host, self.port)

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_connection(self, websocket: ServerConnection):
        raw = await websocket.recv()
        try:
            registration = mesh_pb2.AgentRegistrationRequest()
            registration.ParseFromString(raw)
        except Exception:
            await websocket.close(1002, "Invalid registration")
            return

        agent_id = registration.agent_id or str(uuid.uuid4())

        crypto = CryptoSession.init_for_orchestrator(
            session_id=agent_id,
            agent_public_bytes=registration.public_key,
        )
        if self._token_issuer:
            self._token_issuer.register_session(agent_id, crypto)
            token, expires = self._token_issuer.issue(
                agent_id=agent_id,
                task_id=str(uuid.uuid4()),
                permissions=set(registration.capabilities),
            )
        else:
            token, expires = "", ""

        response = mesh_pb2.AgentRegistrationResponse(
            agent_id=agent_id,
            orchestrator_public_key=crypto.agent_public.public_bytes_raw(),
            nonce=crypto.nonce_base,
            access_token=token,
            token_expires_at=expires,
            stream_lease_seconds=300,
        )
        await websocket.send(response.SerializeToString())

        if self._scheduler:
            await self._scheduler.register(registration)

        auth = WebsocketAuthContext(
            agent_id=agent_id,
            session=crypto,
            access_token=token,
            connected_at=time.time(),
        )

        async def on_task_complete(result: mesh_pb2.TaskResult):
            if self._guardrail:
                guard_result = self._guardrail.validate_inbound(
                    mesh_pb2.SignedPacket(payload=result.SerializeToString()),
                    crypto,
                    token,
                )
                if not guard_result.passed:
                    logger.warning("WebSocket guardrail reject: %s", guard_result.outcome)
                    return
            if self._scheduler:
                success = result.state == mesh_pb2.TASK_STATE_COMPLETED
                await self._scheduler.complete_task(agent_id, success)

        handler = WebsocketAgentHandler(websocket, auth, on_task_complete)
        self._handlers[agent_id] = handler
        await handler.run()
        self._handlers.pop(agent_id, None)

    async def dispatch(self, agent_id: str, task: mesh_pb2.TaskRequest) -> bool:
        handler = self._handlers.get(agent_id)
        if handler is None:
            return False
        return await handler.send_task(task)
