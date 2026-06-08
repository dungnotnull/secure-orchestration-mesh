"""
CrewAI adapter — wraps CrewAI agent calls through the secure-orchestration-mesh protocol.

Production-grade integration. Any CrewAI agent or tool call is intercepted,
encrypted, and routed through the Mesh protocol with full zero-trust guarantees.
No plain-text agent communication ever touches the wire.

Usage:
    adapter = SecureMeshAdapter(
        orchestrator_address="localhost:50051",
        agent_label="crewai-finance-agent",
        capabilities=["web_search", "file_read"],
    )
    await adapter.connect()

    result = await adapter.execute_task(task_description="Search for Q2 earnings")
"""

from __future__ import annotations

import asyncio
import logging
import uuid
import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable

from proto import mesh_pb2
from agent_sdk.client import MeshAgent, AgentConfig
from agent_sdk.crypto import CryptoSession

logger = logging.getLogger(__name__)


class SecureMeshAdapter:
    """Drops into any CrewAI crew/agent setup as a drop-in transport replacement."""

    def __init__(
        self,
        orchestrator_address: str = "localhost:50051",
        agent_label: str = "crewai-agent",
        capabilities: Optional[List[str]] = None,
        sdk_version: str = "0.1.0",
        heartbeat_interval: float = 5.0,
    ):
        self._config = AgentConfig(
            agent_label=agent_label,
            capabilities=capabilities or ["web_search", "file_read", "api_call"],
            orchestrator_address=orchestrator_address,
            sdk_version=sdk_version,
            heartbeat_interval=heartbeat_interval,
        )
        self._agent = MeshAgent(self._config)
        self._connected = False
        self._pending_tasks: Dict[str, asyncio.Future] = {}
        self._task_consumer_task: Optional[asyncio.Task] = None

    async def connect(self) -> bool:
        success = await self._agent.connect()
        if success:
            self._connected = True
            self._task_consumer_task = asyncio.create_task(self._consume_task_responses())
            logger.info("CrewAI adapter connected as '%s'", self._config.agent_label)
        return success

    async def disconnect(self):
        if self._task_consumer_task:
            self._task_consumer_task.cancel()
        await self._agent.disconnect()

    async def _consume_task_responses(self):
        while self._connected:
            try:
                packet = await asyncio.wait_for(self._agent._pending_results.get(), timeout=1.0)
                await self._handle_response(packet)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("Task consumer error: %s", e)

    async def _handle_response(self, signed: mesh_pb2.SignedPacket):
        try:
            plaintext = self._agent.crypto.decrypt(signed.payload, signed.sequence_number)
        except Exception:
            return

        if not self._agent.crypto.verify(signed.payload, signed.hmac_signature):
            return

        task_result = mesh_pb2.TaskResult()
        task_result.ParseFromString(plaintext)

        future = self._pending_tasks.pop(task_result.task_id, None)
        if future and not future.done():
            future.set_result({
                "task_id": task_result.task_id,
                "state": mesh_pb2.TaskState.Name(task_result.state),
                "payload": task_result.payload,
                "error": task_result.error_message,
                "metrics": {
                    "execution_time_ms": task_result.metrics.execution_time_ms,
                    "payload_bytes": task_result.metrics.result_payload_bytes,
                },
            })

    async def execute_task(
        self,
        task_description: str,
        task_type: str = "api_call",
        payload: bytes = b"",
        deadline_seconds: int = 300,
        priority: int = 5,
    ) -> Dict[str, Any]:
        if not self._connected:
            await self.connect()

        task_id = str(uuid.uuid4())
        task_context = mesh_pb2.TaskContext(
            task_id=task_id,
            description=task_description,
            payload=payload,
            task_type=task_type,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            deadline_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + deadline_seconds)),
            priority=priority,
        )

        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending_tasks[task_id] = future

        scope = mesh_pb2.PermissionScope(
            allowed_actions=[task_type],
            max_payload_bytes=10 * 1024 * 1024,
            max_execution_ms=deadline_seconds * 1000,
        )

        task_request = mesh_pb2.TaskRequest(
            access_token=self._agent.access_token or "",
            task=task_context,
            permission_scope=scope,
            sequence_number=self._agent.crypto.sequence_counter if self._agent.crypto else 0,
        )

        signed = self._agent._sign_and_encrypt(task_request)

        try:
            await self._agent._pending_results.put(signed)
        except asyncio.QueueFull:
            self._pending_tasks.pop(task_id, None)
            return {"task_id": task_id, "state": "FAILED", "error": "Send queue full"}

        try:
            result = await asyncio.wait_for(future, timeout=deadline_seconds)
            return result
        except asyncio.TimeoutError:
            self._pending_tasks.pop(task_id, None)
            return {"task_id": task_id, "state": "TIMEOUT", "error": "Task deadline exceeded"}
        except Exception as e:
            self._pending_tasks.pop(task_id, None)
            return {"task_id": task_id, "state": "FAILED", "error": str(e)}

    def wrap_tool(self, tool_func: Callable) -> Callable:
        async def wrapped(*args, **kwargs):
            description = f"Tool: {tool_func.__name__} with args={args}, kwargs={kwargs}"
            result = await self.execute_task(
                task_description=description,
                task_type="api_call",
                payload=str({"args": args, "kwargs": kwargs}).encode(),
            )
            if result.get("state") == "COMPLETED":
                return result.get("payload", b"")
            raise RuntimeError(f"Tool execution failed: {result.get('error')}")
        return wrapped

    def wrap_agent(self, agent_class) -> type:
        original_init = agent_class.__init__

        def new_init(self_agent, *args, **kwargs):
            original_init(self_agent, *args, **kwargs)
            self_agent._mesh_adapter = self
            if hasattr(self_agent, "tools"):
                self_agent.tools = [self.wrap_tool(t) for t in self_agent.tools]

        agent_class.__init__ = new_init
        return agent_class
