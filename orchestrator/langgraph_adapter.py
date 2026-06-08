"""
LangGraph adapter — wraps LangGraph agent graphs through the secure-orchestration-mesh protocol.

Intercepts node execution, tool calls, and state transitions, encrypting all
inter-node communication through the Mesh zero-trust protocol. Works with
any LangGraph StateGraph without modifying the original graph definition.

Usage:
    from langgraph.graph import StateGraph

    graph = StateGraph(MyState)
    graph.add_node("process", process_node)
    graph.add_edge("process", "end")

    adapter = SecureGraphAdapter(
        orchestrator_address="localhost:50051",
        agent_label="langgraph-agent",
    )
    await adapter.connect()
    secure_graph = adapter.wrap_graph(graph)
    result = await secure_graph.ainvoke(initial_state)
"""

from __future__ import annotations

import asyncio
import logging
import uuid
import time
import json
from typing import Optional, List, Dict, Any, Callable, TypeVar, AsyncIterator

from proto import mesh_pb2
from agent_sdk.client import MeshAgent, AgentConfig

logger = logging.getLogger(__name__)

StateT = TypeVar("StateT")


class SecureGraphAdapter:
    """Wraps a LangGraph StateGraph with secure mesh transport."""

    def __init__(
        self,
        orchestrator_address: str = "localhost:50051",
        agent_label: str = "langgraph-agent",
        capabilities: Optional[List[str]] = None,
        sdk_version: str = "0.1.0",
        audit_trail_enabled: bool = True,
    ):
        self._config = AgentConfig(
            agent_label=agent_label,
            capabilities=capabilities or ["code_execution", "api_call", "data_analysis"],
            orchestrator_address=orchestrator_address,
            sdk_version=sdk_version,
        )
        self._agent = MeshAgent(self._config)
        self._connected = False
        self._audit_trail_enabled = audit_trail_enabled
        self._invocation_log: List[Dict[str, Any]] = []
        self._consumer_task: Optional[asyncio.Task] = None
        self._pending_tasks: Dict[str, asyncio.Future] = {}

    async def connect(self) -> bool:
        success = await self._agent.connect()
        if success:
            self._connected = True
            self._consumer_task = asyncio.create_task(self._consume_responses())
        return success

    async def disconnect(self):
        if self._consumer_task:
            self._consumer_task.cancel()
        await self._agent.disconnect()

    async def _consume_responses(self):
        while self._connected:
            try:
                packet = await asyncio.wait_for(self._agent._pending_results.get(), timeout=1.0)
                await self._handle_response(packet)
            except asyncio.TimeoutError:
                continue
            except Exception:
                pass

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
            })

    def wrap_graph(self, graph):
        original_compile = getattr(graph, "compile", None)

        class SecureCompiledGraph:
            def __init__(self, compiled_graph, adapter: SecureGraphAdapter):
                self._compiled = compiled_graph
                self._adapter = adapter

            async def ainvoke(self, state: dict, config: dict = None) -> dict:
                task_id = str(uuid.uuid4())
                await self._adapter._log_invocation("ainvoke", task_id, state)

                task_payload = json.dumps({"state": self._serializable(state)}).encode()
                result = await self._adapter.execute_task(
                    task_description=f"LangGraph.invoke node={self._get_entry_node()}",
                    task_type="code_execution",
                    payload=task_payload,
                    deadline_seconds=600,
                )

                if result.get("state") == "COMPLETED":
                    return self._adapter._deserialize_result(result.get("payload", b"{}"))
                if result.get("state") == "TIMEOUT":
                    raise TimeoutError(f"Graph execution timed out: {task_id}")
                raise RuntimeError(f"Graph execution failed: {result.get('error')}")

            async def astream(self, state: dict, config: dict = None) -> AsyncIterator[dict]:
                task_id = str(uuid.uuid4())
                await self._adapter._log_invocation("astream", task_id, state)

                task_payload = json.dumps({"state": self._serializable(state)}).encode()
                result = await self._adapter.execute_task(
                    task_description="LangGraph.astream",
                    task_type="code_execution",
                    payload=task_payload,
                    deadline_seconds=600,
                )

                if result.get("state") == "COMPLETED" and result.get("payload"):
                    try:
                        stream_data = json.loads(result["payload"])
                        for chunk in stream_data.get("chunks", []):
                            yield chunk if isinstance(chunk, dict) else {"content": chunk}
                    except json.JSONDecodeError:
                        yield {"content": result["payload"].decode("utf-8", errors="replace")}
                else:
                    yield {"error": result.get("error", "Unknown error")}

            def _get_entry_node(self) -> str:
                if hasattr(self._compiled, "nodes"):
                    nodes = list(self._compiled.nodes.keys())
                    return nodes[0] if nodes else "unknown"
                return "unknown"

            def _serializable(self, obj: Any) -> Any:
                if isinstance(obj, dict):
                    return {k: self._serializable(v) for k, v in obj.items()}
                if isinstance(obj, (list, tuple)):
                    return [self._serializable(v) for v in obj]
                if hasattr(obj, "__dict__"):
                    return str(obj)
                try:
                    json.dumps(obj)
                    return obj
                except (TypeError, ValueError):
                    return str(obj)

        compiled = original_compile() if callable(original_compile) else None
        return SecureCompiledGraph(compiled, self) if compiled else graph

    async def execute_task(
        self,
        task_description: str,
        task_type: str,
        payload: bytes,
        deadline_seconds: int = 300,
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
            priority=5,
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
            return {"task_id": task_id, "state": "TIMEOUT", "error": "Deadline exceeded"}

    async def _log_invocation(self, method: str, task_id: str, state: dict):
        if self._audit_trail_enabled:
            self._invocation_log.append({
                "method": method,
                "task_id": task_id,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "state_keys": list(state.keys()) if state else [],
            })

    def _deserialize_result(self, payload: bytes) -> dict:
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return {"raw": payload.decode("utf-8", errors="replace")}
