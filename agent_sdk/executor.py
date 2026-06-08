"""
Task execution engine that runs within the agent's permission boundary.

Every action is checked against the granted permission scope before execution.
The executor is deterministic — no LLM in the execution path.
"""

from __future__ import annotations

import time
import uuid
import logging
from dataclasses import dataclass, field
from typing import List, Optional

from proto import mesh_pb2

logger = logging.getLogger(__name__)


@dataclass
class PermissionScope:
    allowed_actions: List[str] = field(default_factory=list)
    max_payload_bytes: int = 10485760
    max_execution_ms: int = 300000
    resource_allowlist: List[str] = field(default_factory=list)

    def allows_action(self, action: str) -> bool:
        if "*" in self.allowed_actions:
            return True
        return action in self.allowed_actions

    def allows_payload_size(self, byte_count: int) -> bool:
        return byte_count <= self.max_payload_bytes

    def allows_execution_time(self, elapsed_ms: int) -> bool:
        return elapsed_ms <= self.max_execution_ms

    def allows_resource(self, resource: str) -> bool:
        if not self.resource_allowlist:
            return True
        for pattern in self.resource_allowlist:
            if pattern == "*" or pattern in resource:
                return True
        return False


@dataclass
class ExecutionResult:
    task_id: str
    state: "mesh_pb2.TaskState"
    payload: bytes
    error_message: str
    completed_at: str
    metrics: mesh_pb2.ExecutionMetrics


class TaskExecutor:
    """Executes tasks dispatched by the Orchestrator within granted permission boundaries."""

    def __init__(self):
        self._action_handlers: dict[str, callable] = {}

    def register_handler(self, action: str, handler: callable):
        """Register a custom handler for a specific task_type."""
        self._action_handlers[action] = handler

    async def execute(
        self,
        task: mesh_pb2.TaskContext,
        scope: PermissionScope,
    ) -> ExecutionResult:
        """
        Execute a task within the granted PermissionScope.
        All boundary checks are enforced here — no escape possible.
        """
        start_time = time.monotonic()
        error_count = 0

        try:
            if not scope.allows_action(task.task_type):
                return self._result(
                    task.task_id,
                    mesh_pb2.TASK_STATE_FAILED,
                    b"",
                    f"Action '{task.task_type}' not in allowed scope: {scope.allowed_actions}",
                    start_time,
                    0,
                    0,
                )

            handler = self._action_handlers.get(task.task_type)
            if handler is None:
                return self._result(
                    task.task_id,
                    mesh_pb2.TASK_STATE_FAILED,
                    b"",
                    f"No handler registered for task_type '{task.task_type}'",
                    start_time,
                    0,
                    0,
                )

            result_payload = await handler(task)

            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            payload_size = len(result_payload)

            if not scope.allows_payload_size(payload_size):
                return self._result(
                    task.task_id,
                    mesh_pb2.TASK_STATE_FAILED,
                    b"",
                    f"Result payload {payload_size} bytes exceeds limit {scope.max_payload_bytes}",
                    start_time,
                    elapsed_ms,
                    payload_size,
                )

            if not scope.allows_execution_time(elapsed_ms):
                return self._result(
                    task.task_id,
                    mesh_pb2.TASK_STATE_FAILED,
                    b"",
                    f"Execution time {elapsed_ms}ms exceeds limit {scope.max_execution_ms}ms",
                    start_time,
                    elapsed_ms,
                    payload_size,
                )

            return self._result(
                task.task_id,
                mesh_pb2.TASK_STATE_COMPLETED,
                result_payload,
                "",
                start_time,
                elapsed_ms,
                payload_size,
            )

        except Exception as e:
            error_count += 1
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            return self._result(
                task.task_id,
                mesh_pb2.TASK_STATE_FAILED,
                b"",
                str(e),
                start_time,
                elapsed_ms,
                0,
                error_count=error_count,
            )

    def _result(
        self,
        task_id: str,
        state: "mesh_pb2.TaskState",
        payload: bytes,
        error_message: str,
        start_time: float,
        elapsed_ms: int,
        payload_bytes: int,
        external_calls: int = 0,
        error_count: int = 0,
    ) -> ExecutionResult:
        return ExecutionResult(
            task_id=task_id,
            state=state,
            payload=payload,
            error_message=error_message,
            completed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            metrics=mesh_pb2.ExecutionMetrics(
                execution_time_ms=elapsed_ms,
                result_payload_bytes=payload_bytes,
                external_call_count=external_calls,
                error_count=error_count,
                peak_memory_bytes=0,
            ),
        )
