"""
Agent selection, load balancing, and task routing.

Manages the pool of registered agents and dispatches tasks based on
capability matching, agent load, and availability.
"""

from __future__ import annotations

import uuid
import time
import logging
import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from enum import Enum

from proto import mesh_pb2

logger = logging.getLogger(__name__)


class AgentState(Enum):
    REGISTERING = "registering"
    IDLE = "idle"
    BUSY = "busy"
    QUARANTINED = "quarantined"
    OFFLINE = "offline"


@dataclass
class AgentRecord:
    agent_id: str
    label: str
    capabilities: Set[str] = field(default_factory=set)
    state: AgentState = AgentState.REGISTERING
    sdk_version: str = ""
    current_task_id: Optional[str] = None
    registered_at: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)
    tasks_completed: int = 0
    tasks_failed: int = 0
    anomaly_score: float = 0.0
    suspicion_count: int = 0
    session_id: str = ""


class TaskScheduler:
    """Manages agent pool and routes tasks to the best available agent."""

    HEARTBEAT_TIMEOUT_SECONDS = 15
    QUARANTINE_SUSPICION_THRESHOLD = 2

    def __init__(self):
        self._agents: Dict[str, AgentRecord] = {}
        self._task_queue: asyncio.Queue = asyncio.Queue()
        self._lock = asyncio.Lock()

    async def register(self, request: mesh_pb2.AgentRegistrationRequest) -> AgentRecord:
        async with self._lock:
            agent = AgentRecord(
                agent_id=request.agent_id,
                label=request.agent_label,
                capabilities=set(request.capabilities),
                state=AgentState.IDLE,
                sdk_version=request.sdk_version,
            )
            self._agents[request.agent_id] = agent
            logger.info(
                "Agent registered: %s (%s) — capabilities: %s",
                agent.agent_id,
                agent.label,
                agent.capabilities,
            )
            return agent

    async def unregister(self, agent_id: str):
        async with self._lock:
            self._agents.pop(agent_id, None)
            logger.info("Agent unregistered: %s", agent_id)

    async def heartbeat(self, agent_id: str, status: mesh_pb2.AgentStatus):
        async with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                return
            agent.last_heartbeat = time.time()
            status_map = {
                mesh_pb2.AGENT_STATUS_IDLE: AgentState.IDLE,
                mesh_pb2.AGENT_STATUS_BUSY: AgentState.BUSY,
                mesh_pb2.AGENT_STATUS_ERROR: AgentState.IDLE,
                mesh_pb2.AGENT_STATUS_QUARANTINED: AgentState.QUARANTINED,
                mesh_pb2.AGENT_STATUS_OFFLINE: AgentState.OFFLINE,
            }
            agent.state = status_map.get(status, AgentState.OFFLINE)

    async def mark_offline_stale(self):
        """Mark agents offline that haven't sent a heartbeat recently."""
        now = time.time()
        async with self._lock:
            for agent in self._agents.values():
                if now - agent.last_heartbeat > self.HEARTBEAT_TIMEOUT_SECONDS:
                    if agent.state not in (AgentState.OFFLINE, AgentState.QUARANTINED):
                        agent.state = AgentState.OFFLINE
                        logger.warning("Agent %s marked offline (no heartbeat)", agent.agent_id)

    async def dispatch(self, task_type: str, payload: bytes) -> Optional[AgentRecord]:
        """
        Find the best idel agent that matches the requested capability.
        Simple round-robin among matching agents.
        """
        async with self._lock:
            candidates = [
                a for a in self._agents.values()
                if a.state == AgentState.IDLE and task_type in a.capabilities
            ]
            if not candidates:
                logger.warning("No idle agent available for task_type=%s", task_type)
                return None

            # Pick the agent with the lowest current load (fewest tasks in flight)
            candidate = min(candidates, key=lambda a: a.tasks_completed - a.tasks_failed)
            candidate.state = AgentState.BUSY
            return candidate

    async def complete_task(self, agent_id: str, success: bool = True):
        async with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                return
            if success:
                agent.tasks_completed += 1
            else:
                agent.tasks_failed += 1
            agent.state = AgentState.IDLE
            agent.current_task_id = None

    async def quarantine(self, agent_id: str, reason: str) -> bool:
        """Quarantine an agent immediately."""
        async with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                return False
            agent.state = AgentState.QUARANTINED
            agent.current_task_id = None
            logger.warning(
                "Agent %s QUARANTINED: %s",
                agent_id,
                reason,
            )
            return True

    async def update_anomaly_score(self, agent_id: str, score: float):
        async with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                return
            agent.anomaly_score = score
            if score > 0.65:
                agent.suspicion_count += 1
                if agent.suspicion_count >= self.QUARANTINE_SUSPICION_THRESHOLD:
                    await self.quarantine(
                        agent_id,
                        f"Auto-quarantine: anomaly score {score:.4f} exceeded threshold "
                        f"for {agent.suspicion_count} consecutive windows",
                    )
            else:
                agent.suspicion_count = max(0, agent.suspicion_count - 1)

    def get_agent(self, agent_id: str) -> Optional[AgentRecord]:
        return self._agents.get(agent_id)

    def get_all_agents(self) -> List[AgentRecord]:
        return list(self._agents.values())

    def get_idle_count(self) -> int:
        return sum(1 for a in self._agents.values() if a.state == AgentState.IDLE)

    def get_busy_count(self) -> int:
        return sum(1 for a in self._agents.values() if a.state == AgentState.BUSY)
