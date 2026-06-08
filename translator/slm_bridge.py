"""
Human-intent → Protobuf translation bridge using Phi-3-mini via Ollama.

This is the ONLY place LLMs interact with the protocol — and even here,
the LLM output is strictly validated against the JSON schema before it
ever touches a protocol packet.

The LLM operates on human-provided natural language ONLY. It NEVER
sees raw agent protocol packets.
"""

from __future__ import annotations

import json
import time
import uuid
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any

from llm.backend import LLMProvider

logger = logging.getLogger(__name__)


# Strict system prompt that constrains LLM output to schema-compliant JSON only
TRANSLATOR_SYSTEM_PROMPT = """You are a task-to-schema translator for a secure multi-agent orchestration system.
Your ONLY job is to parse natural language task descriptions and convert them into
strictly-valid JSON following the TaskRequest schema below.

RULES:
1. Output ONLY valid JSON. No explanatory text, no markdown fences, nothing else.
2. All fields are required unless marked optional.
3. task_type MUST be one of: web_search, file_read, file_write, code_execution, api_call, data_analysis
4. payload is the task body as a string
5. priority is an integer from 1 (highest) to 10 (lowest)
6. max_results is an integer (default: 10)

SCHEMA:
{
  "task_id": "<UUID v7 string>",
  "task_type": "<one of the allowed types>",
  "description": "<brief human-readable summary>",
  "payload": "<task content as string>",
  "priority": <integer 1-10>,
  "max_results": <integer>,
  "deadline_seconds": <integer, 0 = no deadline>,
  "permissions_required": ["<action1>", "<action2>"]
}

USER TASK: """


@dataclass
class TranslatedTask:
    task_id: str
    task_type: str
    description: str
    payload: str
    priority: int
    max_results: int
    deadline_seconds: int
    permissions_required: list[str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TranslatedTask":
        return cls(
            task_id=data.get("task_id", str(uuid.uuid4())),
            task_type=data["task_type"],
            description=data.get("description", ""),
            payload=data.get("payload", ""),
            priority=int(data.get("priority", 5)),
            max_results=int(data.get("max_results", 10)),
            deadline_seconds=int(data.get("deadline_seconds", 0)),
            permissions_required=list(data.get("permissions_required", [])),
        )


class SLMBridge:
    """
    Translates natural language human task descriptions into validated
    Protobuf TaskRequest payloads using a local SLM (Phi-3-mini via Ollama).
    """

    ALLOWED_TASK_TYPES = {
        "web_search", "file_read", "file_write",
        "code_execution", "api_call", "data_analysis",
    }

    def __init__(self, llm_provider: Optional[LLMProvider] = None):
        self._llm = llm_provider or LLMProvider(provider="ollama")

    def register_llm(self, provider: LLMProvider):
        self._llm = provider

    async def translate(self, human_task: str) -> TranslatedTask:
        """
        Convert a natural language task into a validated TranslatedTask.
        Raises ValueError if the LLM output fails schema validation.
        """
        prompt = TRANSLATOR_SYSTEM_PROMPT + human_task

        try:
            response = await self._llm.generate(
                prompt=prompt,
                system_prompt="",
                max_tokens=512,
                temperature=0.1,
                json_mode=False,
            )
        except Exception as e:
            raise RuntimeError(f"SLM translation failed: {e}")

        try:
            data = self._extract_json(response.text)
        except json.JSONDecodeError as e:
            logger.error("SLM returned invalid JSON: %s", response.text[:200])
            raise ValueError(f"SLM output is not valid JSON: {e}")

        task = TranslatedTask.from_dict(data)
        self._validate(task)
        return task

    async def translate_batch(self, tasks: list[str]) -> list[TranslatedTask]:
        """Translate multiple tasks concurrently."""
        import asyncio
        results = await asyncio.gather(
            *[self.translate(t) for t in tasks],
            return_exceptions=True,
        )
        return [r for r in results if not isinstance(r, Exception)]

    def _validate(self, task: TranslatedTask):
        """Validate translated task against allowed schema."""
        if task.task_type not in self.ALLOWED_TASK_TYPES:
            raise ValueError(
                f"Invalid task_type '{task.task_type}'. Allowed: {sorted(self.ALLOWED_TASK_TYPES)}"
            )
        if not (1 <= task.priority <= 10):
            raise ValueError(f"Priority must be 1-10, got {task.priority}")
        if task.max_results < 0:
            raise ValueError(f"max_results must be >= 0, got {task.max_results}")
        if task.deadline_seconds < 0:
            raise ValueError(f"deadline_seconds must be >= 0, got {task.deadline_seconds}")

    def _extract_json(self, text: str) -> dict:
        """Extract JSON from LLM output, handling markdown fences."""
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines)
        return json.loads(text)
