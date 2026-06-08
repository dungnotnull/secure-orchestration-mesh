"""
Anthropic Claude API backend for incident report generation.

Uses the official anthropic SDK. Requires CLAUDE_API_KEY env var.
Not on the security-critical execution path.
"""

from __future__ import annotations

import os
import time
import logging
from typing import Optional

from llm.backend import LLMBackend, LLMResponse

logger = logging.getLogger(__name__)


class ClaudeBackend:
    """Claude API backend using Anthropic Python SDK."""

    provider_name = "claude"

    def __init__(
        self,
        api_key_env: str = "CLAUDE_API_KEY",
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 4096,
        timeout_seconds: float = 60.0,
    ):
        self.api_key_env = api_key_env
        self.model = model
        self.max_tokens = max_tokens
        self.timeout_seconds = timeout_seconds
        self._client = None

    async def generate(
        self,
        prompt: str,
        system_prompt: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.3,
        json_mode: bool = False,
    ) -> LLMResponse:
        api_key = os.getenv(self.api_key_env)
        if not api_key:
            raise RuntimeError(f"Environment variable {self.api_key_env} is not set")

        try:
            import anthropic
        except ImportError:
            raise RuntimeError(
                "anthropic package not installed. Install with: pip install anthropic"
            )

        if self._client is None:
            self._client = anthropic.AsyncAnthropic(
                api_key=api_key,
                timeout=self.timeout_seconds,
            )

        kwargs = {
            "model": self.model,
            "max_tokens": min(max_tokens, self.max_tokens),
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }

        if system_prompt:
            kwargs["system"] = system_prompt

        start = time.perf_counter()
        response = await self._client.messages.create(**kwargs)
        elapsed = (time.perf_counter() - start) * 1000

        text = response.content[0].text if response.content else ""

        return LLMResponse(
            text=text,
            model=self.model,
            provider=self.provider_name,
            tokens_used=response.usage.input_tokens + response.usage.output_tokens,
            latency_ms=elapsed,
        )
