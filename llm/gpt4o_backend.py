"""
OpenAI GPT-4o backend — fallback for incident report generation.

Uses the official openai SDK. Requires OPENAI_API_KEY env var.
"""

from __future__ import annotations

import os
import time
import logging
from typing import Optional

from llm.backend import LLMResponse

logger = logging.getLogger(__name__)


class GPT4oBackend:
    """GPT-4o backend using OpenAI Python SDK."""

    provider_name = "gpt4o"

    def __init__(
        self,
        api_key_env: str = "OPENAI_API_KEY",
        model: str = "gpt-4o",
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
            from openai import AsyncOpenAI
        except ImportError:
            raise RuntimeError(
                "openai package not installed. Install with: pip install openai"
            )

        if self._client is None:
            self._client = AsyncOpenAI(
                api_key=api_key,
                timeout=self.timeout_seconds,
            )

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        kwargs = {
            "model": self.model,
            "messages": messages,
            "max_tokens": min(max_tokens, self.max_tokens),
            "temperature": temperature,
        }

        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        start = time.perf_counter()
        response = await self._client.chat.completions.create(**kwargs)
        elapsed = (time.perf_counter() - start) * 1000

        text = response.choices[0].message.content or ""

        return LLMResponse(
            text=text,
            model=self.model,
            provider=self.provider_name,
            tokens_used=response.usage.total_tokens or 0,
            latency_ms=elapsed,
        )
