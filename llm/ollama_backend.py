"""
Local Ollama backend — Phi-3-mini for human-intent → Protobuf translation.

Runs entirely locally. No API costs. Primary translator backend.
"""

from __future__ import annotations

import os
import json
import time
import logging
from typing import Optional

from llm.backend import LLMResponse

logger = logging.getLogger(__name__)


class OllamaBackend:
    """Local Ollama backend for LLM inference."""

    provider_name = "ollama"

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "phi3:mini",
        max_tokens: int = 1024,
        timeout_seconds: float = 30.0,
    ):
        self.base_url = base_url
        self.model = model
        self.max_tokens = max_tokens
        self.timeout_seconds = timeout_seconds

    async def generate(
        self,
        prompt: str,
        system_prompt: str = "",
        max_tokens: int = 1024,
        temperature: float = 0.3,
        json_mode: bool = False,
    ) -> LLMResponse:
        try:
            import ollama
        except ImportError:
            raise RuntimeError(
                "ollama package not installed. Install with: pip install ollama"
            )

        client = ollama.AsyncClient(host=self.base_url)

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        start = time.perf_counter()

        try:
            response = await client.chat(
                model=self.model,
                messages=messages,
                options={
                    "temperature": temperature,
                    "num_predict": min(max_tokens, self.max_tokens),
                },
                stream=False,
            )
        except Exception as e:
            raise RuntimeError(
                f"Ollama request failed (is Ollama running at {self.base_url}?): {e}"
            )

        elapsed = (time.perf_counter() - start) * 1000
        text = response.get("message", {}).get("content", "")

        tokens = response.get("eval_count", 0) + response.get("prompt_eval_count", 0)

        return LLMResponse(
            text=text,
            model=self.model,
            provider=self.provider_name,
            tokens_used=tokens,
            latency_ms=elapsed,
        )

    async def health_check(self) -> bool:
        """Check if Ollama server is reachable."""
        try:
            import ollama
        except ImportError:
            return False

        try:
            client = ollama.AsyncClient(host=self.base_url)
            await client.list()
            return True
        except Exception:
            return False
