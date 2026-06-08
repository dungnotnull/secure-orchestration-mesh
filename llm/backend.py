"""
Abstract LLM backend interface with provider chain fallback.

All LLM-dependent features go through this interface.
The LLM layer is intentionally isolated from the security-critical path.
"""

from __future__ import annotations

import os
import logging
from abc import ABC, abstractmethod
from typing import Optional, Protocol, runtime_checkable
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    text: str
    model: str
    provider: str
    tokens_used: int = 0
    latency_ms: float = 0.0


@runtime_checkable
class LLMBackend(Protocol):
    """Protocol that all LLM backends must implement."""

    provider_name: str

    async def generate(
        self,
        prompt: str,
        system_prompt: str = "",
        max_tokens: int = 1024,
        temperature: float = 0.3,
        json_mode: bool = False,
    ) -> LLMResponse: ...


class LLMProvider:
    """
    Manages LLM backend selection and fallback chain.
    Fallback order: claude → gpt4o → ollama
    """

    def __init__(self, provider: str = "ollama"):
        self.provider_name = provider
        self._backends: dict[str, LLMBackend] = {}
        self._fallback_chain = ["claude", "gpt4o", "ollama"]

    def register(self, name: str, backend: LLMBackend):
        self._backends[name] = backend
        logger.info("LLM backend registered: %s", name)

    def get(self, name: str = "") -> Optional[LLMBackend]:
        return self._backends.get(name or self.provider_name)

    async def generate(
        self,
        prompt: str,
        system_prompt: str = "",
        max_tokens: int = 1024,
        temperature: float = 0.3,
        json_mode: bool = False,
    ) -> LLMResponse:
        """Try primary provider, fall back through chain on failure."""
        errors: list[str] = []

        primary = self._backends.get(self.provider_name)
        if primary:
            try:
                return await primary.generate(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    json_mode=json_mode,
                )
            except Exception as e:
                errors.append(f"{self.provider_name}: {e}")
                logger.warning("Primary LLM (%s) failed, trying fallbacks", self.provider_name)

        for fallback_name in self._fallback_chain:
            if fallback_name == self.provider_name:
                continue
            backend = self._backends.get(fallback_name)
            if backend is None:
                continue
            try:
                logger.info("Falling back to %s", fallback_name)
                return await backend.generate(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    json_mode=json_mode,
                )
            except Exception as e:
                errors.append(f"{fallback_name}: {e}")

        raise RuntimeError(f"All LLM backends failed: {'; '.join(errors)}")
