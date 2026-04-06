"""Anthropic API client -- direct HTTP to /v1/messages, no SDK required."""

from __future__ import annotations
import sys

try:
    import requests
except ImportError:
    requests = None  # type: ignore

from emulator.llm_provider import BaseLLMClient

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"


class AnthropicError(Exception):
    pass


class AnthropicClient(BaseLLMClient):
    provider = "anthropic"

    def __init__(self, model: str, api_key: str, timeout: int = 60) -> None:
        self.model = model
        self._api_key = api_key
        self._timeout = timeout
        self._headers = {
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }

    def generate(self, prompt: str, temperature: float = 0.7, max_tokens: int = 200) -> str:
        if requests is None:
            raise AnthropicError("requests library not installed")
        try:
            resp = requests.post(
                ANTHROPIC_API_URL,
                headers=self._headers,
                json={
                    "model": self.model,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=self._timeout,
            )
            resp.raise_for_status()
            content = resp.json().get("content", [])
            return "".join(c.get("text", "") for c in content if c.get("type") == "text")
        except requests.exceptions.Timeout:
            raise AnthropicError(f"Anthropic timeout after {self._timeout}s")
        except requests.exceptions.HTTPError as exc:
            body = exc.response.text[:300] if exc.response else str(exc)
            raise AnthropicError(f"Anthropic HTTP {exc.response.status_code}: {body}") from exc
        except Exception as exc:
            raise AnthropicError(str(exc)) from exc

    def is_available(self) -> bool:
        if requests is None or not self._api_key:
            return False
        # Lightweight check: list models endpoint
        try:
            resp = requests.get(
                "https://api.anthropic.com/v1/models",
                headers=self._headers,
                timeout=10,
            )
            return resp.status_code == 200
        except Exception:
            return False
