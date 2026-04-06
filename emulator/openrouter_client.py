"""OpenRouter API client -- OpenAI-compatible endpoint, no SDK required.

Free models (append :free to use without billing):
  meta-llama/llama-3.2-3b-instruct:free
  meta-llama/llama-3.1-8b-instruct:free
  mistralai/mistral-7b-instruct:free
  google/gemma-2-9b-it:free
  microsoft/phi-3-mini-128k-instruct:free
  qwen/qwen-2-7b-instruct:free

Full list: https://openrouter.ai/models?q=free
"""

from __future__ import annotations
import sys

try:
    import requests
except ImportError:
    requests = None  # type: ignore

from emulator.llm_provider import BaseLLMClient

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"
APP_REFERER = "https://github.com/rsfl/agentic-llm-mcp-threat-emulator"
APP_TITLE = "Agentic LLM MCP Threat Emulator"


class OpenRouterError(Exception):
    pass


class OpenRouterClient(BaseLLMClient):
    provider = "openrouter"

    def __init__(self, model: str, api_key: str, timeout: int = 60) -> None:
        self.model = model
        self._api_key = api_key
        self._timeout = timeout
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "HTTP-Referer": APP_REFERER,
            "X-Title": APP_TITLE,
            "Content-Type": "application/json",
        }

    def generate(self, prompt: str, temperature: float = 0.7, max_tokens: int = 200) -> str:
        if requests is None:
            raise OpenRouterError("requests library not installed")
        try:
            resp = requests.post(
                OPENROUTER_API_URL,
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
            data = resp.json()
            # Surface provider-level errors (e.g. model unavailable, quota exceeded)
            if "error" in data:
                raise OpenRouterError(
                    f"OpenRouter error {data['error'].get('code')}: {data['error'].get('message')}"
                )
            choices = data.get("choices", [])
            if not choices:
                raise OpenRouterError("OpenRouter returned no choices")
            return choices[0].get("message", {}).get("content", "")
        except requests.exceptions.Timeout:
            raise OpenRouterError(f"OpenRouter timeout after {self._timeout}s")
        except requests.exceptions.HTTPError as exc:
            body = exc.response.text[:300] if exc.response else str(exc)
            raise OpenRouterError(f"OpenRouter HTTP {exc.response.status_code}: {body}") from exc
        except OpenRouterError:
            raise
        except Exception as exc:
            raise OpenRouterError(str(exc)) from exc

    def is_available(self) -> bool:
        if requests is None or not self._api_key:
            return False
        try:
            resp = requests.get(
                OPENROUTER_MODELS_URL,
                headers=self._headers,
                timeout=10,
            )
            if resp.status_code != 200:
                return False
            # Verify the requested model is in the list
            ids = {m.get("id", "") for m in resp.json().get("data", [])}
            return self.model in ids
        except Exception:
            return False

    def list_free_models(self) -> list[str]:
        """Return all currently available free models from OpenRouter."""
        if requests is None:
            return []
        try:
            resp = requests.get(OPENROUTER_MODELS_URL, headers=self._headers, timeout=10)
            resp.raise_for_status()
            return sorted(
                m["id"]
                for m in resp.json().get("data", [])
                if m.get("id", "").endswith(":free")
            )
        except Exception:
            return []
