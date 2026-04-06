"""Direct HTTP client for Ollama /api/generate and /api/chat."""

from __future__ import annotations
import sys

try:
    import requests
except ImportError:
    requests = None  # type: ignore

# Canned responses used when --no-ollama flag is set
CANNED_RESPONSES = [
    "I will check the available models now.",
    "I found the following security events in the logs.",
    "Listing all available MCP tools for inspection.",
    "Running a security audit on the provided data.",
    "Generating a status report based on collected information.",
    "Task acknowledged. Proceeding with the next action.",
    "Analysis complete. Results have been summarized.",
    "I have reviewed the tool output and will continue.",
]


class OllamaError(Exception):
    pass


class OllamaClient:
    provider = "ollama"

    def __init__(self, url: str, tags_url: str, model: str, timeout: int = 60) -> None:
        self._url = url
        self._chat_url = url.replace("/api/generate", "/api/chat")
        self._tags_url = tags_url
        self.model = model
        self._timeout = timeout
        self._canned_index = 0

    def generate(self, prompt: str, temperature: float = 0.7, num_predict: int = 200) -> str:
        if requests is None:
            raise OllamaError("requests library not installed")
        try:
            resp = requests.post(
                self._url,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": temperature, "num_predict": num_predict},
                },
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return resp.json().get("response", "")
        except requests.exceptions.Timeout:
            raise OllamaError(f"Ollama timeout after {self._timeout}s")
        except Exception as exc:
            raise OllamaError(str(exc)) from exc

    def chat(self, messages: list[dict], temperature: float = 0.0, num_predict: int = 80) -> str:
        """Send a chat-format request via /api/chat (applies model's tokenizer template).
        Required for models like LlamaGuard that expect a specific chat template."""
        if requests is None:
            raise OllamaError("requests library not installed")
        try:
            resp = requests.post(
                self._chat_url,
                json={
                    "model": self.model,
                    "messages": messages,
                    "stream": False,
                    "options": {"temperature": temperature, "num_predict": num_predict},
                },
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return resp.json().get("message", {}).get("content", "")
        except requests.exceptions.Timeout:
            raise OllamaError(f"Ollama timeout after {self._timeout}s")
        except Exception as exc:
            raise OllamaError(str(exc)) from exc

    def generate_canned(self, _prompt: str = "") -> str:
        """Return a canned response without hitting Ollama (for --no-ollama mode)."""
        resp = CANNED_RESPONSES[self._canned_index % len(CANNED_RESPONSES)]
        self._canned_index += 1
        return resp

    def is_available(self) -> bool:
        if requests is None:
            return False
        try:
            resp = requests.get(self._tags_url, timeout=5)
            if resp.status_code != 200:
                return False
            models = [m.get("name", "") for m in resp.json().get("models", [])]
            return self.model in models
        except Exception:
            return False
