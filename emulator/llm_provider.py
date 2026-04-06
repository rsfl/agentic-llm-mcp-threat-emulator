"""LLM provider abstraction -- factory and base class for all LLM backends."""

from __future__ import annotations
import os

# Canned responses shared across all providers when --no-llm is set
CANNED_RESPONSES = [
    "I will check the available data sources now.",
    "I found the following information in the retrieved content.",
    "Listing all available tools for this workflow.",
    "Running analysis on the provided data.",
    "Generating a status report based on collected information.",
    "Task acknowledged. Proceeding with the next action.",
    "Analysis complete. Results have been summarized.",
    "I have reviewed the tool output and will continue.",
]

# Provider defaults
DEFAULT_MODELS = {
    "ollama":      "llama3.2:latest",
    "anthropic":   "claude-haiku-4-5-20251001",
    "openrouter":  "meta-llama/llama-3.2-3b-instruct:free",
}

OPENROUTER_FREE_MODELS = [
    "meta-llama/llama-3.2-3b-instruct:free",
    "meta-llama/llama-3.1-8b-instruct:free",
    "mistralai/mistral-7b-instruct:free",
    "google/gemma-2-9b-it:free",
    "microsoft/phi-3-mini-128k-instruct:free",
    "qwen/qwen-2-7b-instruct:free",
    "huggingfaceh4/zephyr-7b-beta:free",
]


class BaseLLMClient:
    """Minimal interface every LLM backend must implement."""

    provider: str = "base"
    model: str = ""

    def generate(self, prompt: str, temperature: float = 0.7, max_tokens: int = 200) -> str:
        raise NotImplementedError

    def is_available(self) -> bool:
        return False

    def generate_canned(self, _prompt: str = "") -> str:
        if not hasattr(self, "_canned_index"):
            self._canned_index = 0
        resp = CANNED_RESPONSES[self._canned_index % len(CANNED_RESPONSES)]
        self._canned_index += 1
        return resp


def get_llm_client(
    provider: str,
    model: str | None = None,
    api_key: str | None = None,
    ollama_url: str = "http://localhost:11434",
    timeout: int = 60,
) -> BaseLLMClient:
    """Factory: return the right LLM client for the given provider."""
    provider = provider.lower()

    if provider == "ollama":
        from emulator.ollama_client import OllamaClient
        m = model or DEFAULT_MODELS["ollama"]
        return OllamaClient(
            url=f"{ollama_url}/api/generate",
            tags_url=f"{ollama_url}/api/tags",
            model=m,
            timeout=timeout,
        )

    if provider == "anthropic":
        from emulator.anthropic_client import AnthropicClient
        key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            raise ValueError(
                "Anthropic API key required. Pass --api-key or set ANTHROPIC_API_KEY env var."
            )
        return AnthropicClient(model=model or DEFAULT_MODELS["anthropic"], api_key=key, timeout=timeout)

    if provider == "openrouter":
        from emulator.openrouter_client import OpenRouterClient
        key = api_key or os.environ.get("OPENROUTER_API_KEY", "")
        if not key:
            raise ValueError(
                "OpenRouter API key required. Pass --api-key or set OPENROUTER_API_KEY env var."
            )
        return OpenRouterClient(model=model or DEFAULT_MODELS["openrouter"], api_key=key, timeout=timeout)

    raise ValueError(
        f"Unknown provider '{provider}'. Choose from: ollama, anthropic, openrouter"
    )
