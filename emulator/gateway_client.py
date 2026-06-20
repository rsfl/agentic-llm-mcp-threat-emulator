"""OpenAI-compatible client for Bifrost and LiteLLM gateways."""

from __future__ import annotations

try:
    import requests
except ImportError:
    requests = None  # type: ignore

from emulator.llm_provider import BaseLLMClient, CANNED_RESPONSES


class GatewayError(Exception):
    pass


class GatewayClient(BaseLLMClient):

    def __init__(
        self,
        url: str,
        api_key: str,
        model: str,
        provider_name: str = "gateway",
        timeout: int = 60,
    ) -> None:
        self._base_url = url.rstrip("/")
        self._completions_url = self._base_url + "/v1/chat/completions"
        self._health_url = self._base_url + "/health"
        self._api_key = api_key
        self.model = model
        self.provider = provider_name
        self._timeout = timeout
        self._canned_index = 0

    def generate(self, prompt: str, temperature: float = 0.7, max_tokens: int = 200) -> str:
        if requests is None:
            raise GatewayError("requests library not installed")
        try:
            resp = requests.post(
                self._completions_url,
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    "stream": False,
                },
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
        except requests.exceptions.Timeout:
            raise GatewayError(f"Gateway timeout after {self._timeout}s")
        except Exception as exc:
            raise GatewayError(str(exc)) from exc

    def is_available(self) -> bool:
        if requests is None:
            return False
        for path in ["/health/liveliness", "/health"]:
            try:
                resp = requests.get(self._base_url + path, timeout=5)
                if resp.status_code == 200:
                    return True
            except Exception:
                pass
        return False

    def generate_canned(self, _prompt: str = "") -> str:
        resp = CANNED_RESPONSES[self._canned_index % len(CANNED_RESPONSES)]
        self._canned_index += 1
        return resp
