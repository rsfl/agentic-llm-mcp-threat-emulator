"""JSON-RPC 2.0 client for the Ollama MCP server at :3456."""

from __future__ import annotations
import sys
from itertools import count

try:
    import requests
except ImportError:
    requests = None  # type: ignore


class MCPError(Exception):
    pass


class MCPClient:
    def __init__(self, base_url: str, timeout: int = 15) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._id_counter = count(1)

    def _rpc(self, method: str, params: dict) -> dict:
        rpc_id = next(self._id_counter)
        payload = {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": method,
            "params": params,
        }
        try:
            resp = requests.post(
                f"{self._base}/",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            raise MCPError(f"MCP RPC failed: {exc}") from exc

        if "error" in data:
            raise MCPError(f"MCP error {data['error'].get('code')}: {data['error'].get('message')}")
        return data.get("result", {})

    def list_tools(self) -> list[dict]:
        result = self._rpc("tools/list", {})
        return result.get("tools", [])

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        result = self._rpc("tools/call", {"name": tool_name, "arguments": arguments})
        return result

    def is_available(self) -> bool:
        if requests is None:
            return False
        try:
            self.list_tools()
            return True
        except Exception:
            return False

    def canned_tool_response(self, tool_name: str) -> dict:
        """Return a synthetic tool response without hitting the MCP server."""
        if tool_name == "list_models":
            return {
                "content": [{"type": "text", "text": '{"models":[{"name":"llama3.2:latest"}]}'}],
                "isError": False,
            }
        return {
            "content": [{"type": "text", "text": f"Tool '{tool_name}' executed successfully."}],
            "isError": False,
        }
