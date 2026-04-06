"""Ships AgentEvents to Splunk via HTTP Event Collector (HEC)."""

from __future__ import annotations
import sys
from typing import Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None  # type: ignore

from logging_.event_schema import AgentEvent


class HECShipper:
    def __init__(
        self,
        hec_url: str,
        token: str,
        index: str,
        sourcetype: str,
        batch_size: int = 10,
        enabled: bool = True,
    ) -> None:
        self._url = hec_url
        self._headers = {
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
        }
        self._index = index
        self._sourcetype = sourcetype
        self._batch_size = batch_size
        self._enabled = enabled and requests is not None
        self._batch: list[AgentEvent] = []
        self._sent = 0
        self._failed = 0

    def add(self, event: AgentEvent) -> None:
        self._batch.append(event)
        if len(self._batch) >= self._batch_size:
            self.flush()

    def flush(self) -> tuple[int, int]:
        if not self._batch or not self._enabled:
            self._batch.clear()
            return self._sent, self._failed
        if self._post_batch(self._batch):
            self._sent += len(self._batch)
        else:
            self._failed += len(self._batch)
        self._batch.clear()
        return self._sent, self._failed

    def _post_batch(self, batch: list[AgentEvent]) -> bool:
        # HEC raw batching: newline-separated JSON payloads (not a JSON array)
        body = "\n".join(e.to_hec_payload(self._index, self._sourcetype) for e in batch)
        try:
            resp = requests.post(
                self._url,
                data=body,
                headers=self._headers,
                timeout=10,
                verify=False,
            )
            if resp.status_code not in (200, 201):
                print(
                    f"[HEC] WARNING: {resp.status_code} — {resp.text[:200]}",
                    file=sys.stderr,
                )
                return False
            return True
        except Exception as exc:
            print(f"[HEC] ERROR: {exc}", file=sys.stderr)
            return False

    @property
    def stats(self) -> dict:
        return {"sent": self._sent, "failed": self._failed, "queued": len(self._batch)}
