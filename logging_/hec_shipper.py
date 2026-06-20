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
        batch = list(self._batch)
        self._batch.clear()
        if self._post_batch(batch):
            self._sent += len(batch)
        else:
            self._failed += len(batch)
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
            if resp.status_code in (200, 201):
                return True
            # Splunk returns 400 "invalid-event-number:N" when one event in the
            # batch is malformed/oversized. Fall back to one-by-one so good
            # events still land and only the bad one is dropped.
            if resp.status_code == 400 and "invalid-event-number" in resp.text:
                return self._post_one_by_one(batch)
            print(f"[HEC] WARNING: {resp.status_code} — {resp.text[:200]}", file=sys.stderr)
            return False
        except Exception as exc:
            print(f"[HEC] ERROR: {exc}", file=sys.stderr)
            return False

    def _post_one_by_one(self, batch: list[AgentEvent]) -> bool:
        sent = 0
        for event in batch:
            body = event.to_hec_payload(self._index, self._sourcetype)
            try:
                resp = requests.post(
                    self._url,
                    data=body,
                    headers=self._headers,
                    timeout=10,
                    verify=False,
                )
                if resp.status_code in (200, 201):
                    sent += 1
                else:
                    print(f"[HEC] DROP: {resp.status_code} — {resp.text[:120]}", file=sys.stderr)
            except Exception as exc:
                print(f"[HEC] ERROR (single): {exc}", file=sys.stderr)
        return sent > 0

    @property
    def stats(self) -> dict:
        return {"sent": self._sent, "failed": self._failed, "queued": len(self._batch)}
