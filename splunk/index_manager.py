"""Creates and verifies Splunk indexes via the REST API."""

from __future__ import annotations
import sys

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None  # type: ignore


class IndexManager:
    def __init__(self, rest_url: str, username: str, password: str) -> None:
        self._base = rest_url.rstrip("/")
        self._auth = (username, password)

    def index_exists(self, name: str) -> bool:
        try:
            resp = requests.get(
                f"{self._base}/servicesNS/admin/search/data/indexes/{name}",
                auth=self._auth,
                params={"output_mode": "json"},
                verify=False,
                timeout=10,
            )
            return resp.status_code == 200
        except Exception as exc:
            print(f"[IndexManager] Cannot check index: {exc}", file=sys.stderr)
            return False

    def create_index(self, name: str, max_hot_buckets: int = 10, max_mem_mb: int = 150) -> bool:
        try:
            resp = requests.post(
                f"{self._base}/servicesNS/admin/search/data/indexes",
                auth=self._auth,
                data={
                    "name": name,
                    "maxHotBuckets": str(max_hot_buckets),
                    "maxMemMB": str(max_mem_mb),
                },
                params={"output_mode": "json"},
                verify=False,
                timeout=15,
            )
            if resp.status_code in (200, 201):
                print(f"[IndexManager] Created index '{name}'")
                return True
            print(
                f"[IndexManager] Failed to create index '{name}': {resp.status_code} {resp.text[:300]}",
                file=sys.stderr,
            )
            return False
        except Exception as exc:
            print(f"[IndexManager] Error creating index: {exc}", file=sys.stderr)
            return False

    def ensure_index(self, name: str) -> bool:
        if self.index_exists(name):
            print(f"[IndexManager] Index '{name}' already exists.")
            return True
        print(f"[IndexManager] Index '{name}' not found — creating...")
        return self.create_index(name)

    def verify_hec(self, hec_url: str, token: str) -> bool:
        health_url = hec_url.replace("/services/collector/event", "/services/collector/health")
        try:
            resp = requests.get(
                health_url,
                headers={"Authorization": f"Splunk {token}"},
                verify=False,
                timeout=5,
            )
            return resp.status_code == 200
        except Exception as exc:
            print(f"[IndexManager] HEC health check failed: {exc}", file=sys.stderr)
            return False
