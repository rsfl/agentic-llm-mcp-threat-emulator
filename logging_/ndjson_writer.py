"""Writes AgentEvents to a NDJSON log file."""

from __future__ import annotations
import os
from pathlib import Path

from logging_.event_schema import AgentEvent


class NDJSONWriter:
    def __init__(self, log_dir: str, log_file: str) -> None:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        self._path = os.path.join(log_dir, log_file)
        self._fh = open(self._path, "a", encoding="utf-8")

    @property
    def path(self) -> str:
        return self._path

    def write(self, event: AgentEvent) -> None:
        self._fh.write(event.to_ndjson_line() + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "NDJSONWriter":
        return self

    def __exit__(self, *_) -> None:
        self.close()
