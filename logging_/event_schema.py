"""AgentEvent -- single NDJSON schema for all emulated events.

Field groups:
  Identity      -- who/what the agent is
  Pipeline      -- where in the workflow and current state
  Attack        -- MITRE ATLAS mapping and threat metadata
  Payload       -- prompt, response, tool interaction
  Data Transit  -- classification and flow of data moving between components
  Data At Rest  -- what gets stored and where
  Flags         -- boolean anomaly/malicious markers
"""

from __future__ import annotations
import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_epoch() -> float:
    return time.time()


@dataclass
class AgentEvent:
    # ── Identity ──────────────────────────────────────────────────────────
    timestamp: str
    epoch: float
    session_id: str
    agent_id: str
    agent_role: str          # e.g. customer_service_rep, soc_analyst
    agent_trust_level: str   # low | medium | high | privileged
    workflow_id: str

    # ── Pipeline State ────────────────────────────────────────────────────
    event_type: str
    step_number: int
    total_steps: int
    pipeline_stage: str      # e.g. intake, lookup, analysis, decision, action
    pipeline_status: str     # running | completed | hijacked | anomalous

    # ── Attack / MITRE ATLAS ──────────────────────────────────────────────
    attack_type: str
    mitre_atlas_technique: str
    severity: str
    bypasses_controls: list   # controls the attack bypasses e.g. ["human_approval"]

    # ── Payload ───────────────────────────────────────────────────────────
    prompt: str
    response: str
    tool_name: str
    tool_args: dict
    tool_result: str

    # ── Data in Transit ───────────────────────────────────────────────────
    data_classification: str   # public | internal | confidential | restricted
    data_source: str           # crm_api | news_feed | resume_parser | siem_api ...
    data_destination: str      # agent_context | tool_api | user | external
    contains_pii: bool
    contains_credentials: bool
    transit_encrypted: bool

    # ── Data at Rest ──────────────────────────────────────────────────────
    data_stored: bool
    storage_type: str          # agent_context | external_db | log | none

    # ── Guardrail ─────────────────────────────────────────────────────────
    guardrail_verdict: str    # safe | unsafe | skipped
    guardrail_blocked: bool
    guardrail_reason: str
    guardrail_category: str   # e.g. S13:prompt_injection | keyword_match | ""
    guardrail_method: str     # heuristic | llamaguard | none
    guardrail_model: str      # llama-guard3:1b | regex | none

    # ── Flags ─────────────────────────────────────────────────────────────
    is_malicious: bool
    is_anomalous: bool

    # ── Extra (flattened into top-level on serialisation) ─────────────────
    extra: dict = field(default_factory=dict)

    @classmethod
    def make(
        cls,
        session_id: str,
        agent_id: str,
        workflow_id: str,
        event_type: str,
        # identity
        agent_role: str = "",
        agent_trust_level: str = "medium",
        # pipeline
        step_number: int = 0,
        total_steps: int = 0,
        pipeline_stage: str = "",
        pipeline_status: str = "running",
        # attack
        attack_type: str = "",
        mitre_atlas_technique: str = "",
        severity: str = "none",
        bypasses_controls: list | None = None,
        # payload
        prompt: str = "",
        response: str = "",
        tool_name: str = "",
        tool_args: dict | None = None,
        tool_result: str = "",
        # data in transit
        data_classification: str = "",
        data_source: str = "",
        data_destination: str = "",
        contains_pii: bool = False,
        contains_credentials: bool = False,
        transit_encrypted: bool = False,
        # data at rest
        data_stored: bool = False,
        storage_type: str = "none",
        # guardrail
        guardrail_verdict: str = "skipped",
        guardrail_blocked: bool = False,
        guardrail_reason: str = "",
        guardrail_category: str = "",
        guardrail_method: str = "none",
        guardrail_model: str = "none",
        # flags
        is_malicious: bool = False,
        is_anomalous: bool = False,
        extra: dict | None = None,
    ) -> "AgentEvent":
        return cls(
            timestamp=_now_iso(),
            epoch=_now_epoch(),
            session_id=session_id,
            agent_id=agent_id,
            agent_role=agent_role,
            agent_trust_level=agent_trust_level,
            workflow_id=workflow_id,
            event_type=event_type,
            step_number=step_number,
            total_steps=total_steps,
            pipeline_stage=pipeline_stage,
            pipeline_status=pipeline_status,
            attack_type=attack_type,
            mitre_atlas_technique=mitre_atlas_technique,
            severity=severity,
            bypasses_controls=bypasses_controls or [],
            prompt=prompt,
            response=response,
            tool_name=tool_name,
            tool_args=tool_args or {},
            tool_result=tool_result,
            data_classification=data_classification,
            data_source=data_source,
            data_destination=data_destination,
            contains_pii=contains_pii,
            contains_credentials=contains_credentials,
            transit_encrypted=transit_encrypted,
            data_stored=data_stored,
            storage_type=storage_type,
            guardrail_verdict=guardrail_verdict,
            guardrail_blocked=guardrail_blocked,
            guardrail_reason=guardrail_reason,
            guardrail_category=guardrail_category,
            guardrail_method=guardrail_method,
            guardrail_model=guardrail_model,
            is_malicious=is_malicious,
            is_anomalous=is_anomalous,
            extra=extra or {},
        )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        extra = d.pop("extra", {})
        d.update(extra)
        return d

    def to_ndjson_line(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    def to_hec_payload(self, index: str, sourcetype: str) -> str:
        return json.dumps({
            "time": self.epoch,
            "index": index,
            "sourcetype": sourcetype,
            "event": self.to_dict(),
        }, ensure_ascii=False)
