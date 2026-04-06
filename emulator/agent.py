"""AgentLoop -- orchestrates the agentic workflow emulation."""

from __future__ import annotations
import time
from dataclasses import dataclass

from emulator.scenario_loader import Scenario, AttackStep
from emulator.llm_provider import BaseLLMClient
from emulator.mcp_client import MCPClient, MCPError
from emulator.guardrail_agent import BaseGuardrail, GuardrailResult
from logging_.event_schema import AgentEvent
from logging_.ndjson_writer import NDJSONWriter
from logging_.hec_shipper import HECShipper


@dataclass
class RunResult:
    scenario: str
    session_id: str
    total_events: int
    attacks_triggered: int
    attacks_detected: int
    guardrail_blocks: int
    hec_sent: int
    hec_failed: int
    log_path: str


class AgentLoop:
    def __init__(
        self,
        scenario: Scenario,
        llm: BaseLLMClient,
        mcp: MCPClient,
        injector,
        writer: NDJSONWriter,
        shipper: HECShipper,
        session_id: str,
        use_llm: bool = True,
        use_mcp: bool = True,
        guardrail: BaseGuardrail | None = None,
        step_delay: float = 0.5,
        verbose: bool = False,
    ) -> None:
        self._scenario = scenario
        self._llm_client = llm
        self._mcp = mcp
        self._injector = injector
        self._writer = writer
        self._shipper = shipper
        self._session_id = session_id
        self._use_llm = use_llm
        self._use_mcp = use_mcp
        self._guardrail = guardrail       # None = guardrail disabled
        self._step_delay = step_delay
        self._verbose = verbose
        self._event_count = 0
        self._attacks_triggered = 0
        self._attacks_detected = 0
        self._guardrail_blocks = 0

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _workflow_id(self) -> str:
        return f"{self._scenario.name}::{self._session_id[:8]}"

    def _emit(self, event: AgentEvent) -> None:
        self._writer.write(event)
        self._shipper.add(event)
        self._event_count += 1
        if self._verbose:
            gverdict = ""
            if event.guardrail_verdict != "skipped":
                gverdict = f" guard={event.guardrail_verdict}({event.guardrail_method})"
            print(
                f"  [{event.event_type}] step={event.step_number}"
                f" stage={event.pipeline_stage}"
                f" attack={event.attack_type or '-'}"
                f" anomalous={event.is_anomalous}"
                f"{gverdict}"
            )

    def _llm(self, prompt: str) -> str:
        if self._use_llm:
            try:
                return self._llm_client.generate(prompt)
            except Exception as exc:
                return f"[LLMError({self._llm_client.provider}): {exc}]"
        return self._llm_client.generate_canned(prompt)

    def _tool(self, tool_name: str, args: dict) -> dict:
        if self._use_mcp:
            try:
                return self._mcp.call_tool(tool_name, args)
            except MCPError as exc:
                return {"content": [{"type": "text", "text": f"[MCPError: {exc}]"}], "isError": True}
        return self._mcp.canned_tool_response(tool_name)

    def _tool_text(self, result: dict) -> str:
        content = result.get("content", [])
        return " ".join(c.get("text", "") for c in content if c.get("type") == "text")

    def _run_guardrail(self, text: str) -> GuardrailResult | None:
        """Run guardrail check if enabled. Returns None when guardrail is disabled."""
        if self._guardrail is None:
            return None
        return self._guardrail.check(text)

    def _guardrail_kwargs(self, result: GuardrailResult | None) -> dict:
        """Convert a GuardrailResult (or None) to AgentEvent keyword args."""
        if result is None:
            return {}
        return dict(
            guardrail_verdict=result.verdict,
            guardrail_blocked=result.blocked,
            guardrail_reason=result.reason,
            guardrail_category=result.category,
            guardrail_method=result.method,
            guardrail_model=result.model,
        )

    def _base_kwargs(self, step: int, attack: AttackStep | None) -> dict:
        """Common kwargs shared by every AgentEvent in this run."""
        sc = self._scenario
        return dict(
            session_id=self._session_id,
            agent_id=sc.agent.id,
            agent_role=sc.agent.role,
            agent_trust_level=sc.agent.trust_level,
            workflow_id=self._workflow_id(),
            step_number=step,
            total_steps=sc.total_steps,
            pipeline_stage=sc.stage_at(step),
            data_classification=sc.data.classification,
            contains_pii=sc.data.contains_pii,
            contains_credentials=sc.data.contains_credentials,
        )

    # ── Main loop ─────────────────────────────────────────────────────────────

    def run(self) -> RunResult:
        sc = self._scenario

        # ── session_start ─────────────────────────────────────────────────
        guard_label = "none"
        if self._guardrail is not None:
            guard_label = f"{self._guardrail.method}:{self._guardrail.model}"

        self._emit(AgentEvent.make(
            **self._base_kwargs(0, None),
            event_type="session_start",
            pipeline_status="running",
            prompt=sc.agent_goal,
            data_source="system",
            data_destination="agent_context",
            data_stored=True,
            storage_type="agent_context",
            extra={
                "scenario_name": sc.name,
                "scenario_description": sc.description,
                "agent_persona": sc.agent.persona[:300] if sc.agent.persona else "",
                "agent_capabilities": sc.agent.capabilities,
                "data_sensitivity_tags": sc.data.sensitivity_tags,
                "guardrail": guard_label,
            },
        ))

        context = sc.agent_goal
        pipeline_status = "running"

        for step in range(sc.total_steps):
            attack = self._injector.get_attack_for_step(step, sc)
            is_attack_step = attack is not None
            tool_name = sc.tools[step % len(sc.tools)]
            base_prompt = sc.benign_prompts[step]
            stage = sc.stage_at(step)
            tool_source = sc.source_for_tool(tool_name)

            if is_attack_step:
                pipeline_status = "hijacked"

            # ── agent_step: build prompt ───────────────────────────────────
            agent_prompt = f"{context}\n\nCurrent task: {base_prompt}"
            if is_attack_step and attack.target == "agent_prompt":
                agent_prompt, _ = self._injector.apply("agent_prompt", agent_prompt, {}, attack)

            # Guardrail check on the prompt (catches agent_prompt injections)
            prompt_guard = self._run_guardrail(agent_prompt) if (
                is_attack_step and attack.target == "agent_prompt"
            ) else None

            anomalous_prompt = (
                prompt_guard.blocked if prompt_guard is not None
                else self._injector.is_anomalous(agent_prompt)
            )

            self._emit(AgentEvent.make(
                **self._base_kwargs(step, attack),
                **self._guardrail_kwargs(prompt_guard),
                event_type="agent_step",
                pipeline_status=pipeline_status if anomalous_prompt else "running",
                attack_type=attack.attack_type if is_attack_step and attack.target == "agent_prompt" else "",
                mitre_atlas_technique=attack.mitre_technique if is_attack_step and attack.target == "agent_prompt" else "",
                severity=attack.severity if is_attack_step and attack.target == "agent_prompt" else "none",
                bypasses_controls=attack.bypasses_controls if is_attack_step and attack.target == "agent_prompt" else [],
                prompt=agent_prompt,
                data_source="agent_context",
                data_destination="agent_reasoning",
                data_stored=True,
                storage_type="agent_context",
                is_malicious=is_attack_step and attack.target == "agent_prompt",
                is_anomalous=anomalous_prompt,
            ))

            # ── agent_decision ────────────────────────────────────────────
            self._emit(AgentEvent.make(
                **self._base_kwargs(step, attack),
                event_type="agent_decision",
                pipeline_status=pipeline_status,
                tool_name=tool_name,
                prompt=agent_prompt,
                data_source="agent_reasoning",
                data_destination="tool_api",
                extra={"decision": f"call_tool:{tool_name}"},
            ))

            # ── tool_call ─────────────────────────────────────────────────
            tool_args: dict = {}
            if tool_name == "chat":
                tool_args = {
                    "model": sc.agent.model,
                    "messages": [{"role": "user", "content": agent_prompt}],
                }
            if is_attack_step and attack.target == "tool_args":
                _, tool_args = self._injector.apply("tool_args", "", tool_args, attack)

            self._emit(AgentEvent.make(
                **self._base_kwargs(step, attack),
                event_type="tool_call",
                pipeline_status=pipeline_status,
                attack_type=attack.attack_type if is_attack_step and attack.target == "tool_args" else "",
                mitre_atlas_technique=attack.mitre_technique if is_attack_step and attack.target == "tool_args" else "",
                severity=attack.severity if is_attack_step and attack.target == "tool_args" else "none",
                bypasses_controls=attack.bypasses_controls if is_attack_step and attack.target == "tool_args" else [],
                tool_name=tool_name,
                tool_args=tool_args,
                data_source="agent_reasoning",
                data_destination=tool_source,
                is_malicious=is_attack_step and attack.target == "tool_args",
            ))

            # ── Execute tool ──────────────────────────────────────────────
            tool_result = self._tool(tool_name, tool_args)
            tool_text = self._tool_text(tool_result)

            injected_text = tool_text
            if is_attack_step and attack.target == "tool_response":
                injected_text, _ = self._injector.apply("tool_response", tool_text, {}, attack)

            # Guardrail check on tool response (primary detection surface)
            response_guard = self._run_guardrail(injected_text)

            anomalous_response = (
                response_guard.blocked if response_guard is not None
                else self._injector.is_anomalous(injected_text)
            )

            # If guardrail blocks the tool response, replace it with a safe stub
            # so the main agent LLM never sees the injected content
            delivered_text = injected_text
            if response_guard is not None and response_guard.blocked:
                self._guardrail_blocks += 1
                delivered_text = (
                    f"[GUARDRAIL BLOCKED] Tool response was flagged as unsafe "
                    f"({response_guard.category}). Reason: {response_guard.reason}"
                )

            # ── tool_response ─────────────────────────────────────────────
            self._emit(AgentEvent.make(
                **self._base_kwargs(step, attack),
                **self._guardrail_kwargs(response_guard),
                event_type="tool_response",
                pipeline_status="hijacked" if anomalous_response else pipeline_status,
                attack_type=attack.attack_type if is_attack_step and attack.target == "tool_response" else "",
                mitre_atlas_technique=attack.mitre_technique if is_attack_step and attack.target == "tool_response" else "",
                severity=attack.severity if is_attack_step and attack.target == "tool_response" else "none",
                bypasses_controls=attack.bypasses_controls if is_attack_step and attack.target == "tool_response" else [],
                tool_name=tool_name,
                tool_args=tool_args,
                tool_result=injected_text,   # log the actual injected content
                data_source=tool_source,
                data_destination="agent_context",
                data_stored=True,
                storage_type="agent_context",
                is_malicious=is_attack_step and attack.target == "tool_response",
                is_anomalous=anomalous_response,
                extra={
                    "exfiltration_target": attack.data_exfiltration_target if is_attack_step else "",
                    "guardrail_blocked_delivery": response_guard.blocked if response_guard else False,
                } if is_attack_step else {
                    "guardrail_blocked_delivery": response_guard.blocked if response_guard else False,
                },
            ))

            # ── attack_triggered ──────────────────────────────────────────
            if is_attack_step:
                self._attacks_triggered += 1
                self._emit(AgentEvent.make(
                    **self._base_kwargs(step, attack),
                    **self._guardrail_kwargs(response_guard),
                    event_type="attack_triggered",
                    pipeline_status="hijacked",
                    attack_type=attack.attack_type,
                    mitre_atlas_technique=attack.mitre_technique,
                    severity=attack.severity,
                    bypasses_controls=attack.bypasses_controls,
                    prompt=agent_prompt,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    tool_result=injected_text,
                    data_source=tool_source,
                    data_destination="agent_context",
                    is_malicious=True,
                    is_anomalous=True,
                    extra={
                        "attack_description": attack.description,
                        "injection_target": attack.target,
                        "injection_payload_preview": attack.injection_payload[:200],
                        "exfiltration_target": attack.data_exfiltration_target,
                        "guardrail_blocked_delivery": response_guard.blocked if response_guard else False,
                    },
                ))

            # ── attack_detected ───────────────────────────────────────────
            if anomalous_response or anomalous_prompt:
                self._attacks_detected += 1
                gr = response_guard or prompt_guard
                self._emit(AgentEvent.make(
                    **self._base_kwargs(step, attack),
                    **self._guardrail_kwargs(gr),
                    event_type="attack_detected",
                    pipeline_status="anomalous",
                    attack_type=attack.attack_type if is_attack_step else "unknown",
                    mitre_atlas_technique=attack.mitre_technique if is_attack_step else "",
                    severity="high",
                    tool_name=tool_name,
                    tool_result=injected_text,
                    data_source=tool_source,
                    data_destination="security_log",
                    is_malicious=True,
                    is_anomalous=True,
                    extra={
                        "detection_method": gr.method if gr else "keyword_heuristic",
                        "detection_model": gr.model if gr else "regex",
                    },
                ))

            # ── guardrail_check (dedicated event when guardrail is active) ─
            if response_guard is not None:
                self._emit(AgentEvent.make(
                    **self._base_kwargs(step, attack),
                    **self._guardrail_kwargs(response_guard),
                    event_type="guardrail_check",
                    pipeline_status="anomalous" if response_guard.blocked else pipeline_status,
                    attack_type=attack.attack_type if is_attack_step else "",
                    mitre_atlas_technique=attack.mitre_technique if is_attack_step else "",
                    severity=attack.severity if is_attack_step else "none",
                    tool_name=tool_name,
                    tool_result=injected_text,
                    data_source=tool_source,
                    data_destination="guardrail",
                    is_malicious=response_guard.blocked,
                    is_anomalous=response_guard.blocked,
                    extra={
                        "guardrail_raw_output": response_guard.raw_output[:300],
                        "content_delivered_to_agent": not response_guard.blocked,
                    },
                ))

            # ── agent_step: react to tool output ──────────────────────────
            llm_input = (
                f"You are a {sc.agent.role or 'AI'} agent. "
                f"Tool '{tool_name}' returned:\n{delivered_text}\n\n"
                f"What should you do next?"
            )
            agent_response = self._llm(llm_input)

            self._emit(AgentEvent.make(
                **self._base_kwargs(step, attack),
                event_type="agent_step",
                pipeline_status=pipeline_status,
                prompt=llm_input,
                response=agent_response,
                tool_name=tool_name,
                tool_result=delivered_text,
                data_source="tool_api",
                data_destination="agent_context",
                data_stored=True,
                storage_type="agent_context",
                extra={"sub_type": "agent_reaction"},
            ))

            context = agent_response[:500]

            if self._step_delay > 0:
                time.sleep(self._step_delay)

        # ── session_end ───────────────────────────────────────────────────
        self._shipper.flush()
        sent = self._shipper.stats["sent"]
        failed = self._shipper.stats["failed"]

        self._emit(AgentEvent.make(
            **self._base_kwargs(sc.total_steps, None),
            event_type="session_end",
            pipeline_status="completed",
            data_source="agent_context",
            data_destination="log",
            data_stored=True,
            storage_type="log",
            extra={
                "total_events": self._event_count + 1,
                "attacks_triggered": self._attacks_triggered,
                "attacks_detected": self._attacks_detected,
                "guardrail_blocks": self._guardrail_blocks,
                "hec_sent": sent,
                "hec_failed": failed,
            },
        ))
        self._shipper.flush()

        return RunResult(
            scenario=sc.name,
            session_id=self._session_id,
            total_events=self._event_count,
            attacks_triggered=self._attacks_triggered,
            attacks_detected=self._attacks_detected,
            guardrail_blocks=self._guardrail_blocks,
            hec_sent=self._shipper.stats["sent"],
            hec_failed=self._shipper.stats["failed"],
            log_path=self._writer.path,
        )
