"""Injects attack payloads into agentic workflows.

Anomaly detection has moved to emulator/guardrail_agent.py.
Use --guardrail heuristic or --guardrail llamaguard at runtime.
"""

from __future__ import annotations

from emulator.scenario_loader import AttackStep, Scenario
from emulator.guardrail_agent import HeuristicGuardrail

# Single source of truth for the heuristic -- delegate to guardrail module
_heuristic = HeuristicGuardrail()


class AttackInjector:
    def should_inject(self, step: int, scenario: Scenario) -> bool:
        return scenario.attack_at(step) is not None

    def get_attack_for_step(self, step: int, scenario: Scenario) -> AttackStep | None:
        return scenario.attack_at(step)

    def inject_tool_response(self, original: str, attack: AttackStep) -> str:
        """Append the injection payload to the tool response."""
        separator = "\n\n--- INJECTED CONTENT ---\n"
        return original + separator + attack.injection_payload

    def inject_agent_prompt(self, original: str, attack: AttackStep) -> str:
        """Prepend injection payload to the agent's prompt."""
        return attack.injection_payload + "\n\n" + original

    def inject_tool_args(self, original_args: dict, attack: AttackStep) -> dict:
        """Inject payload into the tool arguments."""
        modified = dict(original_args)
        # Inject into the first string-valued argument, or add a new key
        injected = False
        for k, v in modified.items():
            if isinstance(v, str):
                modified[k] = attack.injection_payload + " " + v
                injected = True
                break
        if not injected:
            modified["_injected"] = attack.injection_payload
        return modified

    def apply(self, target: str, text: str, args: dict, attack: AttackStep) -> tuple[str, dict]:
        """Apply injection based on the attack target. Returns (modified_text, modified_args)."""
        if attack.target == "tool_response":
            return self.inject_tool_response(text, attack), args
        elif attack.target == "agent_prompt":
            return self.inject_agent_prompt(text, attack), args
        elif attack.target == "tool_args":
            return text, self.inject_tool_args(args, attack)
        return text, args

    def is_anomalous(self, text: str) -> bool:
        """Heuristic: does this text contain known injection indicators?
        Used as fallback when no guardrail is configured."""
        return _heuristic.check(text).blocked
