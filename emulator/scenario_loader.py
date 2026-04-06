"""Loads and validates YAML attack scenario definitions."""

from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore


# ── Sub-dataclasses ────────────────────────────────────────────────────────────

@dataclass
class AgentIdentity:
    """Who and what the agent is."""
    id: str = "agent-primary"
    role: str = ""
    persona: str = ""
    model: str = "llama3.2:latest"
    trust_level: str = "medium"       # low | medium | high | privileged
    capabilities: list = field(default_factory=list)


@dataclass
class DataProfile:
    """Data classification and sensitivity for this workflow."""
    classification: str = "internal"  # public | internal | confidential | restricted
    contains_pii: bool = False
    contains_credentials: bool = False
    sources: list = field(default_factory=list)
    sensitivity_tags: list = field(default_factory=list)


@dataclass
class AttackStep:
    step: int
    attack_type: str
    mitre_technique: str
    severity: str
    target: str                # tool_response | agent_prompt | tool_args
    injection_payload: str
    description: str = ""
    bypasses_controls: list = field(default_factory=list)
    data_exfiltration_target: str = ""


@dataclass
class Scenario:
    name: str
    description: str
    mitre_atlas_technique: str
    agent_goal: str
    total_steps: int
    tools: list
    benign_prompts: list
    attack_steps: list
    agent: AgentIdentity = field(default_factory=AgentIdentity)
    data: DataProfile = field(default_factory=DataProfile)
    pipeline_stages: dict = field(default_factory=dict)   # {step_int: stage_name}
    tool_data_sources: dict = field(default_factory=dict) # {tool_name: source_system}
    tags: list = field(default_factory=list)

    def attack_at(self, step: int) -> AttackStep | None:
        for a in self.attack_steps:
            if a.step == step:
                return a
        return None

    def stage_at(self, step: int) -> str:
        return self.pipeline_stages.get(step, self.pipeline_stages.get(str(step), "processing"))

    def source_for_tool(self, tool_name: str) -> str:
        return self.tool_data_sources.get(tool_name, tool_name)


# ── Loader ─────────────────────────────────────────────────────────────────────

class ScenarioLoader:
    def load(self, yaml_path: str) -> Scenario:
        if yaml is None:
            raise ImportError("pyyaml is required: pip install pyyaml")

        with open(yaml_path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)

        name = raw.get("name", Path(yaml_path).stem)
        total_steps = int(raw.get("total_steps", 5))

        # Pad/trim benign_prompts to exactly total_steps
        prompts = raw.get("benign_prompts", [])
        prompts += ["Continue the agentic workflow."] * max(0, total_steps - len(prompts))
        prompts = prompts[:total_steps]

        # Agent identity block
        a_raw = raw.get("agent", {})
        agent = AgentIdentity(
            id=a_raw.get("id", "agent-primary"),
            role=a_raw.get("role", ""),
            persona=a_raw.get("persona", ""),
            model=a_raw.get("model", "llama3.2:latest"),
            trust_level=a_raw.get("trust_level", "medium"),
            capabilities=a_raw.get("capabilities", []),
        )

        # Data profile block
        d_raw = raw.get("data", {})
        data = DataProfile(
            classification=d_raw.get("classification", "internal"),
            contains_pii=bool(d_raw.get("contains_pii", False)),
            contains_credentials=bool(d_raw.get("contains_credentials", False)),
            sources=d_raw.get("sources", []),
            sensitivity_tags=d_raw.get("sensitivity_tags", []),
        )

        # Pipeline stages (keys may be int or str in YAML)
        pipeline_stages = {
            int(k): str(v)
            for k, v in raw.get("pipeline_stages", {}).items()
        }

        # Tool -> data source mapping
        tool_data_sources = raw.get("tool_data_sources", {})

        # Attack steps
        attack_steps = [
            AttackStep(
                step=int(a["step"]),
                attack_type=a.get("attack_type", "unknown"),
                mitre_technique=a.get("mitre_technique", ""),
                severity=a.get("severity", "medium"),
                target=a.get("target", "tool_response"),
                injection_payload=str(a.get("injection_payload", "")),
                description=a.get("description", ""),
                bypasses_controls=a.get("bypasses_controls", []),
                data_exfiltration_target=a.get("data_exfiltration_target", ""),
            )
            for a in raw.get("attack_steps", [])
        ]

        return Scenario(
            name=name,
            description=raw.get("description", ""),
            mitre_atlas_technique=raw.get("mitre_atlas_technique", ""),
            agent_goal=raw.get("agent_goal", ""),
            total_steps=total_steps,
            tools=raw.get("tools", ["chat", "list_models"]),
            benign_prompts=prompts,
            attack_steps=attack_steps,
            agent=agent,
            data=data,
            pipeline_stages=pipeline_stages,
            tool_data_sources=tool_data_sources,
            tags=raw.get("tags", []),
        )

    def load_all(self, scenarios_dir: str) -> list[Scenario]:
        scenarios = []
        for entry in sorted(Path(scenarios_dir).glob("*.yaml")):
            if entry.stem.startswith("_") or entry.stem == "TEMPLATE":
                continue
            try:
                scenarios.append(self.load(str(entry)))
            except Exception as exc:
                print(f"[ScenarioLoader] Skipping {entry.name}: {exc}")
        return scenarios
