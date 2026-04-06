#!/usr/bin/env python3
"""
Agentic LLM MCP Threat Emulator
CLI entrypoint -- run attack scenarios against local or cloud LLM providers.

Usage:
  python main.py setup
  python main.py list
  python main.py providers
  python main.py run --scenario tool_poisoning
  python main.py run --scenario all --provider anthropic --api-key sk-ant-...
  python main.py run --scenario customer_service_agent --provider openrouter --model mistralai/mistral-7b-instruct:free
  python main.py run --scenario all --no-llm --no-splunk
"""

from __future__ import annotations
import os
import sys
import uuid
import time

try:
    import click
except ImportError:
    sys.exit("ERROR: 'click' not installed. Run: pip install -r requirements.txt")

from config import settings
from emulator.agent import AgentLoop
from emulator.attack_injector import AttackInjector
from emulator.guardrail_agent import get_guardrail
from emulator.llm_provider import get_llm_client, DEFAULT_MODELS, OPENROUTER_FREE_MODELS
from emulator.mcp_client import MCPClient
from emulator.ollama_client import OllamaClient
from emulator.scenario_loader import ScenarioLoader
from logging_.hec_shipper import HECShipper
from logging_.ndjson_writer import NDJSONWriter
from splunk.index_manager import IndexManager


SCENARIOS_DIR = os.path.join(os.path.dirname(__file__), "scenarios")

BANNER = (
    "\n"
    "=============================================================================\n"
    "  AGENTIC LLM MCP THREAT EMULATOR\n"
    "  Agentic Attack Showcase for Splunk + MITRE ATLAS\n"
    "  Providers: Ollama (local) | Anthropic API | OpenRouter\n"
    "=============================================================================\n"
)


# ── CLI root ──────────────────────────────────────────────────────────────────

@click.group()
def cli() -> None:
    """Agentic LLM MCP Threat Emulator -- run agentic attack scenarios."""
    pass


# ── setup ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--rest-url",  default=settings.SPLUNK_REST_URL)
@click.option("--user",      default=settings.SPLUNK_USER)
@click.option("--password",  default=settings.SPLUNK_PASSWORD)
@click.option("--hec-url",   default=settings.SPLUNK_HEC_URL)
@click.option("--hec-token", default=settings.SPLUNK_HEC_TOKEN)
@click.option("--provider",  default="ollama", type=click.Choice(["ollama","anthropic","openrouter"], case_sensitive=False))
@click.option("--api-key",   default=None, envvar=["ANTHROPIC_API_KEY","OPENROUTER_API_KEY"])
def setup(rest_url, user, password, hec_url, hec_token, provider, api_key) -> None:
    """Create the Splunk 'agent' index and verify all connectivity."""
    click.echo(BANNER)
    click.echo("=== Setup ===\n")

    # Splunk
    mgr = IndexManager(rest_url, user, password)
    click.echo("[ ] Checking Splunk REST API...")
    ok = mgr.ensure_index(settings.SPLUNK_INDEX)
    click.echo(f"  {'[OK]' if ok else '[FAIL]'} index={settings.SPLUNK_INDEX}")

    click.echo("[ ] Checking HEC...")
    hec_ok = mgr.verify_hec(hec_url, hec_token)
    click.echo(f"  {'[OK]' if hec_ok else '[FAIL]'} HEC at {hec_url}")

    # LLM provider
    click.echo(f"[ ] Checking LLM provider ({provider})...")
    try:
        llm = get_llm_client(provider, api_key=api_key)
        llm_ok = llm.is_available()
        click.echo(f"  {'[OK]' if llm_ok else '[WARN]'} {llm.model} via {provider}")
        if not llm_ok:
            click.echo(f"  NOTE: {provider} unavailable -- use --no-llm to run with canned responses.")
    except ValueError as exc:
        click.echo(f"  [FAIL] {exc}")

    # MCP
    click.echo("[ ] Checking MCP server...")
    mcp = MCPClient(settings.MCP_URL)
    mcp_ok = mcp.is_available()
    click.echo(f"  {'[OK]' if mcp_ok else '[WARN]'} MCP at {settings.MCP_URL}")
    if not mcp_ok:
        click.echo("  NOTE: MCP unavailable -- use --no-mcp flag when running scenarios.")

    click.echo("\nSetup complete.")


# ── list ──────────────────────────────────────────────────────────────────────

@cli.command(name="list")
@click.option("--scenarios-dir", default=SCENARIOS_DIR)
def list_scenarios(scenarios_dir: str) -> None:
    """List all available attack scenarios."""
    loader = ScenarioLoader()
    scenarios = loader.load_all(scenarios_dir)
    if not scenarios:
        click.echo("No scenarios found in: " + scenarios_dir)
        return
    click.echo(f"\n{'NAME':<35} {'TECHNIQUE':<20} {'ROLE':<30} {'STEPS':>5}")
    click.echo("-" * 95)
    for s in scenarios:
        click.echo(f"{s.name:<35} {s.mitre_atlas_technique:<20} {s.agent.role:<30} {s.total_steps:>5}")
    click.echo(f"\nTotal: {len(scenarios)} scenario(s)")


# ── providers ────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--api-key", default=None, envvar="OPENROUTER_API_KEY",
              help="OpenRouter API key to list live free models")
def providers(api_key) -> None:
    """Show available LLM providers and models."""
    click.echo("\n=== LLM Providers ===\n")

    click.echo("  ollama      (local)")
    click.echo(f"    Default model : {DEFAULT_MODELS['ollama']}")
    click.echo(f"    URL           : {settings.OLLAMA_URL}")
    click.echo(f"    Flag          : --provider ollama\n")

    click.echo("  anthropic   (cloud, requires ANTHROPIC_API_KEY)")
    click.echo(f"    Default model : {DEFAULT_MODELS['anthropic']}")
    click.echo(f"    Other models  : claude-opus-4-6, claude-sonnet-4-6, claude-haiku-4-5-20251001")
    click.echo(f"    Flag          : --provider anthropic --api-key sk-ant-...\n")

    click.echo("  openrouter  (cloud, requires OPENROUTER_API_KEY)")
    click.echo(f"    Default model : {DEFAULT_MODELS['openrouter']}")
    click.echo(f"    Flag          : --provider openrouter --api-key sk-or-...\n")

    click.echo("  Known free models on OpenRouter:")
    for m in OPENROUTER_FREE_MODELS:
        click.echo(f"    {m}")

    if api_key:
        click.echo("\n  Fetching live free model list from OpenRouter...")
        from emulator.openrouter_client import OpenRouterClient
        client = OpenRouterClient(DEFAULT_MODELS["openrouter"], api_key)
        live = client.list_free_models()
        if live:
            click.echo(f"  {len(live)} free models available:")
            for m in live:
                click.echo(f"    {m}")
        else:
            click.echo("  Could not fetch live list.")


# ── run ───────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--scenario",      default="all", help="Scenario name or 'all'")
@click.option("--scenarios-dir", default=SCENARIOS_DIR)
@click.option("--log-dir",       default=settings.LOG_DIR)
@click.option("--hec-url",       default=settings.SPLUNK_HEC_URL)
@click.option("--hec-token",     default=settings.SPLUNK_HEC_TOKEN)
@click.option("--index",         default=settings.SPLUNK_INDEX)
@click.option("--sourcetype",    default=settings.SPLUNK_SOURCETYPE)
@click.option("--provider",      default="ollama",
              type=click.Choice(["ollama","anthropic","openrouter"], case_sensitive=False),
              help="LLM backend to use")
@click.option("--model",         default=None,
              help="Override default model for the chosen provider")
@click.option("--api-key",       default=None,
              envvar=["ANTHROPIC_API_KEY","OPENROUTER_API_KEY"],
              help="API key (or set ANTHROPIC_API_KEY / OPENROUTER_API_KEY env var)")
@click.option("--no-splunk",          is_flag=True, default=False, help="Write NDJSON only, skip HEC")
@click.option("--no-llm",             is_flag=True, default=False, help="Use canned responses (no LLM calls)")
@click.option("--no-mcp",             is_flag=True, default=False, help="Use canned MCP responses")
@click.option("--guardrail",          default="none",
              type=click.Choice(["none", "heuristic", "llamaguard"], case_sensitive=False),
              help="Guardrail method: none | heuristic (regex) | llamaguard (llama-guard3:1b)")
@click.option("--guardrail-model",    default="llama-guard3:1b",
              help="Ollama model for llamaguard method  [default: llama-guard3:1b]")
@click.option("--delay",              default=0.3, type=float, help="Seconds between steps")
@click.option("--verbose", "-v",      is_flag=True, default=False)
def run(
    scenario, scenarios_dir, log_dir,
    hec_url, hec_token, index, sourcetype,
    provider, model, api_key,
    no_splunk, no_llm, no_mcp,
    guardrail, guardrail_model,
    delay, verbose,
) -> None:
    """Run one or more agentic attack scenarios."""
    click.echo(BANNER)

    # Build LLM client
    try:
        llm = get_llm_client(
            provider=provider,
            model=model,
            api_key=api_key,
            ollama_url=settings.OLLAMA_URL.replace("/api/generate", ""),
            timeout=settings.OLLAMA_TIMEOUT,
        )
    except ValueError as exc:
        click.echo(f"ERROR: {exc}")
        sys.exit(1)

    # Load scenarios
    loader = ScenarioLoader()
    all_scenarios = loader.load_all(scenarios_dir)
    if scenario == "all":
        selected = all_scenarios
    else:
        selected = [s for s in all_scenarios if s.name == scenario]
        if not selected:
            click.echo(f"ERROR: scenario '{scenario}' not found. Run 'list' to see options.")
            sys.exit(1)

    # Build guardrail
    guard_instance = None
    if guardrail == "heuristic":
        guard_instance = get_guardrail("heuristic")
    elif guardrail == "llamaguard":
        ollama_base = settings.OLLAMA_URL.replace("/api/generate", "")
        guard_llm = OllamaClient(
            url=settings.OLLAMA_URL,
            tags_url=settings.OLLAMA_TAGS,
            model=guardrail_model,
            timeout=settings.OLLAMA_TIMEOUT,
        )
        if not guard_llm.is_available():
            click.echo(
                f"WARN: guardrail model '{guardrail_model}' not found in Ollama.\n"
                f"  Pull it with: docker exec security-range-ollama ollama pull {guardrail_model}\n"
                f"  Falling back to heuristic guardrail."
            )
            guard_instance = get_guardrail("heuristic")
        else:
            guard_instance = get_guardrail("llamaguard", llm_client=guard_llm)

    guardrail_label = "none"
    if guard_instance is not None:
        guardrail_label = f"{guard_instance.method}:{guard_instance.model}"

    llm_label = "canned" if no_llm else f"{provider}/{llm.model}"
    click.echo(
        f"Running {len(selected)} scenario(s)\n"
        f"  LLM     : {llm_label}\n"
        f"  MCP     : {'canned' if no_mcp else settings.MCP_URL}\n"
        f"  HEC     : {'disabled' if no_splunk else hec_url}\n"
        f"  Index   : {index}\n"
        f"  Guardrail: {guardrail_label}\n"
    )

    mcp = MCPClient(settings.MCP_URL, settings.MCP_TIMEOUT)
    injector = AttackInjector()

    session_id = str(uuid.uuid4())
    log_filename = f"agent_{session_id[:8]}.log"

    results = []
    with NDJSONWriter(log_dir, log_filename) as writer:
        shipper = HECShipper(
            hec_url=hec_url,
            token=hec_token,
            index=index,
            sourcetype=sourcetype,
            batch_size=settings.HEC_BATCH_SIZE,
            enabled=not no_splunk,
        )

        for sc in selected:
            click.echo(f">> {sc.name}  [{sc.mitre_atlas_technique}]  role={sc.agent.role}  steps={sc.total_steps}")
            if verbose:
                click.echo(f"   Goal: {sc.agent_goal}")

            loop = AgentLoop(
                scenario=sc,
                llm=llm,
                mcp=mcp,
                injector=injector,
                writer=writer,
                shipper=shipper,
                session_id=session_id,
                use_llm=not no_llm,
                use_mcp=not no_mcp,
                guardrail=guard_instance,
                step_delay=delay,
                verbose=verbose,
            )

            t0 = time.time()
            result = loop.run()
            elapsed = time.time() - t0
            results.append(result)

            click.echo(
                f"   done: {result.total_events} events | "
                f"{result.attacks_triggered} triggered | "
                f"{result.attacks_detected} detected | "
                f"{result.guardrail_blocks} blocked | "
                f"{elapsed:.1f}s"
            )
            if not no_splunk:
                click.echo(f"   HEC : {result.hec_sent} sent, {result.hec_failed} failed")

        shipper.flush()

    click.echo(f"\nLog : {writer.path}")
    click.echo("\nSPL quickstart:")
    click.echo(f'  index={index} session_id="{session_id}" | stats count by event_type, attack_type')
    click.echo(f'  index={index} is_malicious=true | table _time, agent_role, pipeline_stage, attack_type, severity')
    click.echo(f'  index={index} event_type=attack_triggered | stats count by mitre_atlas_technique, severity')


# ── validate ─────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--scenarios-dir", default=SCENARIOS_DIR)
def validate(scenarios_dir: str) -> None:
    """Validate all scenario YAML files."""
    loader = ScenarioLoader()
    files = list(__import__("pathlib").Path(scenarios_dir).glob("*.yaml"))
    ok = fail = 0
    for f in files:
        try:
            sc = loader.load(str(f))
            assert len(sc.benign_prompts) == sc.total_steps
            click.echo(f"  [OK]  {f.name:<45} role={sc.agent.role}")
            ok += 1
        except Exception as exc:
            click.echo(f"  [FAIL] {f.name}: {exc}")
            fail += 1
    click.echo(f"\n{ok} valid, {fail} invalid")


if __name__ == "__main__":
    cli()
