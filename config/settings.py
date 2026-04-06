"""
Agentic LLM MCP Threat Emulator -- Configuration

Splunk defaults match the splunk-mcp-llm-siemulator local stack.
Override any value via environment variable or .env file.
"""

import os

# ── Splunk ────────────────────────────────────────────────────────────────────
# Defaults match the splunk-mcp-llm-siemulator docker-compose stack.
# The HEC token below is the agent-specific token created by setup.
SPLUNK_HEC_URL    = os.environ.get("SPLUNK_HEC_URL",   "http://localhost:8088/services/collector/event")
SPLUNK_HEC_TOKEN  = os.environ.get("SPLUNK_HEC_TOKEN", "50e334a4-3a58-4e68-bbba-584b82d04b17")
SPLUNK_REST_URL   = os.environ.get("SPLUNK_REST_URL",  "https://localhost:8089")
SPLUNK_USER       = os.environ.get("SPLUNK_USER",      "admin")
SPLUNK_PASSWORD   = os.environ.get("SPLUNK_PASSWORD",  "Password1")
SPLUNK_INDEX      = os.environ.get("SPLUNK_INDEX",     "agent")
SPLUNK_SOURCETYPE = os.environ.get("SPLUNK_SOURCETYPE","agent:workflow")

# ── Ollama (local) ────────────────────────────────────────────────────────────
OLLAMA_URL     = os.environ.get("OLLAMA_URL",   "http://localhost:11434/api/generate")
OLLAMA_TAGS    = os.environ.get("OLLAMA_TAGS",  "http://localhost:11434/api/tags")
OLLAMA_MODEL   = os.environ.get("OLLAMA_MODEL", "llama3.2:latest")
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "60"))

# ── MCP server ────────────────────────────────────────────────────────────────
MCP_URL     = os.environ.get("MCP_URL",     "http://localhost:3456")
MCP_TIMEOUT = int(os.environ.get("MCP_TIMEOUT", "15"))

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_DIR        = os.environ.get("LOG_DIR",  "./logs")
LOG_FILE       = "agent.log"
HEC_BATCH_SIZE = int(os.environ.get("HEC_BATCH_SIZE", "10"))
