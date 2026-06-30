# ScamShield AI

Multi-agent scam protection system: a **GuardianAgent** orchestrates specialist
agents (call, email/phishing, financial) backed by an **MCP tool server**
(text analysis, URL reputation, risk scoring, notifications), with a
security layer (PII redaction, rate limiting, tamper-evident audit log),
a full CLI, and a runnable demo.

## Project Structure

```
scamshield-ai/
├── README.md
├── .env.example
├── .gitignore
├── .dockerignore
├── Dockerfile
├── requirements.txt
├── setup.py
├── main.py
├── agents/
│   ├── guardian_agent.py          # Orchestrator + Google ADK wrapper
│   ├── call_protection_agent.py
│   ├── phishing_email_agent.py
│   ├── financial_scam_agent.py
│   ├── risk_memory_agent.py
│   └── family_notification_agent.py
├── mcp_server/
│   ├── server.py                  # Real MCP stdio server + dispatch fallback
│   ├── tools/
│   │   ├── analyze_text.py
│   │   ├── check_url.py
│   │   ├── risk_scorer.py
│   │   └── notification_tool.py
│   └── resources/
│       ├── scam_patterns.json
│       └── legitimate_domains.json
├── security/
│   ├── input_sanitizer.py         # PII redaction + injection detection
│   ├── rate_limiter.py
│   └── audit_logger.py            # Hash-chained + SIEM webhook
├── cli/
│   └── scamshield_cli.py          # scan · batch-scan · export · verify-audit · serve-webhook
├── demo/
│   ├── demo_script.py
│   └── sample_inputs/
│       ├── scam_call_transcript.txt
│       ├── phishing_email.txt
│       └── fake_investment.txt
├── tests/
│   ├── test_guardian.py
│   ├── test_email_agent.py
│   └── test_financial_agent.py
└── docs/
    ├── architecture.md
    └── presentation_outline.md
```

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the demo (no API key required)
cd scamshield-ai
python main.py
```

## CLI Usage

```bash
# Scan a single email file
python -m cli.scamshield_cli scan \
  --type email \
  --file demo/sample_inputs/phishing_email.txt \
  --sender support@amaz0n-secure-login.xyz

# Batch-scan a directory of .txt files
python -m cli.scamshield_cli batch-scan \
  --type email \
  --dir demo/sample_inputs \
  --output report.json

# Export audit log as CSV
python -m cli.scamshield_cli export --format csv --output audit.csv

# Verify the tamper-evident audit log
python -m cli.scamshield_cli verify-audit

# Start a webhook ingestion server (HMAC-signed)
WEBHOOK_SECRET=mysecret \
python -m cli.scamshield_cli serve-webhook --type email --port 8080
```

## MCP Server (Claude Desktop / Cursor)

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "scamshield": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "/absolute/path/to/scamshield-ai"
    }
  }
}
```

## Docker

```bash
docker build -t scamshield .

# Run the MCP server (default)
docker run scamshield

# Run the webhook server
docker run -e WEBHOOK_SECRET=mysecret -p 8080:8080 scamshield \
  python -m cli.scamshield_cli serve-webhook --type email --port 8080
```

## Tests

```bash
pytest tests/ -v
```

## Google ADK Integration

```python
from agents.guardian_agent import GuardianADKAgent

agent = GuardianADKAgent()
result = agent.process(user_id="alice", input_type="email", text=email_body)
```

`GuardianADKAgent` wraps `GuardianAgent` as a `google.adk.agents.Agent` with
all four MCP tools registered as ADK `FunctionTool` objects. Falls back to
plain rule-based `GuardianAgent` when `google-adk` is not installed.

## Environment Variables

See [.env.example](.env.example) for the full list.

Key variables:
- `GOOGLE_API_KEY` — enable Gemini-backed ADK planning
## Architecture

See [docs/architecture.md](docs/architecture.md) for the full system diagram,
component breakdown, scoring formula, and deployment options.
