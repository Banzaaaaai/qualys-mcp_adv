# Qualys MCP Server

> ⚠️ **Unofficial project.** This is a personal project to showcase the viability of connecting AI assistants to Qualys via the Model Context Protocol. It is not affiliated with, endorsed by, or supported by Qualys, Inc.

An MCP server that connects AI assistants to Qualys security data. **8 tools** covering vulnerability management, cloud security, containers, compliance, remediation, and more. Pure Python, zero config beyond credentials.

Works with **Claude Desktop** (local stdio) and **Claude.ai** (remote SSE + OAuth 2.0).

**📖 [Full documentation →](https://qualys-mcp.netlify.app/)**

## Setup

### Claude Desktop (local)

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "qualys": {
      "command": "uvx",
      "args": ["qualys-mcp"],
      "env": {
        "QUALYS_USERNAME": "your-username",
        "QUALYS_PASSWORD": "your-password",
        "QUALYS_POD": "US2"
      }
    }
  }
}
```

Requires [uv](https://docs.astral.sh/uv/): `brew install uv` or `curl -LsSf https://astral.sh/uv/install.sh | sh`

### Claude.ai (remote / internet)

Run the server with SSE transport and OAuth 2.0:

```bash
MCP_TRANSPORT=sse \
MCP_BASE_URL=https://qualys-mcp.example.com \
MCP_OAUTH_PIN=your-secret-pin \
MCP_PORT=8000 \
QUALYS_USERNAME=your-username \
QUALYS_PASSWORD=your-password \
QUALYS_POD=US2 \
qualys-mcp
```

Then in Claude.ai → **Settings → Integrations** → add your server URL:

```
https://qualys-mcp.example.com/sse
```

Claude.ai will open a browser authorization page — enter your `MCP_OAUTH_PIN` to grant access. The issued token is valid for one year; you won't need to re-authorize on every session.

> **TLS required.** Put a reverse proxy (Caddy, nginx) or Cloudflare Tunnel in front. `MCP_BASE_URL` must be the public `https://` address — OAuth metadata URLs won't work over plain HTTP.

#### SSE environment variables

| Variable | Required | Default | Description |
| -------- | -------- | ------- | ----------- |
| `MCP_TRANSPORT` | yes | `stdio` | Set to `sse` to enable remote mode |
| `MCP_BASE_URL` | yes | — | Public HTTPS URL of this server |
| `MCP_OAUTH_PIN` | yes | — | PIN entered during browser authorization |
| `MCP_HOST` | no | `0.0.0.0` | Bind address |
| `MCP_PORT` | no | `8000` | Listen port |

### Common options

**Supported pods:** `US1` `US2` `US3` `US4` `EU1` `EU2` `EU3` `IN1` `CA1` `AE1` `UK1` `AU1` `KSA1`

Set `QUALYS_POD` to your platform POD — the server derives the correct API and gateway URLs automatically.

> **Advanced:** If you need to override the auto-derived URLs, set `QUALYS_BASE_URL` and `QUALYS_GATEWAY_URL` explicitly instead of `QUALYS_POD`. Explicit URLs take priority.
> **Self-signed certificates:** Add `QUALYS_SSL_VERIFY=false` to the env block.

### pip alternative

```bash
pip install qualys-mcp
qualys-mcp
```

## Tools

8 tools that intelligently dispatch to 42 internal aggregators across all Qualys modules. Each tool handles routing, concurrent API calls, cross-domain correlation, and response synthesis automatically.

| Tool | What it answers |
|------|----------------|
| `investigate` | Deep-dive any security topic — CVEs, threat actors, assets, EDR/FIM events, KB searches |
| `assess_risk` | Cross-domain risk — VMs, cloud (AWS/Azure/GCP/OCI), containers, web apps, certificates, assets |
| `check_compliance` | Compliance posture — PCI, HIPAA, CIS, NIST, SOC2 pass/fail, failing controls, exceptions |
| `plan_remediation` | Patch priorities, deployment status, mitigation coverage, program gap analysis |
| `security_overview` | Daily/weekly/monthly briefing — scanner health, scan status, vulnerability findings |
| `reports` | Generate, list, download, and manage Qualys reports |
| `manage_scan` | Scan lifecycle — list, launch, pause, resume, cancel, delete, results |
| `cache_status` | View and clear API caches |

### Key Parameters

**investigate**
- `target` — CVE ID, threat actor, hostname, IP, or free-text topic
- `depth` — `quick` (~10s) / `standard` (~20s) / `deep` (~45s)
- `scope` — `all` / `vulns` / `threats` / `assets` / `edr` / `fim`

**assess_risk**
- `scope` — `all` / `cloud` / `containers` / `web` / `certs` / `assets`
- `tag` / `asset_group` — filter by business group
- `provider` — `aws` / `azure` / `gcp` (cloud scope)
- `asset_id` — single asset deep-dive

**check_compliance**
- `framework` — `PCI` / `HIPAA` / `CIS` / `NIST` / `SOC2`
- `include_exceptions` — include risk acceptances

**plan_remediation**
- `scope` — `all` / `patches` / `mitigations` / `program`
- `severity` — `critical` / `high` / `moderate`
- `cves` / `qids` — check mitigation coverage for specific vulns

**security_overview**
- `period` — `today` / `week` / `month`
- `quick` — fast snapshot (~2s) vs full briefing

#### manage_scan

- `action` — `list` / `launch` / `pause` / `resume` / `cancel` / `delete` / `status` / `fetch_results`
- `ip` — IPs or CIDR ranges (launch)
- `scan_ref` — scan reference e.g. `scan/12345.67890`

## Example Conversations

### Daily Operations
```
"Give me a security overview"                  → security_overview(quick=True)
"What happened this week?"                     → security_overview(period="week")
"What should we patch first?"                  → plan_remediation(scope="patches", severity="critical")
"How's our compliance?"                        → check_compliance()
```

### Investigation
```
"Tell me about CVE-2024-3400"                  → investigate(target="CVE-2024-3400")
"Are we exposed to ransomware?"                → investigate(target="ransomware")
"What do we know about Iranian threats?"        → investigate(target="iran")
"Investigate this host: 10.0.0.1"              → investigate(target="10.0.0.1", scope="edr")
```

### Risk Assessment
```
"What's our overall risk?"                     → assess_risk(scope="all")
"How's our cloud security?"                    → assess_risk(scope="cloud")
"Any container vulnerabilities?"               → assess_risk(scope="containers")
"Web app security status?"                     → assess_risk(scope="web")
"Show me risk for Production assets"           → assess_risk(tag="Production")
```

### Compliance & Remediation
```
"Are we PCI compliant?"                        → check_compliance(framework="PCI")
"What's our patch coverage?"                   → plan_remediation(scope="patches")
"Is there a mitigation for CVE-2024-3400?"     → plan_remediation(cves=["CVE-2024-3400"])
"What security gaps do we have?"               → plan_remediation(scope="program")
```

### Scan Management

```
"What scans are running?"                      → manage_scan(action="list")
"Launch a scan on 10.0.0.0/24"                → manage_scan(action="launch", ip="10.0.0.0/24")
"Pause scan scan/12345.67890"                  → manage_scan(action="pause", scan_ref="scan/12345.67890")
"Show me scan results"                         → manage_scan(action="fetch_results", scan_ref="...")
```

### Multi-Step Workflows
```
"New critical CVE dropped — what do I need to know?"
→ investigate(target="CVE-...") → plan_remediation(cves=["CVE-..."]) → check_compliance()

"Prepare me for the weekly security standup"
→ security_overview(period="week") → assess_risk(scope="all") → plan_remediation(scope="patches")

"PCI audit prep"
→ check_compliance(framework="PCI", include_exceptions=True) → assess_risk(scope="all") → plan_remediation()
```

## Architecture

```
AI Assistant → qualys_mcp.py (8 tools) → workflows/ (dispatch + synthesis) → aggregators.py (42 functions) → api.py (HTTP + caching) → Qualys APIs
```

### Transports

- `stdio` — Claude Desktop, local use, spawned as a subprocess
- `sse` — Claude.ai and any remote MCP client; OAuth 2.0 authorization code + PKCE flow, dynamic client registration

Each workflow tool:
1. Builds a dispatch plan based on parameters
2. Runs selected aggregators concurrently
3. Merges results into a unified response envelope
4. Applies cross-domain correlation
5. Returns prioritized findings and recommended actions

## Performance

Tested on an 89,000-asset environment (US2 POD):

| Workflow | Time |
|----------|------|
| `security_overview(quick=True)` | 1.7s |
| `assess_risk(scope="cloud")` | 1.3s |
| `assess_risk(scope="containers")` | 3.1s |
| `check_compliance()` | <1ms (cached) |
| `plan_remediation(scope="patches")` | 2.6s |
| `investigate(target="CVE-2024-3400")` | ~33s |
| `assess_risk(scope="all")` | 4.9s |

> **Cold start:** The first query after launching takes 2-10s longer while the bearer token is acquired and caches warm up. A background thread pre-fetches VMDR detections on startup. After the first query, responses are significantly faster. Ask `security_overview(quick=True)` first to warm caches.

## Eval Harness

300 routing test questions + 900 variants + 30 multi-turn conversation workflows for automated evaluation.

```bash
# Install eval dependencies
pip install anthropic mcp python-dotenv pyyaml

# Run eval
python -m eval --quick
```

## Testing

```bash
# Unit tests (282 tests)
pip install pytest
pytest tests/ --ignore=tests/conversations -q

# Smoke test
bash test_tools.sh fast
```

## Qualys PODs

| POD | BASE_URL | GATEWAY_URL |
|-----|----------|-------------|
| US1 | qualysapi.qualys.com | gateway.qg1.apps.qualys.com |
| US2 | qualysapi.qg2.apps.qualys.com | gateway.qg2.apps.qualys.com |
| US3 | qualysapi.qg3.apps.qualys.com | gateway.qg3.apps.qualys.com |
| US4 | qualysapi.qg4.apps.qualys.com | gateway.qg4.apps.qualys.com |
| EU1 | qualysapi.qualys.eu | gateway.qg1.apps.qualys.eu |
| EU2 | qualysapi.qg2.apps.qualys.eu | gateway.qg2.apps.qualys.eu |
| EU3 | qualysapi.qg3.apps.qualys.eu | gateway.qg3.apps.qualys.eu |
| IN1 | qualysapi.qg1.apps.qualys.in | gateway.qg1.apps.qualys.in |
| CA1 | qualysapi.qg1.apps.qualys.ca | gateway.qg1.apps.qualys.ca |
| AE1 | qualysapi.qg1.apps.qualys.ae | gateway.qg1.apps.qualys.ae |
| UK1 | qualysapi.qg1.apps.qualys.co.uk | gateway.qg1.apps.qualys.co.uk |
| AU1 | qualysapi.qg1.apps.qualys.com.au | gateway.qg1.apps.qualys.com.au |
| KSA1 | qualysapi.qg1.apps.qualysksa.com | gateway.qg1.apps.qualysksa.com |

## License

MIT - Copyright (c) 2026 Andrew Nelson
