# Qualys MCP Server

A lightweight MCP server that connects AI assistants to Qualys security data. **22 tools**, pure Python, zero config beyond credentials. Install with `uvx` and start asking security questions in plain English.

## Setup

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
        "QUALYS_BASE_URL": "qualysapi.qualys.com",
        "QUALYS_GATEWAY_URL": "gateway.qg1.apps.qualys.com"
      }
    }
  }
}
```

Requires [uv](https://docs.astral.sh/uv/): `brew install uv` or `curl -LsSf https://astral.sh/uv/install.sh | sh`

### Alternative

```bash
pip install qualys-mcp
qualys-mcp
```

### Self-Signed Certificates

For environments with self-signed certs, add `"QUALYS_SSL_VERIFY": "false"` to the env block.

## Tools

22 tools covering vulnerability management, threat intelligence, asset risk, cloud security, containers, TruRisk Eliminate, ETM findings, and security program coaching.

### Daily Operations & Coaching

| Tool | What it answers |
|------|----------------|
| `get_morning_report` | What happened overnight? New vulns, ransomware/exploit flags, top risks, action items |
| `get_recommendations` | What should we improve? Module gaps, risk reduction opportunities, prioritized next steps |
| `get_eliminate_status` | What's our patching and mitigation status? Patch jobs, mitigation jobs, catalog coverage |
| `get_etm_findings` | What confirmed vulnerabilities exist across all sources? ETM findings with QID, QDS, TruRisk, CVE, patch status |
| `get_scanner_health` | Are our scanners healthy? Appliance status, failed scans, capacity utilization, signature updates |

### Security Posture & Priorities

| Tool | What it answers |
|------|----------------|
| `get_security_posture` | How secure are we overall? Health score, risk distribution, container and cloud stats |
| `get_weekly_priorities` | What should my team fix this week? Top risk assets ranked by TruRisk |
| `get_patch_status` | What's our patching coverage? Risk distribution and assets needing remediation |

### Vulnerability Intelligence

| Tool | What it answers |
|------|----------------|
| `investigate_cve` | Are we affected by CVE-XXXX? QIDs, severity, patches, threat intel |
| `get_cve_details` | Tell me about these 5 CVEs. Bulk lookup with concurrent fetching |
| `get_new_vulns` | What new vulns dropped this week? Severity breakdown, RTI tags, patch status |
| `get_vulns_by_software` | What vulns affect Apache? Search by software, vendor, or product name |
| `get_threat_intel` | What vulns have ransomware/active exploits? RTI breakdown across 12+ threat categories |

### Asset & Infrastructure Risk

| Tool | What it answers |
|------|----------------|
| `get_asset_risk` | Why is this asset risky? TruRisk score, software inventory, EOL status |
| `get_asset_full_profile` | Full single-asset profile combining CSAM + ETM + VMDR detections in parallel (~5-8s) |
| `get_risk_by_tag` | Risk distribution for a tagged asset group (e.g., 'PCI', 'Production', 'AWS') |
| `get_environment_summary` | Fast all-CSAM environment snapshot: OS, cloud, EOL, criticality tiers (<3s) |
| `get_tech_debt` | How many EOL/EOS systems do we have? OS and hardware lifecycle status |
| `get_cloud_risk` | What's our cloud security posture? AWS/Azure/GCP accounts and failed controls |
| `get_image_vulns` | What vulns are in this container image? Severity breakdown and fixes |

### Threat Intel Categories

`get_threat_intel` supports filtering by any RTI (Real-Time Threat Indicator) tag:

`Ransomware` `Malware` `Active_Attacks` `Exploit_Public` `Easy_Exploit` `Wormable` `Cisa_Known_Exploited_Vulns` `Denial_of_Service` `Privilege_Escalation` `Remote_Code_Execution` `Predicted_High_Risk` `Unauthenticated_Exploitation`

## Example Conversations

### Daily Operations
```
"What happened overnight?"                     → get_morning_report()
"What should my team focus on this week?"      → get_weekly_priorities()
"How secure are we?"                           → get_security_posture()
"What new vulns came out this week?"           → get_new_vulns(days=7)
"What modules should we add?"                  → get_recommendations()
```

### CVE Investigation
```
"Are we affected by Log4Shell?"                → investigate_cve("CVE-2021-44228")
"Show me everything about CVE-2024-3400"       → investigate_cve("CVE-2024-3400")
"Compare CVE-2024-3400 and CVE-2023-4966"      → get_cve_details("CVE-2024-3400,CVE-2023-4966")
```

### Threat Intelligence
```
"What vulns have active ransomware?"           → get_threat_intel(threat_type="Ransomware")
"Show me vulns with public exploits"           → get_threat_intel(threat_type="Exploit_Public")
"Which CISA KEV vulns are we exposed to?"      → get_threat_intel(threat_type="Cisa_Known_Exploited_Vulns")
```

### Software Vulnerabilities
```
"Show me Apache vulnerabilities"               → get_vulns_by_software("Apache")
"Are we running vulnerable Log4j?"            → get_vulns_by_software("log4j")
"What OpenSSL vulnerabilities do we have?"    → get_vulns_by_software("OpenSSL")
```

### Asset & Patching
```
"What should we patch first?"                  → get_patch_status()
"What's wrong with asset 233946644?"           → get_asset_risk("233946644")
"How many EOL systems do we have?"             → get_tech_debt()
"What's our patch/mitigate status?"            → get_eliminate_status()
```

### Cloud & Infrastructure
```
"What's our cloud posture?"                    → get_cloud_risk()
"What cloud threats were detected this week?"  → get_cdr_findings(days=7)
"Show me critical AWS CDR findings"            → get_cdr_findings(severity="CRITICAL", cloud_provider="AWS")
"Are our scanners healthy?"                    → get_scanner_health()
```

### ETM Findings
```
"Show me all confirmed critical findings"      → get_etm_findings(qql="vulnerabilities.vulnerability.severity:5")
"Am I affected by Log4Shell across all sources?" → get_etm_findings(qql="vulnerabilities.vulnerability.cveIds:CVE-2021-44228")
```

### Multi-Tool Workflows
```
"New critical CVE just dropped — what do I need to know?"
→ investigate_cve() → get_threat_intel() → get_patch_status()

"Prepare me for the weekly security standup"
→ get_morning_report() → get_weekly_priorities() → get_eliminate_status()

"Briefing the CISO on our security program"
→ get_security_posture() → get_threat_intel() → get_patch_status() → get_recommendations()
```

See [docs/examples.md](docs/examples.md) for the full Q&A reference with 100+ mapped examples.

## Qualys PODs

| POD | BASE_URL | GATEWAY_URL |
|-----|----------|-------------|
| US1 | qualysapi.qualys.com | gateway.qg1.apps.qualys.com |
| US2 | qualysapi.qg2.apps.qualys.com | gateway.qg2.apps.qualys.com |
| US3 | qualysapi.qg3.apps.qualys.com | gateway.qg3.apps.qualys.com |
| EU1 | qualysapi.qualys.eu | gateway.qg1.apps.qualys.eu |
| EU2 | qualysapi.qg2.apps.qualys.eu | gateway.qg2.apps.qualys.eu |

## License

MIT - Copyright (c) 2026 Andrew Nelson
