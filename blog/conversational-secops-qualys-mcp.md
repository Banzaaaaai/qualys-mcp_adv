# Conversational SecOps: Building an MCP Server for Qualys

*How we built a natural language interface to security data using the Model Context Protocol*

**By Andrew Nelson** | [github.com/nelssec](https://github.com/nelssec)

---

Security operations has a context-switching problem. Your vulnerability data lives in VMDR. Asset risk is in CSAM. Cloud posture is in CloudView. Container security is somewhere else. And when a new CVE drops, you're clicking between tabs trying to answer one question: *Am I affected?*

What if you could just ask?

```
"Is CVE-2024-3400 in my environment?"
```

And get an answer — severity, patch status, threat intel, ransomware linkage — in seconds?

That's what we built with **qualys-mcp**: a lightweight MCP server that gives Claude direct access to Qualys security data through 12 focused tools.

## The Problem: Security Data Silos

Modern security teams don't lack data. They're drowning in it. The challenge is correlation and context.

Consider a typical "Am I vulnerable?" workflow:

1. Search the KnowledgeBase for the CVE
2. Find the associated QID(s)
3. Check severity and patch availability
4. Look at threat intelligence — is this being actively exploited?
5. Cross-reference with asset inventory for exposure

That's 5 context switches, 3 different dashboards, and 15 minutes minimum — for a single CVE. During a zero-day event, multiply by every CVE variant and you're looking at hours.

## The Solution: MCP as a Security Query Layer

The Model Context Protocol (MCP) is Anthropic's standard for giving AI models access to external tools. We built qualys-mcp to answer security questions by orchestrating Qualys API calls behind the scenes:

| Tool | Question It Answers |
|------|---------------------|
| `get_security_posture` | How secure are we overall? |
| `get_weekly_priorities` | What should my team fix this week? |
| `get_patch_status` | What's our patching coverage? |
| `investigate_cve` | Are we affected by this specific CVE? |
| `get_cve_details` | Compare these 5 CVEs side by side |
| `get_new_vulns` | What new vulnerabilities dropped this week? |
| `get_vulns_by_software` | What vulns affect Apache/OpenSSL/F5? |
| `get_threat_intel` | What vulns have ransomware/active exploits? |
| `get_asset_risk` | Why is this specific asset risky? |
| `get_tech_debt` | How many EOL/EOS systems do we have? |
| `get_cloud_risk` | What's our cloud security posture? |
| `get_image_vulns` | What vulns are in this container image? |

**12 tools. One conversation.**

## How It Works

### Architecture

```
┌─────────────────────────────────────────────────┐
│              Claude / AI Assistant               │
│         "What new vulns came out this week?"      │
└─────────────────────┬───────────────────────────┘
                      │ MCP Protocol (stdio)
                      ▼
┌─────────────────────────────────────────────────┐
│                  qualys-mcp                      │
│                                                  │
│  ┌──────────────┐  ┌────────────┐  ┌──────────┐ │
│  │ Posture &    │  │ Vuln Intel │  │ Asset &  │ │
│  │ Priorities   │  │ & Threat   │  │ Infra    │ │
│  └──────────────┘  └────────────┘  └──────────┘ │
│                                                  │
│  Auth (JWT + Basic) │ Caching │ Concurrency      │
└──────────┬──────────────────────┬───────────────┘
           │                      │
           ▼                      ▼
┌──────────────────┐  ┌──────────────────────────┐
│  Qualys Base API │  │   Qualys Gateway API     │
│  KB (XML)        │  │   CSAM, Cloud, Container │
└──────────────────┘  └──────────────────────────┘
```

The server handles:
- **Dual authentication**: JWT tokens for Gateway API, Basic Auth for classic KB API
- **Concurrent API calls**: 4-8 parallel requests per tool for fast responses
- **KB caching**: Vulnerability data cached across tool calls
- **Response aggregation**: Multiple API results combined into structured answers

### Example: CVE Investigation

**User:** "Check if we're affected by CVE-2024-3400"

**Claude:**
```
[Calling investigate_cve("CVE-2024-3400")]

CVE-2024-3400: Palo Alto Networks PAN-OS Command Injection

Severity: 5 (Critical)
Patch Available: Yes
Ransomware-linked: Yes

Threat Intelligence:
  Active_Attacks, Cisa_Known_Exploited_Vulns, Exploit_Public,
  Ransomware, Remote_Code_Execution, Wormable,
  Unauthenticated_Exploitation, Easy_Exploit

3 related QIDs found. Patch is available — prioritize remediation
given active exploitation and ransomware linkage.
```

One question. Complete context.

### Example: Weekly Security Briefing

**User:** "What should we focus on this week?"

**Claude:**
```
[Calling get_weekly_priorities()]

Summary:
  88,511 total assets
  47 critical risk (TruRisk > 900)
  1,931 high risk (TruRisk > 700)
  EOL systems: needs attention

Top Risk Assets:
  1. HQWIN7RD27 - Risk 1000 - Windows 7 (EOL)
  2. HQWIN2003  - Risk 985  - Windows Server 2003 (EOL)
  3. PROD-DB-01 - Risk 920  - Ubuntu 18.04 (EOL)

Priorities:
  1. Remediate 47 critical-risk assets (TruRisk > 900)
  2. Address 1,931 high-risk assets (TruRisk > 700)
  3. Plan upgrades for EOL systems
```

### Example: Bulk CVE Comparison

**User:** "Compare Log4Shell, CVE-2024-3400, and the Citrix Bleed bug"

**Claude:**
```
[Calling get_cve_details("CVE-2021-44228,CVE-2024-3400,CVE-2023-4966")]

All 3 found:

CVE-2021-44228 (Log4Shell): Severity 5, Patch YES, Ransomware YES
  TI: Active_Attacks, CISA KEV, Exploit_Public, Wormable, RCE

CVE-2024-3400 (PAN-OS): Severity 5, Patch YES, Ransomware YES
  TI: Active_Attacks, CISA KEV, Exploit_Public, Wormable, RCE

CVE-2023-4966 (Citrix Bleed): Severity 5, Patch YES, Ransomware YES
  TI: Active_Attacks, CISA KEV, Exploit_Public, Easy_Exploit

All three are actively exploited, ransomware-linked, and on the
CISA KEV list. Patches available for all.
```

### Example: Software-Specific Vulnerabilities

**User:** "What vulnerabilities affect Apache?"

**Claude:**
```
[Calling get_vulns_by_software("Apache")]

294 Apache vulnerabilities found (last 90 days):
  Critical: 54
  High: 129
  Medium: 99
  Low: 12

287 have patches available (97.6% patchable)

Top critical:
  - Apache HTTP Server Request Smuggling
  - Apache Tomcat Remote Code Execution
  - Apache Struts Remote Code Execution
```

## Security for Every Role

The same 12 tools serve different audiences:

**Security Analysts:**
```
"What vulns have active ransomware exploits?"
→ get_threat_intel(threat_type="Ransomware")
```

**Developers:**
```
"What vulns are in container image sha256:abc123?"
→ get_image_vulns("sha256:abc123")
```

**Compliance:**
```
"How many EOL systems do we have?"
→ get_tech_debt()
```

**Executives:**
```
"How secure are we?"
→ get_security_posture() → Health score: 78/100
```

**Incident Response:**
```
"Is CVE-2024-3400 being actively exploited?"
→ investigate_cve("CVE-2024-3400") → Yes, 14 threat intel tags
```

Same tools, different questions, appropriate answers for each audience.

## Try It

qualys-mcp is open source: [github.com/nelssec/qualys-mcp](https://github.com/nelssec/qualys-mcp)

```bash
# Install and run (no build step)
pip install qualys-mcp

# Or use uvx for zero-install execution
# Just add to claude_desktop_config.json:
```

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

Then just ask Claude:
- "What new vulns came out this week?"
- "Are we affected by Log4Shell?"
- "Show me Apache vulnerabilities"
- "What should we patch first?"

## Conclusion

Security operations shouldn't require memorizing API endpoints and query syntax. The data exists — it's locked behind interfaces designed for a pre-AI world.

MCP gives us conversational security operations. Ask questions in plain English. Get answers that span vulnerability data, asset risk, cloud posture, and container security.

qualys-mcp is 12 tools and one Python file. No framework, no database, no Docker. Just `uvx qualys-mcp` and start asking.

The future of SecOps is conversational. Let's build it.

---

*qualys-mcp is an independent open-source project and is not affiliated with or endorsed by Qualys, Inc.*

*Copyright (c) 2026 Andrew Nelson. MIT License.*
