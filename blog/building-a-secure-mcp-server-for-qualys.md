# Building a Lightweight MCP Server for Qualys Security APIs

**TL;DR:** We built a single-file Python MCP server that gives AI assistants like Claude access to Qualys vulnerability, asset, and cloud security data through 12 focused tools. This post covers the design decisions, performance optimizations, and how we achieved fast response times across all tools.

## What is MCP?

Model Context Protocol (MCP) is an open standard developed by Anthropic that allows AI assistants to interact with external tools and data sources. Think of it as a standardized way for LLMs to call functions — any client, any server, one protocol.

```
User → "What new vulns dropped this week?"
Claude → [calls get_new_vulns(days=7)]
qualys-mcp → Qualys KB API → 3,432 vulns, 251 critical
Claude → "3,432 new vulnerabilities published in the last 7 days..."
```

## Why Qualys + MCP?

Qualys has comprehensive security APIs, but using them requires:

1. Knowing which of the 30+ API endpoints to hit
2. Understanding XML vs JSON response formats
3. Handling JWT tokens for Gateway API vs Basic Auth for classic API
4. Manually correlating data across VMDR, CSAM, KB, CloudView, and Container Security

An MCP server abstracts all of this. Security teams just ask questions:

- "Are we affected by CVE-2024-3400?"
- "What vulns have active ransomware exploits?"
- "What should we patch this week?"

## Design Philosophy: 12 Tools, Not 60

Early iterations had dozens of tools mapping 1:1 to API endpoints. That approach failed for two reasons:

1. **LLMs don't know which tool to pick** when there are 60 options. Tool selection accuracy drops dramatically past ~15 tools.
2. **Raw API wrappers aren't useful** — they return data, not answers.

Instead, we built 12 *question-answering* tools. Each tool answers a specific security question by orchestrating multiple API calls, aggregating data, and returning structured results.

| Tool | Question | APIs Used |
|------|----------|-----------|
| `get_security_posture` | How secure are we? | CSAM counts, Container API, CloudView |
| `get_weekly_priorities` | What to fix this week? | CSAM search + counts, Container API |
| `get_patch_status` | Patching coverage? | CSAM counts + search |
| `investigate_cve` | Affected by this CVE? | KB API (CVE→QID mapping) |
| `get_cve_details` | Details on these CVEs? | KB API (bulk, concurrent) |
| `get_new_vulns` | New vulns this week? | KB API (published_after) |
| `get_vulns_by_software` | Vulns in Apache? | KB API (title/diagnosis search) |
| `get_threat_intel` | Ransomware-linked vulns? | KB API (RTI tags) |
| `get_asset_risk` | Why is this asset risky? | CSAM v2 search |
| `get_tech_debt` | EOL systems? | CSAM v2 (lifecycle filters) |
| `get_cloud_risk` | Cloud posture? | CloudView connectors + evaluations |
| `get_image_vulns` | Container vulnerabilities? | Container Security API |

## Architecture: Single File, No Framework

The entire server is one Python file (`qualys_mcp.py`). No web framework, no ORM, no dependencies beyond `fastmcp`. This was intentional:

```
qualys_mcp.py (~1,400 lines)
├── Auth layer (JWT bearer tokens + Basic Auth)
├── API helpers (api_get, csam_count, csam_search)
├── Data parsers (XML for KB, JSON for Gateway)
├── Caching (KB cache, detection cache, bearer token cache)
├── Concurrency (_run_concurrent for parallel API calls)
└── 12 MCP tools (@mcp.tool() decorated functions)
```

**Why single-file?** Distribution. The server installs with `uvx qualys-mcp` or `pip install qualys-mcp`. No build step, no config files, no migrations. Add four environment variables and it works.

### Dual API Authentication

Qualys has two API surfaces with different auth:

```python
def api_get(url, gateway=False, timeout=30):
    req = Request(url)
    if gateway:
        token = get_bearer_token()  # JWT from /auth endpoint
        req.add_header('Authorization', f'Bearer {token}')
    else:
        req.add_header('Authorization', f'Basic {BASIC_AUTH}')
    ...
```

- **Classic API** (`qualysapi.*`): Basic Auth, XML responses. Used for KB (vulnerability data).
- **Gateway API** (`gateway.*`): JWT Bearer tokens (refreshed every 3.5 hours), JSON responses. Used for CSAM (assets), CloudView, Container Security.

The server handles token lifecycle automatically — users never see auth complexity.

### Concurrent API Calls

Most tools need data from multiple sources. Sequential calls would be too slow. We use `ThreadPoolExecutor` to parallelize:

```python
def _run_concurrent(**tasks):
    results = {}
    with ThreadPoolExecutor(max_workers=min(len(tasks), 8)) as executor:
        futures = {executor.submit(fn): name for name, fn in tasks.items()}
        for future in as_completed(futures):
            results[futures[future]] = future.result()
    return results
```

Example: `get_security_posture` makes 8 API calls concurrently — asset counts at multiple risk tiers, container images, running containers — all in a single round-trip.

### Multi-Tier Asset Ranking

A subtle problem: CSAM's search API doesn't sort results. If you search for `truRisk > 500`, you might get assets with score 501 instead of the 1000s. We solve this by searching multiple tiers and merging:

```python
# Search at multiple risk tiers to get actual highest-risk assets
assets_900 = csam_search([...truRisk > 900...])
assets_700 = csam_search([...truRisk > 700...])

# Merge, deduplicate, sort by actual risk score
seen = set()
high_risk = []
for asset in assets_900 + assets_700:
    aid = asset.get('assetId')
    if aid not in seen:
        seen.add(aid)
        high_risk.append(asset)
high_risk.sort(key=lambda a: int(a.get('riskScore') or 0), reverse=True)
```

### KB API: Threat Intelligence Extraction

The Qualys Knowledge Base API returns rich threat intelligence data embedded in XML:

```xml
<VULN>
  <QID>379548</QID>
  <TITLE>xz Utils Backdoor</TITLE>
  <THREAT_INTELLIGENCE>
    <THREAT_INTEL>Active_Attacks</THREAT_INTEL>
    <THREAT_INTEL>Exploit_Public</THREAT_INTEL>
    <THREAT_INTEL>Ransomware</THREAT_INTEL>
    <THREAT_INTEL>Cisa_Known_Exploited_Vulns</THREAT_INTEL>
  </THREAT_INTELLIGENCE>
</VULN>
```

We parse and expose these RTI tags across multiple tools. `get_threat_intel` supports filtering by any tag: Ransomware, Active_Attacks, Exploit_Public, Cisa_Known_Exploited_Vulns, Easy_Exploit, Wormable, and more.

### Bulk CVE Lookup with Concurrency

`get_cve_details` accepts comma-separated CVEs and fetches them all concurrently:

```python
@mcp.tool()
def get_cve_details(cves: str) -> dict:
    cve_list = [c.strip() for c in cves.split(',') if c.strip()]

    def fetch_cve(cve):
        qids = get_cve_qids(cve)      # KB API: CVE → QID mapping
        kb_data = get_kb_batch(qids)    # KB API: QID → details (cached)
        # Aggregate severity, threat intel, patches across all QIDs
        ...

    tasks = {cve: (lambda c=cve: fetch_cve(c)) for cve in cve_list[:20]}
    fetched = _run_concurrent(**tasks)
```

Up to 20 CVEs in a single call. The KB cache means repeated lookups are instant.

## Caching Strategy

Three cache layers, no external dependencies:

```python
KB_CACHE = {}           # QID → parsed vuln data (persists for session)
DETECTION_CACHE = {}    # severity_limit_qds → detections (5-minute TTL)
BEARER_TOKEN = None     # JWT token (3.5-hour TTL, auto-refresh)
```

The KB cache is particularly effective — vulnerability data rarely changes, so every `investigate_cve` or `get_cve_details` call benefits from prior lookups.

## Deployment

```json
{
  "mcpServers": {
    "qualys": {
      "command": "uvx",
      "args": ["qualys-mcp"],
      "env": {
        "QUALYS_USERNAME": "your-username",
        "QUALYS_PASSWORD": "your-password",
        "QUALYS_BASE_URL": "qualysapi.qg2.apps.qualys.com",
        "QUALYS_GATEWAY_URL": "gateway.qg2.apps.qualys.com"
      }
    }
  }
}
```

That's it. No build step. No Docker. No database. `uvx` handles installation and execution.

For self-signed certificate environments (common in Qualys POD deployments), add `"QUALYS_SSL_VERIFY": "false"`.

## What We Learned

1. **Fewer tools, better answers.** 12 well-designed tools beat 60 API wrappers. The AI picks the right tool almost every time.
2. **Concurrency is essential.** Security questions need data from multiple sources. Sequential calls are too slow for interactive use.
3. **Cache aggressively.** Vulnerability KB data doesn't change often. Cache it.
4. **Return answers, not data.** Tools should compute severity breakdowns, risk rankings, and actionable summaries — not dump raw API responses.
5. **Single-file distribution wins.** `uvx qualys-mcp` beats `git clone && docker build && docker run`.

---

*Built with Python + FastMCP | 12 tools*

*qualys-mcp is an independent open-source project and is not affiliated with or endorsed by Qualys, Inc.*

*Copyright (c) 2026 Andrew Nelson. MIT License.*
