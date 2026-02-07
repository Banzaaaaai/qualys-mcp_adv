#!/usr/bin/env python3
"""Qualys MCP Server - Pure Python implementation using FastMCP"""

import os
import sys
import json
import ssl
import base64
from urllib.request import Request, urlopen
from urllib.parse import urlencode, quote
from urllib.error import HTTPError, URLError
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from fastmcp import FastMCP

mcp = FastMCP("qualys-mcp")

USERNAME = os.environ.get('QUALYS_USERNAME', '')
PASSWORD = os.environ.get('QUALYS_PASSWORD', '')

def normalize_url(url):
    url = url.strip().rstrip('/')
    if url and not url.startswith('http'):
        url = f"https://{url}"
    return url

BASE_URL = normalize_url(os.environ.get('QUALYS_BASE_URL', ''))
GATEWAY_URL = normalize_url(os.environ.get('QUALYS_GATEWAY_URL', ''))
BASIC_AUTH = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
BEARER_TOKEN = None
BEARER_TOKEN_TIME = None
KB_CACHE = {}
DETECTION_CACHE = {}
DETECTION_CACHE_TIME = None

AUTH_ERROR = None

# SSL context for environments with self-signed certificates
SSL_CTX = None
if os.environ.get('QUALYS_SSL_VERIFY', '').lower() in ('0', 'false', 'no'):
    SSL_CTX = ssl.create_default_context()
    SSL_CTX.check_hostname = False
    SSL_CTX.verify_mode = ssl.CERT_NONE

def _open(req, timeout=30):
    """urlopen wrapper that handles SSL context for self-signed certs."""
    return urlopen(req, timeout=timeout, context=SSL_CTX)

def _log(msg):
    """Log to stderr (visible in MCP server logs, not in protocol output)."""
    print(f"[qualys-mcp] {msg}", file=sys.stderr)


def get_bearer_token():
    """Get bearer token, refreshing if expired (tokens last ~4 hours)."""
    global BEARER_TOKEN, BEARER_TOKEN_TIME, AUTH_ERROR
    # Refresh if older than 3.5 hours
    if BEARER_TOKEN and BEARER_TOKEN_TIME:
        age = (datetime.now(timezone.utc) - BEARER_TOKEN_TIME).total_seconds()
        if age < 12600:  # 3.5 hours
            return BEARER_TOKEN
        _log("Bearer token expired, refreshing...")
    try:
        auth_data = urlencode({'username': USERNAME, 'password': PASSWORD, 'token': 'true'}).encode()
        req = Request(f"{GATEWAY_URL}/auth", data=auth_data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        with _open(req, timeout=30) as resp:
            BEARER_TOKEN = resp.read().decode().strip()
            BEARER_TOKEN_TIME = datetime.now(timezone.utc)
            AUTH_ERROR = None
            return BEARER_TOKEN
    except Exception as e:
        AUTH_ERROR = str(e)
        _log(f"Auth error: {e}")
        return None


def api_get(url, gateway=False, timeout=30):
    req = Request(url)
    if gateway:
        token = get_bearer_token()
        req.add_header('Authorization', f'Bearer {token}' if token else f'Basic {BASIC_AUTH}')
    else:
        req.add_header('Authorization', f'Basic {BASIC_AUTH}')
    req.add_header('X-Requested-With', 'qualys-mcp')
    try:
        with _open(req, timeout=timeout) as resp:
            return resp.read()
    except HTTPError as e:
        _log(f"API error {e.code}: {url.split('?')[0]}")
        return None
    except URLError as e:
        _log(f"Connection error: {e.reason}")
        return None
    except Exception as e:
        _log(f"Request failed: {e}")
        return None


def get_detections(severity=5, limit=200, use_cache=True, days=30, qds_min=0):
    """Get VMDR detections with hostname and QDS. Uses 5-minute cache.
    Best practices: filter_superseded_qids, vm_processed_after, qds_min.
    Note: VMDR classic API is slow (~2min) for large environments."""
    global DETECTION_CACHE, DETECTION_CACHE_TIME

    cache_key = f"{severity}_{limit}_{qds_min}"
    now = datetime.now(timezone.utc)

    if use_cache and cache_key in DETECTION_CACHE and DETECTION_CACHE_TIME:
        age = (now - DETECTION_CACHE_TIME).total_seconds()
        if age < 300:  # 5-minute cache
            return DETECTION_CACHE[cache_key]

    after_date = (now - timedelta(days=days)).strftime('%Y-%m-%d')
    url = (
        f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/?action=list"
        f"&severities={severity}&truncation_limit={limit}&status=Active"
        f"&show_qds=1&filter_superseded_qids=1"
        f"&vm_processed_after={after_date}"
    )
    if qds_min > 0:
        url += f"&qds_min={qds_min}"

    data = api_get(url, timeout=180)
    if not data:
        return []
    dets = []
    try:
        root = ET.fromstring(data)
        for host in root.findall('.//HOST'):
            hid = host.findtext('ID', '')
            ip = host.findtext('IP', '')
            hostname = host.findtext('DNS', '')
            for d in host.findall('.//DETECTION'):
                qds_el = d.find('QDS')
                qds = 0
                if qds_el is not None and qds_el.text:
                    try:
                        qds = int(qds_el.text)
                    except ValueError:
                        pass
                dets.append({
                    'host_id': hid, 'ip': ip, 'hostname': hostname,
                    'qid': int(d.findtext('QID', '0')),
                    'severity': int(d.findtext('SEVERITY', '0')),
                    'status': d.findtext('STATUS', ''),
                    'qds': qds,
                    'first_found': d.findtext('FIRST_FOUND_DATETIME', ''),
                })
    except ET.ParseError as e:
        _log(f"XML parse error in detections: {e}")

    DETECTION_CACHE[cache_key] = dets
    DETECTION_CACHE_TIME = now
    return dets


def get_host_detections(host_id, severity=4, days=30):
    """Get detections for a specific host by ID."""
    after_date = (datetime.now(timezone.utc) - timedelta(days=days)).strftime('%Y-%m-%d')
    data = api_get(
        f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/?action=list"
        f"&ids={host_id}&severities={severity}&show_qds=1&filter_superseded_qids=1"
        f"&vm_processed_after={after_date}",
        timeout=120
    )
    if not data:
        return []
    dets = []
    try:
        root = ET.fromstring(data)
        for host in root.findall('.//HOST'):
            for d in host.findall('.//DETECTION'):
                qds_el = d.find('QDS')
                qds = 0
                if qds_el is not None and qds_el.text:
                    try:
                        qds = int(qds_el.text)
                    except ValueError:
                        pass
                dets.append({
                    'qid': int(d.findtext('QID', '0')),
                    'severity': int(d.findtext('SEVERITY', '0')),
                    'status': d.findtext('STATUS', ''),
                    'qds': qds,
                    'first_found': d.findtext('FIRST_FOUND_DATETIME', ''),
                })
    except ET.ParseError:
        pass
    return dets


def parse_vuln_xml(v):
    """Parse a VULN XML element into a dict"""
    qid = int(v.findtext('QID', '0'))
    # Extract threat intelligence / RTI tags
    threat_intel = []
    ti = v.find('THREAT_INTELLIGENCE')
    if ti is not None:
        for t in ti.findall('THREAT_INTEL'):
            text = (t.text or '').strip()
            if text:
                threat_intel.append(text)
    return {
        'qid': qid,
        'title': v.findtext('TITLE', ''),
        'severity': int(v.findtext('SEVERITY_LEVEL', '0')),
        'cves': [c.findtext('ID', '') for c in v.findall('.//CVE_LIST/CVE')],
        'solution': v.findtext('SOLUTION', ''),
        'diagnosis': v.findtext('DIAGNOSIS', ''),
        'patch_available': v.findtext('PATCHABLE', '0') == '1',
        'threat_intel': threat_intel,
        'ransomware': 'Ransomware' in threat_intel,
    }


def get_kb(qid):
    """Get KB entry for a single QID (uses cache)"""
    if qid in KB_CACHE:
        return KB_CACHE[qid]
    data = api_get(f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&ids={qid}&details=All")
    if not data:
        return None
    try:
        root = ET.fromstring(data)
        v = root.find('.//VULN')
        if v is None:
            return None
        result = parse_vuln_xml(v)
        KB_CACHE[qid] = result
        return result
    except ET.ParseError:
        return None


def get_kb_batch(qids):
    """Get KB entries for multiple QIDs in one API call (uses cache)"""
    if not qids:
        return {}

    uncached = [q for q in qids if q not in KB_CACHE]

    if uncached:
        # Fetch in batches of 50
        for i in range(0, len(uncached), 50):
            batch = uncached[i:i+50]
            ids_str = ','.join(map(str, batch))
            data = api_get(f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&ids={ids_str}&details=All", timeout=60)
            if data:
                try:
                    root = ET.fromstring(data)
                    for v in root.findall('.//VULN'):
                        parsed = parse_vuln_xml(v)
                        KB_CACHE[parsed['qid']] = parsed
                except ET.ParseError:
                    pass

    return {q: KB_CACHE.get(q) for q in qids}


def get_cve_qids(cve):
    data = api_get(f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&details=All&cve={cve}", timeout=60)
    if not data:
        return []
    try:
        result = []
        for v in ET.fromstring(data).findall('.//VULN'):
            qid = v.findtext('QID')
            if qid:
                parsed = parse_vuln_xml(v)
                KB_CACHE[parsed['qid']] = parsed  # Cache while we have it
                result.append(int(qid))
        return result
    except ET.ParseError:
        return []


def csam_count(filters=None):
    """Count assets with optional structured filters. Fast (~0.2s).
    filters: list of {"field": "...", "operator": "...", "value": "..."} dicts
    """
    token = get_bearer_token()
    url = f"{GATEWAY_URL}/rest/2.0/count/am/asset"
    body = json.dumps({"filters": filters}) if filters else "{}"
    req = Request(url, data=body.encode(), method='POST')
    req.add_header('Authorization', f'Bearer {token}' if token else f'Basic {BASIC_AUTH}')
    req.add_header('Content-Type', 'application/json')
    req.add_header('Accept', 'application/json')
    req.add_header('X-Requested-With', 'qualys-mcp')
    try:
        with _open(req, timeout=30) as resp:
            return json.loads(resp.read()).get('count', 0)
    except Exception:
        return 0


def csam_search(filters=None, limit=100, fields=None):
    """Search assets with optional structured filters. Returns list of assets.
    filters: list of {"field": "...", "operator": "...", "value": "..."} dicts
    fields: comma-separated includeFields (e.g. "operatingSystem,hardware")
    """
    token = get_bearer_token()
    url = f"{GATEWAY_URL}/rest/2.0/search/am/asset?pageSize={limit}"
    if fields:
        url += f"&includeFields={fields}"
    body = json.dumps({"filters": filters}) if filters else "{}"
    req = Request(url, data=body.encode(), method='POST')
    req.add_header('Authorization', f'Bearer {token}' if token else f'Basic {BASIC_AUTH}')
    req.add_header('Content-Type', 'application/json')
    req.add_header('Accept', 'application/json')
    req.add_header('X-Requested-With', 'qualys-mcp')
    try:
        with _open(req, timeout=30) as resp:
            return json.loads(resp.read()).get('assetListData', {}).get('asset', [])
    except Exception as e:
        _log(f"csam_search error: {e}")
        return []


def get_asset_by_id(asset_id):
    """Get a single asset by ID using CSAM v2 (fast, targeted)."""
    assets = csam_search(
        filters=[{"field": "asset.id", "operator": "EQUALS", "value": str(asset_id)}],
        limit=1
    )
    return assets[0] if assets else None


def get_assets(limit=100, filters=None):
    """Search assets using CSAM v2 structured filters."""
    return csam_search(filters=filters, limit=limit)


def get_asset_count():
    """Fast total asset count."""
    return csam_count()


def is_eol_stage(stage):
    """Check if stage indicates EOL/EOS status"""
    if not stage:
        return False
    s = stage.upper()
    return ('EOL' in s or 'EOS' in s) and s != 'NOT APPLICABLE'


def get_images(limit=100, severity=None):
    url = f"{GATEWAY_URL}/csapi/v1.3/images?pageSize={limit}"
    if severity:
        url += f"&filter=vulnerabilities.severity:{severity}"
    data = api_get(url, gateway=True)
    try:
        return json.loads(data).get('data', []) if data else []
    except json.JSONDecodeError:
        return []


def get_containers(limit=100):
    data = api_get(f"{GATEWAY_URL}/csapi/v1.3/containers?pageSize={limit}&filter=state:RUNNING", gateway=True)
    try:
        return json.loads(data).get('data', []) if data else []
    except json.JSONDecodeError:
        return []


def get_connectors(provider='aws', limit=50):
    data = api_get(f"{GATEWAY_URL}/cloudview-api/rest/v1/{provider}/connectors?pageSize={limit}", gateway=True)
    try:
        return json.loads(data).get('content', []) if data else []
    except json.JSONDecodeError:
        return []


def get_evaluations(account_id, provider='aws', limit=500):
    data = api_get(f"{GATEWAY_URL}/cloudview-api/rest/v1/{provider}/evaluations/{account_id}?pageSize={limit}", gateway=True)
    try:
        return json.loads(data).get('content', []) if data else []
    except json.JSONDecodeError:
        return []


def get_cdr(days=7, limit=100):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    data = api_get(f"{GATEWAY_URL}/cdr-api/rest/v1/findings/?startAt={start.isoformat()}Z&endAt={end.isoformat()}Z&limit={limit}", gateway=True)
    try:
        return json.loads(data).get('content', []) if data else []
    except json.JSONDecodeError:
        return []


def get_image_details(image_id):
    data = api_get(f"{GATEWAY_URL}/csapi/v1.3/images/{image_id}", gateway=True)
    try:
        return json.loads(data) if data else None
    except json.JSONDecodeError:
        return None


def get_image_vulns_api(image_id):
    data = api_get(f"{GATEWAY_URL}/csapi/v1.3/images/{image_id}/vuln", gateway=True)
    try:
        return json.loads(data).get('data', []) if data else []
    except json.JSONDecodeError:
        return []


def get_certificates(limit=100, days_expiring=None):
    url = f"{GATEWAY_URL}/certview/v1/certificates?pageSize={limit}"
    if days_expiring:
        future = (datetime.now(timezone.utc) + timedelta(days=days_expiring)).strftime('%Y-%m-%d')
        url += f"&filter=validTo:<{future}"
    data = api_get(url, gateway=True)
    try:
        return json.loads(data).get('data', []) if data else []
    except json.JSONDecodeError:
        return []


def get_fim_events(limit=100, days=7):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    data = api_get(f"{BASE_URL}/fim/v2/events?filter=dateTime:[{start.strftime('%Y-%m-%dT%H:%M:%SZ')}...{end.strftime('%Y-%m-%dT%H:%M:%SZ')}]&pageSize={limit}")
    try:
        return json.loads(data).get('data', []) if data else []
    except json.JSONDecodeError:
        return []


def get_edr_events(limit=100, severity=None):
    url = f"{GATEWAY_URL}/edr/v1/events?pageSize={limit}"
    if severity:
        url += f"&filter=severity:{severity}"
    data = api_get(url, gateway=True)
    try:
        return json.loads(data).get('data', []) if data else []
    except json.JSONDecodeError:
        return []


def get_was_findings(limit=100, severity=None):
    url = f"{BASE_URL}/qps/rest/3.0/search/was/finding"
    criteria = "<ServiceRequest><filters><Criteria field=\"status\" operator=\"EQUALS\">ACTIVE</Criteria>"
    if severity:
        criteria += f"<Criteria field=\"severity\" operator=\"EQUALS\">{severity}</Criteria>"
    criteria += f"</filters><preferences><limitResults>{limit}</limitResults></preferences></ServiceRequest>"

    req = Request(url, data=criteria.encode(), method='POST')
    req.add_header('Authorization', f'Basic {BASIC_AUTH}')
    req.add_header('Content-Type', 'text/xml')
    req.add_header('X-Requested-With', 'qualys-mcp')
    try:
        with _open(req, timeout=60) as resp:
            root = ET.fromstring(resp.read())
            findings = []
            for f in root.findall('.//Finding'):
                findings.append({
                    'id': f.findtext('id', ''),
                    'qid': int(f.findtext('qid', '0')),
                    'name': f.findtext('name', ''),
                    'severity': int(f.findtext('severity', '0')),
                    'url': f.findtext('url', ''),
                    'webAppId': f.findtext('webApp/id', ''),
                    'webAppName': f.findtext('webApp/name', '')
                })
            return findings
    except Exception as e:
        _log(f"WAS findings error: {e}")
        return []


def get_criticality(asset):
    """Extract criticality score from asset"""
    crit = asset.get('criticality')
    if isinstance(crit, dict):
        return crit.get('score', 0) or 0
    return crit or 0


def fetch_all_eol(eol_type, limit=1000, max_pages=50):
    """Fetch EOL assets with pagination. eol_type is 'os' or 'hardware'."""
    token = get_bearer_token()
    if eol_type == 'os':
        filters = [{"field": "operatingSystem.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]
    else:
        filters = [{"field": "hardware.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]

    results = []
    seen = set()
    last_id = None

    for _ in range(max_pages):
        if len(results) >= limit:
            break

        url = f"{GATEWAY_URL}/rest/2.0/search/am/asset?pageSize=100"
        if last_id:
            url += f"&lastSeenAssetId={last_id}"

        body = json.dumps({"filters": filters})
        req = Request(url, data=body.encode(), method='POST')
        req.add_header('Authorization', f'Bearer {token}' if token else f'Basic {BASIC_AUTH}')
        req.add_header('Content-Type', 'application/json')
        req.add_header('Accept', 'application/json')
        req.add_header('X-Requested-With', 'qualys-mcp')

        try:
            with _open(req, timeout=30) as resp:
                data = json.loads(resp.read())
                assets = data.get('assetListData', {}).get('asset', [])
                if not assets:
                    break

                for a in assets:
                    aid = a.get('assetId')
                    if aid in seen:
                        continue
                    seen.add(aid)

                    if eol_type == 'os':
                        info = a.get('operatingSystem', {}) or {}
                        name_field = 'os'
                        name_val = info.get('osName', '') or 'Unknown'
                    else:
                        info = a.get('hardware', {}) or {}
                        name_field = 'hardware'
                        name_val = info.get('model', '') or 'Unknown'

                    lifecycle = info.get('lifecycle', {}) or {}
                    stage = lifecycle.get('stage', '')

                    if is_eol_stage(stage):
                        results.append({
                            'assetId': aid,
                            'address': a.get('address', ''),
                            'hostname': a.get('dnsHostName', '') or a.get('dnsName', ''),
                            name_field: name_val,
                            'stage': stage,
                            'criticality': get_criticality(a),
                            'riskScore': a.get('riskScore') or 0
                        })

                if not data.get('hasMore'):
                    break
                last_id = assets[-1].get('assetId')
        except Exception:
            break

    return results[:limit]


# --- Concurrent helper ---
def _run_concurrent(**tasks):
    """Run named tasks concurrently. Returns dict of {name: result}.
    Each task value is a callable (lambda or function).
    """
    results = {}
    with ThreadPoolExecutor(max_workers=min(len(tasks), 8)) as executor:
        futures = {executor.submit(fn): name for name, fn in tasks.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as e:
                _log(f"Concurrent task '{name}' failed: {e}")
                results[name] = None
    return results


@mcp.tool()
def get_weekly_priorities(limit: int = 10) -> dict:
    """Get prioritized security actions for the week. Returns top high-risk assets with TruRisk scores, risk distribution, and container risks. Fast (~5s). Use get_asset_risk(assetId) for per-asset vulnerability details."""
    result = {'summary': {}, 'priorities': [], 'topRiskAssets': []}

    # All fast CSAM v2 queries (~0.2-3s each, run in parallel)
    # Search at multiple risk tiers to ensure we get the actual highest-risk assets
    # (CSAM API doesn't sort results, so a broad >500 search may miss >900 assets)
    concurrent = _run_concurrent(
        total=lambda: csam_count(),
        risk_900=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "900"}]),
        risk_700=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}]),
        risk_500=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "500"}]),
        eol_count=lambda: csam_count([{"field": "operatingSystem.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]),
        assets_900=lambda: csam_search(
            [{"field": "asset.truRisk", "operator": "GREATER", "value": "900"}],
            limit=limit
        ),
        assets_700=lambda: csam_search(
            [{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}],
            limit=limit
        ),
        vuln_imgs=lambda: get_images(50, 5),
        containers=lambda: get_containers(100),
    )

    total = concurrent.get('total') or 0
    risk_900 = concurrent.get('risk_900') or 0
    risk_700 = concurrent.get('risk_700') or 0
    risk_500 = concurrent.get('risk_500') or 0
    eol_count = concurrent.get('eol_count') or 0

    result['summary'] = {
        'totalAssets': total,
        'criticalRisk': risk_900,
        'highRisk': risk_700,
        'elevatedRisk': risk_500,
        'eolSystems': eol_count,
    }

    # Merge assets from multiple tiers, deduplicate, sort by risk
    seen = set()
    high_risk = []
    for asset in (concurrent.get('assets_900') or []) + (concurrent.get('assets_700') or []):
        aid = asset.get('assetId')
        if aid and aid not in seen:
            seen.add(aid)
            high_risk.append(asset)
    high_risk.sort(key=lambda a: int(a.get('riskScore') or 0), reverse=True)
    for i, asset in enumerate(high_risk[:limit]):
        result['topRiskAssets'].append({
            'rank': i + 1,
            'assetId': str(asset.get('assetId', '')),
            'hostId': str(asset.get('hostId') or ''),
            'hostname': asset.get('dnsHostName', '') or asset.get('dnsName', ''),
            'ip': asset.get('address', ''),
            'riskScore': int(asset.get('riskScore') or 0),
            'os': (asset.get('operatingSystem') or {}).get('osName', ''),
            'criticality': get_criticality(asset),
        })

    # Build actionable priorities
    rank = 1
    if risk_900 > 0:
        result['priorities'].append({
            'rank': rank, 'severity': 5,
            'title': f"Remediate {risk_900} critical-risk assets (TruRisk > 900)",
            'action': 'Use get_asset_risk(assetId) for specific vulnerabilities per asset',
        })
        rank += 1

    if risk_700 > 0:
        result['priorities'].append({
            'rank': rank, 'severity': 4,
            'title': f"Address {risk_700} high-risk assets (TruRisk > 700)",
            'action': 'Focus on highest TruRisk scores first',
        })
        rank += 1

    if eol_count > 0:
        result['priorities'].append({
            'rank': rank, 'severity': 4,
            'title': f"Plan upgrades for {eol_count} EOL/EOS systems",
            'action': 'Use get_tech_debt() for full EOL inventory',
        })
        rank += 1

    # Container risks
    vuln_imgs = concurrent.get('vuln_imgs') or []
    containers = concurrent.get('containers') or []
    vuln_img_ids = {img.get('imageId') for img in vuln_imgs}
    at_risk = [c for c in containers if c.get('imageId') in vuln_img_ids]
    if at_risk:
        result['priorities'].append({
            'rank': rank, 'severity': 5,
            'title': f"Update {len(at_risk)} vulnerable containers",
            'action': 'Rebuild container images with patched base images',
        })
        result['summary']['containersAtRisk'] = len(at_risk)

    return result


@mcp.tool()
def investigate_cve(cve: str) -> dict:
    """Investigate if your environment is affected by a specific CVE. Returns QIDs, KB details, severity, and remediation. Fast (~5s)."""
    result = {'cve': cve, 'qids': [], 'severity': 0,
              'title': '', 'patchAvailable': False, 'solution': '',
              'allKbDetails': [], 'threatIntel': [],
              'ransomware': False,
              'summary': {'qidCount': 0, 'patchAvailable': False}}

    # Step 1: CVE -> QIDs + KB data (KB API is fast, ~3s)
    qids = get_cve_qids(cve)
    result['qids'] = qids
    result['summary']['qidCount'] = len(qids)

    if qids:
        # Get KB details for all related QIDs
        kb_data = get_kb_batch(qids[:20])
        max_sev = 0
        all_threat_intel = set()
        for qid in qids:
            kb = kb_data.get(qid)
            if kb:
                if kb.get('severity', 0) > max_sev:
                    max_sev = kb['severity']
                    result['title'] = kb.get('title', '')
                    result['severity'] = kb['severity']
                    result['patchAvailable'] = kb.get('patch_available', False)
                    result['solution'] = kb.get('solution', '')[:500]
                    result['diagnosis'] = kb.get('diagnosis', '')[:300]
                    result['summary']['patchAvailable'] = kb.get('patch_available', False)
                ti = kb.get('threat_intel', [])
                all_threat_intel.update(ti)
                if kb.get('ransomware'):
                    result['ransomware'] = True
                result['allKbDetails'].append({
                    'qid': qid,
                    'title': kb.get('title', ''),
                    'severity': kb.get('severity', 0),
                    'patchAvailable': kb.get('patch_available', False),
                    'cves': kb.get('cves', [])[:5],
                    'threatIntel': ti,
                    'ransomware': kb.get('ransomware', False),
                })

        result['threatIntel'] = sorted(all_threat_intel)
        result['allKbDetails'].sort(key=lambda x: x['severity'], reverse=True)

    return result


@mcp.tool()
def get_security_posture() -> dict:
    """Get overall security health score and stats across assets, vulns, containers, and cloud. Uses fast CSAM v2 counts (~5s)."""
    health = 100
    result = {'healthScore': 0, 'assets': {'total': 0, 'highRisk': 0},
              'vulns': {'critical': 0, 'high': 0}, 'containers': {'total': 0, 'atRisk': 0},
              'cloud': {'accounts': 0, 'failedControls': 0}, 'warnings': []}

    # All fast CSAM v2 count queries (~0.2s each, run in parallel)
    concurrent = _run_concurrent(
        asset_count=lambda: csam_count(),
        risk_900=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "900"}]),
        risk_700=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}]),
        risk_500=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "500"}]),
        eol_os=lambda: csam_count([{"field": "operatingSystem.lifecycle.stage", "operator": "CONTAINS", "value": "EOL"}]),
        images=lambda: get_images(50),
        vuln_images=lambda: get_images(30, 5),
        containers=lambda: get_containers(50),
    )

    # Assets
    total = concurrent.get('asset_count') or 0
    risk_900 = concurrent.get('risk_900') or 0
    risk_700 = concurrent.get('risk_700') or 0
    risk_500 = concurrent.get('risk_500') or 0
    eol_count = concurrent.get('eol_os') or 0
    result['assets']['total'] = total
    result['assets']['highRisk'] = risk_700
    if total > 0:
        health -= min(50, int(risk_700 / total * 100))

    # Risk-based severity (TruRisk ranges as proxy for vuln severity)
    result['vulns']['critical'] = risk_900  # assets with TruRisk > 900
    result['vulns']['high'] = risk_500  # assets with TruRisk > 500
    result['vulns']['eolSystems'] = eol_count
    if risk_900 > 50:
        health -= 20
    elif risk_900 > 10:
        health -= 10

    # Containers
    images = concurrent.get('images') or []
    vuln_images = concurrent.get('vuln_images') or []
    containers = concurrent.get('containers') or []
    result['containers']['total'] = len(images)
    vuln_ids = {i.get('imageId') for i in vuln_images}
    result['containers']['atRisk'] = len([c for c in containers if c.get('imageId') in vuln_ids])

    # Cloud (sequential since needs account ID from connectors)
    try:
        for p in ['aws', 'azure', 'gcp']:
            conns = get_connectors(p, 5)
            if conns:
                result['cloud']['accounts'] += len(conns)
                acc = conns[0].get('awsAccountId') or conns[0].get('azureSubscriptionId') or conns[0].get('gcpProjectId')
                if acc:
                    evals = get_evaluations(acc, p, 50)
                    result['cloud']['failedControls'] += len([e for e in evals if e.get('result') in ['FAIL', 'FAILED']])
    except Exception:
        result['warnings'].append('cloud data unavailable')

    if not result['warnings']:
        del result['warnings']
    result['healthScore'] = max(0, health)
    return result


@mcp.tool()
def get_patch_status(limit: int = 20) -> dict:
    """Get patching coverage - TruRisk distribution and top assets needing remediation. Fast (~5s). Use get_asset_risk(assetId) for per-asset patch details."""
    result = {'coverage': 0, 'assetsTotal': 0, 'riskDistribution': {},
              'highRiskAssets': []}

    # All fast CSAM v2 queries (~0.2-3s each, run in parallel)
    # Search at multiple risk tiers to ensure we get the actual highest-risk assets
    concurrent = _run_concurrent(
        total=lambda: csam_count(),
        risk_900=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "900"}]),
        risk_700=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}]),
        risk_500=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "500"}]),
        risk_100=lambda: csam_count([{"field": "asset.truRisk", "operator": "GREATER", "value": "100"}]),
        assets_900=lambda: csam_search(
            [{"field": "asset.truRisk", "operator": "GREATER", "value": "900"}],
            limit=limit
        ),
        assets_700=lambda: csam_search(
            [{"field": "asset.truRisk", "operator": "GREATER", "value": "700"}],
            limit=limit
        ),
    )

    total = concurrent.get('total') or 0
    risk_900 = concurrent.get('risk_900') or 0
    risk_700 = concurrent.get('risk_700') or 0
    risk_500 = concurrent.get('risk_500') or 0
    risk_100 = concurrent.get('risk_100') or 0
    result['assetsTotal'] = total
    result['riskDistribution'] = {
        'critical_900plus': risk_900,
        'high_700plus': risk_700,
        'elevated_500plus': risk_500,
        'medium_100plus': risk_100,
        'low_under100': total - risk_100,
    }

    # Merge assets from multiple tiers, deduplicate, sort by risk
    seen = set()
    top_risk = []
    for asset in (concurrent.get('assets_900') or []) + (concurrent.get('assets_700') or []):
        aid = asset.get('assetId')
        if aid and aid not in seen:
            seen.add(aid)
            top_risk.append(asset)
    top_risk.sort(key=lambda a: int(a.get('riskScore') or 0), reverse=True)
    for asset in top_risk[:limit]:
        result['highRiskAssets'].append({
            'assetId': str(asset.get('assetId', '')),
            'hostId': str(asset.get('hostId') or ''),
            'hostname': asset.get('dnsHostName', '') or asset.get('dnsName', ''),
            'ip': asset.get('address', ''),
            'riskScore': int(asset.get('riskScore') or 0),
            'os': (asset.get('operatingSystem') or {}).get('osName', ''),
        })

    # Coverage: % of assets with TruRisk < 100 (low risk)
    if total > 0:
        result['coverage'] = round((total - risk_100) / total * 100, 1)

    return result


@mcp.tool()
def get_threat_intel(threat_type: str = "", days: int = 30) -> dict:
    """Get vulnerability threat intelligence from Qualys KB. Shows RTI (Real-Time Threat Indicator) breakdown for recently published vulnerabilities.
    threat_type filters: Ransomware, Malware, Active_Attacks, Exploit_Public, Easy_Exploit, Wormable, Cisa_Known_Exploited_Vulns, Denial_of_Service, Privilege_Escalation, Remote_Code_Execution, Predicted_High_Risk, Unauthenticated_Exploitation.
    Use 'Ransomware' for ransomware-linked vulns, 'Active_Attacks' for actively exploited, 'Exploit_Public' for weaponized exploits, 'Cisa_Known_Exploited_Vulns' for CISA KEV list.
    Default (no filter) shows all RTI types for vulns published in last 30 days (~10s)."""
    from datetime import timedelta
    after = (datetime.now(timezone.utc) - timedelta(days=days)).strftime('%Y-%m-%d')
    result = {'days': days, 'threatFilter': threat_type or 'all',
              'matchingVulns': [], 'totalVulns': 0, 'totalWithThreatIntel': 0,
              'threatBreakdown': {}, 'summary': ''}

    data = api_get(
        f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&details=All"
        f"&published_after={after}",
        timeout=30
    )
    if not data:
        result['summary'] = 'Failed to fetch KB data'
        return result

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        result['summary'] = 'Failed to parse KB data'
        return result

    # Parse all vulns and collect threat intel
    matching = []
    threat_counts = {}
    all_vulns = root.findall('.//VULN')
    ti_count = 0
    for v in all_vulns:
        parsed = parse_vuln_xml(v)
        KB_CACHE[parsed['qid']] = parsed
        ti = parsed.get('threat_intel', [])
        if ti:
            ti_count += 1
        for tag in ti:
            threat_counts[tag] = threat_counts.get(tag, 0) + 1
        # Filter by threat type if specified
        if threat_type:
            if any(threat_type.lower() in t.lower() for t in ti):
                matching.append(parsed)
        elif ti:
            matching.append(parsed)

    result['totalVulns'] = len(all_vulns)
    result['totalWithThreatIntel'] = ti_count
    result['threatBreakdown'] = dict(sorted(threat_counts.items(), key=lambda x: -x[1]))

    # Sort by severity desc, return top entries
    matching.sort(key=lambda x: (-x['severity'], -len(x.get('threat_intel', []))))
    for v in matching[:50]:
        result['matchingVulns'].append({
            'qid': v['qid'],
            'title': v['title'],
            'severity': v['severity'],
            'cves': v.get('cves', [])[:5],
            'patchAvailable': v.get('patch_available', False),
            'threatIntel': v.get('threat_intel', []),
            'ransomware': v.get('ransomware', False),
        })

    filter_label = f"'{threat_type}'" if threat_type else 'any RTI'
    patched = sum(1 for v in matching if v.get('patch_available'))
    result['totalMatching'] = len(matching)
    result['summary'] = (
        f"{len(matching)} vulns with {filter_label} out of {len(all_vulns)} "
        f"published in last {days} days. {patched} have patches available."
    )
    return result


@mcp.tool()
def get_new_vulns(days: int = 7) -> dict:
    """Get newly published vulnerabilities from the Qualys Knowledge Base. Returns CVEs, severity, RTI threat tags, and patch status for vulns published in the last N days. Fast (~5s for 7 days). Use days=1 for today's vulns, days=30 for the last month."""
    after = (datetime.now(timezone.utc) - timedelta(days=days)).strftime('%Y-%m-%d')
    result = {'days': days, 'publishedAfter': after, 'totalVulns': 0,
              'severityBreakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
              'withPatch': 0, 'withThreatIntel': 0, 'vulns': []}

    data = api_get(
        f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&details=All"
        f"&published_after={after}",
        timeout=30
    )
    if not data:
        result['error'] = 'Failed to fetch KB data'
        return result

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        result['error'] = 'Failed to parse KB data'
        return result

    all_vulns = []
    for v in root.findall('.//VULN'):
        parsed = parse_vuln_xml(v)
        KB_CACHE[parsed['qid']] = parsed
        all_vulns.append(parsed)

        sev = parsed['severity']
        if sev >= 5:
            result['severityBreakdown']['critical'] += 1
        elif sev >= 4:
            result['severityBreakdown']['high'] += 1
        elif sev >= 3:
            result['severityBreakdown']['medium'] += 1
        else:
            result['severityBreakdown']['low'] += 1

        if parsed.get('patch_available'):
            result['withPatch'] += 1
        if parsed.get('threat_intel'):
            result['withThreatIntel'] += 1

    result['totalVulns'] = len(all_vulns)

    # Sort by severity desc, then by threat intel count
    all_vulns.sort(key=lambda x: (-x['severity'], -len(x.get('threat_intel', []))))
    for v in all_vulns[:100]:
        result['vulns'].append({
            'qid': v['qid'],
            'title': v['title'],
            'severity': v['severity'],
            'cves': v.get('cves', [])[:5],
            'patchAvailable': v.get('patch_available', False),
            'threatIntel': v.get('threat_intel', []),
            'ransomware': v.get('ransomware', False),
        })

    return result


@mcp.tool()
def get_vulns_by_software(software: str) -> dict:
    """Search for vulnerabilities affecting a specific software, vendor, or product. Searches Qualys KB by title and diagnosis text. Examples: 'Apache', 'F5 BIG-IP', 'OpenSSL', 'Microsoft Exchange'. Fast (~5s)."""
    result = {'software': software, 'totalVulns': 0,
              'severityBreakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
              'withPatch': 0, 'vulns': []}

    # KB API doesn't have a server-side software filter, so we search by title
    # Use the most recent vulns (last 90 days) to keep it fast
    after = (datetime.now(timezone.utc) - timedelta(days=90)).strftime('%Y-%m-%d')
    data = api_get(
        f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/?action=list&details=All"
        f"&published_after={after}",
        timeout=30
    )
    if not data:
        result['error'] = 'Failed to fetch KB data'
        return result

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        result['error'] = 'Failed to parse KB data'
        return result

    search_lower = software.lower()
    matching = []
    for v in root.findall('.//VULN'):
        parsed = parse_vuln_xml(v)
        KB_CACHE[parsed['qid']] = parsed
        title = parsed.get('title', '').lower()
        diagnosis = parsed.get('diagnosis', '').lower()
        if search_lower in title or search_lower in diagnosis:
            matching.append(parsed)

    result['totalVulns'] = len(matching)
    for v in matching:
        sev = v['severity']
        if sev >= 5:
            result['severityBreakdown']['critical'] += 1
        elif sev >= 4:
            result['severityBreakdown']['high'] += 1
        elif sev >= 3:
            result['severityBreakdown']['medium'] += 1
        else:
            result['severityBreakdown']['low'] += 1
        if v.get('patch_available'):
            result['withPatch'] += 1

    matching.sort(key=lambda x: (-x['severity'], -len(x.get('threat_intel', []))))
    for v in matching[:100]:
        result['vulns'].append({
            'qid': v['qid'],
            'title': v['title'],
            'severity': v['severity'],
            'cves': v.get('cves', [])[:5],
            'patchAvailable': v.get('patch_available', False),
            'threatIntel': v.get('threat_intel', []),
            'ransomware': v.get('ransomware', False),
        })

    return result


@mcp.tool()
def get_cve_details(cves: str) -> dict:
    """Get details for multiple CVEs at once. Accepts comma-separated CVE IDs (e.g. 'CVE-2021-44228,CVE-2024-3400'). Returns severity, patches, threat intel, and remediation for each. Fast (~5s)."""
    cve_list = [c.strip() for c in cves.split(',') if c.strip()]
    result = {'requested': len(cve_list), 'found': 0, 'cves': []}

    def fetch_cve(cve):
        qids = get_cve_qids(cve)
        if not qids:
            return {'cve': cve, 'found': False}
        kb_data = get_kb_batch(qids[:20])
        max_sev = 0
        best = None
        all_threat_intel = set()
        is_ransomware = False
        all_kb = []
        for qid in qids:
            kb = kb_data.get(qid)
            if kb:
                if kb.get('severity', 0) > max_sev:
                    max_sev = kb['severity']
                    best = kb
                all_threat_intel.update(kb.get('threat_intel', []))
                if kb.get('ransomware'):
                    is_ransomware = True
                all_kb.append({
                    'qid': qid,
                    'title': kb.get('title', ''),
                    'severity': kb.get('severity', 0),
                    'patchAvailable': kb.get('patch_available', False),
                })
        entry = {
            'cve': cve, 'found': True, 'qids': qids,
            'severity': max_sev,
            'title': best.get('title', '') if best else '',
            'patchAvailable': best.get('patch_available', False) if best else False,
            'solution': (best.get('solution', '') if best else '')[:500],
            'diagnosis': (best.get('diagnosis', '') if best else '')[:300],
            'threatIntel': sorted(all_threat_intel),
            'ransomware': is_ransomware,
            'kbEntries': all_kb,
        }
        return entry

    # Fetch all CVEs concurrently
    tasks = {cve: (lambda c=cve: fetch_cve(c)) for cve in cve_list[:20]}
    fetched = _run_concurrent(**tasks)

    for cve in cve_list[:20]:
        entry = fetched.get(cve)
        if entry:
            if entry.get('found'):
                result['found'] += 1
            result['cves'].append(entry)

    result['cves'].sort(key=lambda x: (-x.get('severity', 0), x['cve']))
    return result


def get_compliance_gaps(limit: int = 20) -> dict:
    """Get top failing compliance controls that could fail audits."""
    result = {'passRate': 0, 'failingControls': 0, 'topFailing': []}

    fails = {}
    passes = 0
    for p in ['aws', 'azure', 'gcp']:
        conns = get_connectors(p, 10)
        if conns:
            acc = conns[0].get('awsAccountId') or conns[0].get('azureSubscriptionId') or conns[0].get('gcpProjectId')
            if acc:
                for e in get_evaluations(acc, p, 500):
                    if e.get('result') in ['FAIL', 'FAILED']:
                        cid = e.get('controlId', '')
                        fails[cid] = fails.get(cid, 0) + 1
                    elif e.get('result') in ['PASS', 'PASSED']:
                        passes += 1

    result['failingControls'] = len(fails)
    result['topFailing'] = [{'controlId': c, 'failCount': n} for c, n in sorted(fails.items(), key=lambda x: x[1], reverse=True)[:limit]]

    total = sum(fails.values()) + passes
    result['passRate'] = round(passes / total * 100, 1) if total else 0
    return result


@mcp.tool()
def get_cloud_risk(limit: int = 20) -> dict:
    """Get cloud security posture across AWS, Azure, GCP - accounts, failed controls, and threats."""
    result = {'accounts': [], 'failedControls': [], 'threats': [], 'stats': {'total': 0, 'critical': 0}}

    for p in ['aws', 'azure', 'gcp']:
        for c in get_connectors(p, 50):
            acc = c.get('awsAccountId') or c.get('azureSubscriptionId') or c.get('gcpProjectId', '')
            result['accounts'].append({'id': acc, 'provider': p.upper(), 'name': c.get('name', '')})

    result['stats']['total'] = len(result['accounts'])

    if result['accounts']:
        acc = result['accounts'][0]
        fails = {}
        for e in get_evaluations(acc['id'], acc['provider'].lower(), 500):
            if e.get('result') in ['FAIL', 'FAILED']:
                cid = e.get('controlId', '')
                fails[cid] = fails.get(cid, 0) + 1
        result['failedControls'] = [{'id': c, 'count': n} for c, n in sorted(fails.items(), key=lambda x: x[1], reverse=True)[:limit]]

    for f in get_cdr(7, limit):
        sev = str(f.get('severity', ''))
        if sev in ['CRITICAL', '5']:
            result['stats']['critical'] += 1
        result['threats'].append({'severity': sev, 'category': f.get('category', ''), 'resource': f.get('resourceId', '')})

    return result


@mcp.tool()
def get_asset_risk(asset_id: str) -> dict:
    """Get risk summary for a specific asset - TruRisk score, OS, criticality, software details. Fast (~3s). Accepts CSAM assetId."""
    result = {'assetId': asset_id, 'riskScore': 0, 'software': [], 'eolSoftware': []}

    asset = get_asset_by_id(asset_id)
    if asset:
        result['ip'] = asset.get('address', '')
        result['hostname'] = asset.get('dnsHostName', '') or asset.get('dnsName', '')
        result['riskScore'] = int(asset.get('riskScore') or 0)
        result['os'] = (asset.get('operatingSystem') or {}).get('osName', '')
        result['criticality'] = get_criticality(asset)
        result['hostId'] = str(asset.get('hostId') or '')
        result['lastUpdated'] = asset.get('lastModifiedDate', '')
        result['provider'] = (asset.get('cloudProvider') or {}).get('aws', {}).get('ec2', {}).get('region', {}).get('name', '') if asset.get('cloudProvider') else ''

        # Extract software info if available
        sw_list = asset.get('softwareListData', {})
        if sw_list and isinstance(sw_list, dict):
            for sw in (sw_list.get('software') or [])[:30]:
                name = sw.get('fullName') or sw.get('productName') or sw.get('name') or ''
                sw_info = {
                    'name': name.strip(),
                    'version': sw.get('version', ''),
                    'category': sw.get('category', ''),
                }
                lifecycle = (sw.get('lifecycle') or {})
                if lifecycle.get('stage') and lifecycle['stage'] not in ('Unknown', 'Not Applicable', 'OS Dependent'):
                    sw_info['lifecycleStage'] = lifecycle['stage']
                    if is_eol_stage(lifecycle['stage']):
                        result['eolSoftware'].append(sw_info)
                result['software'].append(sw_info)

        # Extract OS lifecycle
        os_info = asset.get('operatingSystem') or {}
        os_lifecycle = (os_info.get('lifecycle') or {})
        if os_lifecycle.get('stage'):
            result['osLifecycle'] = os_lifecycle['stage']

    return result


@mcp.tool()
def get_tech_debt(limit: int = 100) -> dict:
    """Get EOL/EOS systems sorted by criticality. Default 100 (~25s). Use limit=500 for more (~2min)."""
    max_pages = max(5, (limit // 10) + 2)

    # Run OS and hardware EOL fetches concurrently
    concurrent = _run_concurrent(
        os_eol=lambda: fetch_all_eol('os', limit, max_pages),
        hw_eol=lambda: fetch_all_eol('hardware', limit, max_pages),
    )

    result = {
        'os': concurrent.get('os_eol') or [],
        'hardware': concurrent.get('hw_eol') or [],
    }

    result['os'].sort(key=lambda x: (-x['criticality'], -x['riskScore']))
    result['hardware'].sort(key=lambda x: (-x['criticality'], -x['riskScore']))
    result['summary'] = {'osEOL': len(result['os']), 'hardwareEOL': len(result['hardware'])}

    return result


@mcp.tool()
def get_image_vulns(image_id: str, limit: int = 50) -> dict:
    """Get vulnerabilities for a specific container image. Returns severity breakdown and top vulns."""
    result = {
        'imageId': image_id, 'repo': '', 'tag': '',
        'stats': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0},
        'vulns': []
    }

    # Run image details and vulns concurrently
    concurrent = _run_concurrent(
        img=lambda: get_image_details(image_id),
        vulns=lambda: get_image_vulns_api(image_id),
    )

    img = concurrent.get('img')
    if img:
        result['repo'] = img.get('repo', '')
        result['tag'] = img.get('tag', '')
        result['created'] = img.get('created', '')

    vulns = concurrent.get('vulns') or []
    for v in vulns[:limit]:
        sev = v.get('severity', 0)
        if sev == 5:
            result['stats']['critical'] += 1
        elif sev == 4:
            result['stats']['high'] += 1
        elif sev == 3:
            result['stats']['medium'] += 1
        else:
            result['stats']['low'] += 1

        result['vulns'].append({
            'qid': v.get('qid'), 'cve': v.get('cveId', ''),
            'severity': sev, 'title': v.get('title', ''),
            'fixVersion': v.get('fixedVersion', '')
        })

    result['stats']['total'] = len(vulns)
    result['vulns'] = sorted(result['vulns'], key=lambda x: x['severity'], reverse=True)[:limit]
    return result


def get_expiring_certs(days: int = 30, limit: int = 50) -> dict:
    """Get SSL/TLS certificates expiring within specified days. Default 30 days."""
    result = {
        'days': days,
        'stats': {'expiring': 0, 'expired': 0, 'valid': 0},
        'expiring': [], 'expired': []
    }

    today = datetime.now(timezone.utc)

    certs = get_certificates(limit * 2, days)
    for c in certs:
        cert_info = {
            'id': c.get('id', ''),
            'subject': c.get('subject', {}).get('commonName', ''),
            'issuer': c.get('issuer', {}).get('commonName', ''),
            'validTo': c.get('validTo', ''),
            'hosts': [h.get('hostname', '') for h in c.get('hosts', [])[:5]]
        }

        valid_to = c.get('validTo', '')
        if valid_to:
            try:
                exp_date = datetime.strptime(valid_to[:10], '%Y-%m-%d')
                days_left = (exp_date - today).days
                cert_info['daysUntilExpiry'] = days_left

                if days_left < 0:
                    result['stats']['expired'] += 1
                    if len(result['expired']) < limit:
                        result['expired'].append(cert_info)
                elif days_left <= days:
                    result['stats']['expiring'] += 1
                    if len(result['expiring']) < limit:
                        result['expiring'].append(cert_info)
                else:
                    result['stats']['valid'] += 1
            except ValueError:
                pass

    result['expiring'] = sorted(result['expiring'], key=lambda x: x.get('daysUntilExpiry', 999))
    result['expired'] = sorted(result['expired'], key=lambda x: x.get('daysUntilExpiry', 0))
    return result


def get_threats(days: int = 7, limit: int = 50) -> dict:
    """Get combined threat view from FIM (file integrity), EDR (endpoint), and CDR (cloud detection). Returns recent security events."""
    result = {
        'days': days,
        'stats': {'fim': 0, 'edr': 0, 'cdr': 0, 'critical': 0, 'high': 0},
        'fim': [], 'edr': [], 'cdr': []
    }

    # Run all three sources concurrently
    concurrent = _run_concurrent(
        fim=lambda: get_fim_events(limit, days),
        edr_crit=lambda: get_edr_events(limit, 'Critical'),
        edr_high=lambda: get_edr_events(limit, 'High'),
        cdr=lambda: get_cdr(days, limit),
    )

    fim_events = concurrent.get('fim') or []
    for e in fim_events:
        sev = e.get('severity', '')
        if sev in ['CRITICAL', '5']:
            result['stats']['critical'] += 1
        elif sev in ['HIGH', '4']:
            result['stats']['high'] += 1
        result['fim'].append({
            'action': e.get('action', ''), 'path': e.get('filePath', ''),
            'hostname': e.get('hostname', ''), 'dateTime': e.get('dateTime', ''),
            'severity': sev
        })
    result['stats']['fim'] = len(fim_events)

    edr_events = (concurrent.get('edr_crit') or []) + (concurrent.get('edr_high') or [])
    for e in edr_events[:limit]:
        sev = e.get('severity', '')
        if sev == 'Critical':
            result['stats']['critical'] += 1
        elif sev == 'High':
            result['stats']['high'] += 1
        result['edr'].append({
            'type': e.get('eventType', ''), 'process': e.get('processName', ''),
            'hostname': e.get('hostname', ''), 'dateTime': e.get('dateTime', ''),
            'severity': sev
        })
    result['stats']['edr'] = len(edr_events)

    cdr_findings = concurrent.get('cdr') or []
    for f in cdr_findings:
        sev = str(f.get('severity', ''))
        if sev in ['CRITICAL', '5']:
            result['stats']['critical'] += 1
        elif sev in ['HIGH', '4']:
            result['stats']['high'] += 1
        result['cdr'].append({
            'category': f.get('category', ''), 'resource': f.get('resourceId', ''),
            'provider': f.get('cloudProvider', ''), 'dateTime': f.get('createdAt', ''),
            'severity': sev
        })
    result['stats']['cdr'] = len(cdr_findings)

    return result


def get_webapp_vulns(severity: int = 4, limit: int = 50) -> dict:
    """Get web application vulnerabilities from WAS scans. Default severity 4+ (high/critical)."""
    result = {
        'minSeverity': severity,
        'stats': {'critical': 0, 'high': 0, 'medium': 0, 'total': 0, 'webApps': 0},
        'vulns': [], 'byWebApp': []
    }

    findings = get_was_findings(limit * 2, severity)
    webapp_vulns = {}

    for f in findings:
        sev = f.get('severity', 0)
        if sev >= 5:
            result['stats']['critical'] += 1
        elif sev >= 4:
            result['stats']['high'] += 1
        elif sev >= 3:
            result['stats']['medium'] += 1

        webapp_id = f.get('webAppId', '')
        webapp_name = f.get('webAppName', '')
        if webapp_id:
            if webapp_id not in webapp_vulns:
                webapp_vulns[webapp_id] = {'id': webapp_id, 'name': webapp_name, 'critical': 0, 'high': 0, 'total': 0}
            webapp_vulns[webapp_id]['total'] += 1
            if sev >= 5:
                webapp_vulns[webapp_id]['critical'] += 1
            elif sev >= 4:
                webapp_vulns[webapp_id]['high'] += 1

        result['vulns'].append({
            'qid': f.get('qid'), 'name': f.get('name', ''),
            'severity': sev, 'url': f.get('url', ''), 'webApp': webapp_name
        })

    result['stats']['total'] = len(findings)
    result['stats']['webApps'] = len(webapp_vulns)
    result['vulns'] = sorted(result['vulns'], key=lambda x: x['severity'], reverse=True)[:limit]
    result['byWebApp'] = sorted(webapp_vulns.values(), key=lambda x: (x['critical'], x['high'], x['total']), reverse=True)[:20]
    return result


def cache_status(clear: bool = False) -> dict:
    """Show cache stats or clear all caches. Use clear=True to reset caches."""
    global DETECTION_CACHE_TIME

    result = {
        'kb_entries': len(KB_CACHE),
        'detection_entries': len(DETECTION_CACHE),
        'detection_cache_age_seconds': None,
        'bearer_token_age_seconds': None,
    }

    if DETECTION_CACHE_TIME:
        result['detection_cache_age_seconds'] = int((datetime.now(timezone.utc) - DETECTION_CACHE_TIME).total_seconds())
    if BEARER_TOKEN_TIME:
        result['bearer_token_age_seconds'] = int((datetime.now(timezone.utc) - BEARER_TOKEN_TIME).total_seconds())

    if clear:
        KB_CACHE.clear()
        DETECTION_CACHE.clear()
        DETECTION_CACHE_TIME = None
        result['cleared'] = True
        result['kb_entries'] = 0
        result['detection_entries'] = 0
        result['detection_cache_age_seconds'] = None

    return result


def main():
    mcp.run()


if __name__ == "__main__":
    main()
