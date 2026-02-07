#!/usr/bin/env python3
"""Qualys MCP Server - Pure Python implementation using FastMCP"""

import os
import sys
import json
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
        with urlopen(req, timeout=30) as resp:
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
        with urlopen(req, timeout=timeout) as resp:
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


def get_host_detections(host_id, severity=4):
    """Get detections for a specific host by ID (targeted, fast)."""
    data = api_get(
        f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/?action=list"
        f"&ids={host_id}&severities={severity}&show_qds=1&filter_superseded_qids=1",
        timeout=60
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
    return {
        'qid': qid,
        'title': v.findtext('TITLE', ''),
        'severity': int(v.findtext('SEVERITY_LEVEL', '0')),
        'cves': [c.findtext('ID', '') for c in v.findall('.//CVE_LIST/CVE')],
        'solution': v.findtext('SOLUTION', ''),
        'diagnosis': v.findtext('DIAGNOSIS', ''),
        'patch_available': v.findtext('PATCHABLE', '0') == '1'
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


def get_asset_by_id(asset_id):
    """Get a single asset by ID using CSAM v2 POST endpoint (fast, targeted)."""
    token = get_bearer_token()
    url = f"{GATEWAY_URL}/rest/2.0/search/am/asset?pageSize=1"
    body = json.dumps({"filter": f"assetId:{asset_id}"})
    req = Request(url, data=body.encode(), method='POST')
    req.add_header('Authorization', f'Bearer {token}' if token else f'Basic {BASIC_AUTH}')
    req.add_header('Content-Type', 'application/json')
    req.add_header('X-Requested-With', 'qualys-mcp')
    try:
        with urlopen(req, timeout=30) as resp:
            assets = json.loads(resp.read()).get('assetListData', {}).get('asset', [])
            return assets[0] if assets else None
    except Exception as e:
        _log(f"get_asset_by_id error: {e}")
        return None


def get_assets(limit=100, qql=None):
    """Search assets using CSAM v2 POST endpoint."""
    token = get_bearer_token()
    url = f"{GATEWAY_URL}/rest/2.0/search/am/asset?pageSize={limit}"
    body = json.dumps({"filter": qql}) if qql else "{}"
    req = Request(url, data=body.encode(), method='POST')
    req.add_header('Authorization', f'Bearer {token}' if token else f'Basic {BASIC_AUTH}')
    req.add_header('Content-Type', 'application/json')
    req.add_header('X-Requested-With', 'qualys-mcp')
    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read()).get('assetListData', {}).get('asset', [])
    except Exception as e:
        _log(f"get_assets error: {e}")
        return []


def get_asset_count():
    """Fast asset count using dedicated count endpoint."""
    token = get_bearer_token()
    url = f"{GATEWAY_URL}/rest/2.0/count/am/asset"
    req = Request(url, data=b'{}', method='POST')
    req.add_header('Authorization', f'Bearer {token}' if token else f'Basic {BASIC_AUTH}')
    req.add_header('Content-Type', 'application/json')
    req.add_header('X-Requested-With', 'qualys-mcp')
    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read()).get('count', 0)
    except Exception:
        return 0


def get_eol_count(qql_filter):
    """Get count of assets matching QQL filter (fast, no pagination)"""
    token = get_bearer_token()
    url = f"{GATEWAY_URL}/rest/2.0/count/am/asset"
    filter_body = json.dumps({"filter": qql_filter})
    req = Request(url, data=filter_body.encode(), method='POST')
    req.add_header('Authorization', f'Bearer {token}' if token else f'Basic {BASIC_AUTH}')
    req.add_header('Content-Type', 'application/json')
    req.add_header('X-Requested-With', 'qualys-mcp')
    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read()).get('count', 0)
    except Exception:
        return 0


def is_eol_stage(stage):
    """Check if stage indicates EOL/EOS status"""
    if not stage:
        return False
    s = stage.upper()
    return ('EOL' in s or 'EOS' in s) and s != 'NOT APPLICABLE'


def get_eol_sample(qql_filter, limit=100):
    """Get single page of assets (no pagination) and filter for EOL"""
    token = get_bearer_token()
    url = f"{GATEWAY_URL}/rest/2.0/search/am/asset?pageSize={limit}"
    filter_body = json.dumps({"filter": qql_filter})
    req = Request(url, data=filter_body.encode(), method='POST')
    req.add_header('Authorization', f'Bearer {token}' if token else f'Basic {BASIC_AUTH}')
    req.add_header('Content-Type', 'application/json')
    req.add_header('X-Requested-With', 'qualys-mcp')
    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read()).get('assetListData', {}).get('asset', [])
    except Exception:
        return []


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
        with urlopen(req, timeout=60) as resp:
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


def fetch_all_eol(qql_filter, limit=1000, max_pages=50):
    """Fetch EOL assets with pagination until limit or max_pages reached"""
    token = get_bearer_token()
    results = []
    seen = set()
    last_id = None

    for _ in range(max_pages):
        if len(results) >= limit:
            break

        url = f"{GATEWAY_URL}/rest/2.0/search/am/asset?pageSize=100"
        if last_id:
            url += f"&lastSeenAssetId={last_id}"

        filter_body = json.dumps({"filter": qql_filter})
        req = Request(url, data=filter_body.encode(), method='POST')
        req.add_header('Authorization', f'Bearer {token}' if token else f'Basic {BASIC_AUTH}')
        req.add_header('Content-Type', 'application/json')
        req.add_header('X-Requested-With', 'qualys-mcp')

        try:
            with urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
                assets = data.get('assetListData', {}).get('asset', [])
                if not assets:
                    break

                for a in assets:
                    aid = a.get('assetId')
                    if aid in seen:
                        continue
                    seen.add(aid)

                    if 'operatingSystem' in qql_filter:
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
                            'riskScore': a.get('assetRiskScore') or 0
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
    """Get prioritized security actions for the week. Returns top critical vulns and container risks ranked by severity and impact."""
    result = {'summary': {'totalCritical': 0, 'assetsAffected': 0, 'containersAtRisk': 0, 'patchable': 0},
              'priorities': [], 'byEffort': {'patch': 0, 'config': 0, 'upgrade': 0}}

    # Run detections (QDS 70+ = high/critical risk) and container checks concurrently
    concurrent = _run_concurrent(
        dets=lambda: get_detections(5, 200, qds_min=70),
        vuln_imgs=lambda: get_images(50, 5),
        containers=lambda: get_containers(100),
    )

    dets = concurrent.get('dets') or []
    qids = {}
    hosts = set()
    for d in dets:
        qid = d['qid']
        if qid not in qids:
            qids[qid] = {'count': 0, 'hosts': set(), 'sev': d['severity']}
        qids[qid]['count'] += 1
        qids[qid]['hosts'].add(d['host_id'])
        hosts.add(d['host_id'])

    top_qids = sorted(qids.items(), key=lambda x: (x[1]['sev'], len(x[1]['hosts'])), reverse=True)[:limit]
    kb_data = get_kb_batch([q[0] for q in top_qids])

    for i, (qid, data) in enumerate(top_qids):
        kb = kb_data.get(qid)
        patch = kb.get('patch_available', False) if kb else False
        result['byEffort']['patch' if patch else 'config'] += 1
        if patch:
            result['summary']['patchable'] += 1
        result['priorities'].append({
            'rank': i + 1, 'qid': qid,
            'title': kb['title'] if kb else f"QID {qid}",
            'cves': kb.get('cves', [])[:3] if kb else [],
            'hosts': len(data['hosts']),
            'severity': data['sev'],
            'effort': 'patch' if patch else 'config',
            'fix': (kb.get('solution', '') if kb else '')[:150]
        })

    vuln_imgs = concurrent.get('vuln_imgs') or []
    containers = concurrent.get('containers') or []
    vuln_img_ids = {img.get('imageId') for img in vuln_imgs}
    at_risk = [c for c in containers if c.get('imageId') in vuln_img_ids]
    if at_risk:
        result['priorities'].append({'rank': len(result['priorities']) + 1, 'title': 'Vulnerable containers',
                                     'containers': len(at_risk), 'effort': 'upgrade', 'severity': 5})
        result['byEffort']['upgrade'] = len(at_risk)
        result['summary']['containersAtRisk'] = len(at_risk)

    result['summary']['totalCritical'] = len(qids)
    result['summary']['assetsAffected'] = len(hosts)
    return result


@mcp.tool()
def investigate_cve(cve: str) -> dict:
    """Investigate if your environment is affected by a specific CVE. Returns QIDs, affected hosts, KB details, and remediation."""
    result = {'cve': cve, 'qids': [], 'affectedHosts': [], 'severity': 0,
              'title': '', 'patchAvailable': False, 'solution': '',
              'summary': {'hostsAffected': 0, 'patchAvailable': False}}

    # Step 1: CVE -> QIDs + KB data
    qids = get_cve_qids(cve)
    result['qids'] = qids

    if qids:
        kb = KB_CACHE.get(qids[0]) or get_kb(qids[0])
        if kb:
            result['title'] = kb.get('title', '')
            result['severity'] = kb.get('severity', 0)
            result['patchAvailable'] = kb.get('patch_available', False)
            result['solution'] = kb.get('solution', '')[:500]
            result['diagnosis'] = kb.get('diagnosis', '')[:300]
            result['cves'] = kb.get('cves', [])
            result['summary']['patchAvailable'] = kb.get('patch_available', False)

    # Step 2: Search VMDR detections for affected hosts (filter by QIDs for speed)
    if qids:
        qid_str = ','.join(str(q) for q in qids[:5])
        data = api_get(
            f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/?action=list"
            f"&qids={qid_str}&status=Active&truncation_limit=200"
            f"&show_qds=1&filter_superseded_qids=1",
            timeout=180
        )
        if data:
            try:
                root = ET.fromstring(data)
                qid_set = set(qids)
                for host in root.findall('.//HOST'):
                    hid = host.findtext('ID', '')
                    ip = host.findtext('IP', '')
                    hostname = host.findtext('DNS', '')
                    for d in host.findall('.//DETECTION'):
                        det_qid = int(d.findtext('QID', '0'))
                        if det_qid in qid_set:
                            result['affectedHosts'].append({
                                'hostId': hid, 'ip': ip, 'hostname': hostname,
                                'qid': det_qid,
                                'status': d.findtext('STATUS', ''),
                                'firstFound': d.findtext('FIRST_FOUND_DATETIME', ''),
                            })
                            break
            except ET.ParseError:
                pass

    result['summary']['hostsAffected'] = len(result['affectedHosts'])
    return result


@mcp.tool()
def get_security_posture() -> dict:
    """Get overall security health score and stats across assets, vulns, containers, and cloud."""
    health = 100
    result = {'healthScore': 0, 'assets': {'total': 0, 'highRisk': 0},
              'vulns': {'critical': 0, 'high': 0}, 'containers': {'total': 0, 'atRisk': 0},
              'cloud': {'accounts': 0, 'failedControls': 0}, 'warnings': []}

    # Run everything concurrently
    concurrent = _run_concurrent(
        asset_count=lambda: get_asset_count(),
        high_risk=lambda: get_assets(100, 'truriskScore:[700-1000]'),
        crit_dets=lambda: get_detections(5, 100, qds_min=90),
        high_dets=lambda: get_detections(4, 100, qds_min=70),
        images=lambda: get_images(50),
        vuln_images=lambda: get_images(30, 5),
        containers=lambda: get_containers(50),
    )

    # Assets
    total = concurrent.get('asset_count') or 0
    high_risk = concurrent.get('high_risk') or []
    result['assets']['total'] = total
    result['assets']['highRisk'] = len(high_risk)
    if total > 0:
        health -= int(len(high_risk) / total * 50)

    # Vulns
    crit_dets = concurrent.get('crit_dets') or []
    high_dets = concurrent.get('high_dets') or []
    result['vulns']['critical'] = len(crit_dets)
    result['vulns']['high'] = len(high_dets)
    if len(crit_dets) > 50:
        health -= 20
    elif len(crit_dets) > 10:
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
    """Get patching coverage - how many assets need patches and which patches are most common."""
    result = {'coverage': 0, 'assetsTotal': 0, 'assetsNeedPatches': 0, 'topMissing': []}

    # Run asset count and detections concurrently
    concurrent = _run_concurrent(
        total=lambda: get_asset_count(),
        dets=lambda: get_detections(5, 200, qds_min=70),
    )

    result['assetsTotal'] = concurrent.get('total') or 0
    dets = concurrent.get('dets') or []

    unique_qids = list(set(d['qid'] for d in dets))
    kb_data = get_kb_batch(unique_qids)

    qid_counts = {}
    for d in dets:
        kb = kb_data.get(d['qid'])
        if kb and kb.get('patch_available'):
            qid_counts[d['qid']] = qid_counts.get(d['qid'], 0) + 1

    top_qids = sorted(qid_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    result['topMissing'] = [{'qid': q, 'count': c, 'title': kb_data.get(q, {}).get('title', ''),
                              'cves': kb_data.get(q, {}).get('cves', [])[:3]} for q, c in top_qids]

    hosts_need = set(d['host_id'] for d in dets if d['qid'] in qid_counts)
    result['assetsNeedPatches'] = len(hosts_need)
    if result['assetsTotal']:
        result['coverage'] = round((result['assetsTotal'] - len(hosts_need)) / result['assetsTotal'] * 100, 1)

    return result


@mcp.tool()
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
    """Get risk summary for a specific asset - risk score, top vulnerabilities, and remediation."""
    result = {'assetId': asset_id, 'riskScore': 0, 'vulns': []}

    # Run asset lookup and host detections concurrently
    concurrent = _run_concurrent(
        asset=lambda: get_asset_by_id(asset_id),
        dets=lambda: get_host_detections(asset_id, severity=4),
    )

    asset = concurrent.get('asset')
    if asset:
        result['ip'] = asset.get('address', '')
        result['hostname'] = asset.get('dnsHostName', '') or asset.get('dnsName', '')
        result['riskScore'] = int(asset.get('assetRiskScore') or asset.get('truriskScore') or 0)
        result['os'] = (asset.get('operatingSystem') or {}).get('osName', '')
        result['criticality'] = get_criticality(asset)

    asset_dets = concurrent.get('dets') or []
    if asset_dets:
        kb_data = get_kb_batch([d['qid'] for d in asset_dets[:10]])
        for d in asset_dets[:10]:
            kb = kb_data.get(d['qid'])
            result['vulns'].append({
                'qid': d['qid'],
                'title': kb['title'] if kb else '',
                'severity': d['severity'],
                'qds': d.get('qds', 0),
                'patchAvailable': kb.get('patch_available', False) if kb else False,
                'fix': (kb.get('solution', '') if kb else '')[:150],
            })

    return result


@mcp.tool()
def get_tech_debt(limit: int = 100) -> dict:
    """Get EOL/EOS systems sorted by criticality. Default 100 (~25s). Use limit=500 for more (~2min)."""
    max_pages = max(5, (limit // 10) + 2)

    # Run OS and hardware EOL fetches concurrently
    concurrent = _run_concurrent(
        os_eol=lambda: fetch_all_eol("operatingSystem.lifecycle.stage:`EOL` OR operatingSystem.lifecycle.stage:`EOL/EOS`", limit, max_pages),
        hw_eol=lambda: fetch_all_eol("hardware.lifecycle.stage:`EOL/EOS`", limit, max_pages),
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


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
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
