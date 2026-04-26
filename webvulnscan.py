#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  WebVulnScan v1.0.0  —  All-in-One Web Vulnerability Scanner               ║
║  Modules: SQL Injection · XSS · Open Redirect · Sensitive File Exposure    ║
║  Author : Security Research Tool  |  For authorized testing ONLY           ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
  python webvulnscan.py https://target.com
  python webvulnscan.py https://target.com -m sqli xss
  python webvulnscan.py https://target.com -o html -r report.html
  python webvulnscan.py https://target.com --cookies '{"session":"abc"}' -v

Install dependencies:
  pip install requests beautifulsoup4 lxml
"""

# ─────────────────────────────────────────────────────────────────────────────
# STANDARD LIBRARY
# ─────────────────────────────────────────────────────────────────────────────
import argparse
import datetime
import json
import sys
import time
import urllib.parse
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────────────────────────────────────
# THIRD-PARTY  (pip install requests beautifulsoup4 lxml)
# ─────────────────────────────────────────────────────────────────────────────
try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] Missing dependencies. Run:  pip install requests beautifulsoup4 lxml")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1  ──  TERMINAL COLOURS
# ══════════════════════════════════════════════════════════════════════════════

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
DRED   = "\033[31m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
GREY   = "\033[90m"

SEVERITY_COLORS = {
    "CRITICAL": RED,
    "HIGH":     DRED,
    "MEDIUM":   YELLOW,
    "LOW":      BLUE,
    "INFO":     CYAN,
}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

BANNER = f"""{GREEN}
 ██╗    ██╗███████╗██████╗ ██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║    ██║██╔════╝██╔══██╗██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║ █╗ ██║█████╗  ██████╔╝██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
 ██║███╗██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
 ╚███╔███╔╝███████╗██████╔╝ ╚████╔╝ ███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
  ╚══╝╚══╝ ╚══════╝╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{RESET}{GREY}                   Web Vulnerability Scanner v1.0.0  |  For authorized testing only{RESET}
"""


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2  ──  SQL INJECTION MODULE
# ══════════════════════════════════════════════════════════════════════════════

SQLI_PAYLOADS = [
    ("'",                          "error"),
    ('"',                          "error"),
    ("' OR '1'='1",                "boolean"),
    ("' OR '1'='2",                "boolean"),
    ("1' ORDER BY 1--",            "error"),
    ("1' ORDER BY 100--",          "error"),
    ("' UNION SELECT NULL--",      "error"),
    ("' UNION SELECT NULL,NULL--", "error"),
    ("admin'--",                   "error"),
    ("' OR 1=1--",                 "boolean"),
    ("'; WAITFOR DELAY '0:0:3'--", "time"),
    ("' AND SLEEP(3)--",           "time"),
    ("1; SELECT SLEEP(3)--",       "time"),
]

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "ora-",
    "pg::syntaxerror",
    "sqlite3::exception",
    "microsoft ole db provider for sql server",
    "odbc microsoft access driver",
    "syntax error",
    "mysql_fetch",
    "num_rows",
]


def sqli_scan_form(session, url, form_tag, timeout, verbose):
    findings = []
    action   = form_tag.get("action", url)
    method   = form_tag.get("method", "get").lower()
    full_url = urllib.parse.urljoin(url, action)

    fields = {
        inp.get("name"): inp.get("value", "test")
        for inp in form_tag.find_all("input")
        if inp.get("type", "text") not in ("submit", "button", "hidden", "image")
        and inp.get("name")
    }
    if not fields:
        return findings

    for payload, ptype in SQLI_PAYLOADS:
        for field in list(fields.keys()):
            test_data = {**fields, field: payload}
            try:
                t0 = time.time()
                if method == "post":
                    resp = session.post(full_url, data=test_data,
                                        timeout=timeout, allow_redirects=True)
                else:
                    resp = session.get(full_url, params=test_data,
                                       timeout=timeout, allow_redirects=True)
                elapsed = time.time() - t0
                body    = resp.text.lower()

                if ptype == "error":
                    for err in SQL_ERRORS:
                        if err in body:
                            if verbose:
                                print(f"    {GREY}[sqli] Error-based at {full_url} [{field}]{RESET}")
                            findings.append({
                                "type": "SQL Injection", "subtype": "Error-based",
                                "url": full_url, "parameter": field,
                                "payload": payload,
                                "evidence": f"DB error keyword: '{err}'",
                                "severity": "HIGH",
                            })
                            break

                elif ptype == "time" and elapsed >= 2.8:
                    if verbose:
                        print(f"    {GREY}[sqli] Time-based blind at {full_url} [{field}]"
                              f" ({elapsed:.1f}s){RESET}")
                    findings.append({
                        "type": "SQL Injection", "subtype": "Time-based Blind",
                        "url": full_url, "parameter": field,
                        "payload": payload,
                        "evidence": f"Response delayed {elapsed:.1f}s",
                        "severity": "CRITICAL",
                    })

            except Exception as e:
                if verbose:
                    print(f"    {GREY}[sqli] Request error: {e}{RESET}")

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3  ──  XSS MODULE
# ══════════════════════════════════════════════════════════════════════════════

XSS_PAYLOADS = [
    '<script>alert("xss")</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><svg onload=alert(1)>',
    "javascript:alert(1)",
    '<body onload=alert(1)>',
    '{{7*7}}',
    '${7*7}',
    '<iframe src="javascript:alert(1)">',
]


def xss_scan_form(session, url, form_tag, timeout, verbose):
    findings = []
    action   = form_tag.get("action", url)
    method   = form_tag.get("method", "get").lower()
    full_url = urllib.parse.urljoin(url, action)

    fields = {
        inp.get("name"): inp.get("value", "test")
        for inp in form_tag.find_all("input")
        if inp.get("type", "text") not in ("submit", "button", "hidden", "image")
        and inp.get("name")
    }
    for ta in form_tag.find_all("textarea"):
        if ta.get("name"):
            fields[ta.get("name")] = "test"

    if not fields:
        return findings

    for payload in XSS_PAYLOADS:
        for field in list(fields.keys()):
            test_data = {**fields, field: payload}
            try:
                if method == "post":
                    resp = session.post(full_url, data=test_data,
                                        timeout=timeout, allow_redirects=True)
                else:
                    resp = session.get(full_url, params=test_data,
                                       timeout=timeout, allow_redirects=True)

                if payload in resp.text:
                    if verbose:
                        print(f"    {GREY}[xss] Reflected at {full_url} [{field}]{RESET}")
                    findings.append({
                        "type": "Cross-Site Scripting (XSS)", "subtype": "Reflected",
                        "url": full_url, "parameter": field,
                        "payload": payload,
                        "evidence": "Payload reflected in response without encoding",
                        "severity": "HIGH",
                    })
                    break

            except Exception as e:
                if verbose:
                    print(f"    {GREY}[xss] Request error: {e}{RESET}")

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4  ──  OPEN REDIRECT MODULE
# ══════════════════════════════════════════════════════════════════════════════

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_to", "redirect_url", "redirecturl",
    "return", "return_url", "returnurl", "next", "next_url",
    "goto", "go", "destination", "dest", "target", "link",
    "to", "from", "forward", "forward_url", "continue",
    "location", "uri", "ref", "referral", "page",
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "//evil.com/%2F..",
    "https://evil.com%23@target.com",
    "https:///evil.com",
    "\thttps://evil.com",
    "/%09/evil.com",
    "//evil%2Ecom",
]


def redirect_scan_url(session, url, timeout, verbose):
    findings = []
    parsed   = urllib.parse.urlparse(url)
    params   = urllib.parse.parse_qs(parsed.query)

    redirect_params = [p for p in params if p.lower() in REDIRECT_PARAMS]
    if not redirect_params:
        return findings

    for param in redirect_params:
        for payload in REDIRECT_PAYLOADS:
            test_params = {**{k: v[0] for k, v in params.items()}, param: payload}
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(test_params))
            )
            try:
                resp = session.get(test_url, timeout=timeout, allow_redirects=False)
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location:
                        if verbose:
                            print(f"    {GREY}[redirect] Open redirect at {url}"
                                  f" [{param}]{RESET}")
                        findings.append({
                            "type": "Open Redirect",
                            "subtype": f"HTTP {resp.status_code}",
                            "url": url, "parameter": param,
                            "payload": payload,
                            "evidence": f"Redirected to: {location}",
                            "severity": "MEDIUM",
                        })
                        break
            except Exception as e:
                if verbose:
                    print(f"    {GREY}[redirect] Request error: {e}{RESET}")

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5  ──  SENSITIVE FILE EXPOSURE MODULE
# ══════════════════════════════════════════════════════════════════════════════

SENSITIVE_PATHS = [
    ("/.env",                   "Environment file (credentials/secrets)",  "CRITICAL"),
    ("/.env.local",             "Local environment file",                   "CRITICAL"),
    ("/.env.production",        "Production environment file",              "CRITICAL"),
    ("/config.php",             "PHP configuration file",                   "HIGH"),
    ("/config.yml",             "YAML configuration file",                  "HIGH"),
    ("/config.json",            "JSON configuration file",                  "HIGH"),
    ("/wp-config.php",          "WordPress configuration file",             "CRITICAL"),
    ("/settings.py",            "Django settings file",                     "HIGH"),
    ("/application.properties", "Spring Boot configuration",                "HIGH"),
    ("/.git/config",            "Git repository configuration",             "HIGH"),
    ("/.git/HEAD",              "Git HEAD reference",                       "HIGH"),
    ("/.svn/entries",           "SVN repository entries",                   "MEDIUM"),
    ("/backup.sql",             "SQL database backup",                      "CRITICAL"),
    ("/database.sql",           "Database dump file",                       "CRITICAL"),
    ("/dump.sql",               "SQL dump file",                            "CRITICAL"),
    ("/backup.zip",             "Zip backup archive",                       "HIGH"),
    ("/backup.tar.gz",          "Tar.gz backup archive",                    "HIGH"),
    ("/index.php.bak",          "PHP backup file",                          "HIGH"),
    ("/admin",                  "Admin panel",                              "MEDIUM"),
    ("/admin/",                 "Admin panel (trailing slash)",             "MEDIUM"),
    ("/administrator/",         "Administrator panel",                      "MEDIUM"),
    ("/phpmyadmin/",            "phpMyAdmin database manager",              "HIGH"),
    ("/phpinfo.php",            "PHP info disclosure page",                 "HIGH"),
    ("/info.php",               "PHP info disclosure page",                 "HIGH"),
    ("/test.php",               "Test PHP file",                            "MEDIUM"),
    ("/debug",                  "Debug endpoint",                           "MEDIUM"),
    ("/console",                "Debug console",                            "HIGH"),
    ("/.htaccess",              "Apache access configuration",              "MEDIUM"),
    ("/.htpasswd",              "Apache password file",                     "CRITICAL"),
    ("/robots.txt",             "Robots file (recon)",                      "LOW"),
    ("/sitemap.xml",            "Sitemap (recon)",                          "LOW"),
    ("/crossdomain.xml",        "Flash cross-domain policy",                "MEDIUM"),
    ("/error.log",              "Error log file",                           "HIGH"),
    ("/access.log",             "Access log file",                          "HIGH"),
    ("/debug.log",              "Debug log file",                           "HIGH"),
    ("/.DS_Store",              "macOS directory metadata",                 "LOW"),
    ("/credentials.json",       "Credentials file",                         "CRITICAL"),
    ("/secrets.json",           "Secrets file",                             "CRITICAL"),
    ("/private.key",            "Private key file",                         "CRITICAL"),
    ("/id_rsa",                 "SSH private key",                          "CRITICAL"),
    ("/id_rsa.pub",             "SSH public key",                           "LOW"),
]

SENSITIVE_KEYWORDS = {
    "/.env":             ["DB_PASSWORD", "APP_KEY", "SECRET_KEY", "API_KEY", "DATABASE_URL"],
    "/.git/config":      ["[core]", "[remote", "repositoryformatversion"],
    "/phpinfo.php":      ["PHP Version", "phpinfo"],
    "/info.php":         ["PHP Version", "phpinfo"],
    "/.htpasswd":        ["$apr1$", "$2y$"],
    "/wp-config.php":    ["DB_PASSWORD", "DB_USER", "table_prefix"],
    "/config.php":       ["password", "database", "db_pass"],
    "/settings.py":      ["SECRET_KEY", "DATABASES", "PASSWORD"],
    "/credentials.json": ["private_key", "client_email"],
    "/id_rsa":           ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"],
}


def files_scan(session, base_url, timeout, verbose):
    findings = []
    base_url = base_url.rstrip("/")

    for path, description, severity_hint in SENSITIVE_PATHS:
        url = base_url + path
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=False)

            if resp.status_code == 200:
                body       = resp.text
                matched_kw = [kw for kw in SENSITIVE_KEYWORDS.get(path, []) if kw in body]

                if matched_kw or any(k in path for k in
                                     ["id_rsa", "htpasswd", ".env", "credentials"]):
                    severity = "CRITICAL"
                elif any(k in path for k in ["config", "backup", ".git", "sql", "key"]):
                    severity = "HIGH"
                else:
                    severity = severity_hint

                evidence = f"HTTP 200, {len(body)} bytes"
                if matched_kw:
                    evidence += f" | keywords: {', '.join(matched_kw)}"

                if verbose:
                    print(f"    {GREY}[files] {severity}: {url}{RESET}")
                findings.append({
                    "type": "Sensitive File Exposure", "subtype": description,
                    "url": url, "parameter": "path",
                    "payload": path, "evidence": evidence,
                    "severity": severity,
                })

            elif resp.status_code == 403:
                if verbose:
                    print(f"    {GREY}[files] 403 Forbidden (exists): {url}{RESET}")
                findings.append({
                    "type": "Sensitive File Exposure",
                    "subtype": f"{description} (access denied)",
                    "url": url, "parameter": "path",
                    "payload": path,
                    "evidence": "HTTP 403 – resource exists but access is restricted",
                    "severity": "LOW",
                })

        except Exception as e:
            if verbose:
                print(f"    {GREY}[files] Error: {url}: {e}{RESET}")

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6  ──  CRAWLER
# ══════════════════════════════════════════════════════════════════════════════

def crawl(session, target_url, depth, timeout, verbose):
    queue       = deque([(target_url, 0)])
    visited     = {target_url}
    forms       = []
    base_domain = urllib.parse.urlparse(target_url).netloc

    while queue:
        url, current_depth = queue.popleft()
        if current_depth > depth:
            continue
        if verbose:
            print(f"  {GREY}[crawl] {url}{RESET}")
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True)
            soup = BeautifulSoup(resp.text, "html.parser")

            for form in soup.find_all("form"):
                forms.append({"url": url, "form": form})

            for tag in soup.find_all("a", href=True):
                full   = urllib.parse.urljoin(url, tag["href"])
                parsed = urllib.parse.urlparse(full)
                if parsed.netloc == base_domain and full not in visited:
                    visited.add(full)
                    queue.append((full, current_depth + 1))

        except Exception as e:
            if verbose:
                print(f"  {GREY}[crawl] Error: {e}{RESET}")

    return visited, forms


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7  ──  SCAN ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def _module_summary(findings):
    if findings:
        print(f"  {RED}[!] {len(findings)} issue(s) found{RESET}")
    else:
        print(f"  {GREEN}[✓] No issues found{RESET}")


def run_scan(target_url, modules, depth, threads, timeout, cookies, headers, verbose):
    session = requests.Session()
    session.headers.update({"User-Agent": "WebVulnScan/1.0 (Security Research)",
                             **(headers or {})})
    session.cookies.update(cookies or {})

    print(f"\n{CYAN}[*] Phase 1: Crawling target...{RESET}")
    visited_urls, forms_collected = crawl(session, target_url, depth, timeout, verbose)
    print(f"{GREEN}[+] Crawled {len(visited_urls)} pages, "
          f"found {len(forms_collected)} forms{RESET}")

    results = {"sqli": [], "xss": [], "redirect": [], "files": []}
    print(f"\n{CYAN}[*] Phase 2: Running {len(modules)} module(s)...{RESET}")

    def threaded(fn, items):
        out = []
        with ThreadPoolExecutor(max_workers=threads) as pool:
            for fut in as_completed({pool.submit(fn, *item): item for item in items}):
                try:
                    r = fut.result()
                    if r:
                        out.extend(r)
                except Exception as e:
                    if verbose:
                        print(f"  {GREY}[thread error] {e}{RESET}")
        return out

    if "sqli" in modules:
        print(f"\n{BLUE}[>] Module: SQLI{RESET}")
        results["sqli"] = threaded(
            lambda s, u, f, t, v: sqli_scan_form(s, u, f, t, v),
            [(session, item["url"], item["form"], timeout, verbose)
             for item in forms_collected]
        )
        _module_summary(results["sqli"])

    if "xss" in modules:
        print(f"\n{BLUE}[>] Module: XSS{RESET}")
        results["xss"] = threaded(
            lambda s, u, f, t, v: xss_scan_form(s, u, f, t, v),
            [(session, item["url"], item["form"], timeout, verbose)
             for item in forms_collected]
        )
        _module_summary(results["xss"])

    if "redirect" in modules:
        print(f"\n{BLUE}[>] Module: REDIRECT{RESET}")
        results["redirect"] = threaded(
            lambda s, u, t, v: redirect_scan_url(s, u, t, v),
            [(session, url, timeout, verbose) for url in visited_urls]
        )
        _module_summary(results["redirect"])

    if "files" in modules:
        print(f"\n{BLUE}[>] Module: FILES{RESET}")
        results["files"] = files_scan(session, target_url, timeout, verbose)
        _module_summary(results["files"])

    return results


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8  ──  REPORTER
# ══════════════════════════════════════════════════════════════════════════════

def _all_sorted(results):
    flat = []
    for module, findings in results.items():
        for f in findings:
            f.setdefault("module", module)
            flat.append(f)
    flat.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 4))
    return flat


def report_terminal(results, target_url):
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    findings  = _all_sorted(results)

    print(f"\n{'='*70}")
    print(f"{BOLD}  SCAN REPORT  |  {target_url}{RESET}")
    print(f"  Generated : {timestamp}")
    print(f"{'='*70}\n")

    if not findings:
        print(f"  {CYAN}[✓] No vulnerabilities detected.{RESET}\n")
        return

    counts = {}
    for f in findings:
        s = f.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1

    print(f"  {BOLD}Summary:{RESET}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in counts:
            c = SEVERITY_COLORS[sev]
            print(f"    {c}[{sev}]{RESET}  {counts[sev]} finding(s)")

    print(f"\n  {BOLD}Findings:{RESET}\n")
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO")
        c   = SEVERITY_COLORS.get(sev, "")
        print(f"  [{i}] {c}{BOLD}{f['type']}{RESET} — {f.get('subtype','')}")
        print(f"      {BOLD}Severity  :{RESET} {c}{sev}{RESET}")
        print(f"      {BOLD}URL       :{RESET} {f.get('url','')}")
        print(f"      {BOLD}Parameter :{RESET} {f.get('parameter','')}")
        print(f"      {BOLD}Payload   :{RESET} {f.get('payload','')}")
        print(f"      {BOLD}Evidence  :{RESET} {f.get('evidence','')}")
        print()


def report_json(results, target_url):
    findings  = _all_sorted(results)
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    return json.dumps({
        "scanner":   "WebVulnScan v1.0.0",
        "target":    target_url,
        "timestamp": timestamp,
        "summary": {s: sum(1 for f in findings if f.get("severity") == s)
                    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
        "findings": findings,
    }, indent=2)


def report_html(results, target_url):
    findings  = _all_sorted(results)
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    SEV_CSS   = {"CRITICAL": "#ff2244", "HIGH": "#ff7700",
                 "MEDIUM": "#ffcc00",   "LOW": "#44aaff", "INFO": "#aaaaaa"}

    rows = ""
    for f in findings:
        sev = f.get("severity", "INFO")
        col = SEV_CSS.get(sev, "#aaa")
        rows += (
            f"<tr>"
            f"<td><span class='badge' style='background:{col}20;color:{col};"
            f"border:1px solid {col}50'>{sev}</span></td>"
            f"<td><strong>{f.get('type','')}</strong><br>"
            f"<small>{f.get('subtype','')}</small></td>"
            f"<td><code>{f.get('url','')}</code></td>"
            f"<td><code>{f.get('parameter','')}</code></td>"
            f"<td><code>{f.get('payload','')}</code></td>"
            f"<td>{f.get('evidence','')}</td>"
            f"</tr>"
        )

    counts       = {s: sum(1 for f in findings if f.get("severity") == s)
                    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
    summary_html = "".join(
        f'<div class="chip" style="border-color:{SEV_CSS[s]}40">'
        f'<span style="color:{SEV_CSS[s]};font-size:1.6rem;font-weight:700">'
        f'{counts.get(s,0)}</span>'
        f'<span class="chip-lbl">{s}</span></div>'
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )

    no_data = ('<tr><td colspan="6" style="text-align:center;color:#444;padding:2rem">'
               'No vulnerabilities detected.</td></tr>')

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebVulnScan Report \u2013 {target_url}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Courier New',monospace;background:#080a0f;color:#c9d1d9;
     padding:2rem;line-height:1.6}}
header{{border-bottom:1px solid #1e2535;padding-bottom:1.5rem;margin-bottom:1.5rem}}
h1{{color:#00ff88;font-size:1.6rem;letter-spacing:.05em;margin-bottom:.3rem}}
h2{{color:#4a9eff;font-size:.9rem;font-weight:400}}
.summary{{display:flex;gap:12px;margin:1.5rem 0;flex-wrap:wrap}}
.chip{{background:#0d1117;border:1px solid #1e2535;border-radius:8px;
       padding:12px 20px;text-align:center;min-width:100px;
       display:flex;flex-direction:column;gap:4px}}
.chip-lbl{{font-size:.65rem;letter-spacing:.1em;color:#6e7681}}
table{{width:100%;border-collapse:collapse;font-size:.8rem}}
th{{background:#0d1117;color:#00ff88;padding:10px 12px;text-align:left;
    border-bottom:1px solid #1e2535;font-size:.75rem;letter-spacing:.06em}}
td{{padding:10px 12px;border-bottom:1px solid #0d1117;vertical-align:top}}
tr:hover td{{background:#0d1117}}
.badge{{padding:3px 9px;border-radius:4px;font-size:.7rem;
        font-weight:700;white-space:nowrap}}
code{{background:#0d1117;padding:2px 5px;border-radius:3px;
      font-size:.78rem;word-break:break-all;color:#79c0ff}}
small{{color:#6e7681;font-size:.75rem}}
footer{{margin-top:2rem;font-size:.75rem;color:#444;text-align:center}}
</style>
</head>
<body>
<header>
  <h1>&#128269; WebVulnScan Report</h1>
  <h2>Target: {target_url} &nbsp;|&nbsp; {timestamp} &nbsp;|&nbsp; {len(findings)} findings</h2>
</header>
<div class="summary">{summary_html}</div>
<table>
<thead>
  <tr><th>SEVERITY</th><th>VULNERABILITY</th><th>URL</th>
      <th>PARAM</th><th>PAYLOAD</th><th>EVIDENCE</th></tr>
</thead>
<tbody>{rows if rows else no_data}</tbody>
</table>
<footer>Generated by WebVulnScan v1.0.0 \u2014 For authorized security testing only</footer>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9  ──  CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        description="WebVulnScan \u2013 Automated Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python webvulnscan.py https://testphp.vulnweb.com
  python webvulnscan.py https://testphp.vulnweb.com -m sqli xss
  python webvulnscan.py https://target.com -o html -r report.html -d 3
  python webvulnscan.py https://app.com --cookies '{"session":"abc123"}' -v

Safe test targets (intentionally vulnerable labs):
  http://testphp.vulnweb.com    (Acunetix demo lab)
  http://demo.testfire.net      (IBM demo lab)
  DVWA / WebGoat / OWASP Juice Shop  (run locally via Docker)

LEGAL: Only scan systems you own or have explicit written permission to test.
        """
    )
    parser.add_argument("url",            help="Target URL  e.g. https://example.com")
    parser.add_argument("-m", "--modules", nargs="+",
                        choices=["sqli", "xss", "redirect", "files", "all"],
                        default=["all"],   help="Modules to run (default: all)")
    parser.add_argument("-d", "--depth",   type=int, default=2,
                        help="Crawl depth (default: 2)")
    parser.add_argument("-t", "--threads", type=int, default=5,
                        help="Concurrent threads (default: 5)")
    parser.add_argument("-o", "--output",  choices=["terminal", "json", "html"],
                        default="terminal", help="Output format (default: terminal)")
    parser.add_argument("-r", "--report-file", default=None,
                        help="Save report to file")
    parser.add_argument("--timeout",       type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("-c", "--cookies", default=None,
                        help='Cookies JSON  e.g. \'{"session":"abc"}\'')
    parser.add_argument("--headers",       default=None,
                        help='Custom headers JSON')
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose probe output")
    parser.add_argument("--no-banner",     action="store_true",
                        help="Suppress ASCII banner")
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.no_banner:
        print(BANNER)

    modules = (["sqli", "xss", "redirect", "files"]
               if "all" in args.modules else args.modules)

    print(f"  {BOLD}Target  :{RESET} {args.url}")
    print(f"  {BOLD}Modules :{RESET} {', '.join(modules)}")
    print(f"  {BOLD}Depth   :{RESET} {args.depth}  "
          f"{BOLD}Threads:{RESET} {args.threads}  "
          f"{BOLD}Timeout:{RESET} {args.timeout}s")
    print(f"  {GREY}{'─'*62}{RESET}")

    try:
        cookies = json.loads(args.cookies) if args.cookies else {}
        headers = json.loads(args.headers) if args.headers else {}
    except json.JSONDecodeError as e:
        print(f"{RED}[!] Invalid JSON for cookies/headers: {e}{RESET}")
        sys.exit(1)

    results = run_scan(
        target_url=args.url,
        modules=modules,
        depth=args.depth,
        threads=args.threads,
        timeout=args.timeout,
        cookies=cookies,
        headers=headers,
        verbose=args.verbose,
    )

    # Output
    if args.output == "terminal":
        report_terminal(results, args.url)

    elif args.output == "json":
        out = report_json(results, args.url)
        if args.report_file:
            with open(args.report_file, "w") as fh:
                fh.write(out)
            print(f"\n{GREEN}[+] JSON report saved \u2192 {args.report_file}{RESET}")
        else:
            print(out)

    elif args.output == "html":
        out = report_html(results, args.url)
        if args.report_file:
            with open(args.report_file, "w") as fh:
                fh.write(out)
            print(f"\n{GREEN}[+] HTML report saved \u2192 {args.report_file}{RESET}")
        else:
            print(out)

    total = sum(len(v) for v in results.values())
    color = GREEN if total == 0 else RED
    print(f"\n{color}{'─'*70}")
    print(f"  Scan complete. {total} "
          f"vulnerabilit{'y' if total == 1 else 'ies'} found.")
    print(f"{'─'*70}{RESET}\n")
    sys.exit(1 if total > 0 else 0)


# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  WebVulnScan v1.0.0  —  All-in-One Web Vulnerability Scanner               ║
║  Modules: SQL Injection · XSS · Open Redirect · Sensitive File Exposure    ║
║  Author : Security Research Tool  |  For authorized testing ONLY           ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
  python webvulnscan.py https://target.com
  python webvulnscan.py https://target.com -m sqli xss
  python webvulnscan.py https://target.com -o html -r report.html
  python webvulnscan.py https://target.com --cookies '{"session":"abc"}' -v

Install dependencies:
  pip install requests beautifulsoup4 lxml
"""

# ─────────────────────────────────────────────────────────────────────────────
# STANDARD LIBRARY
# ─────────────────────────────────────────────────────────────────────────────
import argparse
import datetime
import json
import sys
import time
import urllib.parse
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────────────────────────────────────
# THIRD-PARTY  (pip install requests beautifulsoup4 lxml)
# ─────────────────────────────────────────────────────────────────────────────
try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] Missing dependencies. Run:  pip install requests beautifulsoup4 lxml")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1  ──  TERMINAL COLOURS
# ══════════════════════════════════════════════════════════════════════════════

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
DRED   = "\033[31m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
GREY   = "\033[90m"

SEVERITY_COLORS = {
    "CRITICAL": RED,
    "HIGH":     DRED,
    "MEDIUM":   YELLOW,
    "LOW":      BLUE,
    "INFO":     CYAN,
}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

BANNER = f"""{GREEN}
 ██╗    ██╗███████╗██████╗ ██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║    ██║██╔════╝██╔══██╗██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║ █╗ ██║█████╗  ██████╔╝██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
 ██║███╗██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
 ╚███╔███╔╝███████╗██████╔╝ ╚████╔╝ ███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
  ╚══╝╚══╝ ╚══════╝╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{RESET}{GREY}                   Web Vulnerability Scanner v1.0.0  |  For authorized testing only{RESET}
"""


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2  ──  SQL INJECTION MODULE
# ══════════════════════════════════════════════════════════════════════════════

SQLI_PAYLOADS = [
    ("'",                          "error"),
    ('"',                          "error"),
    ("' OR '1'='1",                "boolean"),
    ("' OR '1'='2",                "boolean"),
    ("1' ORDER BY 1--",            "error"),
    ("1' ORDER BY 100--",          "error"),
    ("' UNION SELECT NULL--",      "error"),
    ("' UNION SELECT NULL,NULL--", "error"),
    ("admin'--",                   "error"),
    ("' OR 1=1--",                 "boolean"),
    ("'; WAITFOR DELAY '0:0:3'--", "time"),
    ("' AND SLEEP(3)--",           "time"),
    ("1; SELECT SLEEP(3)--",       "time"),
]

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "ora-",
    "pg::syntaxerror",
    "sqlite3::exception",
    "microsoft ole db provider for sql server",
    "odbc microsoft access driver",
    "syntax error",
    "mysql_fetch",
    "num_rows",
]


def sqli_scan_form(session, url, form_tag, timeout, verbose):
    findings = []
    action   = form_tag.get("action", url)
    method   = form_tag.get("method", "get").lower()
    full_url = urllib.parse.urljoin(url, action)

    fields = {
        inp.get("name"): inp.get("value", "test")
        for inp in form_tag.find_all("input")
        if inp.get("type", "text") not in ("submit", "button", "hidden", "image")
        and inp.get("name")
    }
    if not fields:
        return findings

    for payload, ptype in SQLI_PAYLOADS:
        for field in list(fields.keys()):
            test_data = {**fields, field: payload}
            try:
                t0 = time.time()
                if method == "post":
                    resp = session.post(full_url, data=test_data,
                                        timeout=timeout, allow_redirects=True)
                else:
                    resp = session.get(full_url, params=test_data,
                                       timeout=timeout, allow_redirects=True)
                elapsed = time.time() - t0
                body    = resp.text.lower()

                if ptype == "error":
                    for err in SQL_ERRORS:
                        if err in body:
                            if verbose:
                                print(f"    {GREY}[sqli] Error-based at {full_url} [{field}]{RESET}")
                            findings.append({
                                "type": "SQL Injection", "subtype": "Error-based",
                                "url": full_url, "parameter": field,
                                "payload": payload,
                                "evidence": f"DB error keyword: '{err}'",
                                "severity": "HIGH",
                            })
                            break

                elif ptype == "time" and elapsed >= 2.8:
                    if verbose:
                        print(f"    {GREY}[sqli] Time-based blind at {full_url} [{field}]"
                              f" ({elapsed:.1f}s){RESET}")
                    findings.append({
                        "type": "SQL Injection", "subtype": "Time-based Blind",
                        "url": full_url, "parameter": field,
                        "payload": payload,
                        "evidence": f"Response delayed {elapsed:.1f}s",
                        "severity": "CRITICAL",
                    })

            except Exception as e:
                if verbose:
                    print(f"    {GREY}[sqli] Request error: {e}{RESET}")

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3  ──  XSS MODULE
# ══════════════════════════════════════════════════════════════════════════════

XSS_PAYLOADS = [
    '<script>alert("xss")</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><svg onload=alert(1)>',
    "javascript:alert(1)",
    '<body onload=alert(1)>',
    '{{7*7}}',
    '${7*7}',
    '<iframe src="javascript:alert(1)">',
]


def xss_scan_form(session, url, form_tag, timeout, verbose):
    findings = []
    action   = form_tag.get("action", url)
    method   = form_tag.get("method", "get").lower()
    full_url = urllib.parse.urljoin(url, action)

    fields = {
        inp.get("name"): inp.get("value", "test")
        for inp in form_tag.find_all("input")
        if inp.get("type", "text") not in ("submit", "button", "hidden", "image")
        and inp.get("name")
    }
    for ta in form_tag.find_all("textarea"):
        if ta.get("name"):
            fields[ta.get("name")] = "test"

    if not fields:
        return findings

    for payload in XSS_PAYLOADS:
        for field in list(fields.keys()):
            test_data = {**fields, field: payload}
            try:
                if method == "post":
                    resp = session.post(full_url, data=test_data,
                                        timeout=timeout, allow_redirects=True)
                else:
                    resp = session.get(full_url, params=test_data,
                                       timeout=timeout, allow_redirects=True)

                if payload in resp.text:
                    if verbose:
                        print(f"    {GREY}[xss] Reflected at {full_url} [{field}]{RESET}")
                    findings.append({
                        "type": "Cross-Site Scripting (XSS)", "subtype": "Reflected",
                        "url": full_url, "parameter": field,
                        "payload": payload,
                        "evidence": "Payload reflected in response without encoding",
                        "severity": "HIGH",
                    })
                    break

            except Exception as e:
                if verbose:
                    print(f"    {GREY}[xss] Request error: {e}{RESET}")

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4  ──  OPEN REDIRECT MODULE
# ══════════════════════════════════════════════════════════════════════════════

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_to", "redirect_url", "redirecturl",
    "return", "return_url", "returnurl", "next", "next_url",
    "goto", "go", "destination", "dest", "target", "link",
    "to", "from", "forward", "forward_url", "continue",
    "location", "uri", "ref", "referral", "page",
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "//evil.com/%2F..",
    "https://evil.com%23@target.com",
    "https:///evil.com",
    "\thttps://evil.com",
    "/%09/evil.com",
    "//evil%2Ecom",
]


def redirect_scan_url(session, url, timeout, verbose):
    findings = []
    parsed   = urllib.parse.urlparse(url)
    params   = urllib.parse.parse_qs(parsed.query)

    redirect_params = [p for p in params if p.lower() in REDIRECT_PARAMS]
    if not redirect_params:
        return findings

    for param in redirect_params:
        for payload in REDIRECT_PAYLOADS:
            test_params = {**{k: v[0] for k, v in params.items()}, param: payload}
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(test_params))
            )
            try:
                resp = session.get(test_url, timeout=timeout, allow_redirects=False)
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location:
                        if verbose:
                            print(f"    {GREY}[redirect] Open redirect at {url}"
                                  f" [{param}]{RESET}")
                        findings.append({
                            "type": "Open Redirect",
                            "subtype": f"HTTP {resp.status_code}",
                            "url": url, "parameter": param,
                            "payload": payload,
                            "evidence": f"Redirected to: {location}",
                            "severity": "MEDIUM",
                        })
                        break
            except Exception as e:
                if verbose:
                    print(f"    {GREY}[redirect] Request error: {e}{RESET}")

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5  ──  SENSITIVE FILE EXPOSURE MODULE
# ══════════════════════════════════════════════════════════════════════════════

SENSITIVE_PATHS = [
    ("/.env",                   "Environment file (credentials/secrets)",  "CRITICAL"),
    ("/.env.local",             "Local environment file",                   "CRITICAL"),
    ("/.env.production",        "Production environment file",              "CRITICAL"),
    ("/config.php",             "PHP configuration file",                   "HIGH"),
    ("/config.yml",             "YAML configuration file",                  "HIGH"),
    ("/config.json",            "JSON configuration file",                  "HIGH"),
    ("/wp-config.php",          "WordPress configuration file",             "CRITICAL"),
    ("/settings.py",            "Django settings file",                     "HIGH"),
    ("/application.properties", "Spring Boot configuration",                "HIGH"),
    ("/.git/config",            "Git repository configuration",             "HIGH"),
    ("/.git/HEAD",              "Git HEAD reference",                       "HIGH"),
    ("/.svn/entries",           "SVN repository entries",                   "MEDIUM"),
    ("/backup.sql",             "SQL database backup",                      "CRITICAL"),
    ("/database.sql",           "Database dump file",                       "CRITICAL"),
    ("/dump.sql",               "SQL dump file",                            "CRITICAL"),
    ("/backup.zip",             "Zip backup archive",                       "HIGH"),
    ("/backup.tar.gz",          "Tar.gz backup archive",                    "HIGH"),
    ("/index.php.bak",          "PHP backup file",                          "HIGH"),
    ("/admin",                  "Admin panel",                              "MEDIUM"),
    ("/admin/",                 "Admin panel (trailing slash)",             "MEDIUM"),
    ("/administrator/",         "Administrator panel",                      "MEDIUM"),
    ("/phpmyadmin/",            "phpMyAdmin database manager",              "HIGH"),
    ("/phpinfo.php",            "PHP info disclosure page",                 "HIGH"),
    ("/info.php",               "PHP info disclosure page",                 "HIGH"),
    ("/test.php",               "Test PHP file",                            "MEDIUM"),
    ("/debug",                  "Debug endpoint",                           "MEDIUM"),
    ("/console",                "Debug console",                            "HIGH"),
    ("/.htaccess",              "Apache access configuration",              "MEDIUM"),
    ("/.htpasswd",              "Apache password file",                     "CRITICAL"),
    ("/robots.txt",             "Robots file (recon)",                      "LOW"),
    ("/sitemap.xml",            "Sitemap (recon)",                          "LOW"),
    ("/crossdomain.xml",        "Flash cross-domain policy",                "MEDIUM"),
    ("/error.log",              "Error log file",                           "HIGH"),
    ("/access.log",             "Access log file",                          "HIGH"),
    ("/debug.log",              "Debug log file",                           "HIGH"),
    ("/.DS_Store",              "macOS directory metadata",                 "LOW"),
    ("/credentials.json",       "Credentials file",                         "CRITICAL"),
    ("/secrets.json",           "Secrets file",                             "CRITICAL"),
    ("/private.key",            "Private key file",                         "CRITICAL"),
    ("/id_rsa",                 "SSH private key",                          "CRITICAL"),
    ("/id_rsa.pub",             "SSH public key",                           "LOW"),
]

SENSITIVE_KEYWORDS = {
    "/.env":             ["DB_PASSWORD", "APP_KEY", "SECRET_KEY", "API_KEY", "DATABASE_URL"],
    "/.git/config":      ["[core]", "[remote", "repositoryformatversion"],
    "/phpinfo.php":      ["PHP Version", "phpinfo"],
    "/info.php":         ["PHP Version", "phpinfo"],
    "/.htpasswd":        ["$apr1$", "$2y$"],
    "/wp-config.php":    ["DB_PASSWORD", "DB_USER", "table_prefix"],
    "/config.php":       ["password", "database", "db_pass"],
    "/settings.py":      ["SECRET_KEY", "DATABASES", "PASSWORD"],
    "/credentials.json": ["private_key", "client_email"],
    "/id_rsa":           ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"],
}


def files_scan(session, base_url, timeout, verbose):
    findings = []
    base_url = base_url.rstrip("/")

    for path, description, severity_hint in SENSITIVE_PATHS:
        url = base_url + path
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=False)

            if resp.status_code == 200:
                body       = resp.text
                matched_kw = [kw for kw in SENSITIVE_KEYWORDS.get(path, []) if kw in body]

                if matched_kw or any(k in path for k in
                                     ["id_rsa", "htpasswd", ".env", "credentials"]):
                    severity = "CRITICAL"
                elif any(k in path for k in ["config", "backup", ".git", "sql", "key"]):
                    severity = "HIGH"
                else:
                    severity = severity_hint

                evidence = f"HTTP 200, {len(body)} bytes"
                if matched_kw:
                    evidence += f" | keywords: {', '.join(matched_kw)}"

                if verbose:
                    print(f"    {GREY}[files] {severity}: {url}{RESET}")
                findings.append({
                    "type": "Sensitive File Exposure", "subtype": description,
                    "url": url, "parameter": "path",
                    "payload": path, "evidence": evidence,
                    "severity": severity,
                })

            elif resp.status_code == 403:
                if verbose:
                    print(f"    {GREY}[files] 403 Forbidden (exists): {url}{RESET}")
                findings.append({
                    "type": "Sensitive File Exposure",
                    "subtype": f"{description} (access denied)",
                    "url": url, "parameter": "path",
                    "payload": path,
                    "evidence": "HTTP 403 – resource exists but access is restricted",
                    "severity": "LOW",
                })

        except Exception as e:
            if verbose:
                print(f"    {GREY}[files] Error: {url}: {e}{RESET}")

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6  ──  CRAWLER
# ══════════════════════════════════════════════════════════════════════════════

def crawl(session, target_url, depth, timeout, verbose):
    queue       = deque([(target_url, 0)])
    visited     = {target_url}
    forms       = []
    base_domain = urllib.parse.urlparse(target_url).netloc

    while queue:
        url, current_depth = queue.popleft()
        if current_depth > depth:
            continue
        if verbose:
            print(f"  {GREY}[crawl] {url}{RESET}")
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True)
            soup = BeautifulSoup(resp.text, "html.parser")

            for form in soup.find_all("form"):
                forms.append({"url": url, "form": form})

            for tag in soup.find_all("a", href=True):
                full   = urllib.parse.urljoin(url, tag["href"])
                parsed = urllib.parse.urlparse(full)
                if parsed.netloc == base_domain and full not in visited:
                    visited.add(full)
                    queue.append((full, current_depth + 1))

        except Exception as e:
            if verbose:
                print(f"  {GREY}[crawl] Error: {e}{RESET}")

    return visited, forms


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7  ──  SCAN ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def _module_summary(findings):
    if findings:
        print(f"  {RED}[!] {len(findings)} issue(s) found{RESET}")
    else:
        print(f"  {GREEN}[✓] No issues found{RESET}")


def run_scan(target_url, modules, depth, threads, timeout, cookies, headers, verbose):
    session = requests.Session()
    session.headers.update({"User-Agent": "WebVulnScan/1.0 (Security Research)",
                             **(headers or {})})
    session.cookies.update(cookies or {})

    print(f"\n{CYAN}[*] Phase 1: Crawling target...{RESET}")
    visited_urls, forms_collected = crawl(session, target_url, depth, timeout, verbose)
    print(f"{GREEN}[+] Crawled {len(visited_urls)} pages, "
          f"found {len(forms_collected)} forms{RESET}")

    results = {"sqli": [], "xss": [], "redirect": [], "files": []}
    print(f"\n{CYAN}[*] Phase 2: Running {len(modules)} module(s)...{RESET}")

    def threaded(fn, items):
        out = []
        with ThreadPoolExecutor(max_workers=threads) as pool:
            for fut in as_completed({pool.submit(fn, *item): item for item in items}):
                try:
                    r = fut.result()
                    if r:
                        out.extend(r)
                except Exception as e:
                    if verbose:
                        print(f"  {GREY}[thread error] {e}{RESET}")
        return out

    if "sqli" in modules:
        print(f"\n{BLUE}[>] Module: SQLI{RESET}")
        results["sqli"] = threaded(
            lambda s, u, f, t, v: sqli_scan_form(s, u, f, t, v),
            [(session, item["url"], item["form"], timeout, verbose)
             for item in forms_collected]
        )
        _module_summary(results["sqli"])

    if "xss" in modules:
        print(f"\n{BLUE}[>] Module: XSS{RESET}")
        results["xss"] = threaded(
            lambda s, u, f, t, v: xss_scan_form(s, u, f, t, v),
            [(session, item["url"], item["form"], timeout, verbose)
             for item in forms_collected]
        )
        _module_summary(results["xss"])

    if "redirect" in modules:
        print(f"\n{BLUE}[>] Module: REDIRECT{RESET}")
        results["redirect"] = threaded(
            lambda s, u, t, v: redirect_scan_url(s, u, t, v),
            [(session, url, timeout, verbose) for url in visited_urls]
        )
        _module_summary(results["redirect"])

    if "files" in modules:
        print(f"\n{BLUE}[>] Module: FILES{RESET}")
        results["files"] = files_scan(session, target_url, timeout, verbose)
        _module_summary(results["files"])

    return results


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8  ──  REPORTER
# ══════════════════════════════════════════════════════════════════════════════

def _all_sorted(results):
    flat = []
    for module, findings in results.items():
        for f in findings:
            f.setdefault("module", module)
            flat.append(f)
    flat.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 4))
    return flat


def report_terminal(results, target_url):
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    findings  = _all_sorted(results)

    print(f"\n{'='*70}")
    print(f"{BOLD}  SCAN REPORT  |  {target_url}{RESET}")
    print(f"  Generated : {timestamp}")
    print(f"{'='*70}\n")

    if not findings:
        print(f"  {CYAN}[✓] No vulnerabilities detected.{RESET}\n")
        return

    counts = {}
    for f in findings:
        s = f.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1

    print(f"  {BOLD}Summary:{RESET}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in counts:
            c = SEVERITY_COLORS[sev]
            print(f"    {c}[{sev}]{RESET}  {counts[sev]} finding(s)")

    print(f"\n  {BOLD}Findings:{RESET}\n")
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO")
        c   = SEVERITY_COLORS.get(sev, "")
        print(f"  [{i}] {c}{BOLD}{f['type']}{RESET} — {f.get('subtype','')}")
        print(f"      {BOLD}Severity  :{RESET} {c}{sev}{RESET}")
        print(f"      {BOLD}URL       :{RESET} {f.get('url','')}")
        print(f"      {BOLD}Parameter :{RESET} {f.get('parameter','')}")
        print(f"      {BOLD}Payload   :{RESET} {f.get('payload','')}")
        print(f"      {BOLD}Evidence  :{RESET} {f.get('evidence','')}")
        print()


def report_json(results, target_url):
    findings  = _all_sorted(results)
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    return json.dumps({
        "scanner":   "WebVulnScan v1.0.0",
        "target":    target_url,
        "timestamp": timestamp,
        "summary": {s: sum(1 for f in findings if f.get("severity") == s)
                    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
        "findings": findings,
    }, indent=2)


def report_html(results, target_url):
    findings  = _all_sorted(results)
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    SEV_CSS   = {"CRITICAL": "#ff2244", "HIGH": "#ff7700",
                 "MEDIUM": "#ffcc00",   "LOW": "#44aaff", "INFO": "#aaaaaa"}

    rows = ""
    for f in findings:
        sev = f.get("severity", "INFO")
        col = SEV_CSS.get(sev, "#aaa")
        rows += (
            f"<tr>"
            f"<td><span class='badge' style='background:{col}20;color:{col};"
            f"border:1px solid {col}50'>{sev}</span></td>"
            f"<td><strong>{f.get('type','')}</strong><br>"
            f"<small>{f.get('subtype','')}</small></td>"
            f"<td><code>{f.get('url','')}</code></td>"
            f"<td><code>{f.get('parameter','')}</code></td>"
            f"<td><code>{f.get('payload','')}</code></td>"
            f"<td>{f.get('evidence','')}</td>"
            f"</tr>"
        )

    counts       = {s: sum(1 for f in findings if f.get("severity") == s)
                    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
    summary_html = "".join(
        f'<div class="chip" style="border-color:{SEV_CSS[s]}40">'
        f'<span style="color:{SEV_CSS[s]};font-size:1.6rem;font-weight:700">'
        f'{counts.get(s,0)}</span>'
        f'<span class="chip-lbl">{s}</span></div>'
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )

    no_data = ('<tr><td colspan="6" style="text-align:center;color:#444;padding:2rem">'
               'No vulnerabilities detected.</td></tr>')

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebVulnScan Report \u2013 {target_url}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Courier New',monospace;background:#080a0f;color:#c9d1d9;
     padding:2rem;line-height:1.6}}
header{{border-bottom:1px solid #1e2535;padding-bottom:1.5rem;margin-bottom:1.5rem}}
h1{{color:#00ff88;font-size:1.6rem;letter-spacing:.05em;margin-bottom:.3rem}}
h2{{color:#4a9eff;font-size:.9rem;font-weight:400}}
.summary{{display:flex;gap:12px;margin:1.5rem 0;flex-wrap:wrap}}
.chip{{background:#0d1117;border:1px solid #1e2535;border-radius:8px;
       padding:12px 20px;text-align:center;min-width:100px;
       display:flex;flex-direction:column;gap:4px}}
.chip-lbl{{font-size:.65rem;letter-spacing:.1em;color:#6e7681}}
table{{width:100%;border-collapse:collapse;font-size:.8rem}}
th{{background:#0d1117;color:#00ff88;padding:10px 12px;text-align:left;
    border-bottom:1px solid #1e2535;font-size:.75rem;letter-spacing:.06em}}
td{{padding:10px 12px;border-bottom:1px solid #0d1117;vertical-align:top}}
tr:hover td{{background:#0d1117}}
.badge{{padding:3px 9px;border-radius:4px;font-size:.7rem;
        font-weight:700;white-space:nowrap}}
code{{background:#0d1117;padding:2px 5px;border-radius:3px;
      font-size:.78rem;word-break:break-all;color:#79c0ff}}
small{{color:#6e7681;font-size:.75rem}}
footer{{margin-top:2rem;font-size:.75rem;color:#444;text-align:center}}
</style>
</head>
<body>
<header>
  <h1>&#128269; WebVulnScan Report</h1>
  <h2>Target: {target_url} &nbsp;|&nbsp; {timestamp} &nbsp;|&nbsp; {len(findings)} findings</h2>
</header>
<div class="summary">{summary_html}</div>
<table>
<thead>
  <tr><th>SEVERITY</th><th>VULNERABILITY</th><th>URL</th>
      <th>PARAM</th><th>PAYLOAD</th><th>EVIDENCE</th></tr>
</thead>
<tbody>{rows if rows else no_data}</tbody>
</table>
<footer>Generated by WebVulnScan v1.0.0 \u2014 For authorized security testing only</footer>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9  ──  CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        description="WebVulnScan \u2013 Automated Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python webvulnscan.py https://testphp.vulnweb.com
  python webvulnscan.py https://testphp.vulnweb.com -m sqli xss
  python webvulnscan.py https://target.com -o html -r report.html -d 3
  python webvulnscan.py https://app.com --cookies '{"session":"abc123"}' -v

Safe test targets (intentionally vulnerable labs):
  http://testphp.vulnweb.com    (Acunetix demo lab)
  http://demo.testfire.net      (IBM demo lab)
  DVWA / WebGoat / OWASP Juice Shop  (run locally via Docker)

LEGAL: Only scan systems you own or have explicit written permission to test.
        """
    )
    parser.add_argument("url",            help="Target URL  e.g. https://example.com")
    parser.add_argument("-m", "--modules", nargs="+",
                        choices=["sqli", "xss", "redirect", "files", "all"],
                        default=["all"],   help="Modules to run (default: all)")
    parser.add_argument("-d", "--depth",   type=int, default=2,
                        help="Crawl depth (default: 2)")
    parser.add_argument("-t", "--threads", type=int, default=5,
                        help="Concurrent threads (default: 5)")
    parser.add_argument("-o", "--output",  choices=["terminal", "json", "html"],
                        default="terminal", help="Output format (default: terminal)")
    parser.add_argument("-r", "--report-file", default=None,
                        help="Save report to file")
    parser.add_argument("--timeout",       type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("-c", "--cookies", default=None,
                        help='Cookies JSON  e.g. \'{"session":"abc"}\'')
    parser.add_argument("--headers",       default=None,
                        help='Custom headers JSON')
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose probe output")
    parser.add_argument("--no-banner",     action="store_true",
                        help="Suppress ASCII banner")
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.no_banner:
        print(BANNER)

    modules = (["sqli", "xss", "redirect", "files"]
               if "all" in args.modules else args.modules)

    print(f"  {BOLD}Target  :{RESET} {args.url}")
    print(f"  {BOLD}Modules :{RESET} {', '.join(modules)}")
    print(f"  {BOLD}Depth   :{RESET} {args.depth}  "
          f"{BOLD}Threads:{RESET} {args.threads}  "
          f"{BOLD}Timeout:{RESET} {args.timeout}s")
    print(f"  {GREY}{'─'*62}{RESET}")

    try:
        cookies = json.loads(args.cookies) if args.cookies else {}
        headers = json.loads(args.headers) if args.headers else {}
    except json.JSONDecodeError as e:
        print(f"{RED}[!] Invalid JSON for cookies/headers: {e}{RESET}")
        sys.exit(1)

    results = run_scan(
        target_url=args.url,
        modules=modules,
        depth=args.depth,
        threads=args.threads,
        timeout=args.timeout,
        cookies=cookies,
        headers=headers,
        verbose=args.verbose,
    )

    # Output
    if args.output == "terminal":
        report_terminal(results, args.url)

    elif args.output == "json":
        out = report_json(results, args.url)
        if args.report_file:
            with open(args.report_file, "w") as fh:
                fh.write(out)
            print(f"\n{GREEN}[+] JSON report saved \u2192 {args.report_file}{RESET}")
        else:
            print(out)

    elif args.output == "html":
        out = report_html(results, args.url)
        if args.report_file:
            with open(args.report_file, "w") as fh:
                fh.write(out)
            print(f"\n{GREEN}[+] HTML report saved \u2192 {args.report_file}{RESET}")
        else:
            print(out)

    total = sum(len(v) for v in results.values())
    color = GREEN if total == 0 else RED
    print(f"\n{color}{'─'*70}")
    print(f"  Scan complete. {total} "
          f"vulnerabilit{'y' if total == 1 else 'ies'} found.")
    print(f"{'─'*70}{RESET}\n")
    sys.exit(1 if total > 0 else 0)


# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    main()
