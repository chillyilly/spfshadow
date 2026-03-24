#!/usr/bin/env python3
"""
SPF Shadow 2.0 — Comprehensive email authentication audit & risk analysis.

Performs deep security analysis of SPF, DMARC, DKIM, MTA-STS, DANE/TLSA, and BIMI
across a domain and its subdomains, informed by current attack research:

  Core checks:
    - Subdomain enumeration from 4 OSINT sources (concurrent)
    - SPF shadow detection (subdomain SPF divergence from root)
    - SPF record linting (RFC 7208 compliance, void lookup detection, ptr deprecation,
      +all/?all, macro presence, multiple SPF records, include-tree flattening with
      DNS lookup budget tracking)
    - DMARC policy audit (RFC 7489: p/sp/pct/adkim/aspf alignment, rua/ruf reporting,
      subdomain policy inheritance gaps)
    - DKIM key audit (RFC 6376: key length check, test mode t=y, l= body length tag,
      empty p= revoked keys, selector enumeration)
    - MX fingerprinting (provider identification from exchange hostnames)
    - Dangling DNS / subdomain takeover detection (CNAME to non-resolving targets,
      NS delegation to dead zones, known vulnerable service fingerprints)
    - MTA-STS policy fetch and validation (RFC 8461)
    - SMTP TLS Reporting record check (RFC 8460)
    - DANE/TLSA record check (RFC 7672)
    - BIMI record check (VMC/SVG logo discovery)
    - DMARC external report destination authorization validation
    - SPF-vs-MX provider mismatch detection
    - Per-subdomain risk scoring with weighted factor model

  Output:
    - Interactive terminal UI or CLI one-shot mode
    - Export to CSV, JSON, and dark-themed HTML report
"""

# ----- User Configuration -----
SECURITYTRAILS_API_KEY = ""   # or set env SECURITYTRAILS_API_KEY
VT_API_KEY = ""               # or set env VT_API_KEY

import os
import re
import csv
import sys
import json
import signal
import argparse
import time
import base64
import struct
from html import escape as html_escape
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from dns.resolver import resolve, Resolver, NXDOMAIN, NoAnswer, Timeout, NoNameservers
import dns.resolver
import dns.rdatatype

# ── Globals ──────────────────────────────────────────────────────────────────

SECURITYTRAILS_API_KEY = SECURITYTRAILS_API_KEY or os.getenv("SECURITYTRAILS_API_KEY", "")
VT_API_KEY = VT_API_KEY or os.getenv("VT_API_KEY", "")

COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",     # Google / M365
    "k1", "k2", "k3",                                   # Mailchimp
    "s1", "s2",                                          # Generic
    "mandrill", "smtp", "mail", "dkim", "mx",
    "everlytickey1", "everlytickey2",                    # Everlytic
    "cm",                                                # Campaign Monitor
    "sg", "smtpapi", "s",                                # SendGrid
    "pm",                                                # Postmark
    "mesmtp", "pic", "proddkim1024",                     # Misc enterprise
    "dk",                                                # Legacy DomainKeys
    "amazonses", "ug7nbtf4gccmlpwj322ax3p6ow6fovt7",    # SES
    "scph0316", "hsbnp7p3ensaochzwyq5wwmceodymuwv",     # HubSpot
]

KNOWN_MAIL_PROVIDERS = {
    "google.com":              "Google Workspace",
    "googlemail.com":          "Google Workspace",
    "outlook.com":             "Microsoft 365",
    "protection.outlook.com":  "Microsoft 365",
    "pphosted.com":            "Proofpoint",
    "mimecast.com":            "Mimecast",
    "mailgun.org":             "Mailgun",
    "sendgrid.net":            "SendGrid",
    "amazonses.com":           "Amazon SES",
    "zendesk.com":             "Zendesk",
    "freshdesk.com":           "Freshdesk",
    "mandrillapp.com":         "Mandrill/Mailchimp",
    "postmarkapp.com":         "Postmark",
    "sparkpostmail.com":       "SparkPost",
    "messagelabs.com":         "Broadcom/Symantec",
    "barracudanetworks.com":   "Barracuda",
    "fireeyecloud.com":        "Trellix/FireEye",
    "mailchimp.com":           "Mailchimp",
    "hubspotemail.net":        "HubSpot",
    "exacttarget.com":         "Salesforce MC",
    "cust-spf.exacttarget.com":"Salesforce MC",
    "secureserver.net":        "GoDaddy",
    "emailsrvr.com":           "Rackspace",
    "zoho.com":                "Zoho",
}

# SPF includes that authorize very large IP ranges (millions of IPs)
OVERLY_PERMISSIVE_INCLUDES = {
    "_spf.google.com":      "Google (~millions of IPs)",
    "spf.protection.outlook.com": "Microsoft 365 (~millions of IPs)",
    "_netblocks.google.com": "Google netblocks",
    "_netblocks2.google.com": "Google netblocks",
    "_netblocks3.google.com": "Google netblocks",
    "amazonses.com":        "Amazon SES (shared infrastructure)",
    "sendgrid.net":         "SendGrid (shared infrastructure)",
    "mailgun.org":          "Mailgun (shared infrastructure)",
    "mandrillapp.com":      "Mandrill (shared infrastructure)",
    "servers.mcsv.net":     "Mailchimp (shared infrastructure)",
}

# Known subdomain takeover-vulnerable CNAME targets
TAKEOVER_FINGERPRINTS = [
    ".herokuapp.com",
    ".herokudns.com",
    ".azurewebsites.net",
    ".cloudapp.net",
    ".trafficmanager.net",
    ".blob.core.windows.net",
    ".cloudfront.net",
    ".s3.amazonaws.com",
    ".s3-website",
    ".elasticbeanstalk.com",
    ".ghost.io",
    ".pantheonsite.io",
    ".domains.tumblr.com",
    ".wordpress.com",
    ".myshopify.com",
    ".zendesk.com",
    ".freshdesk.com",
    ".uservoice.com",
    ".surge.sh",
    ".bitbucket.io",
    ".ghost.org",
    ".helpjuice.com",
    ".helpscoutdocs.com",
    ".mashery.com",
    ".statuspage.io",
    ".teamwork.com",
    ".thinkific.com",
    ".unbounce.com",
    ".feedpress.me",
    ".cargocollective.com",
    ".smartling.com",
    ".acquia-test.co",
    ".proposify.biz",
    ".simplebooklet.com",
    ".getresponse.com",
    ".vend-dns.com",
    ".appspot.com",
    ".fly.dev",
    ".netlify.app",
    ".vercel.app",
    ".render.com",
    ".pages.dev",
]

# Map SPF include patterns to provider names (for SPF-MX mismatch detection)
SPF_INCLUDE_PROVIDERS = {
    "google.com":              "Google Workspace",
    "_spf.google.com":         "Google Workspace",
    "protection.outlook.com":  "Microsoft 365",
    "spf.protection.outlook.com": "Microsoft 365",
    "pphosted.com":            "Proofpoint",
    "mimecast":                "Mimecast",
    "mailgun.org":             "Mailgun",
    "sendgrid.net":            "SendGrid",
    "amazonses.com":           "Amazon SES",
    "mandrillapp.com":         "Mandrill/Mailchimp",
    "servers.mcsv.net":        "Mailchimp",
    "postmarkapp.com":         "Postmark",
    "sparkpostmail.com":       "SparkPost",
    "zendesk.com":             "Zendesk",
    "freshdesk.com":           "Freshdesk",
    "zoho.com":                "Zoho",
    "secureserver.net":        "GoDaddy",
    "emailsrvr.com":           "Rackspace",
    "hubspotemail.net":        "HubSpot",
    "exacttarget.com":         "Salesforce MC",
}

def signal_handler(sig, frame):
    print("\n[!] Interrupted. Exiting.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ── DNS Helpers ──────────────────────────────────────────────────────────────

def _resolver(timeout=3, lifetime=6):
    r = Resolver()
    r.timeout = timeout
    r.lifetime = lifetime
    return r

def query_txt(domain, timeout=3):
    try:
        answers = _resolver(timeout).resolve(domain, "TXT")
        return [
            txt.decode("utf-8")
            for rdata in answers
            for txt in rdata.strings
        ]
    except (NXDOMAIN, NoAnswer, Timeout, NoNameservers):
        return []
    except Exception:
        return []

def query_mx(domain, timeout=3):
    try:
        answers = _resolver(timeout).resolve(domain, "MX")
        return sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in answers],
            key=lambda x: x[0],
        )
    except (NXDOMAIN, NoAnswer, Timeout, NoNameservers):
        return []
    except Exception:
        return []

def query_a(domain, timeout=2):
    try:
        answers = _resolver(timeout).resolve(domain, "A")
        return [str(r) for r in answers]
    except Exception:
        return []

def query_aaaa(domain, timeout=2):
    try:
        answers = _resolver(timeout).resolve(domain, "AAAA")
        return [str(r) for r in answers]
    except Exception:
        return []

def query_cname(domain, timeout=2):
    try:
        answers = _resolver(timeout).resolve(domain, "CNAME")
        return [str(r.target).rstrip(".") for r in answers]
    except Exception:
        return []

def query_ns(domain, timeout=2):
    try:
        answers = _resolver(timeout).resolve(domain, "NS")
        return [str(r.target).rstrip(".") for r in answers]
    except Exception:
        return []

def query_tlsa(domain, port=25, timeout=3):
    """Query DANE TLSA records for SMTP (RFC 7672)."""
    name = f"_{port}._tcp.{domain}"
    try:
        answers = _resolver(timeout).resolve(name, "TLSA")
        results = []
        for rdata in answers:
            results.append({
                "usage": rdata.usage,
                "selector": rdata.selector,
                "mtype": rdata.mtype,
                "cert": rdata.cert.hex(),
            })
        return results
    except Exception:
        return []

# ── Subdomain Enumeration Sources ────────────────────────────────────────────

def get_crtsh_subdomains(domain, debug=False):
    """Query crt.sh Certificate Transparency logs for subdomains.

    crt.sh is a free service that can be slow (30-60s for large domains)
    and returns 503 when overloaded. We retry up to 3 times with backoff
    and use a generous timeout.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0"}
    max_retries = 3

    for attempt in range(1, max_retries + 1):
        try:
            if debug and attempt > 1:
                print(f"  [crt.sh] Retry {attempt}/{max_retries}...")
            resp = requests.get(url, headers=headers, timeout=60)
            if resp.status_code == 503:
                if debug:
                    print(f"  [crt.sh] 503 (overloaded), "
                          f"waiting {10 * attempt}s...")
                time.sleep(10 * attempt)
                continue
            if resp.status_code != 200:
                raise Exception(f"HTTP {resp.status_code}")
            if not resp.headers.get("Content-Type", "").startswith("application/json"):
                raise Exception("non-JSON response")
            text = resp.text.strip()
            if not text.startswith("["):
                raise Exception("unexpected format")
            seen = set()
            for entry in resp.json():
                for sub in entry.get("name_value", "").splitlines():
                    sub = sub.strip().lower()
                    if sub.endswith(domain) and "*" not in sub:
                        seen.add(sub)
            if debug:
                print(f"  [crt.sh] {len(seen)} subdomains")
            return seen
        except requests.exceptions.Timeout:
            if debug:
                print(f"  [crt.sh] Timeout on attempt {attempt} (60s), "
                      f"{'retrying' if attempt < max_retries else 'giving up'}...")
            if attempt < max_retries:
                time.sleep(5)
                continue
        except Exception as e:
            if debug:
                print(f"  [crt.sh] Error: {e}")
            break
    return set()

def get_securitytrails_subdomains(domain, debug=False):
    if not SECURITYTRAILS_API_KEY:
        if debug:
            print("  [securitytrails] No API key, skipping")
        return set()
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        r = requests.get(url, headers={"APIKEY": SECURITYTRAILS_API_KEY}, timeout=15)
        data = r.json()
        subs = {f"{s}.{domain}" for s in data.get("subdomains", [])}
        if debug:
            print(f"  [securitytrails] {len(subs)} subdomains")
        return subs
    except Exception as e:
        if debug:
            print(f"  [securitytrails] Error: {e}")
        return set()

def _vt_click_load_more(page, target_idx):
    """Click the Nth vt-ui-button.load-more web component in the shadow DOM."""
    return page.evaluate("""(targetIdx) => {
        let idx = 0;
        function search(root, d) {
            if (d > 10) return false;
            const els = root.querySelectorAll ?
                root.querySelectorAll('*') : [];
            for (const el of els) {
                if (el.shadowRoot && search(el.shadowRoot, d + 1))
                    return true;
                if (el.tagName === 'VT-UI-BUTTON' &&
                    (el.className || '').toString().includes('load-more')) {
                    idx++;
                    if (idx === targetIdx) {
                        el.scrollIntoView({block: 'center'});
                        el.click();
                        return true;
                    }
                }
            }
            return false;
        }
        return search(document, 0);
    }""", target_idx)


def _vt_scrape_headless(domain, debug=False):
    """Scrape VirusTotal subdomains using a stealth headless browser.

    Applies anti-detection patches (navigator.webdriver, WebGL, plugins, etc.)
    to appear as a normal browser session. Loads the relations page, intercepts
    subdomain API responses, then clicks the load-more button to paginate.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        if debug:
            print("  [virustotal/browser] playwright not installed, skipping")
        return set()

    # Optional stealth patches
    stealth_obj = None
    try:
        from playwright_stealth import Stealth
        stealth_obj = Stealth(
            navigator_webdriver=True,
            navigator_plugins=True,
            navigator_languages=True,
            navigator_platform=True,
            navigator_vendor=True,
            navigator_user_agent=True,
            webgl_vendor=True,
            chrome_runtime=True,
            chrome_app=True,
            hairline=True,
            media_codecs=True,
            navigator_hardware_concurrency=True,
            iframe_content_window=True,
            navigator_permissions=True,
            sec_ch_ua=True,
            error_prototype=True,
        )
    except ImportError:
        pass

    all_subs = set()
    start_time = time.time()
    max_duration = 120
    import random

    def _handle_response(response):
        if "/subdomains" in response.url and response.status == 200:
            try:
                data = response.json()
                for entry in data.get("data", []):
                    sid = entry.get("id")
                    if sid:
                        all_subs.add(sid)
            except Exception:
                pass

    try:
        with sync_playwright() as p:
            # Use Firefox — fewer headless detection vectors than Chromium
            browser = p.firefox.launch(headless=True)

            # Realistic browser context
            context = browser.new_context(
                viewport={
                    "width": random.choice([1366, 1440, 1536, 1920]),
                    "height": random.choice([768, 900, 864, 1080]),
                },
                locale="en-US",
                timezone_id="America/New_York",
                color_scheme="dark",
            )

            # Apply stealth patches if available
            if stealth_obj:
                stealth_obj.apply_stealth_sync(context)
                if debug:
                    print("  [virustotal/browser] Stealth patches applied")

            page = context.new_page()
            page.on("response", _handle_response)

            # Simulate human: visit VT homepage first, then navigate
            if debug:
                print("  [virustotal/browser] Visiting homepage first...")
            page.goto("https://www.virustotal.com/gui/home/search",
                      wait_until="domcontentloaded", timeout=20000)
            page.wait_for_timeout(random.randint(2000, 4000))

            # Dismiss cookie/CAPTCHA overlays
            page.evaluate("""() => {
                document.querySelectorAll(
                    'captcha-dialog, vt-ui-cookie-dialog, .modal-backdrop, .cookie-banner'
                ).forEach(el => el.remove());
            }""")
            page.wait_for_timeout(random.randint(500, 1500))

            # Simulate human mouse movement
            page.mouse.move(
                random.randint(200, 800),
                random.randint(200, 600),
                steps=random.randint(5, 15)
            )

            # Navigate to the target domain's relations page
            gui_url = f"https://www.virustotal.com/gui/domain/{domain}/relations"
            if debug:
                print(f"  [virustotal/browser] Navigating to {domain}")
            page.goto(gui_url, wait_until="domcontentloaded", timeout=30000)

            # Wait for initial API calls with human-like patience
            page.wait_for_timeout(random.randint(3000, 5000))

            # Dismiss any CAPTCHA/overlays that appeared
            page.evaluate("""() => {
                document.querySelectorAll(
                    'captcha-dialog, vt-ui-cookie-dialog, .modal-backdrop'
                ).forEach(el => el.remove());
                // Also remove from shadow DOM
                function clean(root, d) {
                    if (d > 5) return;
                    const els = root.querySelectorAll ?
                        root.querySelectorAll('*') : [];
                    for (const el of els) {
                        if (el.shadowRoot) clean(el.shadowRoot, d + 1);
                        if (el.tagName === 'CAPTCHA-DIALOG' ||
                            el.tagName === 'VT-UI-COOKIE-DIALOG')
                            el.remove();
                    }
                }
                clean(document, 0);
            }""")

            # Wait for subdomain data to load
            page.wait_for_timeout(random.randint(4000, 6000))

            if debug:
                print(f"  [virustotal/browser] Initial page captured "
                      f"{len(all_subs)} subdomains")

            if len(all_subs) == 0:
                if debug:
                    print("  [virustotal/browser] No initial data — "
                          "likely CAPTCHA blocked. Aborting gracefully.")
                browser.close()
                return all_subs

            # Simulate a small scroll (human behavior)
            page.mouse.wheel(0, random.randint(200, 500))
            page.wait_for_timeout(random.randint(800, 1500))

            # Find which load-more button is for subdomains by probing
            total_btns = page.evaluate("""() => {
                let count = 0;
                function search(root, d) {
                    if (d > 10) return;
                    const els = root.querySelectorAll ?
                        root.querySelectorAll('*') : [];
                    for (const el of els) {
                        if (el.shadowRoot) search(el.shadowRoot, d + 1);
                        if (el.tagName === 'VT-UI-BUTTON' &&
                            (el.className || '').toString().includes('load-more'))
                            count++;
                    }
                }
                search(document, 0);
                return count;
            }""")

            sub_btn_idx = None
            for test_idx in range(1, min(total_btns + 1, 8)):
                prev = len(all_subs)
                _vt_click_load_more(page, test_idx)
                page.wait_for_timeout(random.randint(1500, 2500))
                if len(all_subs) > prev:
                    sub_btn_idx = test_idx
                    if debug:
                        print(f"  [virustotal/browser] Subdomain button is "
                              f"#{test_idx} (+{len(all_subs) - prev})")
                    break

            if sub_btn_idx is None:
                if debug:
                    print(f"  [virustotal/browser] Could not identify subdomain "
                          f"button among {total_btns}")
            else:
                # Click repeatedly with human-like timing
                max_clicks = 200
                stale = 0
                clicks = 1
                while clicks < max_clicks and (time.time() - start_time) < max_duration:
                    prev_count = len(all_subs)
                    _vt_click_load_more(page, sub_btn_idx)
                    # Randomized wait between clicks
                    page.wait_for_timeout(random.randint(1200, 2200))
                    if len(all_subs) > prev_count:
                        clicks += 1
                        stale = 0
                        if debug and clicks % 5 == 0:
                            print(f"  [virustotal/browser] {len(all_subs)} "
                                  f"subdomains ({clicks} pages)...")
                    else:
                        stale += 1
                        if stale >= 3:
                            break

            elapsed = time.time() - start_time
            if debug:
                print(f"  [virustotal/browser] Done: {len(all_subs)} subdomains "
                      f"in {elapsed:.1f}s")

            browser.close()
    except Exception as e:
        if debug:
            print(f"  [virustotal/browser] Error: {e}")

    return all_subs


def get_virustotal_subdomains(domain, debug=False):
    """Harvest subdomains from VirusTotal using three methods in priority order:

    1. Headless browser (playwright) — scrapes the public website at
       /gui/domain/{domain}/relations with full JS execution, intercepts
       the /ui/ API responses, and clicks through pagination. No API key needed.
    2. v3 API — if an API key is configured, uses the authenticated endpoint.
    3. Graceful skip if neither works.
    """
    all_subs = set()

    # --- Method 1: Headless browser scrape (no API key required) ---
    all_subs = _vt_scrape_headless(domain, debug)
    if all_subs:
        return all_subs

    # --- Method 2: Fallback to v3 API (requires API key) ---
    if not VT_API_KEY:
        if debug:
            print("  [virustotal/api] No API key and browser scrape yielded 0, skipping")
        return all_subs
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        headers = {"x-apikey": VT_API_KEY}
        while url:
            r = requests.get(url, headers=headers, timeout=15)
            data = r.json()
            for entry in data.get("data", []):
                sid = entry.get("id")
                if sid:
                    all_subs.add(sid)
            url = data.get("links", {}).get("next")
        if debug:
            print(f"  [virustotal/api] {len(all_subs)} subdomains total")
        return all_subs
    except Exception as e:
        if debug:
            print(f"  [virustotal/api] Error: {e}")
        return all_subs

def get_hackertarget_subdomains(domain, debug=False):
    """Query HackerTarget's free host search API. No key required.
    Returns plain text: hostname,ip per line.
    """
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}"
        r = requests.get(url, timeout=20)
        if r.status_code != 200:
            raise Exception(f"HTTP {r.status_code}")
        # Check for API error messages (plain text starting with "error")
        if r.text.strip().lower().startswith("error"):
            raise Exception(r.text.strip()[:100])
        subs = set()
        for line in r.text.strip().splitlines():
            parts = line.split(",")
            if parts and parts[0].strip().endswith(domain):
                subs.add(parts[0].strip().lower())
        if debug:
            print(f"  [hackertarget] {len(subs)} subdomains")
        return subs
    except Exception as e:
        if debug:
            print(f"  [hackertarget] Error: {e}")
        return set()

def get_rapiddns_subdomains(domain, debug=False):
    """Scrape RapidDNS.io for subdomains. No key required.
    Returns an HTML page with subdomains in table rows.
    """
    try:
        url = f"https://rapiddns.io/subdomain/{quote(domain)}?full=1"
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=25)
        if r.status_code != 200:
            raise Exception(f"HTTP {r.status_code}")
        pattern = r"([\w][\w\.-]*\." + re.escape(domain) + r")"
        subs = {s.lower() for s in re.findall(pattern, r.text)}
        if debug:
            print(f"  [rapiddns] {len(subs)} subdomains")
        return subs
    except Exception as e:
        if debug:
            print(f"  [rapiddns] Error: {e}")
        return set()

def enumerate_subdomains(domain, debug=False, workers=5):
    """Fetch subdomains from all OSINT sources concurrently."""
    sources = [
        get_crtsh_subdomains,
        get_securitytrails_subdomains,
        get_virustotal_subdomains,
        get_hackertarget_subdomains,
        get_rapiddns_subdomains,
    ]
    all_subs = set()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fn, domain, debug): fn.__name__ for fn in sources}
        for future in as_completed(futures):
            try:
                all_subs.update(future.result())
            except Exception:
                pass
    return sorted(all_subs)

# ── DNS Validation (concurrent) ──────────────────────────────────────────────

def validate_subdomains(subdomains, workers=20):
    """Return set of subdomains that resolve A or AAAA records."""
    valid = set()

    def _check(sub):
        if query_a(sub) or query_aaaa(sub):
            return sub
        return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for result in pool.map(_check, subdomains):
            if result:
                valid.add(result)
    return valid

# ── SPF Analysis ─────────────────────────────────────────────────────────────

def get_spf_records(domain):
    """Return all SPF records for a domain. Multiple = RFC violation."""
    return [txt for txt in query_txt(domain) if txt.startswith("v=spf1")]

def get_spf_record(domain):
    records = get_spf_records(domain)
    return records[0] if records else None

def lint_spf(domain):
    """Deep lint an SPF record for RFC 7208 violations and security issues.

    Returns list of {severity, code, message} dicts.
    Severities: critical, high, medium, low, info
    """
    issues = []
    records = get_spf_records(domain)

    if not records:
        issues.append({"severity": "high", "code": "SPF_MISSING",
                        "message": "No SPF record found"})
        return issues

    if len(records) > 1:
        issues.append({"severity": "critical", "code": "SPF_MULTIPLE",
                        "message": f"Multiple SPF records found ({len(records)}). "
                                   "RFC 7208 §4.5: MUST NOT have more than one. Results in PermError."})

    spf = records[0]

    # Check record length (DNS TXT 255-byte string limit; long records need concatenation)
    if len(spf) > 450:
        issues.append({"severity": "medium", "code": "SPF_LONG",
                        "message": f"SPF record is {len(spf)} chars. "
                                   "Very long records risk truncation or parsing failures."})

    tokens = spf.split()

    # Terminal mechanism check
    last_token = tokens[-1] if tokens else ""
    last_bare = last_token.lstrip("+-~?")

    if last_bare == "all":
        qualifier = last_token[0] if last_token[0] in "+-~?" else "+"
        if qualifier == "+":
            issues.append({"severity": "critical", "code": "SPF_PLUS_ALL",
                            "message": "+all allows ANY server to send as this domain. "
                                       "Equivalent to no SPF."})
        elif qualifier == "?":
            issues.append({"severity": "high", "code": "SPF_NEUTRAL_ALL",
                            "message": "?all (neutral) provides no protection. "
                                       "Receivers treat it as if SPF doesn't exist."})
        elif qualifier == "~":
            issues.append({"severity": "medium", "code": "SPF_SOFTFAIL_ALL",
                            "message": "~all (softfail) is weaker than -all. "
                                       "Some receivers accept softfail messages."})
        # -all is good, no issue
    elif "all" not in spf and "redirect=" not in spf:
        issues.append({"severity": "high", "code": "SPF_NO_ALL",
                        "message": "No 'all' mechanism and no 'redirect='. "
                                   "RFC 7208 §4.7: default result is neutral."})

    # Deprecated ptr mechanism (RFC 7208 §5.5)
    for token in tokens[1:]:
        bare = token.lstrip("+-~?")
        if bare == "ptr" or bare.startswith("ptr:"):
            issues.append({"severity": "medium", "code": "SPF_PTR_DEPRECATED",
                            "message": f"'{token}': ptr mechanism is deprecated (RFC 7208 §5.5). "
                                       "Slow, unreliable, and SHOULD NOT be used."})

    # Macro usage (can be abused for DNS exfiltration / info gathering)
    if "%" in spf:
        macro_tokens = [t for t in tokens if "%" in t]
        issues.append({"severity": "low", "code": "SPF_MACROS",
                        "message": f"SPF uses macros: {macro_tokens}. "
                                   "Macros can leak sender info via DNS and complicate auditing."})

    # ip4/ip6 with overly broad ranges
    for token in tokens[1:]:
        bare = token.lstrip("+-~?")
        if bare.startswith("ip4:") or bare.startswith("ip6:"):
            addr = bare.split(":", 1)[1]
            if "/" in addr:
                try:
                    prefix_len = int(addr.split("/")[1])
                    if bare.startswith("ip4:") and prefix_len < 16:
                        host_count = 2 ** (32 - prefix_len)
                        issues.append({"severity": "high", "code": "SPF_BROAD_IP4",
                                        "message": f"'{token}': /{prefix_len} authorizes "
                                                   f"~{host_count:,} IPs. Overly permissive."})
                    elif bare.startswith("ip4:") and prefix_len < 24:
                        host_count = 2 ** (32 - prefix_len)
                        issues.append({"severity": "medium", "code": "SPF_WIDE_IP4",
                                        "message": f"'{token}': /{prefix_len} authorizes "
                                                   f"~{host_count:,} IPs."})
                    elif bare.startswith("ip6:") and prefix_len < 48:
                        issues.append({"severity": "medium", "code": "SPF_BROAD_IP6",
                                        "message": f"'{token}': /{prefix_len} is a very broad "
                                                   "IPv6 range."})
                except (ValueError, IndexError):
                    pass

    # Check for overly permissive shared-infrastructure includes
    for token in tokens[1:]:
        bare = token.lstrip("+-~?")
        if bare.startswith("include:"):
            target = bare.split(":", 1)[1]
            for pattern, desc in OVERLY_PERMISSIVE_INCLUDES.items():
                if pattern in target:
                    issues.append({"severity": "low", "code": "SPF_SHARED_INFRA",
                                    "message": f"'{token}': includes {desc}. "
                                               "Shared infrastructure means other tenants can "
                                               "also pass SPF for this domain."})

    # Mechanism syntax / typo detection
    VALID_MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists", "redirect"}
    for token in tokens[1:]:
        bare = token.lstrip("+-~?")
        mech_name = bare.split(":")[0].split("/")[0].split("=")[0]
        if mech_name and mech_name not in VALID_MECHANISMS:
            # Check for common typos
            typo_candidates = {"incldue", "inlcude", "inclue", "includ", "inlude",
                               "iclude", "nclude", "incluide", "includee",
                               "ip$", "ipv4", "ipv6", "mx4", "exsits", "exsist",
                               "rediect", "redirct", "reditect"}
            if mech_name.lower() in typo_candidates:
                issues.append({"severity": "high", "code": "SPF_TYPO",
                                "message": f"'{token}': likely typo in mechanism name "
                                           f"('{mech_name}'). Will be silently ignored by validators."})
            else:
                issues.append({"severity": "low", "code": "SPF_UNKNOWN_MECH",
                                "message": f"'{token}': unrecognized mechanism '{mech_name}'."})

    # SPF-MX provider mismatch detection
    mx_providers = set()
    for mx_rec in query_mx(domain):
        _, exchange = mx_rec
        for pattern, name in KNOWN_MAIL_PROVIDERS.items():
            if pattern in exchange.lower():
                mx_providers.add(name)

    spf_providers = set()
    for token in tokens[1:]:
        bare = token.lstrip("+-~?")
        if bare.startswith("include:"):
            target = bare.split(":", 1)[1]
            for pattern, name in SPF_INCLUDE_PROVIDERS.items():
                if pattern in target:
                    spf_providers.add(name)

    # Providers in SPF but not in MX (potential leftover from old provider)
    spf_only = spf_providers - mx_providers
    for provider in spf_only:
        issues.append({"severity": "low", "code": "SPF_MX_MISMATCH",
                        "message": f"SPF authorizes {provider} but MX records don't use it. "
                                   "May be intentional (transactional email) or a stale include "
                                   "that expands the attack surface unnecessarily."})

    return issues

def flatten_spf_includes(domain, depth=0, seen=None, void_count=None):
    """Recursively walk SPF include/redirect tree.

    Returns (mechanisms, dns_lookups, warnings, void_lookups).
    RFC 7208 allows max 10 DNS-causing mechanisms (include, a, mx, ptr, exists, redirect).
    RFC 7208 §4.6.4: max 2 void lookups (NXDOMAIN/empty SPF responses).
    """
    if void_count is None:
        void_count = [0]  # mutable counter shared across recursion
    if seen is None:
        seen = set()
    if domain in seen or depth > 12:
        return [], 0, (["circular:" + domain] if domain in seen and depth > 0 else []), void_count[0]
    seen.add(domain)

    spf = get_spf_record(domain)
    if not spf:
        # This is a void lookup — include target returned no SPF
        if depth > 0:
            void_count[0] += 1
        return [], 0, [], void_count[0]

    mechanisms = []
    lookups = 0
    warnings = []
    tokens = spf.split()

    for token in tokens[1:]:
        t = token.lstrip("+-~?")

        if t.startswith("include:"):
            target = t.split(":", 1)[1]
            lookups += 1
            mechanisms.append((token, domain, depth))
            child_mechs, child_lookups, child_warns, _ = flatten_spf_includes(
                target, depth + 1, seen, void_count)
            mechanisms.extend(child_mechs)
            lookups += child_lookups
            warnings.extend(child_warns)

        elif t.startswith("redirect="):
            target = t.split("=", 1)[1]
            lookups += 1
            mechanisms.append((token, domain, depth))
            child_mechs, child_lookups, child_warns, _ = flatten_spf_includes(
                target, depth + 1, seen, void_count)
            mechanisms.extend(child_mechs)
            lookups += child_lookups
            warnings.extend(child_warns)

        elif t.startswith(("a:", "a/", "mx:", "mx/", "ptr:", "exists:")):
            lookups += 1
            mechanisms.append((token, domain, depth))

        elif t in ("a", "mx", "ptr"):
            lookups += 1
            mechanisms.append((token, domain, depth))

        else:
            mechanisms.append((token, domain, depth))

    if lookups > 10:
        warnings.append(f"{domain}: contributes to >10 DNS lookups")
    if void_count[0] > 2:
        warnings.append(f"void lookups: {void_count[0]} (RFC 7208 §4.6.4 limit is 2)")

    return mechanisms, lookups, warnings, void_count[0]

def spf_complexity_report(domain):
    """Analyze an SPF record's include tree and DNS lookup budget."""
    mechs, total_lookups, warnings, void_lookups = flatten_spf_includes(domain)
    over_limit = total_lookups > 10
    return {
        "domain": domain,
        "root_spf": get_spf_record(domain),
        "mechanisms": mechs,
        "total_dns_lookups": total_lookups,
        "void_lookups": void_lookups,
        "over_limit": over_limit,
        "void_over_limit": void_lookups > 2,
        "warnings": warnings,
    }

# ── DMARC Analysis ───────────────────────────────────────────────────────────

def get_dmarc_record(domain):
    for txt in query_txt(f"_dmarc.{domain}"):
        if txt.startswith("v=DMARC1"):
            return txt
    return None

def parse_dmarc(record):
    """Parse a DMARC record into a dict of tag=value pairs."""
    if not record:
        return {}
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip()] = v.strip()
    return tags

def lint_dmarc(domain):
    """Deep lint a DMARC record for RFC 7489 violations and security gaps.

    Returns list of {severity, code, message} dicts.
    """
    issues = []
    record = get_dmarc_record(domain)

    if not record:
        issues.append({"severity": "high", "code": "DMARC_MISSING",
                        "message": "No DMARC record found at _dmarc." + domain})
        return issues

    tags = parse_dmarc(record)

    # Policy check
    policy = tags.get("p", "").lower()
    if not policy:
        issues.append({"severity": "high", "code": "DMARC_NO_POLICY",
                        "message": "DMARC record has no p= tag (required)."})
    elif policy == "none":
        issues.append({"severity": "medium", "code": "DMARC_POLICY_NONE",
                        "message": "p=none: monitoring only, no enforcement. "
                                   "Spoofed mail is delivered normally."})
    elif policy == "quarantine":
        issues.append({"severity": "low", "code": "DMARC_POLICY_QUARANTINE",
                        "message": "p=quarantine: spoofed mail goes to spam. "
                                   "p=reject is stronger."})

    # Subdomain policy (sp=)
    sp = tags.get("sp", "").lower()
    if not sp and policy != "reject":
        issues.append({"severity": "medium", "code": "DMARC_NO_SP",
                        "message": "No sp= tag. Subdomain policy inherits from p= "
                                   f"(currently '{policy}'). Subdomains may be spoofable."})
    elif sp == "none":
        issues.append({"severity": "high", "code": "DMARC_SP_NONE",
                        "message": "sp=none: subdomains have no DMARC enforcement. "
                                   "SPF shadow attacks on subdomains bypass DMARC."})

    # Percentage (pct=)
    pct = tags.get("pct")
    if pct is not None:
        try:
            pct_val = int(pct)
            if pct_val < 100:
                issues.append({"severity": "medium", "code": "DMARC_PCT_LOW",
                                "message": f"pct={pct_val}: only {pct_val}% of failing mail "
                                           "gets the policy applied. "
                                           f"{100 - pct_val}% is treated as p=none."})
        except ValueError:
            issues.append({"severity": "low", "code": "DMARC_PCT_INVALID",
                            "message": f"pct={pct} is not a valid integer."})

    # Alignment modes
    adkim = tags.get("adkim", "r").lower()
    aspf = tags.get("aspf", "r").lower()
    if adkim == "r":
        issues.append({"severity": "low", "code": "DMARC_ADKIM_RELAXED",
                        "message": "adkim=r (relaxed): DKIM alignment allows organizational "
                                   "domain match. Subdomain DKIM signatures pass for parent."})
    if aspf == "r":
        issues.append({"severity": "low", "code": "DMARC_ASPF_RELAXED",
                        "message": "aspf=r (relaxed): SPF alignment allows organizational "
                                   "domain match. mail.example.com passes for example.com."})

    # Reporting URIs
    if "rua" not in tags:
        issues.append({"severity": "medium", "code": "DMARC_NO_RUA",
                        "message": "No rua= aggregate report URI. "
                                   "Cannot receive DMARC failure reports."})
    if "ruf" not in tags:
        issues.append({"severity": "low", "code": "DMARC_NO_RUF",
                        "message": "No ruf= forensic report URI. "
                                   "Forensic reports provide per-message failure detail."})

    # fo= failure reporting options
    fo = tags.get("fo", "0")
    if fo == "0" and "ruf" in tags:
        issues.append({"severity": "info", "code": "DMARC_FO_DEFAULT",
                        "message": "fo=0 (default): forensic reports only when ALL mechanisms fail. "
                                   "fo=1 sends a report if ANY mechanism fails (more visibility)."})

    # Validate p= value
    if policy and policy not in ("none", "quarantine", "reject"):
        issues.append({"severity": "high", "code": "DMARC_INVALID_POLICY",
                        "message": f"p={policy}: invalid value. "
                                   "Must be 'none', 'quarantine', or 'reject'."})

    # External report destination authorization (RFC 7489 §7.1)
    # If rua/ruf points to an external domain, that domain must publish an
    # authorization record: {dmarc_domain}._report._dmarc.{external_domain}
    org_domain = domain.split(".")[-2] + "." + domain.split(".")[-1] if domain.count(".") >= 1 else domain
    for tag_name in ("rua", "ruf"):
        uri_value = tags.get(tag_name, "")
        for uri in uri_value.split(","):
            uri = uri.strip()
            if uri.startswith("mailto:"):
                email_addr = uri[7:].split("!")[0]  # strip optional size limit
                if "@" in email_addr:
                    report_domain = email_addr.split("@")[1].lower()
                    # External if report domain is not the DMARC domain or its parent
                    if (report_domain != domain.lower() and
                        not report_domain.endswith("." + domain.lower()) and
                        report_domain != org_domain):
                        # Check for authorization DNS record
                        auth_name = f"{domain}._report._dmarc.{report_domain}"
                        auth_txts = query_txt(auth_name, timeout=3)
                        has_auth = any("v=DMARC1" in t for t in auth_txts)
                        if not has_auth:
                            issues.append({
                                "severity": "medium",
                                "code": "DMARC_EXT_REPORT_UNAUTH",
                                "message": f"{tag_name}= sends reports to external domain "
                                           f"'{report_domain}' but no authorization record found "
                                           f"at {auth_name}. Reports may be silently dropped "
                                           "by the receiving domain (RFC 7489 §7.1)."
                            })

    return issues

# ── DKIM Probing & Auditing ──────────────────────────────────────────────────

def parse_dkim_record(record):
    """Parse a DKIM TXT record into tag dict."""
    tags = {}
    for part in record.replace(";", ";").split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip()] = v.strip()
    return tags

def estimate_dkim_key_bits(p_value):
    """Estimate RSA key size from base64-encoded public key."""
    try:
        raw = base64.b64decode(p_value)
        # DER-encoded RSA public key: the modulus length determines key size
        # A rough estimate: key_bits ≈ (len(raw) - overhead) * 8
        # More precise: find the modulus in the ASN.1 structure
        key_bits = (len(raw) - 38) * 8  # ~38 bytes of ASN.1 overhead for RSA
        # Round to nearest standard size
        for standard in [512, 768, 1024, 2048, 4096]:
            if abs(key_bits - standard) < 128:
                return standard
        return key_bits
    except Exception:
        return None

def lint_dkim_record(selector, record):
    """Audit a single DKIM record for security issues.

    Returns list of {severity, code, message} dicts.
    """
    issues = []
    tags = parse_dkim_record(record)

    # Empty public key = revoked (RFC 6376 §3.6.1)
    p_value = tags.get("p", "")
    if not p_value:
        issues.append({"severity": "info", "code": "DKIM_REVOKED",
                        "message": f"Selector '{selector}': empty p= tag means key is revoked. "
                                   "This is intentional and safe."})
        return issues

    # Key length check
    key_bits = estimate_dkim_key_bits(p_value)
    if key_bits is not None:
        if key_bits < 1024:
            issues.append({"severity": "critical", "code": "DKIM_WEAK_KEY",
                            "message": f"Selector '{selector}': ~{key_bits}-bit RSA key. "
                                       "Keys <1024 bits can be factored. MUST be ≥1024, "
                                       "SHOULD be 2048 (RFC 8301)."})
        elif key_bits < 2048:
            issues.append({"severity": "medium", "code": "DKIM_SHORT_KEY",
                            "message": f"Selector '{selector}': ~{key_bits}-bit RSA key. "
                                       "RFC 8301 recommends 2048-bit minimum."})

    # Test mode t=y (RFC 6376 §3.6.1)
    t_flags = tags.get("t", "")
    if "y" in t_flags:
        issues.append({"severity": "high", "code": "DKIM_TEST_MODE",
                        "message": f"Selector '{selector}': t=y (test mode). "
                                   "Verifiers MUST NOT treat test mode failures differently, "
                                   "but some receivers ignore DKIM in test mode."})

    # Body length limit l= tag (truncation attack: RFC 6376 §3.5)
    if "l" in tags:
        issues.append({"severity": "high", "code": "DKIM_L_TAG",
                        "message": f"Selector '{selector}': l= (body length) tag present. "
                                   "Attackers can append arbitrary content after the signed "
                                   "portion of the body while preserving a valid DKIM signature."})

    # Key type
    k_type = tags.get("k", "rsa")
    if k_type == "rsa":
        pass  # standard
    elif k_type == "ed25519":
        issues.append({"severity": "info", "code": "DKIM_ED25519",
                        "message": f"Selector '{selector}': uses Ed25519 key type. "
                                   "Modern and secure, but not all verifiers support it yet."})
    elif k_type:
        issues.append({"severity": "low", "code": "DKIM_UNKNOWN_KEYTYPE",
                        "message": f"Selector '{selector}': unknown key type k={k_type}."})

    # Hash algorithm check (RFC 8301: sha1 signing deprecated)
    h_value = tags.get("h", "")
    if h_value:
        algos = [a.strip() for a in h_value.split(":")]
        if "sha1" in algos and "sha256" not in algos:
            issues.append({"severity": "high", "code": "DKIM_SHA1_ONLY",
                            "message": f"Selector '{selector}': h=sha1 only. "
                                       "SHA-1 is deprecated for DKIM signing (RFC 8301). "
                                       "Verifiers SHOULD NOT accept SHA-1 signatures."})
        elif "sha1" in algos:
            issues.append({"severity": "medium", "code": "DKIM_SHA1_ALLOWED",
                            "message": f"Selector '{selector}': h= accepts sha1. "
                                       "SHA-1 is deprecated (RFC 8301). Consider removing it."})

    return issues

def probe_dkim(domain, selectors=None, workers=10):
    """Probe DKIM selectors. Returns dict of selector -> record."""
    selectors = selectors or COMMON_DKIM_SELECTORS
    found = {}

    def _check(sel):
        name = f"{sel}._domainkey.{domain}"
        txts = query_txt(name, timeout=2)
        for txt in txts:
            if "p=" in txt or "DKIM" in txt.upper():
                return sel, txt
        return sel, None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for sel, rec in pool.map(_check, selectors):
            if rec:
                found[sel] = rec
    return found

def audit_dkim(domain, selectors=None, workers=10):
    """Probe and audit all found DKIM selectors."""
    found = probe_dkim(domain, selectors, workers)
    all_issues = []
    for sel, rec in found.items():
        issues = lint_dkim_record(sel, rec)
        all_issues.extend(issues)
    return found, all_issues

# ── MX Fingerprinting ────────────────────────────────────────────────────────

def fingerprint_mx(domain):
    """Return MX records with identified mail provider names."""
    records = query_mx(domain)
    results = []
    for pref, exchange in records:
        provider = "Unknown"
        for pattern, name in KNOWN_MAIL_PROVIDERS.items():
            if pattern in exchange.lower():
                provider = name
                break
        results.append({"priority": pref, "exchange": exchange, "provider": provider})
    return results

# ── Dangling DNS / Subdomain Takeover Detection ─────────────────────────────

def check_dangling_dns(domain):
    """Check for dangling CNAME and NS records that may indicate subdomain takeover risk.

    A dangling CNAME points to a target that doesn't resolve, suggesting the service
    was decommissioned but the DNS record remains — a subdomain takeover vector.
    """
    findings = []

    cnames = query_cname(domain)
    for target in cnames:
        a = query_a(target)
        aaaa = query_aaaa(target)
        if not a and not aaaa:
            # Check if CNAME target matches a known takeover-vulnerable service
            vuln_service = None
            for pattern in TAKEOVER_FINGERPRINTS:
                if target.lower().endswith(pattern) or pattern in target.lower():
                    vuln_service = pattern
                    break
            if vuln_service:
                findings.append({
                    "type": "dangling_cname_takeover",
                    "severity": "critical",
                    "record": f"CNAME -> {target}",
                    "message": f"CNAME points to {target} (matches known vulnerable "
                               f"service: {vuln_service}) which does not resolve. "
                               "HIGH LIKELIHOOD of subdomain takeover — attacker can "
                               "claim this resource on the hosting platform.",
                })
            else:
                findings.append({
                    "type": "dangling_cname",
                    "severity": "high",
                    "record": f"CNAME -> {target}",
                    "message": f"CNAME points to {target} which does not resolve. "
                               "Potential subdomain takeover if the target service "
                               "can be reclaimed.",
                })

    ns_records = query_ns(domain)
    for ns in ns_records:
        a = query_a(ns)
        if not a:
            findings.append({
                "type": "dangling_ns",
                "severity": "critical",
                "record": f"NS -> {ns}",
                "message": f"NS record delegates to {ns} which does not resolve. "
                           "An attacker who registers this nameserver controls all "
                           "DNS records for {domain}.",
            })

    return findings

# ── MTA-STS (RFC 8461) ──────────────────────────────────────────────────────

def check_mta_sts(domain):
    """Check MTA-STS DNS record and policy file."""
    result = {"dns_record": None, "policy": None, "issues": []}

    # Check _mta-sts TXT record
    for txt in query_txt(f"_mta-sts.{domain}"):
        if txt.startswith("v=STSv1"):
            result["dns_record"] = txt
            break

    if not result["dns_record"]:
        result["issues"].append({
            "severity": "low", "code": "MTA_STS_MISSING",
            "message": "No MTA-STS DNS record. SMTP connections are not protected "
                       "against downgrade attacks."
        })
        return result

    # Fetch the policy file
    try:
        url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        r = requests.get(url, timeout=10, allow_redirects=True)
        if r.status_code == 200:
            result["policy"] = r.text.strip()
            # Parse policy
            policy_lines = {}
            for line in r.text.strip().splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    policy_lines[k.strip().lower()] = v.strip()

            mode = policy_lines.get("mode", "")
            if mode == "testing":
                result["issues"].append({
                    "severity": "medium", "code": "MTA_STS_TESTING",
                    "message": "MTA-STS mode is 'testing'. TLS failures are reported "
                               "but mail is still delivered over plaintext."
                })
            elif mode == "none":
                result["issues"].append({
                    "severity": "medium", "code": "MTA_STS_DISABLED",
                    "message": "MTA-STS mode is 'none' (disabled)."
                })
            elif mode != "enforce":
                result["issues"].append({
                    "severity": "low", "code": "MTA_STS_UNKNOWN_MODE",
                    "message": f"MTA-STS mode is '{mode}' (unexpected)."
                })

            max_age = policy_lines.get("max_age", "0")
            try:
                if int(max_age) < 86400:
                    result["issues"].append({
                        "severity": "low", "code": "MTA_STS_SHORT_MAX_AGE",
                        "message": f"max_age={max_age} seconds (<1 day). "
                                   "Short max_age reduces protection window."
                    })
            except ValueError:
                pass
        else:
            result["issues"].append({
                "severity": "medium", "code": "MTA_STS_NO_POLICY",
                "message": f"MTA-STS DNS record exists but policy file returned HTTP {r.status_code}."
            })
    except Exception as e:
        result["issues"].append({
            "severity": "low", "code": "MTA_STS_FETCH_FAIL",
            "message": f"Could not fetch MTA-STS policy: {e}"
        })

    return result

# ── DANE / TLSA (RFC 7672) ───────────────────────────────────────────────────

def check_dane(domain):
    """Check DANE TLSA records for SMTP on port 25."""
    mx_records = query_mx(domain)
    results = []
    for pref, exchange in mx_records:
        tlsa = query_tlsa(exchange, port=25)
        results.append({
            "mx": exchange,
            "tlsa_records": tlsa,
            "has_dane": len(tlsa) > 0,
        })
    return results

# ── BIMI (Brand Indicators for Message Identification) ───────────────────────

def check_bimi(domain):
    """Check for BIMI record at default._bimi.{domain}."""
    result = {"record": None, "logo_url": None, "vmc_url": None, "issues": []}

    for txt in query_txt(f"default._bimi.{domain}"):
        if txt.startswith("v=BIMI1"):
            result["record"] = txt
            # Parse tags
            for part in txt.split(";"):
                part = part.strip()
                if part.startswith("l="):
                    result["logo_url"] = part[2:].strip()
                elif part.startswith("a="):
                    result["vmc_url"] = part[2:].strip()
            break

    if not result["record"]:
        result["issues"].append({
            "severity": "info", "code": "BIMI_MISSING",
            "message": "No BIMI record. Brand logo will not appear in supporting mail clients."
        })
    elif not result["logo_url"]:
        result["issues"].append({
            "severity": "low", "code": "BIMI_NO_LOGO",
            "message": "BIMI record exists but no l= (logo) URL specified."
        })

    return result

# ── SMTP TLS Reporting (RFC 8460) ────────────────────────────────────────────

def check_tls_rpt(domain):
    """Check SMTP TLS Reporting DNS record at _smtp._tls.{domain}."""
    result = {"record": None, "issues": []}
    for txt in query_txt(f"_smtp._tls.{domain}"):
        if txt.startswith("v=TLSRPTv1"):
            result["record"] = txt
            break

    if not result["record"]:
        result["issues"].append({
            "severity": "info", "code": "TLSRPT_MISSING",
            "message": "No SMTP TLS Reporting record (_smtp._tls). "
                       "TLS negotiation failures will not be reported (RFC 8460)."
        })
    else:
        # Check for rua= (required)
        if "rua=" not in result["record"]:
            result["issues"].append({
                "severity": "low", "code": "TLSRPT_NO_RUA",
                "message": "TLS-RPT record exists but has no rua= reporting URI."
            })

    return result

# ── Risk Scoring ─────────────────────────────────────────────────────────────

RISK_LEVELS = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

def score_subdomain(sub, spf, spf_issues, root_spf, mx_records, dmarc, dmarc_issues,
                    dkim_found, dkim_issues, dangling, resolves):
    """Score a subdomain's email spoofability risk (0–4) using a weighted factor model.

    The score is a composite of authentication gaps, misconfigurations, and
    infrastructure exposure. Each factor adds weight; the total is capped at 4.
    """
    score = 0.0
    reasons = []

    # --- SPF factors ---
    if not spf:
        score += 2.0
        reasons.append("No SPF record")
    else:
        if spf != root_spf:
            score += 0.5
            reasons.append("SPF differs from root domain")
        # Check for critical/high SPF issues
        crit_spf = [i for i in spf_issues if i["severity"] in ("critical", "high")]
        if crit_spf:
            score += 1.5
            reasons.append(f"{len(crit_spf)} critical/high SPF issue(s)")
        elif [i for i in spf_issues if i["severity"] == "medium"]:
            score += 0.5
            reasons.append("SPF has medium-severity issues")

    # --- DMARC factors ---
    if not dmarc:
        score += 1.5
        reasons.append("No DMARC record")
    else:
        tags = parse_dmarc(dmarc)
        policy = tags.get("p", "none")
        sp = tags.get("sp", policy)  # sp inherits from p
        if sp == "none":
            score += 1.0
            reasons.append("DMARC subdomain policy is 'none'")
        elif sp == "quarantine":
            score += 0.3
        if tags.get("pct"):
            try:
                if int(tags["pct"]) < 100:
                    score += 0.5
                    reasons.append(f"DMARC pct={tags['pct']}%")
            except ValueError:
                pass

    # --- DKIM factors ---
    if not dkim_found:
        score += 0.5
        reasons.append("No DKIM selectors found")
    crit_dkim = [i for i in dkim_issues if i["severity"] in ("critical", "high")]
    if crit_dkim:
        score += 1.0
        reasons.append(f"{len(crit_dkim)} critical/high DKIM issue(s)")

    # --- Infrastructure exposure ---
    if mx_records:
        score += 0.3
        reasons.append(f"Has MX records ({len(mx_records)})")

    if resolves:
        score += 0.2
        reasons.append("Subdomain resolves (live)")

    # --- Dangling DNS ---
    if dangling:
        score += 1.5
        reasons.append(f"Dangling DNS: {dangling[0]['type']}")

    final = min(int(round(score)), 4)
    return final, RISK_LEVELS[final], reasons

# ── Full Scan ────────────────────────────────────────────────────────────────

def full_scan(domain, subdomains, debug=False, workers=20, delay=0.2,
              deep_dkim=False):
    """Run the complete email security audit."""
    print(f"[*] Scanning root domain: {domain}")

    # Root domain analysis
    root_spf = get_spf_record(domain)
    root_spf_issues = lint_spf(domain)
    root_dmarc = get_dmarc_record(domain)
    root_dmarc_issues = lint_dmarc(domain)
    root_mx = fingerprint_mx(domain)
    root_dkim, root_dkim_issues = audit_dkim(domain)
    root_complexity = spf_complexity_report(domain)
    root_mta_sts = check_mta_sts(domain)
    root_dane = check_dane(domain)
    root_bimi = check_bimi(domain)
    root_tls_rpt = check_tls_rpt(domain)

    print(f"  Root SPF:     {root_spf or '(none)'}")
    if root_spf_issues:
        for i in root_spf_issues:
            print(f"    [{i['severity'].upper()}] {i['message']}")
    print(f"  Root DMARC:   {root_dmarc or '(none)'}")
    if root_dmarc_issues:
        for i in root_dmarc_issues:
            print(f"    [{i['severity'].upper()}] {i['message']}")
    print(f"  Root MX:      {len(root_mx)} records")
    print(f"  Root DKIM:    {len(root_dkim)} selectors found")
    if root_dkim_issues:
        for i in root_dkim_issues:
            print(f"    [{i['severity'].upper()}] {i['message']}")
    print(f"  SPF lookups:  {root_complexity['total_dns_lookups']}/10"
          f"{' ** OVER LIMIT **' if root_complexity['over_limit'] else ''}")
    if root_complexity.get("void_lookups", 0) > 0:
        print(f"  SPF voids:    {root_complexity['void_lookups']}/2"
              f"{' ** OVER LIMIT **' if root_complexity.get('void_over_limit') else ''}")
    if root_mta_sts["dns_record"]:
        print(f"  MTA-STS:      {root_mta_sts['dns_record'][:60]}")
    else:
        print(f"  MTA-STS:      not configured")
    dane_count = sum(1 for d in root_dane if d["has_dane"])
    print(f"  DANE/TLSA:    {dane_count}/{len(root_dane)} MX hosts have TLSA")
    if root_bimi["record"]:
        print(f"  BIMI:         {root_bimi['record'][:60]}")
    else:
        print(f"  BIMI:         not configured")
    if root_tls_rpt["record"]:
        print(f"  TLS-RPT:      {root_tls_rpt['record'][:60]}")
    else:
        print(f"  TLS-RPT:      not configured")

    if not subdomains:
        print("\n[*] No subdomains to scan.")
        return _build_scan_result(domain, root_spf, root_spf_issues, root_dmarc,
                                   root_dmarc_issues, root_mx, root_dkim,
                                   root_dkim_issues, root_complexity, root_mta_sts,
                                   root_dane, root_bimi, root_tls_rpt, [])

    print(f"\n[*] Analyzing {len(subdomains)} subdomains (workers={workers})...")
    results = []

    def _analyze(sub):
        time.sleep(delay)
        spf = get_spf_record(sub)
        spf_issues = lint_spf(sub) if spf else [{"severity": "high", "code": "SPF_MISSING", "message": "No SPF"}]
        dmarc = get_dmarc_record(sub)
        dmarc_issues = lint_dmarc(sub) if dmarc else []
        mx = fingerprint_mx(sub)
        a_records = query_a(sub)
        resolves = len(a_records) > 0
        dangling = check_dangling_dns(sub)

        dkim_found = {}
        dkim_issues = []
        if deep_dkim:
            dkim_found, dkim_issues = audit_dkim(sub)

        risk_score, risk_label, risk_reasons = score_subdomain(
            sub, spf, spf_issues, root_spf, mx, dmarc, dmarc_issues,
            dkim_found, dkim_issues, dangling, resolves
        )
        return {
            "subdomain": sub,
            "resolves": resolves,
            "spf": spf,
            "spf_issues": spf_issues,
            "dmarc": dmarc,
            "dmarc_issues": dmarc_issues,
            "mx": mx,
            "dkim_selectors": dkim_found,
            "dkim_issues": dkim_issues,
            "dangling": dangling,
            "risk_score": risk_score,
            "risk_label": risk_label,
            "risk_reasons": risk_reasons,
        }

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_analyze, sub): sub for sub in subdomains}
        done = 0
        total = len(futures)
        for future in as_completed(futures):
            done += 1
            try:
                entry = future.result()
                results.append(entry)
                if debug:
                    print(f"  [{done}/{total}] {entry['subdomain']} -> {entry['risk_label']}")
                elif done % 25 == 0 or done == total:
                    print(f"  [{done}/{total}] scanned...")
            except Exception as e:
                if debug:
                    print(f"  Error scanning {futures[future]}: {e}")

    results.sort(key=lambda r: (-r["risk_score"], r["subdomain"]))

    return _build_scan_result(domain, root_spf, root_spf_issues, root_dmarc,
                               root_dmarc_issues, root_mx, root_dkim,
                               root_dkim_issues, root_complexity, root_mta_sts,
                               root_dane, root_bimi, root_tls_rpt, results)

def _build_scan_result(domain, root_spf, root_spf_issues, root_dmarc,
                        root_dmarc_issues, root_mx, root_dkim, root_dkim_issues,
                        root_complexity, root_mta_sts, root_dane, root_bimi,
                        root_tls_rpt, results):
    return {
        "domain": domain,
        "root": {
            "spf": root_spf,
            "spf_issues": root_spf_issues,
            "dmarc": root_dmarc,
            "dmarc_parsed": parse_dmarc(root_dmarc),
            "dmarc_issues": root_dmarc_issues,
            "mx": root_mx,
            "dkim_selectors": root_dkim,
            "dkim_issues": root_dkim_issues,
            "spf_complexity": root_complexity,
            "mta_sts": root_mta_sts,
            "dane": root_dane,
            "bimi": root_bimi,
            "tls_rpt": root_tls_rpt,
        },
        "subdomains": results,
        "summary": {
            "total_scanned": len(results),
            "no_spf": sum(1 for r in results if not r["spf"]),
            "no_dmarc": sum(1 for r in results if not r["dmarc"]),
            "has_mx": sum(1 for r in results if r["mx"]),
            "dangling": sum(1 for r in results if r["dangling"]),
            "critical": sum(1 for r in results if r["risk_score"] == 4),
            "high": sum(1 for r in results if r["risk_score"] == 3),
            "medium": sum(1 for r in results if r["risk_score"] == 2),
            "low": sum(1 for r in results if r["risk_score"] == 1),
        },
    }

# ── Export: CSV ──────────────────────────────────────────────────────────────

def export_csv(scan, path):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Subdomain", "Resolves", "SPF", "DMARC", "MX Count",
                     "Dangling DNS", "Risk Score", "Risk Level", "Risk Reasons",
                     "SPF Issues", "DMARC Issues"])
        for r in scan["subdomains"]:
            w.writerow([
                r["subdomain"],
                r["resolves"],
                r["spf"] or "",
                r["dmarc"] or "",
                len(r["mx"]),
                len(r["dangling"]),
                r["risk_score"],
                r["risk_label"],
                "; ".join(r["risk_reasons"]),
                "; ".join(i["message"] for i in r.get("spf_issues", [])),
                "; ".join(i["message"] for i in r.get("dmarc_issues", [])),
            ])
    print(f"[+] CSV saved: {path}")

# ── Export: JSON ─────────────────────────────────────────────────────────────

def export_json(scan, path):
    with open(path, "w") as f:
        json.dump(scan, f, indent=2, default=str)
    print(f"[+] JSON saved: {path}")

# ── Export: HTML Report ──────────────────────────────────────────────────────

RISK_COLORS = {
    "Critical": "#e74c3c", "High": "#e67e22",
    "Medium": "#f1c40f", "Low": "#3498db", "Info": "#95a5a6",
}
SEVERITY_COLORS = {
    "critical": "#e74c3c", "high": "#e67e22",
    "medium": "#f1c40f", "low": "#3498db", "info": "#95a5a6",
}

def _html_issue_rows(issues, section_label=""):
    rows = []
    for i in issues:
        color = SEVERITY_COLORS.get(i["severity"], "#ccc")
        rows.append(
            f'<tr><td style="color:{color};font-weight:bold">{i["severity"].upper()}</td>'
            f'<td><code>{html_escape(i.get("code", ""))}</code></td>'
            f'<td>{html_escape(i["message"])}</td></tr>'
        )
    return rows

def export_html(scan, path):
    domain = html_escape(scan["domain"])
    root = scan["root"]
    summary = scan["summary"]

    # --- Subdomain detail rows ---
    sub_rows = []
    for r in scan["subdomains"]:
        color = RISK_COLORS.get(r["risk_label"], "#ccc")
        issue_detail = ""
        all_issues = r.get("spf_issues", []) + r.get("dmarc_issues", []) + r.get("dkim_issues", [])
        if all_issues:
            issue_detail = "<br>".join(
                f'<span style="color:{SEVERITY_COLORS.get(i["severity"],"#ccc")}">'
                f'[{i["severity"].upper()}]</span> {html_escape(i["message"])}'
                for i in all_issues
            )
        dangling_detail = ""
        if r.get("dangling"):
            dangling_detail = "<br>".join(
                f'<span style="color:#e74c3c">{html_escape(d["message"])}</span>'
                for d in r["dangling"]
            )

        sub_rows.append(f"""<tr>
  <td>{html_escape(r['subdomain'])}</td>
  <td>{'Yes' if r['resolves'] else 'No'}</td>
  <td class="mono">{html_escape(r['spf'] or '—')}</td>
  <td class="mono">{html_escape(r['dmarc'] or '—')}</td>
  <td>{len(r['mx'])}</td>
  <td style="background:{color};color:#fff;font-weight:bold;text-align:center">{r['risk_label']}</td>
  <td>{html_escape('; '.join(r['risk_reasons']))}</td>
  <td class="detail">{issue_detail}{('<br>' + dangling_detail) if dangling_detail else ''}</td>
</tr>""")

    # --- Root SPF/DMARC/DKIM issue tables ---
    spf_issue_rows = _html_issue_rows(root.get("spf_issues", []))
    dmarc_issue_rows = _html_issue_rows(root.get("dmarc_issues", []))
    dkim_issue_rows = _html_issue_rows(root.get("dkim_issues", []))

    # --- SPF tree ---
    spf_tree_rows = []
    for mech, src, depth in root["spf_complexity"]["mechanisms"]:
        indent = "&nbsp;" * (depth * 4)
        spf_tree_rows.append(
            f"<tr><td>{indent}<code>{html_escape(mech)}</code></td>"
            f"<td class='mono'>{html_escape(src)}</td><td>{depth}</td></tr>"
        )

    # --- DKIM selectors ---
    dkim_rows = []
    for sel, rec in root.get("dkim_selectors", {}).items():
        tags = parse_dkim_record(rec)
        key_bits = estimate_dkim_key_bits(tags.get("p", ""))
        key_info = f" (~{key_bits}b)" if key_bits else ""
        test = " [TEST MODE]" if "y" in tags.get("t", "") else ""
        l_tag = " [l= TAG]" if "l" in tags else ""
        flags = f'<span style="color:#e67e22">{test}{l_tag}</span>'
        dkim_rows.append(
            f"<tr><td><code>{html_escape(sel)}</code></td>"
            f"<td>{key_info} {flags}</td>"
            f"<td class='mono'>{html_escape(rec[:100])}{'...' if len(rec) > 100 else ''}</td></tr>"
        )

    # --- MX ---
    mx_rows = []
    for mx in root.get("mx", []):
        mx_rows.append(
            f"<tr><td>{mx['priority']}</td>"
            f"<td>{html_escape(mx['exchange'])}</td>"
            f"<td>{html_escape(mx['provider'])}</td></tr>"
        )

    # --- MTA-STS ---
    mta_sts = root.get("mta_sts", {})
    mta_sts_html = html_escape(mta_sts.get("dns_record") or "Not configured")
    if mta_sts.get("policy"):
        mta_sts_html += "<br><pre>" + html_escape(mta_sts["policy"][:500]) + "</pre>"
    for i in mta_sts.get("issues", []):
        c = SEVERITY_COLORS.get(i["severity"], "#ccc")
        mta_sts_html += f'<br><span style="color:{c}">[{i["severity"].upper()}] {html_escape(i["message"])}</span>'

    # --- DANE ---
    dane_records = root.get("dane", [])
    dane_html_parts = []
    for d in dane_records:
        if d["has_dane"]:
            dane_html_parts.append(f'{html_escape(d["mx"])}: {len(d["tlsa_records"])} TLSA record(s)')
        else:
            dane_html_parts.append(f'{html_escape(d["mx"])}: no TLSA')
    dane_html = "<br>".join(dane_html_parts) if dane_html_parts else "No MX records to check"

    # --- BIMI ---
    bimi = root.get("bimi", {})
    bimi_html = html_escape(bimi.get("record") or "Not configured")
    if bimi.get("logo_url"):
        bimi_html += f'<br>Logo: <code>{html_escape(bimi["logo_url"])}</code>'

    # TLS-RPT
    tls_rpt = root.get("tls_rpt", {})
    tls_rpt_html = html_escape(tls_rpt.get("record") or "Not configured")
    for i in tls_rpt.get("issues", []):
        c = SEVERITY_COLORS.get(i["severity"], "#ccc")
        tls_rpt_html += f'<br><span style="color:{c}">[{i["severity"].upper()}] {html_escape(i["message"])}</span>'

    lookups = root["spf_complexity"]["total_dns_lookups"]
    voids = root["spf_complexity"].get("void_lookups", 0)
    void_warn = (' <span style="color:#e74c3c;font-weight:bold">'
                 'OVER RFC 7208 LIMIT</span>') if root["spf_complexity"].get("void_over_limit") else ""
    lookup_warn = (' <span style="color:#e74c3c;font-weight:bold">'
                   'OVER RFC 7208 LIMIT</span>') if root["spf_complexity"]["over_limit"] else ""

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>SPF Shadow Report — {domain}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0d1117; color: #c9d1d9; margin: 2em; line-height: 1.5; }}
  h1, h2, h3 {{ color: #58a6ff; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 2em; }}
  th, td {{ border: 1px solid #30363d; padding: 6px 10px; text-align: left; font-size: 13px; }}
  th {{ background: #161b22; color: #58a6ff; position: sticky; top: 0; }}
  tr:nth-child(even) {{ background: #161b22; }}
  .mono {{ font-family: 'Fira Code', 'Cascadia Code', monospace; font-size: 12px; word-break: break-all; }}
  .detail {{ font-size: 11px; max-width: 400px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
                   gap: 12px; margin: 1em 0 2em; }}
  .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
           padding: 16px; text-align: center; }}
  .stat .num {{ font-size: 2em; font-weight: bold; }}
  .stat .label {{ font-size: 0.85em; color: #8b949e; }}
  pre {{ background: #161b22; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; }}
  a {{ color: #58a6ff; }}
  .section {{ background: #0d1117; border: 1px solid #30363d; border-radius: 8px;
              padding: 16px; margin-bottom: 1.5em; }}
</style></head><body>
<h1>Email Auth Audit: {domain}</h1>
<p>Generated by <strong>spfshadow-2</strong></p>

<h2>Root Domain Analysis</h2>

<div class="section">
<h3>SPF</h3>
<table>
  <tr><th style="width:150px">Record</th><td class="mono">{html_escape(root['spf'] or '—')}</td></tr>
  <tr><th>DNS Lookups</th><td>{lookups} / 10{lookup_warn}</td></tr>
  <tr><th>Void Lookups</th><td>{voids} / 2{void_warn}</td></tr>
</table>
{'<h4>SPF Issues</h4><table><tr><th>Severity</th><th>Code</th><th>Detail</th></tr>' + chr(10).join(spf_issue_rows) + '</table>' if spf_issue_rows else ''}
</div>

<div class="section">
<h3>DMARC</h3>
<table>
  <tr><th style="width:150px">Record</th><td class="mono">{html_escape(root['dmarc'] or '—')}</td></tr>
</table>
{'<h4>DMARC Issues</h4><table><tr><th>Severity</th><th>Code</th><th>Detail</th></tr>' + chr(10).join(dmarc_issue_rows) + '</table>' if dmarc_issue_rows else ''}
</div>

<div class="section">
<h3>DKIM Selectors</h3>
<table><tr><th>Selector</th><th>Key Info</th><th>Record (truncated)</th></tr>
{''.join(dkim_rows) if dkim_rows else '<tr><td colspan="3">No DKIM selectors found</td></tr>'}
</table>
{'<h4>DKIM Issues</h4><table><tr><th>Severity</th><th>Code</th><th>Detail</th></tr>' + chr(10).join(dkim_issue_rows) + '</table>' if dkim_issue_rows else ''}
</div>

<div class="section">
<h3>MX Records</h3>
<table><tr><th>Priority</th><th>Exchange</th><th>Provider</th></tr>
{''.join(mx_rows) if mx_rows else '<tr><td colspan="3">No MX records</td></tr>'}
</table>
</div>

<div class="section">
<h3>SPF Include Tree</h3>
<table><tr><th>Mechanism</th><th>Source Domain</th><th>Depth</th></tr>
{''.join(spf_tree_rows) if spf_tree_rows else '<tr><td colspan="3">No mechanisms</td></tr>'}
</table>
</div>

<div class="section">
<h3>Transport Security</h3>
<table>
  <tr><th style="width:150px">MTA-STS</th><td>{mta_sts_html}</td></tr>
  <tr><th>DANE/TLSA</th><td>{dane_html}</td></tr>
  <tr><th>TLS-RPT</th><td>{tls_rpt_html}</td></tr>
  <tr><th>BIMI</th><td>{bimi_html}</td></tr>
</table>
</div>

<h2>Subdomain Risk Summary</h2>
<div class="summary-grid">
  <div class="stat"><div class="num">{summary['total_scanned']}</div><div class="label">Scanned</div></div>
  <div class="stat"><div class="num" style="color:#e74c3c">{summary['critical']}</div><div class="label">Critical</div></div>
  <div class="stat"><div class="num" style="color:#e67e22">{summary['high']}</div><div class="label">High</div></div>
  <div class="stat"><div class="num" style="color:#f1c40f">{summary['medium']}</div><div class="label">Medium</div></div>
  <div class="stat"><div class="num" style="color:#3498db">{summary['low']}</div><div class="label">Low</div></div>
  <div class="stat"><div class="num">{summary['no_spf']}</div><div class="label">No SPF</div></div>
  <div class="stat"><div class="num">{summary['no_dmarc']}</div><div class="label">No DMARC</div></div>
  <div class="stat"><div class="num">{summary.get('dangling', 0)}</div><div class="label">Dangling DNS</div></div>
</div>

<h2>Subdomain Details ({summary['total_scanned']})</h2>
<table>
<tr><th>Subdomain</th><th>Live</th><th>SPF</th><th>DMARC</th><th>MX</th><th>Risk</th><th>Reasons</th><th>Details</th></tr>
{''.join(sub_rows)}
</table>

</body></html>"""

    with open(path, "w") as f:
        f.write(html)
    print(f"[+] HTML report saved: {path}")

# ── Interactive Mode ─────────────────────────────────────────────────────────

def print_risk_table(results, max_rows=30):
    """Pretty-print risk results to terminal."""
    print(f"\n{'Subdomain':<45} {'Risk':<10} {'SPF':<6} {'DMARC':<6} {'MX':<4} {'Dng':<4} Reasons")
    print("-" * 120)
    for r in results[:max_rows]:
        spf_flag = "Yes" if r["spf"] else "NO"
        dmarc_flag = "Yes" if r["dmarc"] else "NO"
        mx_count = str(len(r["mx"]))
        dng = str(len(r.get("dangling", [])))
        reasons = "; ".join(r["risk_reasons"][:3])
        print(f"{r['subdomain']:<45} {r['risk_label']:<10} {spf_flag:<6} {dmarc_flag:<6} "
              f"{mx_count:<4} {dng:<4} {reasons}")
    if len(results) > max_rows:
        print(f"  ... and {len(results) - max_rows} more (export for full list)")

def interactive_mode():
    domain = input("Enter target domain (e.g. example.com): ").strip()
    if not domain:
        print("[!] No domain provided.")
        return
    debug = input("Enable debug mode? (y/N): ").strip().lower().startswith("y")

    print(f"\n[*] Enumerating subdomains for {domain}. This can take up to 2 minutes.")
    subdomains = enumerate_subdomains(domain, debug)
    print(f"[+] Found {len(subdomains)} unique subdomains\n")

    scan_cache = None

    while True:
        print("\n=== SPF Shadow 2.0 ===")
        print(f"  Domain: {domain} | {len(subdomains)} subdomains loaded")
        print()
        print("  1) List subdomains")
        print("  2) Validate subdomains (DNS A/AAAA)")
        print("  3) Full scan (SPF + DMARC + DKIM + MX + dangling + risk)")
        print("  4) SPF include-tree analysis (root)")
        print("  5) SPF record linter (root)")
        print("  6) DMARC audit (root)")
        print("  7) DKIM selector probe + audit (root)")
        print("  8) MTA-STS / DANE / BIMI check (root)")
        print("  9) Export subdomains to CSV")
        print("  q) Quit")
        choice = input("\nChoice: ").strip()

        if choice == "1":
            for sub in subdomains:
                print(f"  {sub}")

        elif choice == "2":
            print("[*] Validating DNS resolution...")
            valid = validate_subdomains(subdomains)
            print(f"[+] {len(valid)} / {len(subdomains)} subdomains resolve")
            if input("Use only resolved subdomains going forward? (y/N): ").strip().lower().startswith("y"):
                subdomains = sorted(valid)
                print(f"[+] Filtered to {len(subdomains)} subdomains")

        elif choice == "3":
            deep = input("Deep DKIM scan per subdomain? (slow) (y/N): ").strip().lower().startswith("y")
            scan_cache = full_scan(domain, subdomains, debug, deep_dkim=deep)
            print_risk_table(scan_cache["subdomains"])

            s = scan_cache["summary"]
            print(f"\n  Summary: {s['critical']} critical, {s['high']} high, "
                  f"{s['medium']} medium, {s['low']} low, "
                  f"{s.get('dangling', 0)} dangling DNS")

            print("\n  Export options:")
            print("    c) CSV   j) JSON   h) HTML   a) All   n) Skip")
            exp = input("  Export: ").strip().lower()
            base = domain.replace(".", "_")
            if exp in ("c", "a"):
                export_csv(scan_cache, f"{base}_spfshadow.csv")
            if exp in ("j", "a"):
                export_json(scan_cache, f"{base}_spfshadow.json")
            if exp in ("h", "a"):
                export_html(scan_cache, f"{base}_spfshadow.html")

        elif choice == "4":
            report = spf_complexity_report(domain)
            print(f"\n  Root SPF: {report['root_spf'] or '(none)'}")
            print(f"  Total DNS lookups: {report['total_dns_lookups']} / 10")
            if report["over_limit"]:
                print("  ** WARNING: Exceeds RFC 7208 10-lookup limit! **")
            if report.get("warnings"):
                for w in report["warnings"]:
                    print(f"  [WARN] {w}")
            print(f"\n  {'Mechanism':<40} {'Source':<30} Depth")
            print("  " + "-" * 80)
            for mech, src, depth in report["mechanisms"]:
                indent = "  " * depth
                print(f"  {indent}{mech:<{40 - len(indent)}} {src:<30} {depth}")

        elif choice == "5":
            issues = lint_spf(domain)
            if issues:
                print(f"\n  SPF lint for {domain}:")
                for i in issues:
                    print(f"  [{i['severity'].upper():<8}] [{i['code']}] {i['message']}")
            else:
                print("  No SPF issues found.")

        elif choice == "6":
            issues = lint_dmarc(domain)
            if issues:
                print(f"\n  DMARC audit for {domain}:")
                for i in issues:
                    print(f"  [{i['severity'].upper():<8}] [{i['code']}] {i['message']}")
            else:
                print("  No DMARC issues found.")

        elif choice == "7":
            extra = input("Additional selectors (comma-separated, or Enter for defaults): ").strip()
            selectors = list(COMMON_DKIM_SELECTORS)
            if extra:
                selectors.extend(s.strip() for s in extra.split(",") if s.strip())
            print(f"[*] Probing {len(selectors)} DKIM selectors...")
            found, issues = audit_dkim(domain, selectors)
            if found:
                for sel, rec in found.items():
                    tags = parse_dkim_record(rec)
                    bits = estimate_dkim_key_bits(tags.get("p", ""))
                    flags = []
                    if "y" in tags.get("t", ""):
                        flags.append("TEST MODE")
                    if "l" in tags:
                        flags.append("l= TAG")
                    flag_str = f" [{', '.join(flags)}]" if flags else ""
                    print(f"  {sel}: ~{bits}b{flag_str}  {rec[:80]}{'...' if len(rec) > 80 else ''}")
            else:
                print("  No DKIM selectors found.")
            if issues:
                print(f"\n  DKIM Issues:")
                for i in issues:
                    print(f"  [{i['severity'].upper():<8}] {i['message']}")

        elif choice == "8":
            print(f"\n  --- MTA-STS ---")
            sts = check_mta_sts(domain)
            print(f"  DNS Record: {sts['dns_record'] or 'Not configured'}")
            if sts["policy"]:
                for line in sts["policy"].splitlines()[:10]:
                    print(f"    {line}")
            for i in sts.get("issues", []):
                print(f"  [{i['severity'].upper()}] {i['message']}")

            print(f"\n  --- DANE/TLSA ---")
            dane = check_dane(domain)
            for d in dane:
                if d["has_dane"]:
                    print(f"  {d['mx']}: {len(d['tlsa_records'])} TLSA record(s)")
                    for t in d["tlsa_records"]:
                        print(f"    usage={t['usage']} selector={t['selector']} "
                              f"mtype={t['mtype']} cert={t['cert'][:32]}...")
                else:
                    print(f"  {d['mx']}: no TLSA records")
            if not dane:
                print("  No MX records to check.")

            print(f"\n  --- BIMI ---")
            bimi = check_bimi(domain)
            if bimi["record"]:
                print(f"  Record: {bimi['record']}")
                if bimi["logo_url"]:
                    print(f"  Logo URL: {bimi['logo_url']}")
                if bimi["vmc_url"]:
                    print(f"  VMC URL: {bimi['vmc_url']}")
            else:
                print("  Not configured.")

            print(f"\n  --- SMTP TLS Reporting ---")
            tls_rpt = check_tls_rpt(domain)
            if tls_rpt["record"]:
                print(f"  Record: {tls_rpt['record']}")
            else:
                print("  Not configured.")
            for i in tls_rpt.get("issues", []):
                print(f"  [{i['severity'].upper()}] {i['message']}")

        elif choice == "9":
            path = f"{domain.replace('.', '_')}_subdomains.csv"
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["Subdomain"])
                for sub in subdomains:
                    w.writerow([sub])
            print(f"[+] Saved to {path}")

        elif choice == "q":
            break
        else:
            print("[!] Invalid option.")

# ── CLI Mode ─────────────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="spfshadow2",
        description="SPF Shadow 2.0 — Email authentication audit & risk analysis",
    )
    p.add_argument("domain", nargs="?", help="Target domain (omit for interactive mode)")
    p.add_argument("-o", "--output", default=None,
                   help="Output base path (without extension); generates .csv, .json, .html")
    p.add_argument("--skip-enum", action="store_true",
                   help="Skip subdomain enumeration; scan root domain only")
    p.add_argument("--subs-file", type=str, default=None,
                   help="Load subdomains from file (one per line)")
    p.add_argument("--workers", type=int, default=20, help="Concurrency (default: 20)")
    p.add_argument("--delay", type=float, default=0.2,
                   help="Delay between DNS queries in seconds (default: 0.2)")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--deep-dkim", action="store_true",
                   help="Probe DKIM selectors on every subdomain (slow)")
    p.add_argument("--spf-tree", action="store_true",
                   help="Print SPF include-tree for root domain and exit")
    p.add_argument("--lint-only", action="store_true",
                   help="Only lint root domain SPF/DMARC/DKIM (no subdomain scan)")
    return p

def cli_mode(args):
    domain = args.domain

    if args.spf_tree:
        report = spf_complexity_report(domain)
        print(f"Root SPF: {report['root_spf'] or '(none)'}")
        print(f"DNS lookups: {report['total_dns_lookups']} / 10"
              f"{' ** OVER LIMIT **' if report['over_limit'] else ''}")
        for w in report.get("warnings", []):
            print(f"  [WARN] {w}")
        for mech, src, depth in report["mechanisms"]:
            print(f"{'  ' * depth}{mech}  (from {src})")
        return

    if args.lint_only:
        print(f"\n=== SPF Lint: {domain} ===")
        for i in lint_spf(domain):
            print(f"  [{i['severity'].upper():<8}] {i['message']}")

        print(f"\n=== DMARC Audit: {domain} ===")
        for i in lint_dmarc(domain):
            print(f"  [{i['severity'].upper():<8}] {i['message']}")

        print(f"\n=== DKIM Audit: {domain} ===")
        found, issues = audit_dkim(domain)
        for sel in found:
            tags = parse_dkim_record(found[sel])
            bits = estimate_dkim_key_bits(tags.get("p", ""))
            print(f"  {sel}: ~{bits}b")
        for i in issues:
            print(f"  [{i['severity'].upper():<8}] {i['message']}")

        print(f"\n=== MTA-STS ===")
        sts = check_mta_sts(domain)
        print(f"  {sts['dns_record'] or 'Not configured'}")
        for i in sts.get("issues", []):
            print(f"  [{i['severity'].upper():<8}] {i['message']}")

        print(f"\n=== BIMI ===")
        bimi = check_bimi(domain)
        print(f"  {bimi['record'] or 'Not configured'}")

        print(f"\n=== SMTP TLS Reporting ===")
        tls_rpt = check_tls_rpt(domain)
        print(f"  {tls_rpt['record'] or 'Not configured'}")
        for i in tls_rpt.get("issues", []):
            print(f"  [{i['severity'].upper():<8}] {i['message']}")
        return

    if args.subs_file:
        with open(args.subs_file) as f:
            subdomains = sorted({line.strip() for line in f if line.strip()})
        print(f"[+] Loaded {len(subdomains)} subdomains from {args.subs_file}")
    elif args.skip_enum:
        subdomains = []
    else:
        print(f"[*] Enumerating subdomains for {domain}...")
        subdomains = enumerate_subdomains(domain, args.debug)
        print(f"[+] Found {len(subdomains)} subdomains")

    scan = full_scan(domain, subdomains, args.debug, args.workers, args.delay,
                     deep_dkim=args.deep_dkim)
    print_risk_table(scan["subdomains"])

    summary = scan["summary"]
    print(f"\nSummary: {summary['critical']} critical, {summary['high']} high, "
          f"{summary['medium']} medium, {summary['low']} low, "
          f"{summary['no_spf']} missing SPF, {summary['no_dmarc']} missing DMARC, "
          f"{summary.get('dangling', 0)} dangling DNS")

    base = args.output or domain.replace(".", "_") + "_spfshadow"
    export_csv(scan, base + ".csv")
    export_json(scan, base + ".json")
    export_html(scan, base + ".html")

# ── Entry ────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.domain:
        cli_mode(args)
    else:
        interactive_mode()

if __name__ == "__main__":
    main()
