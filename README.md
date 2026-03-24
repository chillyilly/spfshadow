# SPF Shadow 2.0

**Email authentication audit & risk analysis tool** — discovers subdomains via 5 OSINT sources, then performs deep security analysis of SPF, DMARC, DKIM, MTA-STS, DANE/TLSA, and BIMI across the entire domain footprint. Identifies SPF shadow vulnerabilities, email spoofing risks, and authentication gaps.

```
$ python3 spfshadow.py example.com --lint-only

=== SPF Lint: example.com ===
  [MEDIUM  ] ~all (softfail) is weaker than -all
  [LOW     ] SPF authorizes SendGrid but MX records don't use it

=== DMARC Audit: example.com ===
  [MEDIUM  ] p=none: monitoring only, no enforcement
  [HIGH    ] sp=none: subdomains have no DMARC enforcement
  [MEDIUM  ] No rua= aggregate report URI

=== DKIM Audit: example.com ===
  selector1: ~2048b
  google: ~2048b
  [HIGH    ] Selector 'k1': t=y (test mode)

=== MTA-STS ===
  Not configured

=== BIMI ===
  Not configured

=== SMTP TLS Reporting ===
  Not configured
```

---

## What is an SPF Shadow Attack?

An SPF shadow occurs when a subdomain lacks its own SPF record while the parent domain's DMARC policy doesn't adequately cover subdomains. An attacker spoofs `From: ceo@hr.example.com` — if `hr.example.com` has no SPF and the DMARC subdomain policy (`sp=`) is `none`, the spoofed email passes authentication checks and gets delivered.

This tool finds those gaps across your entire subdomain surface.

---

## Features

### Subdomain Enumeration (no API keys required)

| Source | Method | Key Required |
|--------|--------|:---:|
| **crt.sh** | Certificate Transparency logs (60s timeout, retry on 503) | No |
| **HackerTarget** | Passive DNS / host search API | No |
| **RapidDNS** | DNS database scraping | No |
| **VirusTotal** | Stealth headless browser with full pagination | No |
| **SecurityTrails** | REST API | Yes (optional) |

All sources run concurrently. The VirusTotal scraper uses Playwright with anti-detection patches to scrape the public website without an API key.

### SPF Analysis

- **SPF record linting** (RFC 7208 compliance):
  - Multiple SPF records detection (PermError per §4.5)
  - Terminal mechanism analysis (`+all` critical, `?all` high, `~all` medium, missing `all`)
  - Deprecated `ptr` mechanism detection (§5.5)
  - SPF macro detection and flagging (`%{s}`, `%{d}` — DNS exfiltration risk)
  - Overly broad IP ranges (flags `/16` and wider with calculated host count)
  - Shared infrastructure warnings (Google, M365, SendGrid, SES, Mailgun — CanSPF cross-tenant risk)
  - Mechanism syntax/typo detection (`incldue:`, `ipv4:`, etc.)
  - Record length warnings (truncation risk)
- **SPF include-tree flattening**:
  - Recursively walks `include:`/`redirect=` chains
  - Counts DNS lookups (RFC 7208 §4.6.4 limit: 10)
  - Counts void lookups (NXDOMAIN responses, limit: 2)
  - Detects circular includes
- **SPF-MX provider mismatch detection**:
  - Cross-references SPF includes against MX records
  - Flags stale provider authorizations that expand attack surface

### DMARC Analysis

- **DMARC record linting** (RFC 7489 compliance):
  - Missing/weak policy (`p=none` monitoring only, `p=quarantine` vs `p=reject`)
  - Subdomain policy gap (`sp=none` — the core SPF shadow vector)
  - Partial enforcement (`pct=` < 100)
  - Alignment mode analysis (`adkim=r`/`aspf=r` relaxed = subdomain bypass risk)
  - Missing aggregate reports (`rua=`) and forensic reports (`ruf=`)
  - Failure reporting options (`fo=0` default vs `fo=1` for better visibility)
  - Invalid `p=` value validation
- **External report destination validation**:
  - Parses `mailto:` URIs in `rua=`/`ruf=` tags
  - Checks DNS authorization records at `{domain}._report._dmarc.{external_domain}` (RFC 7489 §7.1)
  - Flags unauthorized external report destinations (reports silently dropped)

### DKIM Analysis

- **Selector probing**: 30+ common selectors (Google, M365, Mailchimp, SendGrid, Postmark, SES, HubSpot, etc.) scanned concurrently
- **Key audit** (RFC 6376 / RFC 8301):
  - Key length estimation from base64 public key (<1024 = critical, <2048 = medium)
  - Test mode `t=y` detection (high — some receivers ignore DKIM)
  - Body length `l=` tag (high — truncation attack: attacker appends content after signed portion)
  - Hash algorithm check (`h=sha1` deprecated per RFC 8301)
  - Revoked keys (empty `p=` — intentional, flagged as info)
  - Ed25519 key type detection
  - Unknown key type flagging

### MX Fingerprinting

Identifies mail providers from MX exchange hostnames: Google Workspace, Microsoft 365, Proofpoint, Mimecast, Mailgun, SendGrid, Amazon SES, Zendesk, Mandrill/Mailchimp, Postmark, SparkPost, Barracuda, Zoho, and more.

### Dangling DNS / Subdomain Takeover Detection

- **Dangling CNAME** — CNAME targets that don't resolve
- **Known vulnerable service fingerprints** — 42 patterns (Heroku, Azure, S3, CloudFront, GitHub Pages, Netlify, Vercel, Fly.dev, etc.) escalated to critical
- **Dangling NS** — NS delegation to dead nameservers (full DNS takeover risk)

### Transport Security

- **MTA-STS** (RFC 8461) — DNS record + HTTPS policy file fetch, mode validation (`enforce`/`testing`/`none`), `max_age` check
- **DANE/TLSA** (RFC 7672) — TLSA records at `_25._tcp.{mx}` for each MX host
- **SMTP TLS Reporting** (RFC 8460) — `_smtp._tls.{domain}` record check
- **BIMI** — `default._bimi.{domain}` record, logo URL, VMC certificate URL

### Per-Subdomain Risk Scoring

Weighted float model combining:
- SPF presence and issue severity
- DMARC policy strength and subdomain policy inheritance
- DKIM key health
- MX record presence (spoofing surface)
- Dangling DNS indicators
- DMARC percentage enforcement

Scores mapped to: Info, Low, Medium, High, Critical.

### Output

- **Interactive terminal UI** with module-specific views
- **CLI one-shot mode** with `argparse`
- **CSV** — flat spreadsheet export
- **JSON** — full structured data
- **HTML report** — dark-themed dashboard with:
  - Root domain SPF/DMARC/DKIM analysis with severity-colored issue tables
  - SPF include-tree visualization with depth indentation
  - DKIM selector table with key size, test mode, and `l=` tag flags
  - MX records with provider identification
  - MTA-STS policy display, DANE/TLSA status, TLS-RPT, BIMI
  - Risk summary stat cards grid
  - Per-subdomain detail table with SPF, DMARC, MX, risk level, and issue breakdown

---

## Installation

```bash
# Clone the repository
git clone https://github.com/chillyilly/spfshadow.git
cd spfshadow

# Install required dependencies
pip install dnspython requests

# Install optional dependencies (for VirusTotal website scraping)
pip install playwright playwright-stealth
playwright install firefox
```

### Dependencies

| Package | Required | Purpose |
|---------|:---:|---------|
| `dnspython` | Yes | All DNS queries (TXT, MX, A, AAAA, CNAME, NS, TLSA, CAA, SOA) |
| `requests` | Yes | OSINT sources, MTA-STS policy fetch, HTTP probes |
| `playwright` | No | Headless browser for VirusTotal scraping |
| `playwright-stealth` | No | Anti-detection patches for headless browser |

Python 3.8+ required.

---

## Usage

### Interactive Mode

```bash
python3 spfshadow.py
```

```
=== SPF Shadow 2.0 ===
  Domain: example.com | 342 subdomains loaded

  1) List subdomains
  2) Validate subdomains (DNS A/AAAA)
  3) Full scan (SPF + DMARC + DKIM + MX + dangling + risk)
  4) SPF include-tree analysis (root)
  5) SPF record linter (root)
  6) DMARC audit (root)
  7) DKIM selector probe + audit (root)
  8) MTA-STS / DANE / BIMI check (root)
  9) Export subdomains to CSV
  q) Quit
```

Option 3 runs the full scan across all subdomains with concurrent analysis, then offers CSV/JSON/HTML export.

### CLI Mode

```bash
# Full scan with auto-export
python3 spfshadow.py example.com

# Quick root-domain-only audit (no subdomain scan)
python3 spfshadow.py example.com --lint-only

# SPF include-tree analysis
python3 spfshadow.py example.com --spf-tree

# Load subdomains from file
python3 spfshadow.py example.com --subs-file subdomains.txt

# Custom output path
python3 spfshadow.py example.com -o /path/to/report

# Probe DKIM selectors on every subdomain (slow)
python3 spfshadow.py example.com --deep-dkim

# Adjust concurrency and pacing
python3 spfshadow.py example.com --workers 25 --delay 0.1
```

### CLI Arguments

| Argument | Description |
|----------|-------------|
| `domain` | Target domain (omit for interactive mode) |
| `-o, --output` | Output base path (generates `.csv`, `.json`, `.html`) |
| `--lint-only` | Lint root domain SPF/DMARC/DKIM/MTA-STS/BIMI only (no subdomain scan) |
| `--spf-tree` | Print SPF include-tree for root domain and exit |
| `--deep-dkim` | Probe DKIM selectors on every subdomain (slow but thorough) |
| `--subs-file` | Load subdomains from file (one per line) |
| `--skip-enum` | Skip subdomain enumeration; scan root domain only |
| `--workers` | Thread pool concurrency (default: 20) |
| `--delay` | Delay between DNS queries in seconds (default: 0.2) |
| `--debug` | Verbose output |

### API Keys (Optional)

```bash
export SECURITYTRAILS_API_KEY="your_key_here"
export VT_API_KEY="your_key_here"
```

Or edit the configuration section at the top of `spfshadow.py`.

---

## Example Output

### SPF Include-Tree

```
$ python3 spfshadow.py example.com --spf-tree

Root SPF: v=spf1 include:_spf.google.com include:spf.protection.outlook.com ~all
DNS lookups: 11 / 10 ** OVER LIMIT **

include:_spf.google.com  (from example.com)
  include:_netblocks.google.com  (from _spf.google.com)
  include:_netblocks2.google.com  (from _spf.google.com)
  include:_netblocks3.google.com  (from _spf.google.com)
include:spf.protection.outlook.com  (from example.com)
  include:spf-a.outlook.com  (from spf.protection.outlook.com)
  include:spf-b.outlook.com  (from spf.protection.outlook.com)
~all  (from example.com)
```

### Full Scan Summary

```
[*] Scanning root domain: example.com
  Root SPF:     v=spf1 include:_spf.google.com ~all
    [MEDIUM] ~all (softfail) is weaker than -all
  Root DMARC:   v=DMARC1; p=quarantine; sp=none; rua=mailto:dmarc@example.com
    [HIGH] sp=none: subdomains have no DMARC enforcement
  Root MX:      2 records
  Root DKIM:    3 selectors found
    [HIGH] Selector 'k1': t=y (test mode)
  SPF lookups:  7/10
  SPF voids:    0/2
  MTA-STS:      not configured
  DANE/TLSA:    0/2 MX hosts have TLSA
  TLS-RPT:      not configured
  BIMI:         not configured

[*] Analyzing 342 subdomains (workers=20)...
  [25/342] scanned...
  [50/342] scanned...
  ...
  [342/342] scanned...

Subdomain                                     Risk       SPF    DMARC  MX   Dng  Reasons
────────────────────────────────────────────────────────────────────────────────────────
staging.example.com                            Critical   NO     NO     1    0    No SPF; No DMARC; Has MX
dev.example.com                                High       NO     NO     0    1    No SPF; Dangling DNS
mail.example.com                               Medium     Yes    NO     2    0    SPF differs; No DMARC
```

### HTML Report

The HTML export generates a self-contained dark-themed report with:

- **Root domain analysis** — SPF record with DNS lookup/void lookup counts, DMARC record, issue tables for SPF/DMARC/DKIM with severity coloring
- **DKIM selectors table** — selector name, estimated key size, test mode and `l=` tag flags, truncated record
- **MX records** — priority, exchange hostname, identified provider
- **SPF include-tree** — indented mechanism list with source domain and depth
- **Transport security** — MTA-STS (with policy text), DANE/TLSA per MX host, TLS-RPT, BIMI
- **Risk summary dashboard** — stat cards for total scanned, critical/high/medium/low counts, no SPF, no DMARC, dangling DNS
- **Subdomain detail table** — sortable columns with risk-colored badges, SPF/DMARC records, issue detail column

---

## How It Works

```
User Input (domain)
    │
    ▼
Subdomain Enumeration ─── 5 OSINT sources (concurrent)
    │
    ▼
Root Domain Analysis
    ├─ SPF lint + include-tree + void lookups
    ├─ DMARC lint + external report validation
    ├─ DKIM selector probe + key audit
    ├─ MX fingerprinting
    ├─ SPF complexity report (DNS lookup budget)
    ├─ MTA-STS policy fetch
    ├─ DANE/TLSA check per MX host
    ├─ SMTP TLS Reporting check
    └─ BIMI record check
    │
    ▼
Per-Subdomain Analysis (concurrent ThreadPool)
    ├─ SPF record + lint
    ├─ DMARC record + lint
    ├─ MX fingerprinting
    ├─ Dangling DNS check (CNAME + NS + 42 takeover patterns)
    ├─ DKIM audit (optional, --deep-dkim)
    └─ Weighted risk scoring
    │
    ▼
Export: CSV / JSON / HTML / Interactive Viewer
```

---

## Security Checks Reference

### SPF (RFC 7208)

| Check | Code | Severity |
|-------|------|----------|
| No SPF record | `SPF_MISSING` | High |
| Multiple SPF records | `SPF_MULTIPLE` | Critical |
| `+all` (pass all) | `SPF_PLUS_ALL` | Critical |
| `?all` (neutral) | `SPF_NEUTRAL_ALL` | High |
| `~all` (softfail) | `SPF_SOFTFAIL_ALL` | Medium |
| No `all` or `redirect` | `SPF_NO_ALL` | High |
| `ptr` mechanism | `SPF_PTR_DEPRECATED` | Medium |
| SPF macros present | `SPF_MACROS` | Low |
| Broad IPv4 range (< /16) | `SPF_BROAD_IP4` | High |
| Shared infrastructure include | `SPF_SHARED_INFRA` | Low |
| Mechanism typo | `SPF_TYPO` | High |
| SPF-MX provider mismatch | `SPF_MX_MISMATCH` | Low |
| Record > 450 chars | `SPF_LONG` | Medium |

### DMARC (RFC 7489)

| Check | Code | Severity |
|-------|------|----------|
| No DMARC record | `DMARC_MISSING` | High |
| No `p=` tag | `DMARC_NO_POLICY` | High |
| `p=none` | `DMARC_POLICY_NONE` | Medium |
| `sp=none` | `DMARC_SP_NONE` | High |
| No `sp=` with weak `p=` | `DMARC_NO_SP` | Medium |
| `pct=` < 100 | `DMARC_PCT_LOW` | Medium |
| Relaxed DKIM alignment | `DMARC_ADKIM_RELAXED` | Low |
| Relaxed SPF alignment | `DMARC_ASPF_RELAXED` | Low |
| No `rua=` reports | `DMARC_NO_RUA` | Medium |
| No `ruf=` forensic reports | `DMARC_NO_RUF` | Low |
| External report unauthorized | `DMARC_EXT_REPORT_UNAUTH` | Medium |
| Invalid `p=` value | `DMARC_INVALID_POLICY` | High |

### DKIM (RFC 6376 / RFC 8301)

| Check | Code | Severity |
|-------|------|----------|
| Key < 1024 bits | `DKIM_WEAK_KEY` | Critical |
| Key < 2048 bits | `DKIM_SHORT_KEY` | Medium |
| Test mode `t=y` | `DKIM_TEST_MODE` | High |
| Body length `l=` tag | `DKIM_L_TAG` | High |
| SHA-1 only hash | `DKIM_SHA1_ONLY` | High |
| SHA-1 accepted | `DKIM_SHA1_ALLOWED` | Medium |
| Revoked key (empty `p=`) | `DKIM_REVOKED` | Info |
| Ed25519 key type | `DKIM_ED25519` | Info |

### Dangling DNS

| Check | Code | Severity |
|-------|------|----------|
| CNAME to known vulnerable service (non-resolving) | `dangling_cname_takeover` | Critical |
| CNAME to non-resolving target | `dangling_cname` | High |
| NS to non-resolving nameserver | `dangling_ns` | Critical |

---

## Responsible Use

This tool is designed for **authorized email security auditing**. Use it to:

- Audit your organization's email authentication posture
- Identify subdomains vulnerable to SPF shadow / email spoofing
- Verify SPF/DMARC/DKIM deployment across all subdomains
- Check compliance with RFC 7208, RFC 7489, RFC 6376, RFC 8301
- Discover dangling DNS records and subdomain takeover risks
- Validate transport security (MTA-STS, DANE, TLS reporting)

Always obtain proper authorization before scanning domains you do not own.

---

## License

MIT
