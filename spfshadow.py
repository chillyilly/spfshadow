# ----- User Configuration -----
SECURITYTRAILS_API_KEY = ""  # Optional: Add your SecurityTrails API key here
VT_API_KEY = ""              # Optional: Add your VirusTotal API key here

import os
import re
import csv
import sys
import signal
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import quote
from dns.resolver import resolve, Resolver, NXDOMAIN, NoAnswer, Timeout, NoNameservers

def signal_handler(sig, frame):
    print("\n[!] Interrupted. Exiting.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

SECURITYTRAILS_API_KEY = SECURITYTRAILS_API_KEY or os.getenv("SECURITYTRAILS_API_KEY")
VT_API_KEY = VT_API_KEY or os.getenv("VT_API_KEY")

def get_crtsh_subdomains(domain, debug=False):
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        headers = {"User-Agent": "Mozilla/5.0"}
        resp = requests.get(url, headers=headers, timeout=20)
        if resp.status_code != 200 or not resp.headers.get("Content-Type", "").startswith("application/json"):
            raise Exception("crt.sh returned non-JSON content or failed to respond properly.")
        if not resp.text.strip().startswith("["):
            raise Exception("crt.sh response does not look like JSON data.")
        seen = set()
        for entry in resp.json():
            name = entry.get("name_value", "")
            for sub in name.splitlines():
                if sub.endswith(domain):
                    seen.add(sub.strip())
        if debug: print(f"[crt.sh] Found {len(seen)}")
        return seen
    except Exception as e:
        print(f"[crt.sh] Error: {e}")
        return set()

def get_securitytrails_subdomains(domain, debug=False):
    if not SECURITYTRAILS_API_KEY:
        if debug: print("[securitytrails] No API key found, skipping.")
        return set()
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"APIKEY": SECURITYTRAILS_API_KEY}
        r = requests.get(url, headers=headers, timeout=15)
        data = r.json()
        subs = set(f"{sub}.{domain}" for sub in data.get("subdomains", []))
        if debug: print(f"[securitytrails] Found {len(subs)}")
        return subs
    except Exception as e:
        print(f"[securitytrails] Error: {e}")
        return set()

def get_virustotal_subdomains(domain, debug=False):
    if not VT_API_KEY:
        if debug: print("[virustotal] No API key found, skipping.")
        return set()
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        headers = {"x-apikey": VT_API_KEY}
        all_subs = set()
        while url:
            r = requests.get(url, headers=headers, timeout=15)
            data = r.json()
            for entry in data.get("data", []):
                all_subs.add(entry.get("id"))
            url = data.get("links", {}).get("next")
        if debug: print(f"[virustotal] Found {len(all_subs)}")
        return all_subs
    except Exception as e:
        print(f"[virustotal] Error: {e}")
        return set()

def get_subdomain_center(domain, debug=False):
    try:
        url = f"https://subdomain.center/?domain={quote(domain)}"
        r = requests.get(url, timeout=20)
        subdomains = set(re.findall(r"([\w\.-]+\." + re.escape(domain) + r")", r.text))
        if debug: print(f"[subdomain.center] Found {len(subdomains)}")
        return subdomains
    except Exception as e:
        print(f"[subdomain.center] Error: {e}")
        return set()

def get_txt_records(domain):
    try:
        return [txt.decode("utf-8") for rdata in resolve(domain, "TXT") for txt in rdata.strings]
    except Exception:
        return []

def get_spf_record(domain):
    for txt in get_txt_records(domain):
        if txt.startswith("v=spf1"):
            return txt
    return None

def check_spf_vulnerabilities(spf_record):
    issues = []
    if spf_record is None:
        issues.append("No SPF record.")
        return issues
    if "all" not in spf_record:
        issues.append("No 'all' mechanism found.")
    elif "+all" in spf_record:
        issues.append("Dangerous '+all' allows all senders.")
    elif "?all" in spf_record:
        issues.append("Weak '?all' present — neutral policy.")
    elif "~all" in spf_record:
        issues.append("SoftFail '~all' — better than none but still weak.")
    if spf_record.count("include:") > 10:
        issues.append("Too many 'include:' mechanisms (risk of DNS lookup limit).")
    return issues

def get_dmarc_record(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        for txt in get_txt_records(dmarc_domain):
            if txt.startswith("v=DMARC1"):
                return txt
    except Exception:
        pass
    return None

def scan_dkim_selectors(domain, selectors=["default", "selector1", "google", "dkim", "mail"]):
    results = {}
    for selector in selectors:
        try:
            rec = get_txt_records(f"{selector}._domainkey.{domain}")
            if rec:
                results[selector] = rec
        except Exception:
            continue
    return results

def main():
    domain = input("Enter a domain (e.g. example.com): ").strip()
    debug = input("Enable debug mode? (y/N): ").lower().startswith("y")

    print("[*] Gathering subdomains from OSINT sources...")
    all_subs = set()
    all_subs.update(get_crtsh_subdomains(domain, debug))
    all_subs.update(get_securitytrails_subdomains(domain, debug))
    all_subs.update(get_subdomain_center(domain, debug))
    all_subs.update(get_virustotal_subdomains(domain, debug))

    sorted_subs = sorted(all_subs)
    print(f"\n[+] Total unique subdomains found: {len(sorted_subs)}\n")

    while True:
        print("\nChoose an action:")
        print("1) Display subdomain list")
        print("2) Validate subdomains (DNS A lookup)")
        print("3) Perform SPF Shadow Check")
        print("4) Export subdomains to CSV and quit")
        print("5) Check for DMARC records")
        print("6) Check for DKIM selectors")
        print("q) Quit")
        choice = input("Your choice: ").strip()

        if choice == "1":
            for sub in sorted_subs:
                print(sub)

        elif choice == "2":
            resolver = Resolver()
            resolver.timeout = 2
            resolver.lifetime = 4
            valid = set()
            for sub in sorted_subs:
                try:
                    resolver.resolve(sub)
                    valid.add(sub)
                except:
                    pass
            print(f"\n[✓] {len(valid)} subdomains resolved successfully.")
            for v in sorted(valid):
                print(v)

        elif choice == "3":
            root_spf = get_spf_record(domain)
            results = {"with_spf": [], "no_spf": [], "matching_spf": []}
            for sub in sorted_subs:
                time.sleep(0.5)
                spf = get_spf_record(sub)
                if spf:
                    results["with_spf"].append((sub, spf))
                    if spf == root_spf:
                        results["matching_spf"].append((sub, spf))
                else:
                    results["no_spf"].append(sub)
            print(f"\n[✓] SPF Records Found: {len(results['with_spf'])}")
            print(f"[✓] Matching Root SPF: {len(results['matching_spf'])}")
            print(f"[✓] No SPF Records: {len(results['no_spf'])}")

            while True:
                print("\n--- SPF Shadow View Options ---")
                print("1) Show SPF Records")
                print("2) Analyze SPF Records for Vulnerabilities")
                print("b) Back to Main Menu")
                subchoice = input("Choose: ").strip()
                if subchoice == "1":
                    for sub, spf in results["with_spf"]:
                        print(f"{sub}: {spf}")
                elif subchoice == "2":
                    for sub, spf in results["with_spf"]:
                        issues = check_spf_vulnerabilities(spf)
                        if issues:
                            print(f"\n[!] {sub}")
                            for issue in issues:
                                print(f"   - {issue}")
                elif subchoice.lower() == "b":
                    break
                else:
                    print("[!] Invalid option.")

        elif choice == "4":
            filename = f"{domain}_subdomains.csv"
            with open(filename, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Subdomain"])
                for sub in sorted_subs:
                    writer.writerow([sub])
            print(f"[+] Saved to {filename}")
            break

        elif choice == "5":
            for sub in sorted_subs:
                rec = get_dmarc_record(sub)
                if rec:
                    print(f"{sub}: {rec}")
                else:
                    print(f"{sub}: [!] No DMARC record")

        elif choice == "6":
            for sub in sorted_subs:
                dkim = scan_dkim_selectors(sub)
                if dkim:
                    print(f"\n[✓] DKIM for {sub}:")
                    for sel, rec in dkim.items():
                        print(f"  - {sel}: {rec}")
                else:
                    print(f"{sub}: [!] No DKIM selectors found")

        elif choice.lower() == "q":
            break

        else:
            print("[!] Invalid option.")

if __name__ == "__main__":
    main()

