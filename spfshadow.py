# ----- User Configuration -----
SECURITYTRAILS_API_KEY = ""  # Optional: Add your SecurityTrails API key here
VT_API_KEY = ""              # Optional: Add your VirusTotal API key here

import os
import re
import csv
import sys
import signal
import subprocess
import requests
from bs4 import BeautifulSoup
from urllib.parse import quote
from dns.resolver import resolve, Resolver, NXDOMAIN, NoAnswer, Timeout, NoNameservers
import time

# Handle Ctrl+C
def signal_handler(sig, frame):
    print("\n[!] Interrupted. Exiting.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Get keys from config or environment
SECURITYTRAILS_API_KEY = SECURITYTRAILS_API_KEY or os.getenv("SECURITYTRAILS_API_KEY")
VT_API_KEY = VT_API_KEY or os.getenv("VT_API_KEY")

# ------------- Subdomain Sources -------------

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

# ------------- SPF Shadow Logic -------------

def get_spf_record(domain):
    try:
        answers = resolve(domain, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                decoded = txt_string.decode('utf-8')
                if decoded.startswith('v=spf1'):
                    return decoded
    except (NXDOMAIN, NoAnswer, Timeout, NoNameservers):
        return None
    except Exception as e:
        print(f"[spf] Error querying {domain}: {e}")
        return None

def run_spf_shadow_check(domain, subdomains, debug=False):
    root_spf = get_spf_record(domain)
    if debug:
        print(f"[SPF] Root SPF for {domain}: {root_spf}")

    results = {"with_spf": [], "no_spf": [], "matching_spf": []}
    for sub in subdomains:
        time.sleep(0.5)
        spf = get_spf_record(sub)
        if spf:
            results["with_spf"].append((sub, spf))
            if spf == root_spf:
                results["matching_spf"].append((sub, spf))
        else:
            results["no_spf"].append(sub)
    return results

def interactive_spf_view(results):
    while True:
        print("\n--- SPF Shadow View Options ---")
        print("10) Show subdomains with SPF records")
        print("11) Show subdomains with matching root SPF record")
        print("12) Show subdomains with no SPF record")
        print("q) Quit SPF view")
        choice = input("Select an option: ").strip()

        if choice == "10":
            for sub, spf in results["with_spf"]:
                print(f"{sub}: {spf}")
            if input("Save to CSV? (y/N): ").lower().startswith("y"):
                export_spf_to_csv(results, "spf_with")
        elif choice == "11":
            for sub, spf in results["matching_spf"]:
                print(f"{sub}: {spf}")
            if input("Save to CSV? (y/N): ").lower().startswith("y"):
                export_spf_to_csv({"with_spf": results["matching_spf"]}, "spf_match")
        elif choice == "12":
            per_page = 10
            total = len(results["no_spf"])
            for i in range(0, total, per_page):
                for sub in results["no_spf"][i:i + per_page]:
                    print(sub)
                if i + per_page < total:
                    if input("Press Enter to continue, 'q' to quit: ").strip().lower() == 'q':
                        break
            if input("Save to CSV? (y/N): ").lower().startswith("y"):
                filename = f"spf_no.csv"
                with open(filename, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Subdomain"])
                    for sub in results["no_spf"]:
                        writer.writerow([sub])
                print(f"[+] Saved to {filename}")
        elif choice == "q":
            break
        else:
            print("[!] Invalid option.")

# ------------- Validation -------------

def validate_subdomains(subdomains):
    valid = set()
    resolver = Resolver()
    resolver.timeout = 2
    resolver.lifetime = 4
    for sub in subdomains:
        try:
            resolver.resolve(sub)
            valid.add(sub)
        except (NXDOMAIN, NoAnswer, Timeout, NoNameservers):
            pass
    return valid

# ------------- Export -------------

def export_to_csv(subdomains, domain):
    filename = f"{domain}_subdomains.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Subdomain"])
        for sub in sorted(subdomains):
            writer.writerow([sub])
    print(f"[+] Saved subdomains to {filename}")

def export_spf_to_csv(results, label):
    filename = f"{label}_spf_results.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Subdomain", "SPF Record"])
        for sub, spf in results["with_spf"]:
            writer.writerow([sub, spf])
    print(f"[+] Saved SPF results to {filename}")

# ------------- Main Flow -------------

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
        print("Choose an action:")
        print("1) Display subdomain list")
        print("2) Validate subdomains (DNS A lookup)")
        print("3) Perform SPF Shadow Check")
        print("4) Export subdomains to CSV and quit")
        choice = input("Your choice: ").strip()

        if choice == "1":
            for sub in sorted_subs:
                print(sub)
        elif choice == "2":
            valid = validate_subdomains(sorted_subs)
            print(f"\n[✓] {len(valid)} subdomains resolved successfully.")
            for v in sorted(valid):
                print(v)
        elif choice == "3":
            spf_results = run_spf_shadow_check(domain, sorted_subs, debug)
            print(f"\n[✓] SPF Records Found: {len(spf_results['with_spf'])}")
            print(f"[✓] Matching Root SPF: {len(spf_results['matching_spf'])}")
            print(f"[✓] No SPF Records: {len(spf_results['no_spf'])}")
            interactive_spf_view(spf_results)
        elif choice == "4":
            export_to_csv(sorted_subs, domain)
            break
        else:
            print("[!] Invalid option. Try again.")

if __name__ == "__main__":
    main()

