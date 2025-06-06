# SPFShadow v1.1

A comprehensive tool for discovering subdomains using OSINT and performing SPF shadow record analysis.

## Features
- Queries crt.sh, VirusTotal, SecurityTrails, and subdomain.center
- Validates subdomains
- Performs SPF record lookups and classification
- Exports data to CSV
- Interactive CLI menu

## Updated Features for v1.1
- Performs DMARC Scanning
- Performs DKIM Scanning
- Performs SPF Vulnerability Scans

## Additional Information
- Virustotal and SecurityTrails API keys are encourged, but not required.
  
## Install
```bash
git clone https://github.com/chillyilly/spfshadow.git
cd spfshadow
pip install bs4 requests dnspython
```

## Run
```bash
python3 spfshadow.py
```
