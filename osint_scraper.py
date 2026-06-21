#!/usr/bin/env python3
"""
Automated OSINT Data Scraper
Performs passive reconnaissance on a given domain.
Collects DNS records, WHOIS summary, and geolocation of the main server IP.
"""

import sys
import socket
import re
import json
import urllib.request
import urllib.error
from datetime import datetime

# ----------------------------------------------------------------------
# Optional imports with graceful fallback – these are not built-in.
# We check availability to keep the script functional (with limited features)
# even if dependencies are missing.
# ----------------------------------------------------------------------
try:
    import dns.resolver          # For advanced DNS queries (A, MX, TXT, NS)
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois                 # For WHOIS registration data
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


def get_domain():
    """
    Obtain the target domain from command-line argument or interactive input.
    Validates format using a simple regex.
    """
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = input("Enter domain (e.g., example.com): ").strip()

    # Basic domain validation (allows subdomains, hyphens, dots, and TLD)
    if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
        print("[-] Invalid domain format.")
        sys.exit(1)
    return domain


def get_dns_records(domain):
    """
    Query DNS records: A, MX, TXT, NS.
    Uses dnspython if available; otherwise falls back to socket for A record only.
    Returns a dict with lists of record values (strings).
    """
    records = {'A': [], 'MX': [], 'TXT': [], 'NS': []}

    if not DNS_AVAILABLE:
        print("[!] dnspython not installed. Falling back to socket for A record only.")
        try:
            # gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
            ips = socket.gethostbyname_ex(domain)[2]
            records['A'] = ips
        except socket.gaierror:
            records['A'] = ['N/A']
        return records

    # Configure resolver with short timeouts to avoid hanging
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    # A records (IPv4 addresses)
    try:
        answers = resolver.resolve(domain, 'A')
        records['A'] = [str(r) for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        records['A'] = ['N/A']

    # MX records (mail exchangers with preference)
    try:
        answers = resolver.resolve(domain, 'MX')
        mx_list = [(r.preference, str(r.exchange).rstrip('.')) for r in answers]
        mx_list.sort(key=lambda x: x[0])          # Sort by preference (lowest first)
        records['MX'] = [f"{pref} {exch}" for pref, exch in mx_list]
    except Exception:
        records['MX'] = ['N/A']

    # TXT records (text strings, often for SPF/DKIM)
    try:
        answers = resolver.resolve(domain, 'TXT')
        # Each answer may contain multiple strings; join them
        records['TXT'] = [''.join(r.strings) for r in answers]
    except Exception:
        records['TXT'] = ['N/A']

    # NS records (authoritative name servers)
    try:
        answers = resolver.resolve(domain, 'NS')
        records['NS'] = [str(r).rstrip('.') for r in answers]
    except Exception:
        records['NS'] = ['N/A']

    return records


def get_whois_summary(domain):
    """
    Fetch WHOIS registration summary using the python-whois library.
    Extracts key fields: registrar, dates, name servers, registrant country, and emails.
    """
    if not WHOIS_AVAILABLE:
        return {"error": "python-whois not installed. Install with: pip install python-whois"}

    try:
        w = whois.whois(domain)
        summary = {
            'registrar': w.registrar if w.registrar else 'N/A',
            'creation_date': str(w.creation_date) if w.creation_date else 'N/A',
            'expiration_date': str(w.expiration_date) if w.expiration_date else 'N/A',
            'name_servers': w.name_servers if w.name_servers else 'N/A',
            'registrant_country': w.registrant_country if w.registrant_country else 'N/A',
            'emails': w.emails if w.emails else 'N/A',
        }
        return summary
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {str(e)}"}


def get_geolocation(ip):
    """
    Query the free ip-api.com service to obtain geolocation and ISP info for the given IP.
    Uses built-in urllib to avoid additional HTTP library dependencies.
    Returns a dict with location details or an error message.
    """
    if ip == 'N/A':
        return {"error": "No IP available for geolocation"}

    # Request only needed fields to reduce bandwidth
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,org"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            if data.get('status') == 'success':
                return {
                    'country': data.get('country', 'N/A'),
                    'region': data.get('regionName', 'N/A'),
                    'city': data.get('city', 'N/A'),
                    'latitude': data.get('lat', 'N/A'),
                    'longitude': data.get('lon', 'N/A'),
                    'isp': data.get('isp', 'N/A'),
                    'org': data.get('org', 'N/A'),
                }
            else:
                return {"error": data.get('message', 'Unknown API error')}
    except urllib.error.URLError as e:
        return {"error": f"API request failed: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}


def format_report(domain, dns_records, whois_data, geo_data, ip_used):
    """
    Print a well-structured, formatted report to the terminal.
    Uses ASCII headers and simple tables for clarity.
    """
    print("\n" + "=" * 70)
    print(f"  OSINT Reconnaissance Report for: {domain}")
    print("  Timestamp:", datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))
    print("=" * 70)

    # ---------- DNS Records ----------
    print("\n[+] DNS Records")
    print("-" * 50)
    for rec_type, values in dns_records.items():
        print(f"  {rec_type} Records:")
        if isinstance(values, list):
            for val in values:
                print(f"    - {val}")
        else:
            print(f"    {values}")

    # ---------- WHOIS Summary ----------
    print("\n[+] WHOIS Registration Summary")
    print("-" * 50)
    if isinstance(whois_data, dict) and 'error' in whois_data:
        print(f"  [!] {whois_data['error']}")
    else:
        # Pretty-print the WHOIS fields, converting lists to comma-separated strings
        for key, value in whois_data.items():
            if isinstance(value, list):
                value = ', '.join(str(v) for v in value)
            # Replace underscores with spaces and capitalise for readability
            label = key.replace('_', ' ').title()
            print(f"  {label}: {value}")

    # ---------- Geolocation ----------
    print("\n[+] Geolocation of Main Server IP")
    print("-" * 50)
    print(f"  IP Address: {ip_used}")
    if isinstance(geo_data, dict) and 'error' in geo_data:
        print(f"  [!] {geo_data['error']}")
    else:
        for key, value in geo_data.items():
            label = key.replace('_', ' ').title()
            print(f"  {label}: {value}")

    print("\n" + "=" * 70)
    print("  End of Report")
    print("=" * 70 + "\n")


def main():
    """
    Main execution workflow:
      1. Obtain domain.
      2. Perform DNS lookups.
      3. Retrieve WHOIS data.
      4. Get geolocation for the first A record IP.
      5. Display the final intelligence report.
    """
    domain = get_domain()
    print(f"[*] Target domain: {domain}")
    print("[*] Starting reconnaissance...")

    # Step 1: DNS records
    dns_records = get_dns_records(domain)

    # Determine primary IP from the first A record (for geolocation)
    ip_used = 'N/A'
    if dns_records.get('A') and dns_records['A'] != ['N/A']:
        ip_used = dns_records['A'][0]

    # Step 2: WHOIS summary
    whois_data = get_whois_summary(domain)

    # Step 3: Geolocation of the main server IP
    geo_data = get_geolocation(ip_used)

    # Step 4: Format and output the report
    format_report(domain, dns_records, whois_data, geo_data, ip_used)


if __name__ == "__main__":
    main()