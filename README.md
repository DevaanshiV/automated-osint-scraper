# 🕵️ Automated OSINT Data Scraper

> Production‑ready passive reconnaissance tool for domain intelligence gathering.  
> Built for IIT Kanpur B.Cyber portfolio – scripted in Python 3 with clean error handling and structured terminal reporting.

---

## 📋 Table of Contents
- [High‑Level Overview](#high-level-overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [API Endpoints Used](#api-endpoints-used)
- [Output Example](#output-example)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)

---

## 🔍 High‑Level Overview

The **Automated OSINT Data Scraper** performs passive reconnaissance on a given domain name. It follows a modular intelligence workflow:

1. **Input** – domain validation via regex (supports subdomains and multi‑level TLDs).  
2. **DNS Enumeration** – queries A, MX, TXT, and NS records. Uses `dnspython` if available; gracefully falls back to built‑in `socket` for A‑record resolution.  
3. **WHOIS Lookup** – extracts registrar, creation/expiration dates, name servers, registrant country, and contact emails.  
4. **Geolocation** – resolves the first A‑record IP against the free **ip‑api.com** service to retrieve country, region, city, coordinates, ISP, and organization.  
5. **Reporting** – all findings are presented in a clean, ASCII‑formatted terminal report with timestamped headers.

The script is resilient: all external calls are wrapped with timeouts (5–10 seconds) and graceful error handlers. Missing optional dependencies do not break execution – they simply reduce the feature set.

---

## 📦 Prerequisites

| Dependency | Purpose | Installation Command |
|------------|---------|----------------------|
| **Python 3.6+** | Runtime | [Download](https://python.org) |
| `dnspython` | Advanced DNS queries (A, MX, TXT, NS) | `pip install dnspython` |
| `python‑whois` | WHOIS registration data | `pip install python-whois` |

> **Note:** Both libraries are **optional**. If missing, the script will still run – only the corresponding modules will be skipped (fallback to socket for A‑records, WHOIS data will show an error).

---

## 🚀 Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/osint-scraper.git
cd osint-scraper

# 2. (Recommended) Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate

# 3. Install optional dependencies (skip if you prefer limited features)
pip install dnspython python-whois
