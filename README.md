# SSLScraper

A CLI recon tool for SSL/TLS certificate analysis. Given a target domain, SSLScraper maps the attack surface by inspecting live certificates, walking certificate chains, querying historical issuance records, and performing reverse DNS sweeps to discover hosts that share infrastructure.

---

## Features

- **Live cert SAN enumeration** — resolves every Subject Alternative Name in the target's current certificate to its IP addresses
- **Certificate chain inspection** — walks the full chain (leaf → intermediates → root), printing subject, issuer, validity window, and serial number for each cert
- **Historical cert lookup via crt.sh** — queries Certificate Transparency logs for every cert ever issued for the domain, surfacing subdomains that may no longer appear in the live cert
- **Reverse DNS sweep** — runs PTR lookups against all discovered IPs to find additional hostnames sharing the same infrastructure
- **Secondary cert scan** — fetches and inspects certificates on any novel hostnames found via reverse DNS, chaining the discovery further
- **JSON output** — all results can be written to a structured JSON file for use in downstream tooling
- **Concurrent resolution** — uses a thread pool for fast parallel DNS resolution across large SAN lists

---

## Installation

```bash
git clone https://github.com/yourorg/sslscraper.git
cd sslscraper
pip install requests
```

`requests` is the only third-party dependency. Everything else uses the Python standard library.

---

## Usage

```bash
python3 main.py <domain> [options]
```

### Examples

```bash
# Basic scan
python3 main.py example.com

# Custom port (e.g. non-standard HTTPS)
python3 main.py example.com --port 8443

# Skip certificate verification (useful for self-signed or expired certs)
python3 main.py internal.corp --no-verify

# Write full results to JSON
python3 main.py example.com --output results.json

# Increase thread count for faster resolution on large SAN lists
python3 main.py example.com --threads 20
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--port` | `443` | Port to connect on |
| `--no-verify` | off | Disable SSL verification |
| `--output` | — | Write results to a JSON file |
| `--threads` | `10` | Thread count for concurrent DNS resolution |

---

## How It Works

```
Target domain
    │
    ├─▶ [1] Certificate chain inspection
    │       Leaf → Intermediates → Root CA
    │
    ├─▶ [2] Live cert SAN enumeration
    │       Resolves each SAN → IP addresses
    │
    ├─▶ [3] Historical lookup (crt.sh)
    │       Certificate Transparency logs → additional subdomains
    │       Resolves concrete names → more IP addresses
    │
    ├─▶ [4] Reverse DNS sweep
    │       PTR lookups on all collected IPs → hostnames
    │
    └─▶ [5] Secondary cert scan
            Cert fetch + SAN dump for novel reverse DNS hosts
```

---

## Output

Each run prints a structured, section-by-section report to stdout and ends with a summary:

```
══════════════════════════════════════════════════════════
  Summary
══════════════════════════════════════════════════════════
  Target                  : example.com
  Chain depth             : 3 cert(s)
  Live SAN domains        : 12
  Historical domains      : 47
  Unique IPs discovered   : 8
  Reverse DNS hits        : 5
  Novel hosts (rDNS scan) : 2
```

When `--output` is specified, all results are saved as structured JSON:

```json
{
  "target": "example.com",
  "scanned_at": "2025-06-01T12:00:00Z",
  "chain": [...],
  "live_cert_domains": [...],
  "historical_domains": [...],
  "reverse_dns_hosts": [...],
  "all_domains_inspected": [...],
  "all_ips": [...]
}
```

---

## Notes

- **Certificate chain depth** requires Python 3.13+ for full chain traversal via `get_verified_chain()`. On earlier versions the tool falls back to leaf-cert-only inspection and notes this in output.
- **crt.sh rate limiting** — queries are capped at 50 historical domain resolutions per run to avoid hammering the API.
- **Wildcard SANs** (e.g. `*.example.com`) are listed in output but skipped during DNS resolution since they cannot be resolved directly.
- Use `--no-verify` when analyzing self-signed, expired, or internally-issued certificates that would otherwise fail validation.

---

## Legal

This tool is intended for authorized security assessments, bug bounty reconnaissance, and research on infrastructure you own or have explicit permission to test. Unauthorized scanning of third-party systems may violate computer fraud laws in your jurisdiction. Use responsibly.
