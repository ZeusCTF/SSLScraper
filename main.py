import ssl
import socket
import argparse
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

print("""
 ____ ____  _       ____  _            _   _     
/ ___/ ___|| |     / ___|| | ___ _   _| |_| |__  
\___ \___ \| |     \___ \| |/ _ \ | | | __| '_ \ 
 ___) |__) | |___   ___) | |  __/ |_| | |_| | | |
|____/____/|_____| |____/|_|\___|\__,_|\__|_| |_|
      """)

parser = argparse.ArgumentParser(description="SSL certificate recon tool")
parser.add_argument("domain", type=str, help="Domain to scan")
parser.add_argument("--port", type=int, default=443, help="Port to connect on (default: 443)")
parser.add_argument("--no-verify", action="store_true", help="Skip SSL verification (allows inspecting invalid certs)")
parser.add_argument("--output", type=str, help="Write results to a JSON file")
parser.add_argument("--threads", type=int, default=10, help="Thread count for concurrent resolution (default: 10)")
args = parser.parse_args()

results = {
    "target": args.domain,
    "scanned_at": datetime.utcnow().isoformat() + "Z",
    "chain": [],
    "live_cert_domains": [],
    "historical_domains": [],
    "reverse_dns_hosts": [],
    "all_domains_inspected": []
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def section(title):
    width = 60
    print(f"\n{'═' * width}")
    print(f"  {title}")
    print(f"{'═' * width}")

def resolve_domain(domain):
    """Return (domain, [ips]) or (domain, []) on failure."""
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        return domain, ips
    except socket.gaierror:
        return domain, []

def reverse_dns(ip):
    """Return (ip, hostname) or (ip, None) on failure."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return ip, hostname
    except socket.herror:
        return ip, None

# ─── 1. Certificate chain inspection ──────────────────────────────────────────

def get_cert_chain(hostname, port=443, verify=True):
    """
    Retrieve the full certificate chain using a raw DER fetch so we can
    inspect every certificate in the chain, not just the leaf.
    Falls back to a single-cert fetch when the chain pull fails.
    """
    section("Certificate Chain Inspection")

    chain_certs = []

    # Pull the raw binary chain via SSLContext with check_hostname / verify toggled
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.load_default_certs()

    try:
        with socket.create_connection((hostname, port), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
                # getpeercert() gives the leaf; get the full chain via DER
                der_chain = tls.get_verified_chain() if hasattr(tls, "get_verified_chain") else None
                leaf_pem_dict = tls.getpeercert()

        if der_chain:
            for i, der_cert in enumerate(der_chain):
                pem = ssl.DER_cert_to_PEM_cert(der_cert)
                parsed = ssl.PEM_cert_to_DER_cert(pem)  # round-trip confirms parseable
                # Use x509 info from the context decoded cert dict where available
                label = "Leaf" if i == 0 else ("Root" if i == len(der_chain) - 1 else f"Intermediate {i}")
                # Extract Subject / Issuer from the leaf dict for display; raw for others
                cert_info = {
                    "position": label,
                    "index": i,
                }
                # Try to decode subject/issuer via a fresh context peek
                try:
                    tmp_ctx = ssl.create_default_context()
                    tmp_ctx.check_hostname = False
                    tmp_ctx.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((hostname, port), timeout=10) as s2:
                        with tmp_ctx.wrap_socket(s2, server_hostname=hostname) as t2:
                            if i == 0:
                                details = t2.getpeercert()
                                cert_info["subject"] = dict(x[0] for x in details.get("subject", []))
                                cert_info["issuer"] = dict(x[0] for x in details.get("issuer", []))
                                cert_info["not_before"] = details.get("notBefore")
                                cert_info["not_after"] = details.get("notAfter")
                                cert_info["serial"] = details.get("serialNumber")
                                cert_info["san"] = [d[1] for d in details.get("subjectAltName", [])]
                except Exception:
                    pass
                chain_certs.append(cert_info)
        else:
            # Fallback: only leaf cert available
            cert_info = {
                "position": "Leaf (chain unavailable — Python < 3.13)",
                "index": 0,
                "subject": dict(x[0] for x in leaf_pem_dict.get("subject", [])),
                "issuer": dict(x[0] for x in leaf_pem_dict.get("issuer", [])),
                "not_before": leaf_pem_dict.get("notBefore"),
                "not_after": leaf_pem_dict.get("notAfter"),
                "serial": leaf_pem_dict.get("serialNumber"),
                "san": [d[1] for d in leaf_pem_dict.get("subjectAltName", [])],
            }
            chain_certs.append(cert_info)

    except Exception as e:
        print(f"  [!] Chain fetch error: {e}")

    for cert in chain_certs:
        print(f"\n  [{cert['position']}]")
        if "subject" in cert:
            subj = cert["subject"]
            print(f"    Subject CN  : {subj.get('commonName', 'N/A')}")
            print(f"    Subject O   : {subj.get('organizationName', 'N/A')}")
        if "issuer" in cert:
            iss = cert["issuer"]
            print(f"    Issuer CN   : {iss.get('commonName', 'N/A')}")
            print(f"    Issuer O    : {iss.get('organizationName', 'N/A')}")
        if "not_before" in cert:
            print(f"    Valid from  : {cert['not_before']}")
            print(f"    Valid until : {cert['not_after']}")
        if "serial" in cert:
            print(f"    Serial      : {cert['serial']}")
        if cert.get("san"):
            print(f"    SANs        : {', '.join(cert['san'][:5])}" +
                  (f" ... (+{len(cert['san'])-5} more)" if len(cert['san']) > 5 else ""))

    results["chain"] = chain_certs
    return chain_certs

# ─── 2. Live cert SAN scrape ───────────────────────────────────────────────────

def download_ssl_certificate(hostname, port=443, verify=True):
    ctx = ssl.create_default_context() if verify else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert()
    except Exception as e:
        print(f"  [!] Could not fetch cert for {hostname}: {e}")
        return None

def strip_cert(cert, label=""):
    """Extract SAN domains from a cert dict."""
    if not cert:
        return []
    domains = [d[1] for d in cert.get("subjectAltName", [])]
    if label:
        print(f"\n  Domains in cert ({label}): {len(domains)}")
    return domains

# ─── 3. Historical cert lookup via crt.sh ────────────────────────────────────

def crtsh_lookup(domain):
    section(f"Historical Cert Lookup — crt.sh ({domain})")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        entries = resp.json()
    except requests.RequestException as e:
        print(f"  [!] crt.sh request failed: {e}")
        return []
    except json.JSONDecodeError:
        print("  [!] crt.sh returned non-JSON response")
        return []

    seen = set()
    historical = []
    for entry in entries:
        # name_value can contain multiple newline-separated names
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lower()
            if name and name not in seen:
                seen.add(name)
                historical.append({
                    "domain": name,
                    "issuer": entry.get("issuer_name", ""),
                    "not_before": entry.get("not_before", ""),
                    "not_after": entry.get("not_after", ""),
                    "cert_id": entry.get("id"),
                })

    wildcards = [h for h in historical if h["domain"].startswith("*")]
    concrete = [h for h in historical if not h["domain"].startswith("*")]

    print(f"  Found {len(historical)} unique names ({len(wildcards)} wildcards, {len(concrete)} concrete)")
    if wildcards:
        print("\n  Wildcards:")
        for w in wildcards[:10]:
            print(f"    {w['domain']}")
        if len(wildcards) > 10:
            print(f"    ... (+{len(wildcards)-10} more)")

    if concrete:
        print("\n  Concrete historical domains (sample):")
        for h in concrete[:15]:
            print(f"    {h['domain']}  [{h['not_before'][:10] if h['not_before'] else '?'} → {h['not_after'][:10] if h['not_after'] else '?'}]")
        if len(concrete) > 15:
            print(f"    ... (+{len(concrete)-15} more)")

    results["historical_domains"] = historical
    return [h["domain"] for h in concrete]

# ─── 4. Reverse DNS + secondary cert scan ─────────────────────────────────────

def reverse_dns_sweep(ip_list):
    section("Reverse DNS Sweep")
    rdns_results = []
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(reverse_dns, ip): ip for ip in ip_list}
        for future in as_completed(futures):
            ip, hostname = future.result()
            entry = {"ip": ip, "hostname": hostname}
            rdns_results.append(entry)
            if hostname:
                print(f"  {ip}  →  {hostname}")
            else:
                print(f"  {ip}  →  (no PTR record)")

    results["reverse_dns_hosts"] = rdns_results
    return [r["hostname"] for r in rdns_results if r["hostname"]]

def resolve_domains_concurrent(domains):
    """Resolve a list of domains to IPs concurrently. Returns dict domain→[ips]."""
    resolved = {}
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(resolve_domain, d): d for d in domains}
        for future in as_completed(futures):
            domain, ips = future.result()
            resolved[domain] = ips
    return resolved

def scan_secondary_hosts(hostnames):
    """Fetch and display certs for hostnames discovered via reverse DNS."""
    if not hostnames:
        return
    section("Cert Scan — Reverse DNS Discovered Hosts")
    already_scanned = set()
    for host in hostnames:
        if host in already_scanned:
            continue
        already_scanned.add(host)
        print(f"\n  Scanning: {host}")
        cert = download_ssl_certificate(host, args.port, verify=not args.no_verify)
        domains = strip_cert(cert, label=host)
        for d in domains:
            print(f"    SAN: {d}")
        results["all_domains_inspected"].append({
            "host": host,
            "source": "reverse_dns",
            "san_domains": domains
        })

# ─── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    target = args.domain
    port = args.port
    verify = not args.no_verify

    # 1. Certificate chain
    chain = get_cert_chain(target, port, verify)

    # 2. Live cert SAN domains
    section(f"Live Cert SANs — {target}")
    live_cert = download_ssl_certificate(target, port, verify)
    live_domains = strip_cert(live_cert, label=target)

    resolved_map = resolve_domains_concurrent(
        [d for d in live_domains if not d.startswith("*")]
    )

    all_ips = set()
    san_entries = []
    for domain, ips in resolved_map.items():
        all_ips.update(ips)
        entry = {"domain": domain, "ips": ips}
        san_entries.append(entry)
        if ips:
            print(f"  {domain}  →  {', '.join(ips)}")
        else:
            print(f"  {domain}  →  (unresolved)")

    results["live_cert_domains"] = san_entries

    # 3. Historical crt.sh lookup
    historical_domains = crtsh_lookup(target)

    # 4. Resolve historical domains to gather more IPs for reverse DNS
    section("Resolving Historical Domains")
    historical_resolved = resolve_domains_concurrent(
        [d for d in historical_domains if not d.startswith("*")][:50]  # cap at 50 to be polite
    )
    for domain, ips in historical_resolved.items():
        all_ips.update(ips)
        if ips:
            print(f"  {domain}  →  {', '.join(ips)}")

    # 5. Reverse DNS on all collected IPs
    rdns_hostnames = reverse_dns_sweep(sorted(all_ips))

    # Filter out hostnames we already know about
    known = set(live_domains) | set(historical_domains) | {target}
    novel_hosts = [h for h in rdns_hostnames if h not in known]

    # 6. Cert scan on novel reverse DNS hosts
    scan_secondary_hosts(novel_hosts)

    # ─── Summary ──────────────────────────────────────────────────────────────
    section("Summary")
    print(f"  Target                  : {target}")
    print(f"  Chain depth             : {len(results['chain'])} cert(s)")
    print(f"  Live SAN domains        : {len(results['live_cert_domains'])}")
    print(f"  Historical domains      : {len(results['historical_domains'])}")
    print(f"  Unique IPs discovered   : {len(all_ips)}")
    print(f"  Reverse DNS hits        : {sum(1 for r in results['reverse_dns_hosts'] if r['hostname'])}")
    print(f"  Novel hosts (rDNS scan) : {len(novel_hosts)}")

    # ─── Optional JSON output ─────────────────────────────────────────────────
    if args.output:
        results["all_ips"] = sorted(all_ips)
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n  Results written to: {args.output}")
