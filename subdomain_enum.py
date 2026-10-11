#!/usr/bin/env python3
"""
subdomain_enum.py - Passive-aware subdomain enumeration helper.

Enumerates subdomains for a target using (in order of availability):
  1. crt.sh certificate transparency logs
  2. Wordlist-based DNS resolution against the target's resolvers

Only queries public CT logs and public DNS. Performs no scanning of any kind.

Usage:
    python subdomain_enum.py --domain example.com
    python subdomain_enum.py --domain example.com --wordlist wordlist.txt
    python subdomain_enum.py --domain example.com --output found.txt

Legal:
    Only enumerate domains you own or have explicit written permission to test.
"""

import argparse
import concurrent.futures
import json
import socket
import sys
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

USER_AGENT = "recon-toolkit/1.0 (+https://github.com/bhuvanchandt/recon-toolkit)"
DEFAULT_THREADS = 50

DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "dev", "staging", "stage", "test", "qa", "uat", "prod",
    "api", "api-v2", "api-dev", "graphql", "admin", "portal", "dashboard", "panel",
    "internal", "intranet", "vpn", "remote", "git", "gitlab", "jenkins", "ci", "cd",
    "jira", "confluence", "grafana", "kibana", "prometheus", "nagios", "zabbix",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elasticsearch",
    "backup", "backups", "old", "new", "legacy", "beta", "alpha", "demo", "sandbox",
    "cdn", "static", "assets", "media", "img", "images", "files", "download",
    "auth", "login", "sso", "oauth", "id", "identity", "accounts", "account",
    "payments", "payment", "billing", "checkout", "cart", "shop", "store",
    "support", "help", "docs", "documentation", "wiki", "blog", "news",
    "chat", "forum", "crm", "erp", "hr", "jobs", "careers",
    "mobile", "app", "m", "ws", "wss", "gateway", "proxy", "lb", "edge",
]


def log(msg):
    print(msg, flush=True)


def crtsh_subdomains(domain):
    """Query crt.sh certificate transparency logs for subdomains."""
    found = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = Request(url, headers={"User-Agent": USER_AGENT})

    try:
        with urlopen(req, timeout=30) as resp:
            payload = resp.read().decode("utf-8", errors="replace")
    except HTTPError as e:
        log(f"[!] crt.sh returned HTTP {e.code}")
        return found
    except (URLError, socket.timeout):
        log("[!] crt.sh unreachable, skipping CT source")
        return found

    try:
        entries = json.loads(payload)
    except json.JSONDecodeError:
        log("[!] crt.sh returned malformed JSON, skipping CT source")
        return found

    for entry in entries:
        name = (entry.get("name_value") or "").strip().lower()
        if not name:
            continue
        # crt.sh often returns newline-separated multi-SAN entries
        for part in name.split("\n"):
            part = part.strip().lstrip("*.")
            if part.endswith(domain):
                found.add(part)

    log(f"[*] crt.sh returned {len(found)} unique subdomain(s)")
    return found


def resolves(hostname):
    """Return True if hostname resolves to an A/AAAA record."""
    try:
        socket.getaddrinfo(hostname, None)
        return True
    except socket.gaierror:
        return False


def brute_subdomains(domain, wordlist, threads):
    """Resolve candidate subdomains from a wordlist against public DNS."""
    candidates = list(wordlist)
    live = set()

    log(f"[*] Resolving {len(candidates)} candidate(s) with {threads} threads")
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(resolves, f"{c}.{domain}"): c for c in candidates}
        for fut in concurrent.futures.as_completed(futures):
            candidate = futures[fut]
            if fut.result():
                live.add(f"{candidate}.{domain}")
                log(f"[+]    {candidate}.{domain}")

    log(f"[*] {len(live)} subdomain(s) resolved")
    return live


def load_wordlist(path):
    with open(path, "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def main():
    parser = argparse.ArgumentParser(description="Subdomain enumeration helper")
    parser.add_argument("--domain", required=True, help="Target root domain")
    parser.add_argument("--wordlist", help="Custom wordlist (one per line)")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    parser.add_argument("--skip-ct", action="store_true", help="Skip crt.sh source")
    parser.add_argument("--output", help="Write results to this file")
    args = parser.parse_args()

    domain = args.domain.strip().lower().lstrip(".")
    log(f"[*] Enumerating subdomains for {domain}")

    results = set()

    if not args.skip_ct:
        log("[*] Source: crt.sh certificate transparency")
        results |= crtsh_subdomains(domain)
    else:
        log("[*] Skipping crt.sh (--skip-ct)")

    wordlist = load_wordlist(args.wordlist) if args.wordlist else DEFAULT_SUBDOMAINS
    source = args.wordlist if args.wordlist else "built-in list"
    log(f"[*] Source: {source}")
    results |= brute_subdomains(domain, wordlist, args.threads)

    # Filter anything that escaped the target domain
    results = sorted(r for r in results if r.endswith(domain) and r != domain)

    log(f"\n[*] {len(results)} unique subdomain(s) found for {domain}")
    for r in results:
        print(f"    {r}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write("\n".join(results) + "\n")
        log(f"[*] Results written to {args.output}")

    return 0 if results else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("\n[!] Interrupted")
        sys.exit(130)
