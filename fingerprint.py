#!/usr/bin/env python3
"""
fingerprint.py - Identify services running on open ports.

Passive only: connects to host:port, reads a banner if one is offered,
and classifies the result against a signature table. No exploit payloads
are sent and no vulnerability probing is performed.

Usage:
    python fingerprint.py --host scanme.nmap.org
    python fingerprint.py --host scanme.nmap.org --ports 22,80,443
    python fingerprint.py --hosts live_hosts.txt --ports 22,80,443

Legal:
    Only connect to systems you own or have explicit written permission to test.
"""

import argparse
import concurrent.futures
import re
import socket
import ssl
import sys
from urllib.parse import urlsplit

DEFAULT_PORTS = "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,6379,8080,8443,27017"
DEFAULT_TIMEOUT = 3.0
DEFAULT_THREADS = 50

# (name, regex, ports to check on that port)
SIGNATURES = [
    ("OpenSSH",          r"^SSH-2\.0-OpenSSH",                       [22]),
    ("Dropbear SSH",     r"^SSH-2\.0-dropbear",                      [22]),
    ("ProFTPD",          r"^220.*ProFTPD",                           [21]),
    ("vsftpd",           r"^220.*vsftpd",                            [21]),
    ("Microsoft IIS",    r"^IIS/\d",                                 [80, 8080]),
    ("Apache",           r"^Apache/[\d.]+",                          [80, 8080]),
    ("nginx",            r"^nginx/[\d.]+",                           [80, 8080]),
    ("lighttpd",         r"^lighttpd/[\d.]+",                        [80, 8080]),
    ("Microsoft SMTP",   r"^220 .*Microsoft SMTP",                   [25]),
    ("Postfix",          r"^220 .*Postfix",                          [25]),
    ("Exim",             r"^220 .*Exim",                             [25]),
    ("MySQL",            r"^\x00\x00\x00\x0a.*",                     [3306]),
    ("PostgreSQL",       r"^E\x00\x00.{8}",                          [5432]),
    ("RDP",              r"^\x03\x00\x00",                           [3389]),
    ("MongoDB",          r"^\x3a\x00\x00\x00",                       [27017]),
    ("Redis",            r"^-ERR (unknown command|invalid password)", [6379]),
    ("Elasticsearch",    r"^\x00\x0c",                               [9200]),
    ("Jetty",            r"^Jetty\(",                                 [8080, 8443]),
    ("Tomcat",           r"HTTP/[\d.]+ Server: Apache-Coyote",       [8080]),
    ("Python http.server", r"^SimpleHTTP/",                          [8000, 8080]),
]

TLS_PORTS = {443, 8443, 9443}


def grab_banner(host, port, timeout):
    """Connect and read a banner. Returns (banner, is_tls)."""
    is_tls = port in TLS_PORTS
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None, False

    try:
        if is_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        # TLS servers usually only greet after a request
        if is_tls:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
        else:
            sock.settimeout(timeout)
            try:
                sock.sendall(b"\r\n")
            except OSError:
                pass
        data = sock.recv(1024)
        return data, is_tls
    except (socket.timeout, ssl.SSLError, OSError):
        return None, is_tls
    finally:
        try:
            sock.close()
        except OSError:
            pass


def identify(host, port, timeout):
    """Fingerprint a single host:port. Returns a result string or None."""
    banner, is_tls = grab_banner(host, port, timeout)
    if banner is None:
        return None

    header = banner.decode("utf-8", errors="replace").strip()
    # Some services lead with binary; require most of the banner to be
    # printable before we echo it, otherwise show a hex prefix instead
    sample = header[:64]
    ratio = (sum(c.isprintable() or c in "\r\n\t" for c in sample) / len(sample)) if sample else 0

    hits = []
    for name, pattern, ports in SIGNATURES:
        if ports and port not in ports:
            continue
        try:
            if re.search(pattern, header, re.IGNORECASE | re.DOTALL):
                hits.append(name)
        except re.error:
            continue

    label = ", ".join(hits) if hits else "unknown"
    scheme = "https" if is_tls else "http" if port in (80, 443, 8080, 8443) else "tcp"
    preview = header[:80].replace("\n", " ") if ratio >= 0.7 else "0x" + banner[:16].hex()

    return {
        "host": host,
        "port": port,
        "scheme": scheme,
        "service": label,
        "banner": preview,
    }


def parse_ports(spec):
    """Parse '22,80,443' or '1-1024' or a mix of both."""
    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(chunk))
    return sorted(p for p in ports if 0 < p < 65536)


def main():
    ap = argparse.ArgumentParser(description="Passive service fingerprinter")
    ap.add_argument("--host", help="Single host")
    ap.add_argument("--hosts", help="File with one host per line")
    ap.add_argument("--ports", default=DEFAULT_PORTS, help="Port list or range")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    ap.add_argument("--output", help="Write results to this file")
    args = ap.parse_args()

    hosts = []
    if args.host:
        hosts.append(args.host.strip())
    if args.hosts:
        with open(args.hosts, "r", encoding="utf-8") as fh:
            hosts += [l.strip() for l in fh if l.strip()]
    if not hosts:
        ap.error("provide --host or --hosts")

    ports = parse_ports(args.ports)
    targets = [(h, p) for h in hosts for p in ports]

    print(f"[*] Fingerprinting {len(targets)} target(s) with {args.threads} threads", flush=True)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(identify, h, p, args.timeout): (h, p) for h, p in targets}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                results.append(res)
                print(f"[+] {res['host']}:{res['port']}  {res['service']}  |  {res['banner']}", flush=True)

    print(f"\n[*] {len(results)} service(s) identified")

    if args.output and results:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write("host,port,scheme,service,banner\n")
            for r in sorted(results, key=lambda x: (x["host"], x["port"])):
                banner = r["banner"].replace(",", ";")
                fh.write(f"{r['host']},{r['port']},{r['scheme']},\"{r['service']}\",\"{banner}\"\n")
        print(f"[*] Results written to {args.output}")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted", flush=True)
        sys.exit(130)
