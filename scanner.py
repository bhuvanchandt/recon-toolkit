#!/usr/bin/env python3
"""recon-toolkit: lightweight concurrent TCP port scanner with basic service fingerprinting.

Usage:
    python scanner.py --host example.com --ports 1-1024 --threads 200 --timeout 1.5
"""
import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

BANNERS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Proxy",
    27017: "MongoDB",
}


def parse_ports(spec: str) -> list[int]:
    ports = set()
    for part in spec.split(","):
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def grab_banner(host: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(64).decode(errors="ignore").strip()
            except socket.timeout:
                data = ""
            return data[:40] if data else BANNERS.get(port, "open")
    except OSError:
        return ""


def scan_port(host: str, port: int, timeout: float):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            banner = grab_banner(host, port, timeout)
            return port, banner
    except OSError:
        return None


def main() -> int:
    p = argparse.ArgumentParser(description="Concurrent TCP port scanner")
    p.add_argument("--host", required=True, help="Target host or IP")
    p.add_argument("--ports", default="1-1024", help="Ports, e.g. 22,80,443 or 1-1024")
    p.add_argument("--threads", type=int, default=200)
    p.add_argument("--timeout", type=float, default=1.5)
    args = p.parse_args()

    try:
        socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"[!] Could not resolve {args.host}", file=sys.stderr)
        return 2

    ports = parse_ports(args.ports)
    print(f"[*] Scanning {args.host} — {len(ports)} ports, {args.threads} threads")
    found = []
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(scan_port, args.host, port, args.timeout): port for port in ports}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                found.append(res)
                print(f"[+] {res[0]:>5}/tcp  {res[1]}")
    print(f"[*] Done. {len(found)} open port(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
