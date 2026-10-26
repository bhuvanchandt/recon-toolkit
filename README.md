<div align="center">

# 🕵️ recon-toolkit

**Lightweight, dependency-free reconnaissance tooling built with only the Python standard library.**

[![CI](https://github.com/bhuvanchandt/recon-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/bhuvanchandt/recon-toolkit/actions/workflows/ci.yml)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/bhuvanchandt/recon-toolkit?color=6D28D9&label=release&style=flat-square)](https://github.com/bhuvanchandt/recon-toolkit/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-6D28D9.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-4F46E5?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-0-16a34a?style=flat-square)](#requirements)
[![Author](https://img.shields.io/badge/author-%40bhuvanchandt-7C3AED?style=flat-square&logo=github)](https://github.com/bhuvanchandt)
[![Changelog](https://img.shields.io/badge/changes-CHANGELOG.md-7C3AED?style=flat-square)](CHANGELOG.md)

</div>

---

## Overview

Most recon tooling is a dependency treadmill. This is a small, readable set of
scripts that do the three things you actually do at the start of an engagement:
find open ports, find subdomains, and work out what's running.

**No third-party packages. No `pip install`. Python 3.8+ and done.**

---

## Tools

| Script | Purpose |
|---|---|
| `scanner.py` | Concurrent TCP connect scan |
| `subdomain_enum.py` | Subdomain enumeration (crt.sh CT logs + DNS wordlist resolution) |
| `fingerprint.py` | Passive service fingerprinting from service banners |

---

## Install

```bash
git clone https://github.com/bhuvanchandt/recon-toolkit.git
cd recon-toolkit
```

Nothing to install. Optionally:

```bash
pip install -r requirements.txt
```

---

## Usage

### `scanner.py` — port scanning

```bash
python scanner.py --host scanme.nmap.org --ports 1-1024 --threads 200 --timeout 1.5
```

```
[*] Scanning scanme.nmap.org — 1024 ports, 200 threads
[+]    22/tcp  SSH-2.0-OpenSSH_6.6.1p1
[+]    80/tcp  HTTP
[*] Done. 2 open port(s).
```

### `subdomain_enum.py` — subdomain enumeration

```bash
# CT logs + built-in wordlist
python subdomain_enum.py --domain example.com

# Custom wordlist, save results
python subdomain_enum.py --domain example.com \
    --wordlist wordlist.txt \
    --threads 100 \
    --output found.txt
```

```
[*] Enumerating subdomains for example.com
[*] Source: crt.sh certificate transparency
[*] crt.sh returned 412 unique subdomain(s)
[*] Source: built-in list
[*] Resolving 96 candidate(s) with 50 threads
[+]    dev.example.com
[+]    api.example.com
[+]    staging.example.com
[*] 415 subdomain(s) found for example.com
```

### `fingerprint.py` — service identification

```bash
python fingerprint.py --host scanme.nmap.org --ports 22,80,443
```

```
[*] Fingerprinting 3 target(s) with 50 threads
[+] scanme.nmap.org:22  OpenSSH  |  SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
[+] scanme.nmap.org:80  nginx   |  HTTP/1.1 200 OK Server: nginx/1.18.0
[*] 2 service(s) identified
```

Fingerprinting works from a scan output too:

```bash
python scanner.py --host scanme.nmap.org --ports 1-1024 --output open.txt
python fingerprint.py --hosts open.txt --output services.csv
```

---

## Typical workflow

```bash
# 1. find live hosts
python subdomain_enum.py --domain target.com --output subs.txt

# 2. find open ports
python scanner.py --hosts subs.txt --ports 1-10000 --threads 300 --output open.txt

# 3. identify what's running
python fingerprint.py --hosts open.txt --output services.csv
```

---

## Options

### Common

| Flag | Description | Default |
|---|---|---|
| `--threads` | Concurrent workers | 50 |
| `--timeout` | Per-connection timeout (seconds) | varies |

### `scanner.py`

| Flag | Description |
|---|---||
| `--host` | Target host or IP |
| `--ports` | Port list/range (`22,80,443` or `1-1024`) |
| `--threads` | Concurrent workers |
| `--timeout` | Connect timeout |
| `--output` | Write open ports to file |

### `subdomain_enum.py`

| Flag | Description | Default |
|---|---|---|
| `--domain` | Root domain to enumerate | required |
| `--wordlist` | Custom wordlist file | built-in list |
| `--threads` | Concurrent DNS workers | 50 |
| `--skip-ct` | Skip the crt.sh CT source | off |
| `--output` | Write results to file | — |

### `fingerprint.py`

| Flag | Description | Default |
|---|---|---|
| `--host` / `--hosts` | Single host or file of hosts | required |
| `--ports` | Port list/range | common set |
| `--timeout` | Per-connection timeout | 3.0 |
| `--threads` | Concurrent workers | 50 |
| `--output` | Write CSV of results | — |

---

## Requirements

- Python 3.8 or newer
- No third-party dependencies
- `subdomain_enum.py` needs outbound HTTPS (crt.sh) and DNS

---

## Versioning

Releases are tagged `vMAJOR.MINOR.PATCH` following [Semantic Versioning](https://semver.org/).
See the [changelog](CHANGELOG.md) for what changed in each release.

---

## Testing

```bash
python -m unittest discover -s . -v
```

The CI workflow runs lint, unit tests, and a CLI smoke test on every push and PR.

> For testing against a live target, use `scanme.nmap.org` — it is maintained by
> the Nmap project specifically for this purpose.

---

## ⚠️ Legal

**Only run these tools against systems you own or have explicit written
permission to test.**

Unauthorized port scanning and reconnaissance is illegal in many jurisdictions,
including under the Computer Fraud and Abuse Act (US), the Computer Misuse Act
(UK), and equivalent legislation elsewhere. If you do not have permission, do
not run it.

Where a bug bounty program exists, stay inside the defined scope — including any
explicitly excluded hosts, ports, or testing techniques.

---

## Contributing

Issues and pull requests are welcome. Please keep changes dependency-free and
run the test suite before opening a PR.

---

## License

[MIT](LICENSE) © Bhuvan Chand Thangudu

---

<div align="center">
Made by [@bhuvanchandt](https://github.com/bhuvanchandt)
</div>
