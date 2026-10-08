<div align="center">

# 🕵️ recon-toolkit

Lightweight, dependency-free Python reconnaissance toolkit.

<img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/Deps-Zero-6D28D9?style=for-the-badge"/>
<img src="https://img.shields.io/badge/License-MIT-18181B?style=for-the-badge"/>

</div>

## Features
- Concurrent TCP connect scan (`--threads`)
- Port ranges or lists (`--ports 22,80,443` / `--ports 1-1024`)
- Basic banner grabbing & service hints
- No third-party dependencies

## Usage
```bash
python scanner.py --host scanme.nmap.org --ports 1-1024 --threads 200 --timeout 1.5
```

Output:
```
[*] Scanning scanme.nmap.org — 1024 ports, 200 threads
[+]    22/tcp  SSH-2.0-OpenSSH_6.6.1p1
[+]    80/tcp  HTTP
[*] Done. 2 open port(s).
```

## ⚠️ Legal
Only scan systems you own or have explicit written permission to test.

## Author
[@bhuvanchandt](https://github.com/bhuvanchandt)
