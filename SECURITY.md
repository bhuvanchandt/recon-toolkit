# Security Policy

## Supported Versions

Only the latest `main` branch is supported. There are no tagged releases, so
there is nothing backportable.

| Version | Supported |
|---|---|
| `main` | ✅ |
| Anything older | ❌ |

## Reporting a Vulnerability

If you find a security issue in this toolkit, **please report it privately.**
Do not open a public issue.

Report it via GitHub's private vulnerability reporting:

**https://github.com/bhuvanchandt/recon-toolkit/security/advisories/new**

Please include:

- a description of the issue and its impact
- the affected file and line, if you have it
- steps to reproduce
- your Python version

You can expect an acknowledgement within 72 hours and a fix or a reasoned
explanation within 7 days.

## Threat Model

This is a small, single-operator CLI tool. The realistic threat model is:

- **Malicious or compromised target host.** This is the main one. A hostile
  server can send arbitrarily large banners, malformed TLS, or unusual encodings.
  Mitigation in place: banner reads are capped at 1024 bytes, sockets have
  timeouts, TLS verification is disabled only for banner grabbing against
  arbitrary hosts, and every socket is closed in a `finally` block.
- **Untrusted wordlist files.** `--wordlist` files are read line by line and
  length-trimmed; no shell invocation, no format string handling.
- **Local misuse.** The tool does not enforce authorization. That is the
  operator's responsibility — see the legal notice in the README.

## Known Design Decisions

- **TLS verification is disabled** in `fingerprint.py` when grabbing banners.
  This is intentional: fingerprinting self-signed and internal services is a
  core use case, and no sensitive data is transmitted. It does mean the tool
  will identify against a host presenting an invalid certificate.
- **`scanner.py` uses TCP connect**, never SYN. It needs no raw sockets and no
  elevated privileges, which keeps it portable and unprivileged.
- **No exploitation capability.** These tools identify, they do not attack.
