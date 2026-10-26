# Security Policy

## Supported Versions

Only the latest release and the `main` branch are supported.

| Version | Supported |
|---|---|
| `v1.0.0` (latest release) | ✅ |
| `main` (unreleased) | ✅ |
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

## Scope of this toolkit

`recon-toolkit` performs **passive discovery only** — TCP connect scans,
certificate transparency lookups, DNS resolution, and banner fingerprinting.
It does not exploit, brute-force, or fuzz.

If you are testing a third-party system, do so only with explicit written
authorization and within any program-defined scope.
