# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- *(none yet)*

### Changed

- *(none)*

### Fixed

- *(none)*

## [1.0.0] - 2026-10-26

### Added

- **`scanner.py`** — concurrent TCP connect port scanner with banner grabbing,
  threading, and file output. Supports host lists, port ranges, and `--output`.
- **`subdomain_enum.py`** — subdomain enumeration sourcing `crt.sh` certificate
  transparency logs and a built-in DNS wordlist, with optional custom wordlists
  and threaded resolution.
- **`fingerprint.py`** — passive service fingerprinting from live banners and
  from scan output. Writes CSV results.
- **CI workflow** (`.github/workflows/ci.yml`) running lint, unit tests, and a
  CLI smoke test on push and pull request.
- **Unit tests** in `tests/` covering port parsing, target parsing, and CLI
  smoke checks (`scanner.py --help`, `subdomain_enum.py --help`,
  `fingerprint.py --help`).
- **Documentation** — README with quick-start usage, workflow, options tables,
  legal notice, and contributing guidance.
- **Templates** — `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`,
  issue templates, and Dependabot config.

### Notes

- Zero third-party dependencies — standard library only.
- Python 3.8+ compatible.

## Release process

1. Bump the version reference in `README.md` (the version badge / release line).
2. Update `CHANGELOG.md` `[Unreleased]` → new version under a `## [x.y.z]` heading.
3. Tag: `git tag -a vx.y.z -m "Release x.y.z" && git push --tags`.
4. Draft the release on GitHub from the tag.

[Unreleased]: https://github.com/bhuvanchandt/recon-toolkit/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/bhuvanchandt/recon-toolkit/releases/tag/v1.0.0
