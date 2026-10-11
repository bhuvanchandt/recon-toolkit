# Contributing to recon-toolkit

Thanks for taking the time to contribute.

## Ground rules

1. **No third-party dependencies.** The whole point of this toolkit is that
   `git clone` + `python3 script.py` is the entire install. A PR that adds a
   dependency to `requirements.txt` will be declined unless it's clearly
   optional and lazily imported.
2. **Passive by default.** These tools discover and identify. They do not
   exploit, brute-force, or fuzz. New signatures may send a protocol-appropriate
   greeting but never a vulnerability probe.
3. **Python 3.8+ compatibility.** No `match`, no `|` type unions in runtime
   positions, no 3.9+ only stdlib.

## Development

```bash
git clone https://github.com/bhuvanchandt/recon-toolkit.git
cd recon-toolkit
pip install ruff
python -m unittest discover -s . -v
ruff check --select=E,F,W --line-length=120 .
```

Before opening a pull request:

- [ ] `ruff check` passes
- [ ] `ruff format --check --line-length=120 .` passes
- [ ] `python -m unittest discover -s .` passes
- [ ] New behaviour has a unit test
- [ ] `--help` output is updated if you added or changed a flag
- [ ] README documents any new flag

## Testing against a live host

Use `scanme.nmap.org`. It is provided by the Nmap project for exactly this
purpose. Do not point these tools at targets you do not own or have written
permission to test.

## Reporting a vulnerability

If you find a security issue in this toolkit, please report it privately first —
see [SECURITY.md](SECURITY.md). Do not open a public issue for a live
vulnerability.

## Reporting a bug

Open an issue with:

- what you ran
- what you expected
- what happened
- your Python version (`python3 --version`)
