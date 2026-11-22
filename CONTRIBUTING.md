# Contributing

Thanks for helping! Bug reports, captured frames and pull requests are all welcome.

## Development setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check .
pytest
```

## Guidelines

- Keep the core free of required dependencies. Optional features go behind extras.
- Every protocol change needs a test with a frame (build it with `build_message()`
  or paste a real capture).
- **Never commit real data.** When sharing captures from real panels, replace the
  account number, IP addresses, site names and keys with fictitious values. Use
  documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and
  `example.com`.
- The ACK path must stay fast: no I/O before the response is sent.
- New event codes: add them to `codes.py` with category and both English and
  Spanish descriptions. Other translations are welcome as a new column.

## Reporting panel compatibility

Open an issue with: panel/communicator model and firmware, protocol (ADM-CID or
SIA-DCS), transport (TCP/UDP), encryption on/off, and an anonymized frame from
`dc09-receiver parse`. A "works with" list in the README is built from these reports.

## Commits and DCO

Small, focused commits with a clear message. By contributing you agree that your
contribution is licensed under the Apache License 2.0.
