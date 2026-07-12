# AGENTS.md — egressweave

Operating guide for automated agents working on this repository.

`egressweave` is a **security library**. Its entire value is that outbound
requests cannot reach unintended hosts. Treat every change to `validation.py`
and `transport.py` as security-sensitive, and never weaken a check to make a
test pass.

## Invariants that must not regress

1. **Fail closed.** Any parse error, resolution failure, or ambiguous state
   raises `EgressNotAllowedError`. Never return a client or URL on doubtful
   input.
2. **Validate every resolved address**, not just the first. A hostname that
   resolves to one public and one private address must be rejected.
3. **Reject non-global addresses**: private, loopback, link-local, reserved,
   multicast, unspecified, and `not is_global`. The `allow_local` escape hatch
   only widens this for loopback and allowlisted single-label hosts.
4. **Pin and re-validate on connect.** The transport re-checks each address
   immediately before connecting and refuses any host/port that differs from the
   validated one. Do not remove or "optimize away" that re-validation.
5. **No redirects, no environment proxies, no Unix sockets, no embedded
   credentials, no query/fragment, no plaintext `http` to remote hosts.**
6. **Error messages stay generic** — never leak which rule rejected a target or
   which internal host was probed.

## Maintenance notes

- The transport depends on `httpx._config`, `httpx._transports.default`, and
  `httpcore._backends.auto` — private APIs. `httpx`/`httpcore` are version-pinned
  in `pyproject.toml`; when bumping them, run the suite and confirm those symbols
  still exist and behave the same.
- TDD: add a failing test for any new rejection/acceptance rule before the code.
- This package is extracted from naruon; port security fixes in both directions.

## Verify

```bash
pip install -e ".[test]" ruff
ruff check .
pytest -q
```
