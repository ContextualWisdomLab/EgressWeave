# AGENTS.md — egressweave

Operating guide for automated agents working on this repository.

`egressweave` is a **security library**. Its entire value is that outbound
requests cannot reach unintended authorities. Treat every change to
`policy.py`, `validation.py`, and either transport as security-sensitive, and
never weaken a check to make a test pass.

## Invariants that must not regress

1. **Fail closed.** Any parse error, resolution failure, or ambiguous state
   raises `EgressNotAllowedError`. Never return a client or URL on doubtful
   input.
2. **Authorize exact authorities.** Runtime policy checks complete normalized
   `(hostname, port)` pairs. Never reconstruct authorization by checking the
   `allowed_hosts` and `allowed_ports` projections independently.
3. **Validate every resolved address**, not just the first. A hostname that
   resolves to one public and one private address must be rejected.
4. **Reject non-global addresses**: private, loopback, link-local, reserved,
   multicast, unspecified, and `not is_global`. The `allow_local` escape hatch
   only widens this for explicitly allowlisted local authorities.
5. **Pin and re-validate on connect.** The transport re-checks each address
   immediately before connecting and refuses any host/port that differs from the
   validated one. Do not remove or "optimize away" that re-validation.
6. **No redirects, no environment proxies, no Unix sockets, no embedded
   credentials, no query/fragment, no plaintext `http` to remote hosts.**
7. **Bound response consumption.** Identity-coded response bodies must remain
   within the policy's finite decoded-byte budget in both sync and async clients.
8. **Error messages stay generic** — never leak which rule rejected a target or
   which internal host was probed.

## Maintenance notes

- The transport depends on `httpx._config`, `httpx._transports.default`, and
  `httpcore._backends.auto` — private APIs. `httpx`/`httpcore` are version-pinned
  in `pyproject.toml`; when bumping them, run the suite and confirm those symbols
  still exist and behave the same.
- TDD: add a failing test for any new rejection/acceptance rule before the code.
- Every shipped module, class, function, and method requires a useful docstring.
- Production statement and branch coverage must both remain 100% on every
  supported Python version; do not use blanket coverage exclusions to hide a
  reachable branch.
- This package is extracted from naruon; port security fixes in both directions.

## Verify

```bash
pip install -e ".[test]" ruff
ruff check .
coverage run -m pytest -q
coverage report -m
python scripts/ci/hourly_product_guard.py self-test
python -m compileall -q src tests scripts
```

The CI path installs `requirements-ci.txt` with `--require-hashes` and uses the
same coverage configuration from `pyproject.toml`. A local report below 100% is
a failing quality gate, not an advisory metric.

## Code-owner review gates — disabled (on hold)

As of 2026-08-04, code-owner review requirements (`require_code_owner_reviews` in branch
protection, `require_code_owner_review` in rulesets) are disabled across the ContextualWisdomLab
org: there is a single maintainer (solo developer), so a code-owner approval gate can never be
satisfied. This is ON HOLD until the org has multiple maintainers — do NOT re-enable these
settings or add CODEOWNERS-based merge gates before then.
