# AGENTS.md — egressweave

Operating guide for automated agents working on this repository.

`egressweave` is a **security library**. Its entire value is that outbound
requests cannot reach unintended authorities. Treat every change to
`policy.py`, `validation.py`, and either transport as security-sensitive, and
never weaken a check to make a test pass.

## Canonical documentation

Read [`docs/product/PRD.md`](docs/product/PRD.md) for product requirements,
[`docs/product/TRD.md`](docs/product/TRD.md) for the technical contract, root
[`ARCHITECTURE.md`](ARCHITECTURE.md) for protected-main implementation
architecture, and [`docs/adr/README.md`](docs/adr/README.md) for durable
architecture decisions before changing product boundaries.

When a change alters a durable product, architecture, security, ownership,
compatibility, automation, persistence, or release contract, update the relevant
canonical documentation in the same reviewed change. Keep implementation
maturity explicit: active pull requests and target architecture are not shipped
protected-main behavior.

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
7. **Bound transport resources.** Connection-pool capacity, request targets,
   request metadata and bodies, request-phase waits, response metadata, and
   identity-coded response bodies must remain within finite injected policy
   limits in both synchronous and asynchronous clients.
8. **Error messages stay generic** — never leak which rule rejected a target or
   which internal host was probed.

## Maintenance notes

- The transport depends on `httpx._transports.default` and
  `httpcore._backends.auto` private APIs. Connection-pool limits are owned by
  `EgressConnectionPoolPolicy`; do not reintroduce HTTPX private
  `DEFAULT_LIMITS` coupling. `httpx`/`httpcore` are version-pinned in
  `pyproject.toml`; when bumping them, run the suite and confirm those symbols
  still exist and behave the same.
- TDD: add a failing test for any new rejection/acceptance rule before the code.
- Every shipped module, class, function, and method requires a useful docstring.
- Production statement and branch coverage must both remain 100% on every
  supported Python version; do not use blanket coverage exclusions to hide a
  reachable branch.
- This package was extracted from naruon. Evaluate security fixes for reuse in
  both directions, but do not claim the concrete naruon adapter exists until the
  separately governed integration is implemented and verified.

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

## Independent review and code-owner gates

**Independent non-author approval** is an explicit EgressWeave/CWL integration
governance requirement where the repository's current merge contract calls for
it. Automated review, COMMENTED reviews, statuses, checks, reactions, author
reviews, predecessor-head reviews, and synthetic-merge evidence do not satisfy
that requirement, and agents must never self-approve or manufacture approval.

Code-owner review requirements are a separate mechanism and are currently
disabled/on hold. As of 2026-08-04, `require_code_owner_reviews` in branch
protection and `require_code_owner_review` in rulesets are disabled across the
ContextualWisdomLab org because there is a single maintainer and a CODEOWNERS
approval gate cannot be satisfied. Do not re-enable CODEOWNERS-based merge
gates before the organization has an eligible independent maintainer. This
CODEOWNERS hold does not authorize self-approval and does not convert automated
review evidence into independent non-author approval.
