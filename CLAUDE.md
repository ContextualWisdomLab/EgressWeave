# CLAUDE.md — EgressWeave

This file is a compatibility entrypoint for Claude-based development tools.
`AGENTS.md` is the authoritative agent operating contract, and
`ARCHITECTURE.md` is the authoritative architecture and integration contract.
Read both before editing code.

## Non-negotiable rules

- EgressWeave is a security library. Never weaken a policy, validation,
  transport, TLS, framing, resource, integrity, or cleanup boundary to make a
  test pass.
- Use test-first ordering for every behavior change and record the observed
  failing contract before production implementation.
- Preserve provider-neutral dependency injection and standalone operation.
  naruon-specific settings, tenants, credentials, logging, and provider models
  belong in adapters outside the package.
- Runtime policy decisions must use complete normalized identities. Do not
  reconstruct authority from separate hostname and port projections.
- Keep runtime denial errors generic and free of attacker-controlled causes,
  contexts, paths, addresses, credentials, or response data.
- Maintain 100% production statement and branch coverage and useful docstrings
  on every shipped module, class, function, and method.
- Keep synchronous and asynchronous security behavior in parity.
- Update `CHANGELOG.md`, relevant APA 7th research documentation, the security
  model, and architecture documentation whenever a boundary changes.
- Do not use `COPILOT_GITHUB_TOKEN` for autonomous product development. The
  product-development workflow uses pinned OpenCode with
  `NVIDIA_NIM_API_KEY`; the existing organization-owned review-agent identity
  and inherited secret contract must not be repurposed.
- Do not treat queued, pending, cancelled, stale-head, or previous-head checks as
  successful evidence.

## Verification

```bash
python -m pip install --require-hashes -r requirements-ci.txt
ruff check .
coverage run -m pytest -q
coverage report -m
python scripts/ci/hourly_product_guard.py self-test
python -m compileall -q src tests scripts
```

Before proposing a release, also run package acceptance and verify exact version,
CHANGELOG date, immutable tag, checksums, provenance, and Trusted Publishing
configuration.
