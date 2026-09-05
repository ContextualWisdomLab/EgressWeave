# ADR 0005: CWL `.github` CI trust-boundary consumer integration

- **Status:** Accepted
- **Date:** 2026-09-02
- **Decision owners:** ContextualWisdomLab maintainers

## Context

The owner directed that ad-hoc, repo-local communication-security handling
scattered across ContextualWisdomLab product repositories be migrated to route
through `EgressWeave` (this package) and `wardnet` instead. A concrete,
verified instance of such ad-hoc handling is
`ContextualWisdomLab/.github`'s `scripts/ci/pingora_edge_policy.py`
(`_github_open_json`, `NoRedirectHandler`, `_validate_github_api_url`,
`MAX_RESPONSE_BYTES`): a hand-rolled `urllib.request`-based GitHub REST client
that independently reimplements a subset of what this package already does —
origin pinning to `api.github.com`, redirect rejection, and a bounded response
read (16 MiB, identical to this package's `DEFAULT_MAX_RESPONSE_BYTES`). That
script is invoked from a `pull_request_target`-triggered required workflow
(`.github/workflows/opencode-review.yml`, "Enforce Cloudflare Pingora edge
policy" step) that enforces the org-wide Pingora-only edge runtime policy
(`docs/adr/0019-cloudflare-pingora-edge-standard.md` in that repo) — i.e. a
security gate, not an ordinary application.

Two facts materially shape how that migration can happen:

1. **PyPI/source parity gap.** The package published on PyPI as `egressweave`
   0.1.0 ships only `policy.py`, `transport.py` (async client), and
   `validation.py`. It has no `sync_transport.py`, no
   `EgressTimeoutPolicy`/`TLSConfiguration`, no request/response body-size
   bounding, and no port/method allowlisting. Protected `main`'s current
   source (`__version__ = "0.3.0"`) has all of the above, including the exact
   16 MiB `max_response_bytes` default `pingora_edge_policy.py` needs to match
   or exceed its own `MAX_RESPONSE_BYTES` bound without regression. A consumer
   that needs the synchronous client and body-size bounding — as
   `pingora_edge_policy.py` does — cannot get it from the current PyPI
   release.
2. **Zero-third-party-dependency CI scripts.** Every script under
   `.github`'s `scripts/ci/` that makes an outbound HTTP call
   (`pingora_edge_policy.py`, `noema_review_gate.py`,
   `materialize_base_python_requirements.py`,
   `reconcile_repository_metadata.py`, `sandboxed_web_e2e.py`) uses only
   `urllib.request` from the standard library today; none of that repo's
   `scripts/ci/` currently imports `httpx` or `requests`. `.github`'s own
   CI-dependency discipline additionally requires every installed tool come
   from `pip install --require-hashes` against a `uv pip compile
   --generate-hashes`-produced lock file resolved from an index — a
   VCS-sourced or otherwise unpinnable-by-hash requirement cannot satisfy that
   discipline.

Given both constraints, and given this ADR's own package is pre-1.0 and
explicitly gates trust on verified PyPI publication (see this repository's
README, "Publication status"), cutting a new PyPI release from this
migration side effort — an irreversible public action outside a single
migration PR's scope — is not the right first step. `wardnet` (a Rust
gateway/SOC control plane) is not applicable here: `pingora_edge_policy.py` is
a Python script and the mechanism it reimplements is outbound-HTTP-client
SSRF/redirect safety, not inbound gateway/WAF/IDS scoring, which is what
`wardnet` actually provides today (verified by reading its README and
`crates/waf-ids-core`).

## Decision

CWL consumer repositories whose CI dependency discipline requires
hash-pinnable, index-resolved packages, and whose required capability
(synchronous client, body-size bounding, timeout policy, TLS configuration)
is present in this package's protected-`main` source but not yet in the
published PyPI release, integrate this package by vendoring an exact-commit
pin of protected `main` as a git submodule, the same pinning discipline this
organization already uses for CI-time consumption of other pre-release CWL
packages (e.g. `ORCHESTRATOR_PIN_SHA` in
`contextual-orchestrator/scripts/ci/contextual_orchestrator_review_sidecar.sh`),
rather than either (a) waiting on an unrelated PyPI release before any
migration can start, or (b) reimplementing this package's security logic a
second time against the older PyPI surface.

A consumer following this pattern:

1. Adds this repository as a submodule pinned to an exact, reviewed commit
   SHA (never a branch or tag ref, which can move).
2. Adds this package's own runtime dependencies (`httpx==0.28.1`,
   `httpcore==1.0.9`, `idna>=3.18,<4` per `pyproject.toml`) to its own
   hash-pinned requirements for the narrow job that needs them — these are
   ordinary, independently-published PyPI packages, so this step does not
   inherit this package's own publication gap.
3. Writes a small adapter in the consumer repository that constructs an
   `EgressPolicy` for its exact destination authority and calls
   `build_egress_sync_client`/`build_egress_http_client`; the adapter owns no
   security logic of its own beyond constructing the policy value and mapping
   this package's `EgressNotAllowedError` to the consumer's own error type.
4. Lands the vendored submodule and adapter as an additive change that does
   not yet alter the consuming script's live default behavior, so the
   existing working control stays in place until the new path's own tests
   (and, for a required-workflow consumer, that consumer's own CI) confirm it
   is a verified equivalent-or-stronger replacement. The cutover — flipping
   the consumer's default and deleting the superseded ad-hoc implementation —
   is a separate, follow-up change once that evidence exists.

This ADR records that pattern as the accepted integration path for the
`pingora_edge_policy.py` migration and any future CWL CI-trust-boundary
consumer with the same PyPI-parity gap. It does not itself change this
package's public API, security invariants, or release process.

## Alternatives considered

### Wait for a PyPI release that includes the sync transport

Blocks every trust-boundary consumer on this package's own, separately
governed release cadence, and could pressure a premature release to unblock
an unrelated migration. Rejected: release timing stays owned by this
package's own evidence-bound delivery process (ADR 0001 §5), not by consumer
migration schedules.

### Have the consumer `pip install` a VCS ref (`git+https://...@<sha>`)

`pip install --require-hashes` rejects VCS requirements outright, so this
would force the consumer to drop hash-pinning for this one dependency —
weakening, not following, that repository's own documented CI-dependency
discipline. Rejected.

### Reimplement the missing sync/body-bounding behavior directly in the consumer, without depending on this package at all

This is the status quo the owner directed away from: it duplicates
security-relevant logic instead of centralizing it, and a fix to one copy
would not propagate to the other. Rejected.

## Consequences

### Positive

- Trust-boundary consumers with a hash-pin-only CI discipline can adopt this
  package's full protected-`main` security surface (sync client,
  timeout/body bounding, TLS configuration) without waiting on a PyPI
  release.
- The submodule pin is an explicit, reviewable line in every consumer PR
  diff, unlike a runtime `git clone` step.
- The pattern mirrors an already-accepted organization precedent
  (`ORCHESTRATOR_PIN_SHA`), so it does not introduce a new class of
  supply-chain risk to this organization's CI.

### Costs

- A vendoring consumer must remember to bump its submodule pin (and re-review
  the diff) to receive this package's security fixes; it does not get them
  automatically the way a version-range PyPI dependency would.
- Consumers now carry two viable integration paths (PyPI package vs. pinned
  submodule) until this package's PyPI release reaches parity with protected
  `main`, which this ADR must be revisited to retire once that happens.

## Validation

This ADR is supported by:

- direct inspection of `ContextualWisdomLab/.github`'s
  `scripts/ci/pingora_edge_policy.py` (`_github_open_json`,
  `NoRedirectHandler`, `_validate_github_api_url`, `MAX_RESPONSE_BYTES =
  16_777_216`) and its invoking workflow
  (`.github/workflows/opencode-review.yml`);
- direct inspection of the published `egressweave` 0.1.0 wheel on PyPI
  (`egressweave-0.1.0-py3-none-any.whl`), confirming the missing
  `sync_transport`/`timeout_policy`/`tls`/body-bounding modules;
- direct inspection of `ContextualWisdomLab/.github`'s hash-pinned
  `requirements-*-ci.txt` / `requirements-*-ci-hashes.txt` files and CLAUDE.md
  "Hash-pinned requirements discipline" section;
- the existing `ORCHESTRATOR_PIN_SHA` vendoring precedent in
  `ContextualWisdomLab/contextual-orchestrator`'s
  `scripts/ci/contextual_orchestrator_review_sidecar.sh`, referenced from
  `ContextualWisdomLab/.github`'s own CLAUDE.md; and
- `AGENTS.md`'s existing instruction to evaluate security fixes for
  bidirectional reuse with naruon, extended here to CI consumers generally.

## References

Fielding, R. T., Nottingham, M., & Reschke, J. (2022). *HTTP semantics*
(RFC 9110). RFC Editor. https://doi.org/10.17487/RFC9110

OWASP Foundation. (n.d.). *Server side request forgery prevention cheat
sheet*. OWASP Cheat Sheet Series. Retrieved September 2, 2026, from
https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

Python Packaging Authority. (n.d.). *Hash-checking mode*. pip documentation.
Retrieved September 2, 2026, from
https://pip.pypa.io/en/stable/topics/secure-installs/
