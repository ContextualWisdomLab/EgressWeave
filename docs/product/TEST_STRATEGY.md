# EgressWeave Test Strategy

Status: Proposed documentation baseline for the protected-main quality contract.

## 1. Objective

Testing must prove security behavior, numerical/resource bounds, packaging integrity, and public contracts—not merely exercise lines. New acceptance or rejection behavior is developed test-first and verified on the exact candidate head.

## 2. Mandatory quality gates

- Owned production statement coverage: exactly 100%.
- Owned production branch coverage: exactly 100%.
- Shipped module/class/function/method/property docstrings: 100% under repository checks.
- Ruff and `compileall` clean on supported Python versions.
- Wheel and source distribution build and archive validation.
- Installed-wheel smoke test outside the source tree.
- Exact-head CI source identity checks.
- Applicable SAST, dependency/supply-chain, secret, CodeQL, scorecard, and repository-required checks.

A skipped required check, predecessor-head run, synthetic-merge-only result, or fail-open wrapper does not satisfy this strategy.

## 3. Test-first security workflow

For a security boundary change:

1. Reproduce the defect on the exact current head.
2. Add the smallest deterministic regression that fails for the intended behavioral reason.
3. Preserve the RED commit/run as evidence when feasible.
4. Make the narrowest production repair.
5. Run the focused regression.
6. Run the full suite and exact coverage gates.
7. Re-run applicable hosted security/package checks on the final head.
8. Resolve only the review threads actually addressed by that exact tree.

## 4. Test families

### URL and policy construction

Cover malformed schemes, authorities, credentials, fragments, IDNA/Unicode edge cases, port/method configuration, local-address policy, ambiguous host/port construction, and fail-fast finite resource settings.

### DNS and validated state

Cover multiple A/AAAA candidates, duplicates, mixed allowed/denied addresses, empty answers, resolver errors/timeouts, candidate-count limits, policy drift, integrity/state mutation, and exact authority revalidation.

### Transport and TLS

Cover pinned address connection, preserved hostname/SNI, TLS trust/client identity, proxy/Unix-socket/target rejection, synchronous/asynchronous parity, connection staggering, deadlines, loser cleanup, terminal all-candidate failures, and caller cancellation.

### HTTP request boundaries

Cover method grammar, raw header grammar, forbidden connection/proxy fields, `Host` rewriting, target size, header field/byte budgets, body framing, dishonest `Content-Length`, streaming body limits, hostile iterators, cleanup failure, and exactly-once consumption.

### HTTP response boundaries

Cover response header field/byte budgets, `Content-Length`, bodyless semantics, content coding, exact-byte stream accounting, subclasses/non-bytes, over-budget delivery prevention, hostile cleanup, and outer cancellation.

### Decision evidence

Cover determinism, normalized authority, bounded counters, no resolved-IP/path/body leakage, current-policy revalidation, and schema compatibility when a versioned schema becomes protected-main behavior.

### Packaging and release evidence

Cover archive composition, metadata, license/type marker, deterministic checksums, unsafe archive/member/path forms, evidence-set completeness, source identity, immutable file/path boundaries, and release rollback/verification contracts where implemented.

## 5. Property and adversarial testing

Use generated inputs where they add more assurance than enumerated examples:

- Unicode/IDNA host strings and malformed labels;
- IP classifications and mapped forms;
- HTTP token/field/framing grammar;
- streaming chunk boundaries and declared/observed byte totals;
- policy normalization idempotence;
- timeout/pool finite-value normalization;
- filesystem names and archive metadata for release evidence.

Fuzz/property failures must be minimized into deterministic regressions before a security fix is considered complete.

## 6. Concurrency testing

Asynchronous tests must avoid wall-clock flakiness where a fake clock, event barrier, deterministic backend, or controlled future can prove ordering. Explicitly test:

- no candidate launch after a deadline;
- first valid success semantics;
- cancellation of pending losers;
- cleanup of completed losing streams;
- child self-cancellation versus outer coordinator cancellation;
- no stale child exception provenance after terminal denial.

## 7. Realistic integration tests

Public builders should be exercised through representative HTTPX request/response flows with dependency-injected resolvers/backends rather than public Internet dependencies. Tests must remain deterministic and offline while still crossing real package boundaries.

Integration-specific examples should include naruon-style configuration translation and verify that the adapter does not create a second security implementation.

## 8. Regression evidence quality

A passing test added after a production fix is weaker than a demonstrated RED→GREEN sequence. Review descriptions should identify the exact RED head/run and final GREEN head/run for material security changes. The repository must not rewrite source during CI merely to manufacture acceptance.

## 9. Documentation tests

Normative product documentation is testable product surface. Repository tests should check:

- canonical PRD/TRD/API/test/operability/compliance/architecture/ADR/doctoring files exist;
- implementation and target maturity are not conflated;
- Mermaid/code-fence and cross-link integrity;
- no database ownership is invented for the core library;
- security-model statements match current resource controls;
- ADR index/status consistency;
- stale internal/product names are not reintroduced.

## 10. Release acceptance

Release tests run against the exact integrated protected source. Acceptance requires all required repository checks and independent review, package reconstruction/verification, current version/CHANGELOG binding, provenance/SBOM requirements that are actually claimed, and post-publication artifact verification. See [`OPERABILITY.md`](OPERABILITY.md) and [`../doctoring/REFERENCES.md`](../doctoring/REFERENCES.md).
