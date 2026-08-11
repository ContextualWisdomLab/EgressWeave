# EgressWeave Product and Engineering Traceability

Status: **Proposed documentation baseline**. Protected-main code, tests and root [`ARCHITECTURE.md`](../../ARCHITECTURE.md) remain implementation truth.

This document maps durable product requirements to implementation and verification evidence so a buyer, maintainer or reviewer does not have to reconstruct the product contract from chat history or pull-request bodies. It deliberately avoids embedding mutable pull-request numbers or current branch SHAs as timeless architecture.

## 1. Evidence rules

- `IMPLEMENTED-ON-PROTECTED-MAIN` means the cited production path and representative verification exist on the current protected branch.
- `ACTIVE-PR` means the capability may be implemented on an unmerged branch and is not shipped.
- `PROPOSED-GOVERNANCE` means a durable repository-governance decision is under review and does not imply the corresponding workflow behavior is already shipped on protected main.
- Review, CI, SAST, security and release acceptance must describe the exact current head; predecessor evidence does not transfer after a source/head/base change.
- A green aggregate workflow is evidence only for the steps that actually executed.
- Documentation and tests do not promote a target design to protected-main implementation.
- Host-owned adapters, tenant systems, durable databases and infrastructure controls remain outside the EgressWeave package unless a future Accepted ADR changes ownership.

## 2. Requirement traceability

| Requirement | Implementation evidence | Test evidence | ADR / standard | Maturity |
|---|---|---|---|---|
| PRD-FR-001 Policy construction | `src/egressweave/policy.py` | policy construction, authority-pair, port/method, timeout/pool and resource-policy regression suites | ADR 0001; RFC 9110; OWASP SSRF Prevention | IMPLEMENTED-ON-PROTECTED-MAIN |
| PRD-FR-002 URL validation | `src/egressweave/validation.py` | URL/hostname/authority/local-development and validation regressions | ADR 0001; RFC 9110; OWASP SSRF Prevention | IMPLEMENTED-ON-PROTECTED-MAIN |
| PRD-FR-003 Address validation | `src/egressweave/validation.py` | DNS timeout, candidate-bound, address-class and rebinding/TOCTOU regressions | ADR 0001; CWE-918; CWE-350 | IMPLEMENTED-ON-PROTECTED-MAIN |
| PRD-FR-004 Pinned connection behavior | `src/egressweave/transport.py`, `src/egressweave/sync_transport.py` | `tests/test_transport.py`, `tests/test_sync_transport.py`, async staggering and address-revalidation regressions | ADR 0001; RFC 9110; RFC 8305 where connection staggering is relevant | IMPLEMENTED-ON-PROTECTED-MAIN |
| PRD-FR-005 TLS policy | `src/egressweave/tls.py` and pinned transports | `tests/test_tls_configuration.py` plus transport hostname/SNI tests | ADR 0001; TLS identity requirements referenced in doctoring | IMPLEMENTED-ON-PROTECTED-MAIN |
| PRD-FR-006 Request semantics | `src/egressweave/request_safety.py` and protected-main request-body/timeout transport paths | request target/header/body/framing regressions, `tests/test_request_body_limits.py`, `tests/test_request_timeout_policy.py` | RFC 9110; RFC 9112; CWE-400; CWE-444 | IMPLEMENTED-ON-PROTECTED-MAIN |
| PRD-FR-007 Response semantics | protected-main response-safety and transport paths named by root architecture | response header/body/content-coding/resource-bound regression suites | RFC 9110; RFC 9112; CWE-400 | IMPLEMENTED-ON-PROTECTED-MAIN |
| PRD-FR-008 Stable denials | validation/transports plus public `EgressNotAllowedError` contract | generic-error, cleanup-provenance and hostile dependency cleanup regressions | ADR 0001; `docs/security-model.md` | IMPLEMENTED-ON-PROTECTED-MAIN |
| PRD-FR-009 Sync/async parity | synchronous and asynchronous builder/transport implementations | paired sync/async validation, timeout, framing, request/response and cleanup suites | ADR 0001; repository test strategy | IMPLEMENTED-ON-PROTECTED-MAIN |
| PRD-FR-010 Decision evidence | `src/egressweave/decision_evidence.py` | decision-evidence API, determinism, minimization and documentation/runtime-field contract tests | ADR 0001; privacy/minimization boundary in security model | IMPLEMENTED-ON-PROTECTED-MAIN |
| PRD-FR-011 Standalone and host-owned integration | public exports in `src/egressweave/__init__.py`; host creates adapters against public policy/builders | package-installed smoke tests plus documentation contract that forbids claiming a packaged naruon adapter | ADR 0001; ADR 0002 | IMPLEMENTED-ON-PROTECTED-MAIN for reusable core; OUT-OF-SCOPE for host adapter implementation |
| PRD-FR-012 Canonical automation prompt integrity | **ACTIVE-PR** `.github/prompts/hourly-product-maintainer.md` plus workflow loader and 12 KiB guard; protected-main workflow remains implementation truth until merge | `tests/test_hourly_rca_feasibility_contract.py`, `tests/test_hourly_opencode_nvidia_contract.py`, documentation prompt-governance contracts | **ADR 0004** | ACTIVE-PR / PROPOSED-GOVERNANCE |

Representative filenames are anchors, not an exhaustive test manifest. The complete exact-head test inventory and coverage report remain authoritative for merge/release evidence.

## 3. Quality, governance and release traceability

| Requirement | Implementation evidence | Test evidence | ADR / standard | Maturity |
|---|---|---|---|---|
| 100% owned production statement/branch coverage | CI coverage configuration and owned `src`/`scripts` production scope | `tests/test_complete_coverage.py`, `tests/test_final_coverage_branches.py`, exact-head CI coverage report | AGENTS/CLAUDE quality contract; NIST SSDF secure-development evidence | IMPLEMENTED-ON-PROTECTED-MAIN |
| Beginner-readable shipped-symbol documentation | public code docstrings and contributor rules | documentation/docstring coverage contracts in CI | AGENTS/CLAUDE; NIST SSDF | IMPLEMENTED-ON-PROTECTED-MAIN |
| Wheel and source-distribution acceptance | package metadata, build configuration and CI package-acceptance job | archive metadata/content/checksum verification and installed-wheel smoke test | SLSA-informed supply-chain evidence; release docs | IMPLEMENTED-ON-PROTECTED-MAIN for package acceptance |
| Exact-head integration evidence | checkout/source-SHA binding in repository CI and governance rules | workflow source checkout assertions and current-head review/check inspection | ADR 0001; ADR 0002 | IMPLEMENTED-ON-PROTECTED-MAIN |
| Automation governance: work-conserving execution, dependency handoff, control-plane incident recovery and double exit sweep | Proposed contract in `docs/adr/0003-work-conserving-automation-and-dependency-handoff.md` plus UML control-loop view | `tests/test_documentation_automation_governance.py` | ADR 0003 | PROPOSED-GOVERNANCE |
| Bounded canonical prompt and resumable control-plane incident handling | Proposed `docs/adr/0004-bounded-canonical-automation-prompt.md`; **ACTIVE-PR** canonical prompt, workflow loader, byte guard and incident runbook | `tests/test_hourly_rca_feasibility_contract.py`, `tests/test_hourly_opencode_nvidia_contract.py`, `tests/test_documentation_prompt_budget_governance.py` | **ADR 0004** | ACTIVE-PR / PROPOSED-GOVERNANCE |
| Stronger sealed release/SBOM/provenance work | release-evidence implementation only where already merged; additional hardening may be reviewed separately | exact-head release-evidence tests only count for the head that contains them | SLSA v1.2; CycloneDX/SPDX references in doctoring | IMPLEMENTED-ON-PROTECTED-MAIN only for merged capabilities; otherwise ACTIVE-PR |
| Independent review and branch governance | repository/CWL governance rather than runtime package code | formal review and branch-protection evidence on exact head | ADR 0001; repository governance | GOVERNANCE-GATE |

A generic scheduler error is a **control-plane incident**, not product state. The canonical prompt change is not accepted by documentation alone: exact integrated workflow evidence must demonstrate that prompt loading, model authority separation, offline verification and same-run recovery operate as specified. Prompt repair alone never closes the repository work queue.

## 4. Threat and control traceability

The explicit threat analysis is [`../THREAT_MODEL.md`](../THREAT_MODEL.md). The normative runtime boundary remains [`../security-model.md`](../security-model.md).

| Threat/control family | Implementation evidence | Test evidence | ADR / standard |
|---|---|---|---|
| SSRF / exact authority | `policy.py`, `validation.py`, pinned transports | authority, local-address and transport drift regressions | ADR 0001; OWASP SSRF Prevention; CWE-918 |
| DNS rebinding / TOCTOU | validation + pinned/revalidated destination state | DNS rebinding/address-revalidation tests | ADR 0001; CWE-350 |
| HTTP authority/framing | request safety + pinned transport | request target/header/framing tests | RFC 9110; RFC 9112; CWE-444 |
| Resource exhaustion | DNS, pool, timeout, request and response limits | candidate/pool/timeout/body/header limit suites | CWE-400 |
| TLS identity | `tls.py` + pinned transport | TLS configuration and SNI/hostname tests | ADR 0001; TLS references in doctoring |
| Error/evidence disclosure | generic denial and decision-evidence paths | cleanup/error/evidence minimization tests | Security model; privacy section of PRD/compliance mapping |
| Supply-chain / stale evidence | exact source binding, package acceptance, release evidence where merged | workflow/package/release contracts | NIST SSDF; NIST SP 1326; SLSA |
| Prompt/control-plane integrity | canonical prompt path, finite byte guard, deny-by-default model tools, non-publishing handoff and exact-identity recovery | scheduler and documentation prompt-governance contracts | ADR 0003; **ADR 0004** |

## 5. Documentation traceability

| Product concern | Canonical document | Machine-checkable evidence |
|---|---|---|
| Buyer requirements and acceptance | [`PRD.md`](PRD.md) | `tests/test_documentation_architecture_pack.py`, prompt-governance documentation contract |
| Verifiable technical constraints | [`TRD.md`](TRD.md) | documentation architecture/maturity tests plus full product suite |
| Protected-main implementation architecture | [`../../ARCHITECTURE.md`](../../ARCHITECTURE.md) | code/tests remain primary truth |
| Supplementary system views | [`../architecture/SYSTEM_ARCHITECTURE.md`](../architecture/SYSTEM_ARCHITECTURE.md), [`../architecture/UML.md`](../architecture/UML.md) | Mermaid/content/runtime-field/prompt-flow documentation contracts |
| Persistence ownership | [`../architecture/ERD.md`](../architecture/ERD.md) | no-owned-persistence and platform-owned automation-record contract |
| API ownership/compatibility | [`API_CONTRACT.md`](API_CONTRACT.md) | public export, package and documentation integration tests |
| Threat/security boundary | [`../THREAT_MODEL.md`](../THREAT_MODEL.md), [`../security-model.md`](../security-model.md) | security-model resource-bound and governance-document tests |
| Verification strategy | [`TEST_STRATEGY.md`](TEST_STRATEGY.md) | exact-head CI/package/security evidence |
| Operations/shared responsibility | [`OPERABILITY.md`](OPERABILITY.md) | generic scheduler incident and host runbook contracts |
| Compliance/acquisition evidence | [`COMPLIANCE_TRACEABILITY.md`](COMPLIANCE_TRACEABILITY.md) | documentation contracts + exact artifacts available for the release |
| Automation execution/exit/dependency governance | [`../adr/0003-work-conserving-automation-and-dependency-handoff.md`](../adr/0003-work-conserving-automation-and-dependency-handoff.md), [`../architecture/UML.md`](../architecture/UML.md) | `tests/test_documentation_automation_governance.py` |
| Bounded prompt source/budget and recovery | [`../adr/0004-bounded-canonical-automation-prompt.md`](../adr/0004-bounded-canonical-automation-prompt.md), [`OPERABILITY.md`](OPERABILITY.md) | `tests/test_documentation_prompt_budget_governance.py` |
| Decisions | [`../adr/README.md`](../adr/README.md) | ADR index/status documentation contract |
| Standards/APA 7 doctoring | [`../doctoring/REFERENCES.md`](../doctoring/REFERENCES.md) | standards-presence and non-certification tests |

## 6. Shared-responsibility boundaries

The following do not have EgressWeave-core implementation evidence because they are intentionally host/platform responsibilities:

- tenant/user identity and authorization;
- API credential lifecycle and OAuth scopes;
- durable database/audit retention/deletion;
- automation-run and control-plane-incident persistence;
- service SLOs, queues, retries/idempotency and process-wide concurrency;
- firewall/service-mesh/cloud egress policy;
- host-specific naruon/CWL adapter implementation;
- business-level path/query/body authorization; and
- legal/privacy governance for application payloads.

This distinction prevents an acquisition or compliance matrix from converting a library contribution into an unsupported whole-system control claim.

## 7. Change-control rule

A material product/security/ownership/automation-governance change must update the affected PRD/TRD/API/architecture/threat/test/operability/compliance/ADR/doctoring/traceability rows or explicitly prove why no traceability change is required. When implementation maturity changes from `ACTIVE-PR` or `PROPOSED-GOVERNANCE` to `IMPLEMENTED-ON-PROTECTED-MAIN`, documentation must be updated only after the protected merge and exact acceptance evidence exist.
