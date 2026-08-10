# EgressWeave Documentation Fitness Audit

Audit date: 2026-08-10

Baseline inspected: protected `main` at `10d0c51daf2ad278d66f43be479df8cf6b08ba6d` before this documentation PR.

## 1. Purpose

This audit prevents chat history, pull-request bodies, and isolated research notes from becoming the only place where product decisions can be reconstructed. Root [`../../ARCHITECTURE.md`](../../ARCHITECTURE.md) remains the authoritative implementation architecture for behavior actually merged to protected main.

## 2. Fitness vocabulary

Artifact fitness:

- **PRESENT-CURRENT** — discoverable and aligned with protected-main behavior.
- **PRESENT-STALE** — exists but materially contradicts or lags current behavior.
- **PARTIAL** — useful content exists but does not cover the full artifact purpose.
- **MISSING** — no canonical repository artifact was found.
- **NOT-APPLICABLE** — the category does not belong to EgressWeave core; the reason must still be explicit.
- **SUPERSEDED** — retained only for history and replaced by another canonical artifact.

Implementation maturity:

- **IMPLEMENTED-ON-PROTECTED-MAIN**
- **ACTIVE-PR**
- **ACCEPTED-TARGET**
- **PLANNED**
- **RESEARCH-ONLY**
- **OUT-OF-SCOPE**
- **PROPOSED-GOVERNANCE**

## 3. Pre-change audit matrix

| Artifact | Pre-change fitness | Finding | Canonical action in this PR |
|---|---|---|---|
| `README.md` | PARTIAL | Strong user/API/security material, but not a structured product-requirements record and some automation wording can lag active hardening work | Keep as buyer entrypoint; canonical requirements move to PRD/TRD |
| root `ARCHITECTURE.md` | PRESENT-CURRENT | Substantial implementation architecture and trust-boundary source of truth | Preserve as implementation authority; supplementary diagrams link to it |
| `AGENTS.md` | PRESENT-CURRENT | Strong engineering invariants and integration rules | Keep authoritative for contributor constraints |
| `CLAUDE.md` | PRESENT-CURRENT | Repository agent context exists | Keep aligned with AGENTS/architecture over time |
| `docs/security-model.md` | PRESENT-STALE | Explicit non-goal said the package does not cap response size even though protected main implements finite request/response body policies | Correct the non-goal and name current byte policies |
| Explicit threat model | PARTIAL | `docs/security-model.md` already described assets, attacker capabilities, invariants and non-goals, but there was no separate acquisition/design-review threat-analysis view tied to the documentation spine | Add [`../THREAT_MODEL.md`](../THREAT_MODEL.md) while keeping `security-model.md` normative for runtime boundaries |
| Product PRD | MISSING | No canonical buyer/problem/requirement/acceptance document | Add [`PRD.md`](PRD.md) |
| Technical requirements | MISSING | Architecture existed but no separate verifiable TRD | Add [`TRD.md`](TRD.md) |
| API contract | PARTIAL | README/source/tests explain behavior, but compatibility and host-ownership rules are fragmented | Add [`API_CONTRACT.md`](API_CONTRACT.md) |
| Requirement-to-evidence traceability | MISSING | Requirements, code, tests, ADRs and standards were individually strong but not mapped in one durable matrix | Add [`TRACEABILITY.md`](TRACEABILITY.md) with protected-main/active-PR maturity separation |
| Test strategy | PARTIAL | Strong executable tests and contributor rules, but no central verification strategy | Add [`TEST_STRATEGY.md`](TEST_STRATEGY.md) |
| Operability/runbook | PARTIAL | Security integration guidance exists, but SLI/SLO/shared-responsibility/runbooks are fragmented | Add [`OPERABILITY.md`](OPERABILITY.md) |
| Compliance traceability | MISSING | Standards are cited per topic, but SOC 2/CSAP/shared-responsibility mapping is not centralized | Add [`COMPLIANCE_TRACEABILITY.md`](COMPLIANCE_TRACEABILITY.md) |
| System architecture views | PARTIAL | Root architecture is strong prose/text diagrams but lacks a dedicated current system-view pack | Add [`../architecture/SYSTEM_ARCHITECTURE.md`](../architecture/SYSTEM_ARCHITECTURE.md) |
| UML | MISSING | No canonical class/sequence/state diagrams found | Add [`../architecture/UML.md`](../architecture/UML.md) |
| ERD / persistence decision | NOT-APPLICABLE but undocumented | Core owns no durable database; absence alone was ambiguous | Add explicit [`../architecture/ERD.md`](../architecture/ERD.md) with NON-NORMATIVE host/platform model only |
| ADR index | PARTIAL | ADR 0001 exists and is Accepted, but no index/governance spine | Add [`../adr/README.md`](../adr/README.md) plus documentation/persistence and automation-governance ADRs |
| Automation control-plane governance | PARTIAL | Workflow source and conversation/PR instructions described work-conserving execution, but dependency advancement, double-exit semantics, and control-plane error recovery were not captured as one durable architecture decision | Add **ADR 0003** plus UML review view; Proposed governance selects one bounded change by deterministic queue and does not override protected-main workflow source |
| Canonical automation prompt | MISSING | The scheduler policy was embedded in a large inline YAML heredoc, had no explicit byte budget, and generic scheduled-task failures had no canonical recovery/runbook treatment | Add **ADR 0004**, PRD/TRD/Architecture/UML/Operability/Traceability/ERD updates, and machine contracts for one bounded canonical prompt and resumable control-plane incident handling |
| Research/standards | PARTIAL | High-quality topic-specific research notes exist, but no central APA index | Add [`../doctoring/REFERENCES.md`](../doctoring/REFERENCES.md) |
| Release/provenance docs | PARTIAL / ACTIVE-PR work exists | Protected main already has detailed sealed-evidence and SBOM/attestation implementation notes, but release acceptance, rollback/recovery, provenance claims, and active-PR maturity were not discoverable as one buyer/operator product view | Add [`RELEASE_PROVENANCE.md`](RELEASE_PROVENANCE.md), classified **PRESENT-CURRENT** for its protected-main summary while preserving ACTIVE-PR labels for unmerged hardening |

## 4. Current versus target truth

### IMPLEMENTED-ON-PROTECTED-MAIN

The protected-main architecture includes normalized policy construction, URL validation, DNS address validation, integrity-bound validated state, pinned synchronous/asynchronous transports, TLS configuration, finite timeout/pool and request/response resource controls, decision evidence, packaging quality gates, deterministic local release-evidence verification, and host-owned adapter compatibility through provider-neutral public contracts. Exact details remain sourced from root `ARCHITECTURE.md`, code, tests, [`../sealed-release-evidence.md`](../sealed-release-evidence.md), and [`../sbom-attestation-compatibility.md`](../sbom-attestation-compatibility.md). No naruon-specific adapter is packaged or exported by EgressWeave protected main.

[`RELEASE_PROVENANCE.md`](RELEASE_PROVENANCE.md) is the canonical product-level release/recovery/provenance view. It summarizes protected-main evidence without upgrading local source-identity claims into proof of an honest build, a SLSA level, publication, or certification.

### ACTIVE-PR

Multiple security, release-evidence, scheduler, and evidence-schema changes can exist concurrently. Their PR numbers and SHAs are deliberately not embedded as timeless architecture. Until each change reaches protected main, its implementation remains ACTIVE-PR and its prior review/check evidence must not be transferred to a different head or base.

In particular, the repository-local publisher removal, **credentialed release handoff consumption**, **full release identity/digest revalidation**, the matching buyer-facing handoff correction, and the bounded **canonical prompt** implementation **remain ACTIVE-PR** on their dependency-aware stacks. They must not replace protected-main automation truth before integration. The prompt work proposes one `.github/prompts/hourly-product-maintainer.md` source, a 12 KiB guard, removal of the inline YAML heredoc, and resumable **control-plane incident** handling; none of those are shipped until protected merge and operational acceptance.

### ACCEPTED-TARGET

Commercial documentation should remain one cross-linked, machine-tested source-of-truth graph, and hourly maintenance should remain work-conserving rather than stopping at the first blocked action. Target contracts are not shipped merely because they appear in this audit.

### PLANNED / PROPOSED GOVERNANCE

Further buyer-visible product slices, host-owned integration adapters, operational evidence, and automation-governance refinements may be prioritized after current PR/issue work. [`../adr/0003-work-conserving-automation-and-dependency-handoff.md`](../adr/0003-work-conserving-automation-and-dependency-handoff.md) is Proposed governance for work-conserving handoffs and finite exit semantics. [`../adr/0004-bounded-canonical-automation-prompt.md`](../adr/0004-bounded-canonical-automation-prompt.md) is Proposed governance for prompt source/budget and generic control-plane recovery. Neither asserts that every protected-main workflow already implements those semantics.

### OUT-OF-SCOPE

Durable application databases, tenant/user identity, business-object authorization, host integration-adapter implementation, host audit stores/retention, service-mesh/firewall enforcement, service SLOs, external package/release administration, blanket transformation of application PII, automation-run persistence, and scheduler incident storage are host/platform concerns unless a future accepted ADR changes the product boundary.

## 5. Documentation governance

1. Protected-main code/tests and root `ARCHITECTURE.md` are the primary implementation truth.
2. PRD defines buyer problems and product acceptance; TRD defines verifiable technical constraints.
3. API, threat, traceability, test, operability, compliance, release/provenance, UML/ERD, ADR, and doctoring documents refine specific views without overriding implementation truth.
4. [`../THREAT_MODEL.md`](../THREAT_MODEL.md) is the explicit threat-analysis view; [`../security-model.md`](../security-model.md) remains the normative runtime security-boundary description.
5. [`TRACEABILITY.md`](TRACEABILITY.md) maps durable requirements to implementation/test/ADR/standard evidence and must distinguish protected-main evidence from ACTIVE-PR work.
6. [`RELEASE_PROVENANCE.md`](RELEASE_PROVENANCE.md) aggregates release acceptance, rollback/recovery and provenance claim boundaries while the detailed verifier and SBOM/attestation contracts remain authoritative in their implementation-specific documents.
7. ADR 0003 is the canonical Proposed record for automation execution/exit/dependency-handoff semantics; ADR 0004 is the canonical Proposed record for bounded prompt loading and generic control-plane incident recovery. Neither overrides protected-main workflow source.
8. A material architecture/product/security/automation ownership change requires an ADR and corresponding documentation update.
9. Active-PR details use maturity labels and must not be rewritten as already shipped behavior.
10. Machine-checkable documentation contracts should catch missing files, stale security claims, broken cross-links, false persistence or integration ownership, release/provenance overclaims, missing automation-governance handoffs, prompt-policy duplication, missing prompt bounds, and unresolved template markers.

## 6. Remaining audit obligations after this PR

Documentation completeness is continuous. After each material protected-main merge, compare changed behavior against this spine, root architecture, security model, threat model, traceability matrix, API contract, release/provenance guide, runbooks, control mappings, automation-governance ADRs, and standards references. A future artifact can still become PRESENT-STALE even when this baseline PR was green.

The product is not commercially complete merely because the documentation pack exists; implementation, review, checks, operational acceptance, release evidence, dependency handoff, and buyer workflows remain separate gates. A generic scheduled-task error or prompt repair is likewise not completion while safe EgressWeave work remains.
