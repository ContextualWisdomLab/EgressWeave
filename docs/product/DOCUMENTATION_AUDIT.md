# EgressWeave Documentation Fitness Audit

Audit date: 2026-08-09

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

## 3. Pre-change audit matrix

| Artifact | Pre-change fitness | Finding | Canonical action in this PR |
|---|---|---|---|
| `README.md` | PARTIAL | Strong user/API/security material, but not a structured product-requirements record and some automation wording can lag active hardening work | Keep as buyer entrypoint; canonical requirements move to PRD/TRD |
| root `ARCHITECTURE.md` | PRESENT-CURRENT | Substantial implementation architecture and trust-boundary source of truth | Preserve as implementation authority; supplementary diagrams link to it |
| `AGENTS.md` | PRESENT-CURRENT | Strong engineering invariants and integration rules | Keep authoritative for contributor constraints |
| `CLAUDE.md` | PRESENT-CURRENT | Repository agent context exists | Keep aligned with AGENTS/architecture over time |
| `docs/security-model.md` | PRESENT-STALE | Explicit non-goal said the package does not cap response size even though protected main implements finite request/response body policies | Correct the non-goal and name current byte policies |
| Product PRD | MISSING | No canonical buyer/problem/requirement/acceptance document | Add [`PRD.md`](PRD.md) |
| Technical requirements | MISSING | Architecture existed but no separate verifiable TRD | Add [`TRD.md`](TRD.md) |
| API contract | PARTIAL | README/source/tests explain behavior, but compatibility and host-ownership rules are fragmented | Add [`API_CONTRACT.md`](API_CONTRACT.md) |
| Test strategy | PARTIAL | Strong executable tests and contributor rules, but no central verification strategy | Add [`TEST_STRATEGY.md`](TEST_STRATEGY.md) |
| Operability/runbook | PARTIAL | Security integration guidance exists, but SLI/SLO/shared-responsibility/runbooks are fragmented | Add [`OPERABILITY.md`](OPERABILITY.md) |
| Compliance traceability | MISSING | Standards are cited per topic, but SOC 2/CSAP/shared-responsibility mapping is not centralized | Add [`COMPLIANCE_TRACEABILITY.md`](COMPLIANCE_TRACEABILITY.md) |
| System architecture views | PARTIAL | Root architecture is strong prose/text diagrams but lacks a dedicated current system-view pack | Add [`../architecture/SYSTEM_ARCHITECTURE.md`](../architecture/SYSTEM_ARCHITECTURE.md) |
| UML | MISSING | No canonical class/sequence/state diagrams found | Add [`../architecture/UML.md`](../architecture/UML.md) |
| ERD / persistence decision | NOT-APPLICABLE but undocumented | Core owns no durable database; absence alone was ambiguous | Add explicit [`../architecture/ERD.md`](../architecture/ERD.md) with NON-NORMATIVE host model only |
| ADR index | PARTIAL | ADR 0001 exists and is Accepted, but no index/governance spine | Add [`../adr/README.md`](../adr/README.md) and ADR 0002 |
| Research/standards | PARTIAL | High-quality topic-specific research notes exist, but no central APA index | Add [`../doctoring/REFERENCES.md`](../doctoring/REFERENCES.md) |
| Release/provenance docs | PARTIAL / ACTIVE-PR work exists | Protected main has packaging/release foundations while additional evidence hardening is still under review | Keep maturity labels; do not present active PR behavior as shipped |

## 4. Current versus target truth

### IMPLEMENTED-ON-PROTECTED-MAIN

The protected-main architecture includes normalized policy construction, URL validation, DNS address validation, integrity-bound validated state, pinned synchronous/asynchronous transports, TLS configuration, finite timeout/pool and request/response resource controls, decision evidence, packaging quality gates, and modular naruon integration. Exact details remain sourced from root `ARCHITECTURE.md`, code, and tests.

### ACTIVE-PR

Multiple security, release-evidence, scheduler, and evidence-schema changes can exist concurrently. Their PR numbers and SHAs are deliberately not embedded as timeless architecture. Until each change reaches protected main, its implementation remains ACTIVE-PR and its prior review/check evidence must not be transferred to a different head or base.

### ACCEPTED-TARGET

Commercial documentation should remain one cross-linked, machine-tested source-of-truth graph, and hourly maintenance should remain work-conserving rather than stopping at the first blocked action. Target contracts are not shipped merely because they appear in this audit.

### PLANNED

Further buyer-visible product slices, integration adapters, and operational evidence may be prioritized after current PR/issue work. Planned content requires its own test and review evidence before migration to protected-main status.

### OUT-OF-SCOPE

Durable application databases, tenant/user identity, business-object authorization, host audit stores/retention, service-mesh/firewall enforcement, service SLOs, and blanket transformation of application PII are host/platform concerns unless a future accepted ADR changes the product boundary.

## 5. Documentation governance

1. Protected-main code/tests and root `ARCHITECTURE.md` are the primary implementation truth.
2. PRD defines buyer problems and product acceptance; TRD defines verifiable technical constraints.
3. API, test, operability, compliance, UML/ERD, ADR, and doctoring documents refine specific views without overriding implementation truth.
4. A material architecture/product/security ownership change requires an ADR and corresponding documentation update.
5. Active-PR details use maturity labels and must not be rewritten as already shipped behavior.
6. Machine-checkable documentation contracts should catch missing files, stale security claims, broken cross-links, false persistence ownership, and unresolved template markers.

## 6. Remaining audit obligations after this PR

Documentation completeness is continuous. After each material protected-main merge, compare changed behavior against this spine, root architecture, security model, API contract, runbooks, control mappings, and standards references. A future artifact can still become PRESENT-STALE even when this baseline PR was green.

The product is not commercially complete merely because the documentation pack exists; implementation, review, checks, operational acceptance, release evidence, and buyer workflows remain separate gates.
