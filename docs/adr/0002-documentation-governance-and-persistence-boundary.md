# ADR 0002: Documentation governance and persistence boundary

- **Status:** Proposed
- **Date:** 2026-08-09
- **Decision owners:** ContextualWisdomLab maintainers

## Context

EgressWeave has a strong protected-main implementation architecture, security model, operator guidance and protocol-specific research notes. Commercial due diligence, however, also requires a product-level source of truth that separates buyer requirements, technical design, public contracts, operability, compliance evidence and future targets from transient pull-request prose or conversation history.

A second documentation risk is architectural overreach. EgressWeave is currently an in-process security library and does not own a database, tenant store, credential vault, durable audit service, queue or deployment control plane. Producing an ERD without stating that boundary could imply persistence responsibilities that do not exist in code.

A third risk is time-sensitive documentation. Current implementation, an active pull request and a target architecture are different evidence classes. Mixing them can make procurement and engineering readers believe an unmerged design is already shipped.

## Decision drivers

- A buyer or maintainer must reconstruct the product without chat or PR archaeology.
- Root `ARCHITECTURE.md` must remain the authoritative protected-main implementation architecture.
- Active PRs and accepted targets must never be described as protected-main behavior.
- Documentation should be machine-checkable where a stable contract exists.
- EgressWeave must remain standalone and provider-neutral rather than absorbing host persistence, tenancy or deployment concerns for documentation convenience.
- Standards and compliance mappings must distinguish library contributions from host/platform responsibilities and must not claim certification.

## Decision

### 1. Canonical documentation graph

Maintain a discoverable product documentation graph covering, at minimum:

- product requirements (`docs/product/PRD.md`);
- technical requirements (`docs/product/TRD.md`);
- root implementation architecture (`ARCHITECTURE.md`) and supplementary system views;
- API/schema contract;
- test strategy;
- operability and release/rollback expectations;
- compliance/control traceability;
- documentation fitness audit;
- ADR index and durable decisions;
- UML/behavior/deployment diagrams;
- persistence decision / ERD;
- security/threat-model documentation; and
- central standards/research doctoring.

Equivalent stronger documents may replace these filenames when the index clearly identifies the authority. The graph should link rather than duplicate the same normative rule in several places.

### 2. Maturity labels are evidence classes

Product and technical documents use explicit maturity labels when they describe implementation state:

- `IMPLEMENTED-ON-PROTECTED-MAIN`;
- `ACTIVE-PR`;
- `ACCEPTED-TARGET`;
- `PLANNED`;
- `RESEARCH-ONLY`; and
- `OUT-OF-SCOPE`.

An ADR status records the state of a decision, not implementation completion. A Proposed or Accepted target remains non-shipped until protected-main implementation and acceptance evidence exist.

### 3. Root architecture authority

Root `ARCHITECTURE.md` is the protected-main implementation architecture. Supplementary product/system diagrams explain that architecture and accepted targets but may not silently contradict root architecture. Dated incident/PR evidence belongs in PRs, changelog entries, runbooks or evidence appendices rather than timeless architecture claims.

### 4. No invented persistence

**EgressWeave core owns no durable database.** The canonical ERD therefore records the absence of core-owned persistence. It may show a clearly `NON-NORMATIVE`, host-owned conceptual audit model to explain integration boundaries, but such a model is not a migration contract and must not create package-owned tables.

Host applications retain responsibility for tenant persistence, credentials, durable audit stores, retention/deletion, backups, disaster recovery, legal basis and access logging unless a later Accepted ADR explicitly transfers an ownership boundary.

A future core-owned persistence capability requires a superseding ADR plus physical schema, migrations, rollback, tenancy/security ownership, backup/recovery, retention/deletion behavior and realistic migration tests.

### 5. Documentation as tested product surface

Stable documentation contracts should have tests for:

- required canonical documents and index links;
- ADR index/status consistency;
- diagram-as-code presence and parseable fences;
- public API and security-boundary names;
- current-vs-target maturity vocabulary;
- the no-owned-persistence rule;
- standards/compliance references; and
- stale claims that contradict protected-main functionality.

Tests should validate semantic contracts rather than freeze prose unnecessarily.

### 6. Standards and compliance evidence

The doctoring index records authoritative standards and whether they are final or draft. Compliance traceability maps only EgressWeave's technical contribution; complete SOC 2/CSAP or other certification remains a host/organization assessment outcome. The repository does not claim certification solely from a control mapping.

## Alternatives considered

### Keep architecture only in root `ARCHITECTURE.md`

Rejected. It is suitable for implementation boundaries but does not replace buyer requirements, public API contracts, operability, compliance mapping, product maturity or requirements-to-evidence navigation.

### Use README and pull-request bodies as the commercial source of truth

Rejected. README optimizes for onboarding and PR bodies are mutable, dated review artifacts. Neither provides a durable cross-linked decision and requirements system.

### Copy every architectural rule into every document

Rejected. Duplication creates drift. Documents must reference the authoritative layer and add concern-specific detail.

### Add a package-owned audit database because procurement expects an ERD

Rejected. It would invent runtime ownership, migrations and data-governance obligations with no product need. A clearly non-normative host model communicates integration without altering the software boundary.

### Describe target designs as current to simplify the documentation

Rejected. It undermines acquisition diligence and operational safety. Evidence classes remain explicit.

## Consequences

### Positive

- Product, architecture, security and operational claims become independently auditable.
- Buyers can distinguish shipped guarantees from active work and target architecture.
- Documentation drift can fail CI before an incorrect boundary becomes release guidance.
- Persistence, tenant and credential responsibilities remain in the correct host layer.
- Future architecture changes have a clear supersession path.

### Costs

- Material changes may require several cross-linked documentation updates.
- Maintainers must keep maturity labels current as PRs merge or are abandoned.
- Documentation tests add maintenance when stable public contracts change.
- A host implementing audit persistence still needs its own physical data model and controls.

## Failure and recovery

If product docs contradict protected-main code, root `ARCHITECTURE.md`, tests or public types, classify the affected document as stale and repair it before using it as release evidence. If a target PR is closed without merge, update maturity labels from `ACTIVE-PR` to the correct planned/superseded state.

If core-owned persistence is accidentally implied or introduced without governance, stop further expansion, document the actual shipped behavior, and either remove the accidental coupling or write a superseding persistence ADR with migration/security/rollback evidence.

## Security and privacy impact

This decision reduces overcollection risk by keeping core evidence payload-minimized and leaving durable audit enrichment under host purpose/tenant/retention controls. It also prevents procurement documents from overstating security certification or unmerged security behavior.

Documentation itself must not embed secrets, credentials, raw request/response bodies, resolved IPs, sensitive production topology or unstable reviewer tokens.

## Compatibility and migration

This ADR changes documentation governance, not the runtime API. Existing users do not need code changes. New canonical links should be added to onboarding documentation when the documentation PR reaches protected main.

Future renames should preserve redirects/links where practical and update documentation tests atomically.

## Acceptance evidence

- Documentation-contract tests pass on the exact PR head.
- PRD/TRD/API/test/operability/compliance/audit documents are cross-linked.
- UML contains machine-readable structural, sequence and state views.
- ERD states the no-owned-database boundary and labels any host model non-normative.
- Root architecture remains unchanged unless a separately justified implementation-architecture correction is required.
- Security documentation agrees with current finite request/response resource behavior.
- Doctoring distinguishes final standards from drafts and contains no certification claim.

## Rollback and supersession

This ADR can be reverted without runtime migration if the documentation graph proves harmful. A later ADR must supersede it if EgressWeave becomes a service with owned persistence, changes its canonical architecture authority, or replaces the maturity/evidence model with another machine-verifiable governance system.

## References

National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities* (NIST SP 800-218). https://doi.org/10.6028/NIST.SP.800-218

OWASP Foundation. (2025). *OWASP Application Security Verification Standard 5.0.0*.

SLSA Community. (2025). *SLSA specification version 1.2*.
