# EgressWeave Release, Rollback, and Provenance

Status: Proposed commercial documentation baseline grounded in protected-main behavior and explicitly separated from ACTIVE-PR work.

This document is the product-level release, rollback, and provenance view for EgressWeave. It aggregates the buyer and operator contract without replacing the lower-level implementation evidence in [`../sealed-release-evidence.md`](../sealed-release-evidence.md), [`../sbom-attestation-compatibility.md`](../sbom-attestation-compatibility.md), root [`../../ARCHITECTURE.md`](../../ARCHITECTURE.md), or [`../../CHANGELOG.md`](../../CHANGELOG.md).

For durable path-level traceability, the protected-main implementation documents referenced below are `docs/sealed-release-evidence.md` and `docs/sbom-attestation-compatibility.md`.

## Protected-main release truth

**IMPLEMENTED-ON-PROTECTED-MAIN.** Protected main provides package build and acceptance checks, deterministic CycloneDX release evidence, canonical source-identity and checksum sealing, a credential-free release-evidence verifier, and deterministic handoff-manifest generation. The shipped verifier validates one bounded release-evidence set without importing or executing the candidate distributions and binds the accepted evidence to an explicit repository/source claim.

A valid sealed-evidence handoff is preparation evidence. It is not a signature and does not by itself prove that an artifact was honestly built from the claimed source, that dependencies are benign, that a vulnerability scan is complete, or that publication occurred. Those stronger statements require the separately governed protected build, attestation, environment, reviewer, and publication controls that actually establish them.

The exact protected-main source and tests remain authoritative if this overview ever conflicts with implementation detail.

## Release acceptance gate

A buyer-facing EgressWeave release is acceptable only from an exact integrated protected source for which the repository and organization policies establish all applicable evidence on that same identity. At minimum, release acceptance requires:

1. the exact protected source and intended version are fixed and the matching [`../../CHANGELOG.md`](../../CHANGELOG.md) release history is complete;
2. required CI, exact owned production statement/branch coverage, shipped-symbol docstrings, packaging acceptance, and compatibility lanes pass;
3. required SAST, dependency/supply-chain and repository security gates genuinely execute rather than being skipped or replaced by a green wrapper;
4. the final wheel, source distribution, SBOMs, source identity, checksums, and release-evidence handoff are digest-bound and independently revalidated according to `docs/sealed-release-evidence.md`;
5. qualifying independent review and protected-branch/ruleset requirements are satisfied;
6. the protected-main release workflow does not consume the credential-bearing handoff; any elevated signing, attestation, or publication stage used for a future release must have its own separately accepted organization-owned implementation and exact-tree verification evidence; and
7. post-publication verification confirms the intended package/release artifacts and provenance evidence rather than treating a workflow completion status as sufficient proof.

Queued, pending, skipped-required, cancelled, absent, stale-head, predecessor-head, synthetic-only, comment-only, author-only, fail-open, or failed evidence is not release acceptance.

## Rollback and recovery

Rollback is evidence preserving rather than an in-place rewrite of a failed release candidate.

Before publication, a failed or mutated release-evidence candidate and any failed handoff output are untrusted. Operators discard the complete candidate set, rebuild it from the exact reviewed protected source in a clean credential-free environment, choose a fresh output path, and rerun the complete quality, package, security, SBOM, identity, checksum, and manifest gates. Editing a failed checksum, source identity, SBOM, or manifest in place is not recovery.

A protected-main code rollback is a reviewed repository change, normally a revert or a forward fix. It receives a new exact head and must pass the same applicable review and verification gates; prior approvals and checks do not transfer merely because the rollback restores older source text.

After an external package or release is published, EgressWeave does not treat mutable replacement of already published bytes as rollback. Recovery must use the controls actually supported by the package/release platform—for example a new corrective version and, where the platform supports it, an explicit withdrawal/yank or advisory—while preserving the original evidence and documenting the incident and successor artifact. Host release operators own those external-platform actions and must follow their protected environment and approval policy.

## Provenance and attestation boundary

**IMPLEMENTED-ON-PROTECTED-MAIN** release evidence binds distribution bytes, deterministic CycloneDX documents, canonical `SOURCE_IDENTITY.json`, and `SHA256SUMS` into a bounded verifier contract. The source identity is an auditable claim inside the sealed set; it is not cryptographic proof that the build was honest.

The repository-level verifier is deliberately credential free. The protected-main release workflow does not consume the credential-bearing handoff. A future credentialed stage may consume only a **sealed handoff** containing the already credential-free verified payloads and the independently **digest-bound manifest**. Before any elevated operation, that stage must recheck repository identity, the exact **source commit**, the **source-identity digest**, the **checksum digest**, **payload cardinality**, and **every payload digest**. It **must not rebuild**, **resolve dependencies**, **import distributions**, or **execute caller-controlled source** under **`id-token: write`**, **`attestations: write`**, **package-publication**, **release**, **tag**, or **repository-write** credentials.

Credential-bearing signing, attestation, package publication, release/tag mutation, and any OIDC authority belong to separately reviewed organization workflows and protected environments. A credentialed stage must not infer trust from a branch, filename, PR body, or prior workflow status; the sealed-handoff checks above are the minimum handoff revalidation contract.

EgressWeave **does not claim** a SLSA Build level merely because it generates or verifies evidence compatible with provenance workflows. Any future SLSA claim must identify the exact SLSA version and independently map every normative requirement to scoped evidence. Likewise, these controls contribute to auditability but do not constitute SOC 2, CSAP, or other certification.

The detailed compatibility boundary for CycloneDX and attestation consumption remains in `docs/sbom-attestation-compatibility.md`; the canonical local evidence verifier and its failure semantics remain in `docs/sealed-release-evidence.md`.

## Active-PR maturity boundary

**ACTIVE-PR.** Release-evidence, publisher-removal, scheduler, attestation, SBOM, compatibility, or verification hardening may exist on dependency-aware pull-request stacks beyond protected main. Those changes are not shipped behavior until they reach the protected branch through their actual gates.

The current credential-bearing handoff consumer is an **ACTIVE-PR target**, not protected-main behavior. If that target is accepted, it may consume only a **sealed handoff** containing the already credential-free reverified payloads and the independently **digest-bound manifest**. Before any elevated operation, it must recheck repository identity, the exact **source commit**, the **source-identity digest**, the **checksum digest**, **payload cardinality**, and **every payload digest**. It **must not rebuild**, **resolve dependencies**, **import distributions**, or **execute caller-controlled source** under **`id-token: write`**, **`attestations: write`**, **package-publication**, **release**, **tag**, or **repository-write** credentials.

Documentation may describe an ACTIVE-PR target to make ownership and migration visible, but it must not replace the protected-main release truth or transfer a predecessor PR's checks, review, approval, scanner result, or artifact identity. If an active stack changes the release trust boundary, the integrated tree must be re-audited against this document, the root architecture, threat model, operability guidance, traceability matrix, and relevant ADRs before the maturity label is promoted.

## Ownership boundary

EgressWeave core owns deterministic local package/evidence contracts that ship with the library. Organization-owned reusable workflows own elevated signing/attestation/publishing mechanics. Host applications and platform teams own service deployment, environment promotion, incident response, external package/release administration, tenant controls, secrets, and any durable release/audit store unless a future accepted ADR changes that boundary.
