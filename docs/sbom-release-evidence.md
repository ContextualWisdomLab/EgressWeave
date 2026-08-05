# SBOM release evidence

## Purpose and boundary

EgressWeave generates deterministic CycloneDX 1.7 JSON software bills of
materials (SBOMs) for canonical wheel and source-distribution artifacts. Each
SBOM binds the exact distribution bytes by SHA-256, records package identity,
and models the reviewed runtime dependency closure with SPDX license identifiers
and package URLs (purls).

This is a read-only evidence foundation. It does not authorize a pull-request
branch to execute release logic with write credentials. The only permitted
future integration source is a protected-main or organization-level reusable workflow
whose source is immutable before receiving OIDC or attestation permissions.
No SLSA Build level is claimed merely because an SBOM or attestation exists.

## Normative evidence contract

`scripts/ci/generate_release_sbom.py` treats every archive, manifest, and lock
file as untrusted input and never imports EgressWeave. It must:

1. accept only a wheel or gzip source distribution;
2. reject unsafe or duplicate paths, links, devices, excessive member counts,
   ambiguous metadata, oversized metadata, and malformed archives;
3. check the declared wheel metadata size before decompression;
4. read exactly one wheel `METADATA` or root source `PKG-INFO` member;
5. verify package identity, license expression, and complete direct runtime
   requirement declarations against the reviewed manifest;
6. verify every dependency version, SHA-256, and environment marker against the
   executable hash-locked subset in `requirements-ci.txt`, while rejecting
   dependency extras that could activate packages outside the reviewed graph;
7. validate identities, SPDX license identifiers, purls, graph references,
   relationships, reachability, and acyclicity;
8. compute the artifact SHA-256 without trusting its filename; and
9. emit sorted UTF-8 CycloneDX 1.7 JSON without timestamps or random identifiers.

The root component uses a digest-derived `bom-ref`, preventing different
artifacts from sharing evidence identity. The dependency graph is the union
required across supported Python 3.10 through 3.13 runtimes. Conditional
packages retain their environment markers as explicit properties.

The reviewed manifest is
`scripts/ci/release_runtime_dependencies.json`. Its versions, hashes, and
markers must match `requirements-ci.txt`. Lock entries with PEP 508 extras are
invalid for SBOM parity because an extra can introduce additional runtime
requirements that are absent from the reviewed component graph. This prevents
buyer-facing evidence from describing one dependency set while CI executes
another. A dependency change is incomplete until the lock, manifest, tests,
license evidence, and SBOM semantics are reviewed together.

## Generate and verify locally

Build and verify the canonical distributions first. Then generate one SBOM per
artifact:

```bash
python scripts/ci/generate_release_sbom.py \
  --artifact dist/egressweave-<version>-py3-none-any.whl \
  --manifest scripts/ci/release_runtime_dependencies.json \
  --lock requirements-ci.txt \
  --output dist/egressweave-<version>-py3-none-any.whl.cdx.json

python scripts/ci/generate_release_sbom.py \
  --artifact dist/egressweave-<version>.tar.gz \
  --manifest scripts/ci/release_runtime_dependencies.json \
  --lock requirements-ci.txt \
  --output dist/egressweave-<version>.tar.gz.cdx.json
```

Repeat generation and compare bytes with `cmp`. Any archive, manifest, or lock
mismatch must fail closed. Never edit generated evidence to fit existing
artifacts; correct the reviewed inputs, rebuild, and regenerate every evidence
file.

## Offline operator verification

An operator evaluating an acquired or air-gapped release should:

1. obtain each distribution, CycloneDX JSON, `SHA256SUMS`, and signed
   attestation bundle through independently authenticated media;
2. verify `SHA256SUMS` before parsing an archive;
3. confirm the SBOM root hash equals the artifact hash;
4. validate the document against the CycloneDX 1.7 JSON schema;
5. verify attestation subject, repository, immutable workflow source, exact
   commit, and predicate bytes;
6. inventory purls, versions, SPDX licenses, markers, and relationships; and
7. reject any digest, identity, schema, workflow, signature, or graph mismatch.

An SBOM is inventory evidence, not proof that a dependency is vulnerability
free, correctly licensed for every use, or benign. Vulnerability assessment,
legal review, provenance verification, and deployment policy remain separate
controls.

## Protected release integration

A protected integration generates both SBOMs in a read-only exact-main build job
after distribution verification. It adds the SBOMs to the complete
release-evidence artifact and `SHA256SUMS`, while keeping PyPI inputs limited to
the wheel and source distribution.

Attestation runs in a credential-separated job that consumes only the
independently verified exact artifact set. The current `actions/attest` SBOM mode
is pinned to an immutable reviewed commit SHA. The signer receives only
repository and artifact read access plus the OIDC, attestation, and
artifact-metadata permissions required by the reviewed action; it does not check
out or execute repository code.

Before public GitHub Release publication, a separate read-only job verifies each
attestation against the exact artifact SHA-256, repository identity, immutable
workflow source, exact protected-main commit, CycloneDX predicate bytes, hosted
runner policy, and release tag.

Public release fails closed on any mismatch. A branch must never add a temporary
job that publishes, moves refs, writes contents, pushes to a pull-request branch,
self-modifies workflows, or executes model-modified source under a write
credential.

## Threats, failure, and recovery

These controls address omitted inventory, evidence bound to the wrong artifact,
filename substitution, manifest-versus-lock drift, undeclared dependency extras,
mutable dependency resolution, nondeterministic evidence, unsafe archives,
metadata decompression, stale or wrong-workflow attestations, and publication
before exact verification.

They do not detect every compromised upstream source, malicious but correctly
hashed package, license obligation, build-host compromise, or undisclosed
vulnerability. Those risks require provenance, reproducible builds,
vulnerability management, legal review, and hardened runners.

On any generator, digest, semantic, manifest, lock, or attestation failure,
publish nothing. Correct the source through normal review and regenerate from the
exact accepted commit. Never replace published bytes under an existing version.
If protected main advances, discard the stale attempt and rebuild. Partial
publication requires a new version and transparent changelog entry.

## SLSA statement

EgressWeave does not infer a SLSA Build level from SBOM generation, PyPI
attestations, or GitHub artifact attestations. Add a level claim only after every
normative requirement for that level maps to independently verified evidence.

## Signed release attestations and offline verification

The protected release workflow generates one CycloneDX 1.7 document for the
canonical wheel and one for the canonical source distribution, includes both
SBOMs in `SHA256SUMS`, and signs each artifact/SBOM pair with
`actions/attest` 4.1.0 pinned to commit
`59d89421af93a897026c735860bf21b6eb4f7b26`. The signer receives only artifact
read access plus the OIDC, attestation, and artifact-metadata permissions required
by the current official action. It does not check out or execute repository code.

A separate read-only hosted-runner job verifies the local bundle against the
exact artifact bytes, the CycloneDX predicate type, this repository's
`.github/workflows/release.yml` signer identity, the protected-main source ref,
and the exact release commit. It also canonicalizes the signed predicate and
compares it with the checksummed `.cdx.json` document byte-for-semantic-byte
before either PyPI or GitHub Release publication can start.

Online verification for one acquired artifact should be at least as strict as:

```bash
gh attestation verify egressweave-<version>-py3-none-any.whl \
  --repo ContextualWisdomLab/EgressWeave \
  --predicate-type https://cyclonedx.org/bom \
  --signer-workflow ContextualWisdomLab/EgressWeave/.github/workflows/release.yml \
  --source-digest <release-commit-sha> \
  --source-ref refs/heads/main \
  --deny-self-hosted-runners
```

For an offline or air-gapped environment, obtain a fresh trusted root through an
independently authenticated online staging system, then transfer the artifact,
its `*.sbom-attestation.json` bundle, the checksummed CycloneDX document, and the
trusted root through controlled media:

```bash
gh attestation trusted-root > trusted_root.jsonl

gh attestation verify egressweave-<version>-py3-none-any.whl \
  --repo ContextualWisdomLab/EgressWeave \
  --bundle egressweave-<version>-py3-none-any.whl.sbom-attestation.json \
  --custom-trusted-root trusted_root.jsonl \
  --predicate-type https://cyclonedx.org/bom \
  --signer-workflow ContextualWisdomLab/EgressWeave/.github/workflows/release.yml \
  --source-digest <release-commit-sha> \
  --source-ref refs/heads/main \
  --deny-self-hosted-runners
```

The transferred trusted root is itself trust material. Refresh it when importing
newly signed material and authenticate it independently; do not accept a root
merely because it was stored beside the artifact it is supposed to verify.
Attestation signature verification does not replace `SHA256SUMS`, CycloneDX
schema validation, dependency/license review, vulnerability assessment, or
artifact behavior testing. No SLSA Build level is claimed until every normative
requirement of a specific SLSA v1.2 level is independently mapped and verified.

## Authoritative references

Ecma International, & OWASP Foundation. (2025). *CycloneDX specification 1.7
(ECMA-424).* https://cyclonedx.org/specification/overview/

GitHub. (n.d.). *Using artifact attestations to establish provenance for
builds.* GitHub Docs. Retrieved August 5, 2026, from
https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations

GitHub. (n.d.). *Verifying attestations offline*. GitHub Docs. Retrieved August
5, 2026, from
https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline

GitHub. (2026). *actions/attest* (Version 4.1.0) [Computer software].
https://github.com/actions/attest

in-toto Project. (2026). *CycloneDX predicate type*. In *in-toto Attestation
Framework*. https://github.com/in-toto/attestation/blob/main/spec/predicates/cyclonedx.md

Python Packaging Authority. (n.d.). *Core metadata specifications.* Python
Packaging User Guide. Retrieved August 5, 2026, from
https://packaging.python.org/en/latest/specifications/core-metadata/

Supply-chain Levels for Software Artifacts Community. (2025). *SLSA
specification version 1.2.* https://slsa.dev/spec/v1.2/
