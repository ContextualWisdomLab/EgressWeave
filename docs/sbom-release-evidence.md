# SBOM release evidence

## Purpose and current boundary

EgressWeave generates deterministic CycloneDX 1.7 JSON software bills of
materials (SBOMs) for canonical wheel and source-distribution artifacts. Each
SBOM binds the exact distribution bytes by SHA-256, records package identity,
models the reviewed runtime dependency closure, and preserves SPDX license
identifiers and package URLs (purls).

This repository change is a read-only evidence foundation. It does **not**
authorize a pull-request branch to modify or execute a release workflow with
write credentials. Signed attestation, checksum-set integration, and public
publication require a separately reviewed immutable integration source.
Allowed integration source: protected-main or organization-level reusable workflow.
That source must be immutable before it receives OIDC or attestation permissions.
No SLSA Build level is claimed merely because an SBOM or attestation exists.

## Evidence model

`scripts/ci/generate_release_sbom.py` treats distribution archives, the reviewed
manifest, and the executable dependency lock as untrusted input. It never
imports or executes EgressWeave. For each artifact it:

1. accepts only a wheel or gzip source distribution;
2. rejects unsafe or duplicate archive paths, links, devices, excessive member
   counts, ambiguous metadata, oversized metadata, and malformed archives;
3. checks declared wheel metadata size before decompression;
4. reads the sole wheel `METADATA` or root source-distribution `PKG-INFO`;
5. verifies package identity, license expression, and complete direct runtime
   requirement declarations against the reviewed manifest;
6. verifies every SBOM dependency version, SHA-256, and environment marker
   against the executable hash-locked subset in `requirements-ci.txt`;
7. validates dependency identities, SPDX license identifiers, purls,
   relationships, graph references, reachability, and acyclicity;
8. computes the exact artifact SHA-256 without trusting the filename; and
9. emits sorted UTF-8 CycloneDX 1.7 JSON without a clock timestamp or random
   serial number.

The root component uses a digest-derived `bom-ref`, preventing a wheel and source
distribution from sharing evidence identity accidentally. The dependency graph
is the union required across supported Python 3.10 through 3.13 runtimes.
Conditional packages retain their environment markers as explicit properties.

The reviewed manifest is
`scripts/ci/release_runtime_dependencies.json`. Its exact versions, artifact
SHA-256 values, and environment markers must match the executable lock in
`requirements-ci.txt`. This parity check prevents a buyer-facing SBOM from
describing one dependency set while CI executes another. A dependency update is
incomplete until the lock, manifest, tests, license evidence, and generated SBOM
semantics are reviewed together.

## Local generation and verification

After independently building and verifying the canonical artifacts, generate
one SBOM per artifact:

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

Repeat generation and compare bytes with `cmp` to verify determinism. The
generator fails closed when archive metadata, the reviewed manifest, or the
hash-locked runtime subset differs. Never edit generated evidence to make it
match existing artifacts. Correct the reviewed inputs, rebuild the exact
artifact set, and regenerate every evidence file.

## Offline verification procedure

An operator evaluating an acquired or air-gapped release should:

1. obtain each distribution, its CycloneDX JSON, `SHA256SUMS`, and signed
   attestation bundle through independently authenticated media;
2. verify `SHA256SUMS` before parsing any archive;
3. confirm the SBOM root SHA-256 equals the acquired artifact digest;
4. validate the SBOM against the CycloneDX 1.7 JSON schema;
5. confirm the attestation subject digest, repository identity, workflow
   identity, exact commit, and predicate bytes match the artifact and SBOM;
6. inventory purls, versions, SPDX licenses, markers, and relationships; and
7. reject evidence with any digest, identity, schema, workflow, signature, or
   dependency-graph mismatch.

An SBOM is inventory evidence, not proof that a dependency is vulnerability
free, correctly licensed for every use, or benign. Vulnerability assessment,
legal review, provenance verification, and deployment policy remain separate
controls.

## Protected release integration requirements

A future protected integration may generate both SBOMs in the existing
read-only exact-main build job after distribution verification. It may add the
SBOMs to the complete release-evidence artifact and `SHA256SUMS`, while keeping
PyPI inputs limited to the wheel and source distribution.

Attestation must occur in a credential-separated job that consumes only the
independently verified exact artifact set. Use the current `actions/attest` SBOM
mode pinned to an immutable reviewed commit SHA. Grant only the permissions
required by the reviewed action and repository configuration. GitHub currently
documents `id-token: write` and `attestations: write`, while repository contents
remain read-only. Recheck the current permission contract during integration.

Before public GitHub Release publication, verify every attestation against:

- the exact distribution SHA-256;
- `ContextualWisdomLab/EgressWeave` as repository identity;
- the expected immutable workflow source and exact protected-main commit;
- the intended CycloneDX 1.7 predicate bytes; and
- the release tag resolving to the accepted exact commit.

Public release must fail closed on any mismatch. A branch must never add a
temporary job that publishes, moves refs, writes contents, pushes to a pull
request branch, self-modifies workflows, or executes model-modified source under
a write credential.

## Threat model

The controls address omitted inventory, evidence attached to the wrong artifact,
filename substitution, manifest-versus-lock drift, mutable dependency resolution,
nondeterministic evidence, unsafe archive structures, metadata decompression,
stale or wrong-workflow attestations, and publication before exact verification.

They do not claim to detect compromised upstream source, malicious but correctly
hashed packages, every license obligation, build-host compromise, or undisclosed
vulnerabilities. Those risks require provenance, reproducible-build,
vulnerability-management, legal-review, and runner-hardening controls.

## Failure and recovery

- **Generator failure:** publish nothing. Correct the artifact, manifest, lock,
  or generator through normal review, rebuild, and regenerate all evidence.
- **Digest or semantic mismatch:** treat the artifact set as untrusted. Never
  replace evidence under an existing version.
- **Manifest/lock mismatch:** update and review both together, then regenerate
  both artifact SBOMs and rerun every release gate.
- **Attestation failure:** retain no public release. Correct only the protected,
  credential-separated mechanism and rerun it against unchanged verified bytes.
- **Protected main advances:** discard the stale attempt and rebuild from the new
  exact main head. Do not move an existing release tag.
- **Partial publication:** recover with a new version and transparent changelog
  entry; never replace published bytes.

## SLSA statement

EgressWeave does not infer a SLSA Build level from SBOM generation, PyPI
attestations, or GitHub artifact attestations. A statement such as
`SLSA Build Lx (v1.2)` may be added only after every normative requirement for
that level has been mapped to independently verified release evidence.

## Authoritative references

Ecma International, & OWASP Foundation. (2025). *CycloneDX specification 1.7
(ECMA-424).* https://cyclonedx.org/specification/overview/

GitHub. (n.d.). *Using artifact attestations to establish provenance for
builds.* GitHub Docs. Retrieved August 5, 2026, from
https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations

GitHub. (2026). *actions/attest* [Computer software]. GitHub.
https://github.com/actions/attest

Python Packaging Authority. (n.d.). *Core metadata specifications.* Python
Packaging User Guide. Retrieved August 5, 2026, from
https://packaging.python.org/en/latest/specifications/core-metadata/

Supply-chain Levels for Software Artifacts Community. (2025). *SLSA
specification version 1.2.* https://slsa.dev/spec/v1.2/
