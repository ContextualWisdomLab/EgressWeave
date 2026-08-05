# SBOM release evidence

## Purpose and current boundary

EgressWeave generates a deterministic CycloneDX 1.7 JSON software bill of
materials (SBOM) for each canonical wheel and source distribution. The SBOM
binds the exact distribution bytes by SHA-256, records the package identity,
models the reviewed runtime dependency closure, and preserves declared SPDX
license identifiers and package URLs (purls).

This document describes the repository-side, read-only evidence foundation.
It does **not** authorize a pull-request branch to modify or execute a release
workflow with write credentials. Signed attestation and public-release
integration must be performed only by a separately reviewed protected-main or
organization-level reusable workflow whose source is immutable before it
receives OIDC or attestation permissions. No SLSA Build level is claimed by the
presence of an SBOM or an attestation alone.

## Evidence model

`scripts/ci/generate_release_sbom.py` treats the distribution archive as
untrusted data. It does not import or execute EgressWeave. For each artifact it:

1. accepts only a wheel or gzip source distribution;
2. rejects unsafe archive paths, links, devices, ambiguous package metadata,
   oversized metadata, and malformed archives;
3. reads the sole wheel `METADATA` or source-distribution `PKG-INFO` member;
4. verifies package name, version, license expression, and direct runtime
   dependency names against the reviewed manifest;
5. computes the exact artifact SHA-256 without trusting its filename;
6. validates every dependency identity, digest, SPDX license identifier, purl,
   relationship, optional Python-version marker, graph reachability, and graph
   acyclicity; and
7. emits stable, sorted UTF-8 CycloneDX 1.7 JSON without a clock timestamp or
   random serial number.

The root component uses a digest-derived `bom-ref`, so a wheel and source
distribution cannot accidentally share evidence identity. The dependency graph
is the union required across supported Python 3.10 through 3.13 runtimes.
Conditional packages retain their environment markers as explicit properties.
This union is intentional: an operator evaluating any supported runtime can see
all packages that may enter the runtime closure.

The reviewed dependency manifest is
`scripts/ci/release_runtime_dependencies.json`. Its exact versions and artifact
SHA-256 values correspond to the hash-locked runtime closure used by repository
CI. A dependency update is incomplete until the package lock, this manifest,
tests, license evidence, and generated SBOM semantics are reviewed together.

## Local generation and verification

After independently building and verifying the canonical artifacts, generate
one SBOM per artifact:

```bash
python scripts/ci/generate_release_sbom.py \
  --artifact dist/egressweave-<version>-py3-none-any.whl \
  --manifest scripts/ci/release_runtime_dependencies.json \
  --output dist/egressweave-<version>-py3-none-any.whl.cdx.json

python scripts/ci/generate_release_sbom.py \
  --artifact dist/egressweave-<version>.tar.gz \
  --manifest scripts/ci/release_runtime_dependencies.json \
  --output dist/egressweave-<version>.tar.gz.cdx.json
```

Repeat either command and compare bytes to verify deterministic generation:

```bash
cmp first.cdx.json second.cdx.json
```

For offline artifact verification, an operator should:

1. obtain the wheel or source distribution, its CycloneDX JSON, `SHA256SUMS`,
   and the signed attestation bundle through independently authenticated media;
2. verify `SHA256SUMS` before parsing any archive;
3. confirm the SBOM root component SHA-256 equals the acquired artifact digest;
4. validate the SBOM against the CycloneDX 1.7 JSON schema;
5. confirm the attestation subject digest, repository identity, workflow
   identity, commit, and predicate bytes match the acquired artifact and SBOM;
6. inventory purls, versions, SPDX licenses, and dependency relationships; and
7. reject evidence with a digest mismatch, unknown generator or schema version,
   missing dependency node, unexpected runtime marker, mutable workflow source,
   or unverifiable signature.

The SBOM is inventory evidence, not proof that a dependency is vulnerability
free, correctly licensed for every use, or benign. Vulnerability assessment,
license review, provenance verification, and deployment policy remain separate
controls.

## Protected release integration requirements

A future protected integration may generate the two SBOMs in the existing
read-only exact-main build job after archive verification. It may then add the
SBOM files to the complete release-evidence artifact and `SHA256SUMS`, while
keeping the canonical PyPI artifact set limited to the wheel and source
distribution.

Attestation must occur in a credential-separated job that consumes only the
independently verified exact artifact set. Use the current `actions/attest`
SBOM mode, pinned to a reviewed immutable commit SHA rather than a mutable tag.
Grant only the permissions required by the reviewed action and repository
configuration; at minimum, GitHub documents `id-token: write` and
`attestations: write`, with repository contents remaining read-only. Recheck
the action's current permission contract before integration instead of copying
a historical example.

Before public GitHub Release publication, verify every distribution attestation
against all of the following:

- the exact wheel or source-distribution SHA-256;
- `ContextualWisdomLab/EgressWeave` as repository identity;
- the expected immutable workflow source and exact protected-main commit;
- the intended CycloneDX 1.7 SBOM predicate bytes; and
- the release tag that already resolves to the accepted exact commit.

The public release must fail closed when any subject, predicate, repository,
workflow, commit, tag, schema, checksum, or signature check differs. A branch
must never add a temporary job that publishes, moves refs, writes repository
contents, pushes to a pull-request branch, self-modifies workflows, or executes
model-modified source under a write credential.

## Threat model

The evidence controls address these bounded threats:

- dependency or license inventory omitted from acquisition evidence;
- a correct SBOM attached to the wrong wheel or source distribution;
- an archive filename substituted without changing its apparent version;
- mutable or independently resolved dependencies entering evidence;
- nondeterministic timestamps or identifiers preventing reproducibility checks;
- archive path traversal, link, device, metadata-size, or metadata-ambiguity
  attacks against the evidence generator;
- a stale, off-repository, or wrong-workflow attestation being presented as the
  release attestation; and
- public release creation before exact evidence verification.

The controls do not claim to detect compromised upstream source, malicious but
properly hashed dependencies, every license obligation, build-host compromise,
or undisclosed vulnerabilities. Those risks require provenance, reproducible
build, vulnerability-management, legal-review, and runner-hardening controls.

## Failure and recovery

- **Generator failure:** publish nothing. Correct the artifact, reviewed
  dependency manifest, or generator in a normal reviewed pull request, rebuild
  from the exact accepted source, and regenerate all evidence.
- **Digest or semantic mismatch:** treat the artifact set as untrusted. Never
  edit an SBOM to make it match existing bytes; rebuild or issue a new version.
- **Attestation failure:** retain no public release. Correct only the protected
  credential-separated attestation mechanism and rerun it against the unchanged
  exact verified artifact set.
- **Protected main advances:** discard the stale release attempt and rebuild from
  the newly reviewed exact main head. Do not move an existing release tag.
- **Partial external publication:** never replace bytes under an existing
  version. Recover with a new version and a transparent changelog entry.
- **Manifest drift:** update the lock and manifest together, regenerate both
  artifact SBOMs, and require tests to demonstrate the intended graph.

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

Python Packaging Authority. (n.d.). *Package index JSON API.* Python Packaging
User Guide. Retrieved August 5, 2026, from
https://docs.pypi.org/api/json/

Supply-chain Levels for Software Artifacts Community. (2025). *SLSA
specification version 1.2.* https://slsa.dev/spec/v1.2/
