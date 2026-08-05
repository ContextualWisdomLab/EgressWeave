# SBOM release evidence

## Purpose and boundary

EgressWeave generates deterministic CycloneDX 1.7 JSON software bills of
materials (SBOMs) for canonical wheel and source-distribution artifacts. Each
SBOM binds the exact distribution bytes by SHA-256, records package identity,
and models the reviewed runtime dependency closure with SPDX license identifiers
and package URLs (purls).

The generator is a read-only evidence foundation and does not authorize a
pull-request branch to execute release logic with write credentials. Signed
integration is confined to the
protected-main or organization-level reusable workflow boundary. This
repository implements it in
`.github/workflows/release.yml`, which refuses to run unless the dispatched
source equals the exact current protected `main` head. The attestation job is
credential-separated from tag creation, PyPI publication, and GitHub Release
publication. No SLSA Build level is claimed merely because an
SBOM or attestation exists.

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

The protected release workflow generates both SBOMs in its read-only exact-main
build job after distribution verification. It adds them to the complete
release-evidence artifact and `SHA256SUMS`, while keeping PyPI inputs limited to
the wheel and source distribution.

A separate attestation job begins only after the exact immutable release tag has
been created or verified. The job downloads the checksummed evidence, uses
`actions/attest` pinned to reviewed commit
`1e69f48acb82d1966a394da916b4c1698aa569d6`, and signs the wheel and source
distribution separately with custom predicates whose type is
`https://cyclonedx.org/bom`. Custom predicate mode is deliberate: the reviewed
deterministic documents omit random CycloneDX `serialNumber` values, while the
pinned action’s convenience SBOM detector currently requires that field. Its
repository access remains read-only; the only elevated capabilities are the
OIDC and attestation permissions required by the reviewed action.

Before PyPI or public GitHub Release publication, the job verifies the exact
locally generated bundles with `gh attestation verify`. Verification constrains:

- repository identity to `ContextualWisdomLab/EgressWeave`;
- signer workflow to `.github/workflows/release.yml`;
- source digest and source ref to the current workflow event;
- runner provenance to GitHub-hosted infrastructure;
- predicate type to `https://cyclonedx.org/bom`; and
- predicate JSON to the exact generated SBOM bytes after JSON decoding.

The Sigstore bundles are copied into the release-evidence set and a new sorted
`SHA256SUMS` binds the distributions, SBOMs, and bundles. PyPI publication and
public GitHub Release publication both depend on successful signed-evidence
verification. A branch must never add a temporary job that publishes, moves
refs, writes contents, pushes to a pull-request branch, self-modifies workflows,
or executes model-modified source under a write credential.

### Offline verification

The GitHub Release carries the two distribution artifacts, two `.cdx.json`
files, two signed bundle files, and `SHA256SUMS`. Verify the checksum set before
parsing any artifact. On an authenticated online system, obtain the current
trusted roots with `gh attestation trusted-root`; transfer the resulting
`trusted_root.jsonl` through an independently authenticated channel. An
air-gapped verifier can then run:

```bash
gh attestation verify egressweave-<version>-py3-none-any.whl \
  --bundle wheel.sbom.attestation.json \
  --custom-trusted-root trusted_root.jsonl \
  -R ContextualWisdomLab/EgressWeave \
  --predicate-type https://cyclonedx.org/bom \
  --signer-workflow \
    ContextualWisdomLab/EgressWeave/.github/workflows/release.yml
```

Repeat for the source distribution and compare each verified predicate to the
corresponding attached CycloneDX document.

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
