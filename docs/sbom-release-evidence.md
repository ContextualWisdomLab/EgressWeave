# SBOM release evidence

## Purpose and boundary

EgressWeave generates deterministic CycloneDX 1.7 JSON software bills of
materials (SBOMs) for canonical wheel and source-distribution artifacts. Each
SBOM binds the exact distribution bytes by SHA-256, records package identity,
and models the reviewed runtime dependency closure with SPDX license identifiers
and package URLs (purls).

This is a read-only evidence foundation. It does not authorize a pull-request
branch to execute release logic with write credentials. The only permitted
future integration source is protected main or an organization-level reusable
workflow whose source is immutable before receiving OIDC or attestation
permissions. No provenance, signing, publication, attestation, or SLSA Build
level follows merely from direct SBOM generation.

## Normative evidence contract

`scripts/ci/generate_release_sbom.py` treats every archive, manifest, and lock
file as untrusted input and never imports EgressWeave. It must:

1. accept only a canonical wheel or gzip source distribution;
2. inspect the caller-supplied final artifact path without resolving its final
   component, require a regular file, enforce a 256 MiB compressed-byte ceiling,
   open without following a final symbolic link where supported, and bind the
   opened descriptor to the accepted device and inode before any parser runs;
3. parse and hash only that descriptor, keep every parser-visible read and seek
   live-bounded by the same compressed-byte ceiling, bracket metadata parsing
   with finite SHA-256 reads, and reject bytes that change during verification;
4. count wheel central-directory records before `zipfile.ZipFile` allocates a
   complete `ZipInfo` table, permit at most 10,000 members, and require the
   physical record count, record boundaries, directory size, directory offset,
   and classic end-of-central-directory counts to agree exactly;
5. reject multi-disk wheels, ZIP64 wheels, truncated or inconsistent central
   directories, and malformed extra fields because those formats are not needed
   by the bounded canonical release contract;
6. stream the gzip/tar physical headers before semantic parsing, permit at most
   10,000 physical members, enforce an aggregate expanded-tar ceiling of
   512 MiB, and permit at most 1 MiB for each PAX or GNU extension-header payload;
7. reject malformed or truncated tar headers, checksum errors, links, devices,
   FIFOs, sparse forms, unsupported special forms, and nonzero trailing data;
8. use sequential `tarfile` parsing without `getmembers()`, retain only the
   bounded seen-name set and one root `PKG-INFO` payload, and preserve the same
   semantic path, duplicate, type, and member-count checks after preflight;
9. reject unsafe or duplicate paths, ambiguous metadata, malformed archives,
   and metadata larger than 1 MiB, checking declared wheel metadata size before
   decompression and bounding source metadata extraction;
10. read exactly one wheel `METADATA` or root source `PKG-INFO` member;
11. verify package identity, license expression, and complete direct runtime
    requirement declarations against the reviewed manifest;
12. verify every dependency version, SHA-256, and environment marker against the
    executable hash-locked subset in `requirements-ci.txt`, while rejecting
    dependency extras that could activate packages outside the reviewed graph;
13. validate identities, reviewed SPDX license identifiers, purls, graph
    references, relationships, reachability, and acyclicity;
14. compute the artifact SHA-256 without trusting its filename; and
15. emit sorted UTF-8 CycloneDX 1.7 JSON without timestamps or random identifiers.

## Resource boundaries and failure behavior

The controls are deliberately layered rather than interchangeable:

| Boundary | Exact limit | Enforced before | Purpose |
|---|---:|---|---|
| Compressed release artifact | 256 MiB | hashing or archive parsing | Bounds descriptor-visible input and concurrent growth |
| Archive members | 10,000 | `ZipFile` table creation and semantic tar materialization | Prevents member-table and parser-object amplification |
| Expanded gzip/tar stream | 512 MiB | physical payload skipping or semantic tar parsing | Bounds decompression and aggregate tar processing |
| PAX/GNU extension payload | 1 MiB per header | retaining extension bytes | Bounds parser metadata controlled by archive authors |
| Core package metadata | 1 MiB | email metadata parsing | Bounds `METADATA` and `PKG-INFO` processing |

The direct generator normalizes missing, uninspectable, symbolic-link,
directory, device, FIFO, socket, replaced, and other non-regular artifact inputs
to `release artifact is missing or unsafe`. Inputs above the compressed-byte
ceiling fail with `release artifact exceeds the compressed-byte safety bound`.
The parser-facing wrapper rechecks the live regular descriptor before and after
reads and seeks, so an initially accepted archive that grows past the ceiling
fails before the parser consumes the expanded input. Bytes that differ across
the descriptor-bound metadata pass fail with
`release artifact changed during verification`.

Canonical wheels and ordinary gzip-compressed source distributions remain
accepted. Multi-disk or ZIP64 wheels and sparse or special tar forms fail closed
because they add parser complexity without serving the release profile.
Accepted compressed size does not imply safe expansion: member, expanded-tar,
extension-header, metadata, path, type, dependency, and digest controls remain
independent defenses.

The root component uses a digest-derived `bom-ref`, preventing different
artifacts from sharing evidence identity. The dependency graph is the union
required across supported Python 3.10 through 3.13 runtimes. Conditional
packages retain their environment markers as explicit properties.

The reviewed manifest is
`scripts/ci/release_runtime_dependencies.json`. Its versions, hashes, and
markers must match `requirements-ci.txt`. Lock entries with PEP 508 extras are
invalid for SBOM parity because an extra can introduce additional runtime
requirements absent from the reviewed component graph. A dependency change is
incomplete until the lock, manifest, tests, license evidence, and SBOM semantics
are reviewed together.

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

Run direct generation from an isolated, read-only exact-artifact directory.
Descriptor identity, bounded reads, physical archive preflight, and digest
bracketing reduce ordinary pathname-replacement, growth, mutation, and resource
amplification risks. They do not make mutable storage immutable: a privileged
writer able to alter and restore the same inode entirely between observations
remains a residual risk.

## Offline operator verification

An operator evaluating an acquired or air-gapped release should:

1. obtain each distribution, CycloneDX JSON, `SHA256SUMS`, and any separately
   produced signed attestation bundle through independently authenticated media;
2. verify `SHA256SUMS` before parsing an archive;
3. confirm the SBOM root hash equals the artifact hash;
4. validate the document against the CycloneDX 1.7 JSON schema;
5. when attestations exist, independently verify their subject, repository,
   immutable workflow source, exact commit, and predicate bytes;
6. inventory purls, versions, SPDX licenses, markers, and relationships; and
7. reject any digest, identity, schema, workflow, signature, or graph mismatch.

An SBOM is inventory evidence, not proof that a dependency is vulnerability
free, correctly licensed for every use, benign, reproducibly built, or produced
by a trusted builder. Vulnerability assessment, legal review, provenance
verification, deployment policy, and reproducible-build evidence remain
separate controls.

## Protected release integration

A future protected integration may generate both SBOMs in a read-only exact-main
build job after distribution verification. It may add the SBOMs to the complete
release-evidence artifact and `SHA256SUMS`, while keeping PyPI inputs limited to
the wheel and source distribution.

Attestation must run in a credential-separated job that consumes only the
independently verified exact artifact set. Pin the current `actions/attest` SBOM
mode to an immutable reviewed commit SHA. Grant only the permissions required by
the reviewed action; repository contents remain read-only. Recheck GitHub's
current permission contract during protected integration.

Before public GitHub Release publication, verify each attestation against the
exact artifact SHA-256, repository identity, immutable workflow source, exact
protected-main commit, CycloneDX predicate bytes, and release tag. Public release
must fail closed on any mismatch.

A branch must never add a temporary job that publishes, moves refs, writes
contents, pushes to a pull-request branch, self-modifies workflows, or executes
model-modified source under a write credential.

## Threats, failure, and recovery

These controls address omitted inventory, evidence bound to the wrong artifact,
filename substitution, path replacement between inspection and parsing,
manifest-versus-lock drift, undeclared dependency extras, mutable dependency
resolution, nondeterministic evidence, unsafe archives, member-table exhaustion,
compressed-input and decompression resource exhaustion, oversized extension or
package metadata, stale or wrong-workflow attestations, and publication before
exact verification.

They do not detect every compromised upstream source, malicious but correctly
hashed package, license obligation, build-host compromise, undisclosed
vulnerability, or privileged mutable-storage attack. Those risks require
provenance, reproducible builds, vulnerability management, legal review,
hardened runners, and sealed or read-only artifact storage.

On any generator, digest, semantic, manifest, lock, or attestation failure,
publish nothing. Correct the source through normal review and regenerate from
the exact accepted commit. Never replace published bytes under an existing
version. If protected main advances, discard the stale attempt and rebuild.
Partial publication requires a new version and transparent changelog entry.

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

MITRE. (2026). *CWE-400: Uncontrolled resource consumption.* Common Weakness
Enumeration. https://cwe.mitre.org/data/definitions/400.html

MITRE. (2026). *CWE-409: Improper handling of highly compressed data (data
amplification).* Common Weakness Enumeration.
https://cwe.mitre.org/data/definitions/409.html

MITRE. (2026). *CWE-770: Allocation of resources without limits or throttling.*
Common Weakness Enumeration. https://cwe.mitre.org/data/definitions/770.html

Python Software Foundation. (n.d.). *tarfile—Read and write tar archive files.*
Python 3.13 documentation. Retrieved August 7, 2026, from
https://docs.python.org/3.13/library/tarfile.html

Python Software Foundation. (n.d.). *zipfile—Work with ZIP archives.* Python
3.13 documentation. Retrieved August 7, 2026, from
https://docs.python.org/3.13/library/zipfile.html

Python Software Foundation. (n.d.). *zipfile—Work with ZIP archives:
Decompression pitfalls.* Python 3.13 documentation. Retrieved August 7, 2026,
from https://docs.python.org/3.13/library/zipfile.html#decompression-pitfalls

Python Packaging Authority. (n.d.). *Core metadata specifications.* Python
Packaging User Guide. Retrieved August 5, 2026, from
https://packaging.python.org/en/latest/specifications/core-metadata/

Supply-chain Levels for Software Artifacts Community. (2025). *SLSA
specification version 1.2.* https://slsa.dev/spec/v1.2/
