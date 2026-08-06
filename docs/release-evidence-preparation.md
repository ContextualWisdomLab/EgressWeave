# Release evidence preparation runbook

## Purpose and trust boundary

`scripts/ci/prepare_release_evidence.py` prepares the exact credential-free input
set consumed by the shipped sealed-evidence verifier. It operates only on inert,
already-built wheel and source-distribution archives. It does not import either
distribution, resolve dependencies, use the network, sign an artifact, publish a
package, create or move a tag, alter a protected ref, or acquire repository-write,
OIDC, attestation, package-index, or release credentials.

The preparation control is intentionally separate from the organization-owned
credentialed attestation workflow. A valid handoff proves that one exact local
six-file set is internally consistent and bound to an explicit repository and
source commit. It does **not** prove that the distributions were honestly built
from that source and does not claim a SLSA Build level. That stronger claim
requires independently reviewed hosted-build provenance and credential-separated
attestation verification.

## Initial directory contract

Use a fresh real directory reached through a canonical absolute path with no
symbolic-link component. Before preparation, the directory must contain exactly
two regular direct-child files for one matching stable version:

```text
egressweave-X.Y.Z-py3-none-any.whl
egressweave-X.Y.Z.tar.gz
```

Any additional file, nested directory, symbolic link, malformed archive name,
duplicate distribution kind, or wheel/source version mismatch fails before an
evidence output is created. The reviewed dependency manifest and hash-locked
runtime requirements must also be existing canonical regular files.

The handoff-manifest parent must already exist as a real canonical directory. The
handoff path must remain outside the evidence directory. The preparer never
creates convenience directory aliases and never follows an output-path symbolic
link.

## Credential-free command

Run this only after the exact protected-main source commit has passed all quality,
security, review, approval, package-acceptance, and reproducibility gates:

```bash
PYTHONPATH=src python scripts/ci/prepare_release_evidence.py \
  --evidence-dir "$RUNNER_TEMP/release-evidence" \
  --handoff-manifest "$RUNNER_TEMP/release-evidence-manifest.json" \
  --repository ContextualWisdomLab/EgressWeave \
  --source-sha "$GITHUB_SHA" \
  --dependency-manifest scripts/ci/runtime-dependency-manifest.json \
  --runtime-lock requirements-runtime.txt
```

The command must run in a job whose token has no write permission and whose
checkout is detached at the exact accepted source SHA with persisted credentials
disabled. The job must not expose signing, publication, release, tag, model, or
attestation credentials.

## Generated contract

The preparer computes both deterministic CycloneDX 1.7 JSON documents in memory,
constructs canonical strict-JSON source identity, computes sorted lowercase
SHA-256 entries, and then exclusively creates owner-only generated files. After
successful preparation, the evidence directory contains exactly:

```text
egressweave-X.Y.Z-py3-none-any.whl
egressweave-X.Y.Z-py3-none-any.whl.cdx.json
egressweave-X.Y.Z.tar.gz
egressweave-X.Y.Z.tar.gz.cdx.json
SOURCE_IDENTITY.json
SHA256SUMS
```

`SOURCE_IDENTITY.json` uses the versioned canonical profile documented in
`sealed-release-evidence.md`. `SHA256SUMS` covers all five other payloads and is
ordered by filename, not by digest. The SBOM root components bind to the exact
archive filenames and SHA-256 values and use deterministic content-derived UUID
version 5 serial numbers.

The preparer then invokes the shipped verifier to:

1. validate cardinality, names, sizes, strict JSON, source identity, checksums,
   CycloneDX profile, artifact/SBOM bindings, and descriptor/path identity;
2. create a new owner-only deterministic handoff manifest outside the set;
3. independently rebuild the complete manifest semantics from a second bounded
   evidence pass;
4. reread the closed handoff through bounded descriptor/path checks; and
5. report success only when both post-publication snapshots exactly match.

## Failure and retry semantics

Every failure is non-success. A failed run may leave newly created but untrusted
partial evidence because local filesystems cannot atomically publish six separate
paths as one transaction. Never repair, overwrite, or reuse that candidate in
place. Delete the complete disposable directory and failed handoff, rebuild the
wheel and source distribution from the unchanged exact accepted source in a clean
credential-free job, and run the full preparation again with a fresh output path.

Do not treat a queued check, review latency, an incomplete automated review, or a
pending external approval as accepted release evidence. Do not pass a failed or
partially generated set to any job holding write, OIDC, attestation, publication,
tag, or release authority.

## Credentialed consumer requirements

A later organization-owned reusable workflow may consume only an immutable copy
of the six payloads plus the separately stored handoff. Before requesting an
attestation, that workflow must recheck the exact repository, source SHA,
source-identity digest, checksum-file digest, payload cardinality, and every
payload digest. It must not rebuild archives, resolve dependencies, import the
wheel, execute repository scripts, or accept a branch name in place of the exact
source commit while privileged credentials are present.

Workflow source must be immutable and independently reviewed. Artifact transfer
must be digest-bound, and publication must refuse stale protected-main heads,
mutable tags, alternate artifact sets, or handoff/source disagreement. The
repository-side preparer deliberately contains no fallback that weakens these
organization controls.

## Standards alignment and precise claims

- The JSON encoders reject non-finite values and emit deterministic RFC 8259 JSON.
- SBOMs use the CycloneDX 1.7 JSON schema and bind their root components to exact
  distribution bytes.
- Repository and source identity are checksum-covered assertions, not provenance.
- No SLSA Build level is claimed. Future claims must be stated as `SLSA Build Lx
  (v1.2)` only after every normative requirement is mapped to independently
  verifiable evidence.
- The clean rebuild and evidence-preservation procedure supports NIST SSDF
  practices for protecting release integrity and retaining evidence useful to
  suppliers, purchasers, and assessors.

## References

Bray, T. (2017). *The JavaScript Object Notation (JSON) data interchange format*
(RFC 8259). Internet Engineering Task Force. https://doi.org/10.17487/RFC8259

OWASP Foundation. (n.d.). *CycloneDX v1.7 JSON reference*. Retrieved August 6,
2026, from https://cyclonedx.org/docs/1.7/json/

Souppaya, M., Scarfone, K., & Dodson, D. (2022). *Secure software development
framework (SSDF) version 1.1: Recommendations for mitigating the risk of software
vulnerabilities* (NIST SP 800-218). National Institute of Standards and
Technology. https://doi.org/10.6028/NIST.SP.800-218

Supply-chain Levels for Software Artifacts. (n.d.). *Build provenance: SLSA
specification v1.2*. Retrieved August 6, 2026, from
https://slsa.dev/spec/v1.2/build-provenance
