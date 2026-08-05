# Release runbook

EgressWeave releases use a credential-separated GitHub Actions workflow and
PyPI Trusted Publishing. The workflow is dispatched manually from protected
`main` with an explicit `v<version>` input. The build job receives no write or
publishing identity, the tag job receives only repository-content write access,
the PyPI job receives only artifact-read and OIDC permissions, and the final
GitHub Release job receives no PyPI identity.

Release readiness does not itself mean the package is publicly installable.
`pip install egressweave` becomes an authoritative installation path only after
the corresponding version is visible on PyPI with its wheel, source
distribution, and publish-attestation evidence. The public GitHub Release is
created only after PyPI publication succeeds and the exact tag and artifact
checksums have been re-verified.

## One-time repository and PyPI configuration

1. Create a protected GitHub environment named `pypi`.
2. In the PyPI project settings, add a Trusted Publisher for:
   - owner: `ContextualWisdomLab`
   - repository: `EgressWeave`
   - workflow: `release.yml`
   - environment: `pypi`
3. Keep the environment free of long-lived PyPI API tokens. Configure required
   reviewers only when the organization has an independent maintainer able to
   satisfy that gate.
4. Protect the `v*` tag namespace so only authorized release maintainers and the
   reviewed workflow can create release tags. Never permit force-updating a
   release tag.
5. Keep the release workflow and every third-party action pinned to reviewed
   commit SHAs.

The project cannot be published through this workflow until the PyPI project or
pending Trusted Publisher exists. That external enrollment is deliberately not
a repository-secret fallback.

## Prepare a release pull request

1. Confirm the open PR count is zero and `main` is green.
2. Choose the next SemVer version and update both `pyproject.toml` and
   `src/egressweave/__init__.py`.
3. Move all intended entries from `[Unreleased]` into a dated
   `## [<version>] - YYYY-MM-DD` section in `CHANGELOG.md`. Leave the
   `[Unreleased]` body empty.
4. Run the complete local quality and package-acceptance commands:

   ```bash
   python -m pip install --require-hashes -r requirements-ci.txt
   python -m pip install --require-hashes -r requirements-release.txt
   ruff check .
   coverage run -m pytest -q
   coverage report -m
   rm -rf dist
   python -m hatchling build
   python scripts/ci/verify_distribution.py --dist-dir dist
   python -m venv /tmp/egressweave-release-smoke
   /tmp/egressweave-release-smoke/bin/python -m pip install \
     --require-hashes -r requirements-ci.txt
   /tmp/egressweave-release-smoke/bin/python -m pip install \
     --no-deps dist/egressweave-*.whl
   cd /tmp
   /tmp/egressweave-release-smoke/bin/python -c \
     'import egressweave; print(egressweave.__version__)'
   ```

5. Merge only after current-head CI, package acceptance, SAST, security scans,
   100% statement/branch coverage, docstring checks, and independent review
   gates pass.

## Publish

1. Open **Actions → release → Run workflow**.
2. Select `main`, enter the exact `v<version>` release tag, and start the run.
   Dispatching another branch fails closed.
3. The read-only build job verifies that the workflow SHA equals the current
   protected `main` head, reruns all quality gates, builds wheel and sdist with
   hash-locked tooling, rejects any additional publishable archive, binds the
   requested tag to package metadata and the dated changelog, smoke-tests the
   installed wheel, generates deterministic CycloneDX 1.7 SBOMs for both exact
   distributions, and uploads two immutable artifact sets:
   - canonical wheel and sdist only for PyPI;
   - wheel, sdist, both `.cdx.json` files, and `SHA256SUMS` as complete release
     evidence.
4. A credential-separated tag job rechecks that the live protected `main` head
   still equals the accepted workflow SHA, then creates the lightweight
   `v<version>` tag at that exact reviewed commit. If `main` advanced after
   acceptance, or the tag already exists at another commit, the run fails
   rather than publishing stale evidence or moving the tag.
5. A credential-separated attestation job downloads only the exact checksummed
   evidence, verifies it, and uses the immutable `actions/attest` v4 commit to
   create one signed CycloneDX attestation for the wheel and one for the source
   distribution. The workflow uses the action’s custom predicate mode because
   EgressWeave intentionally omits random CycloneDX `serialNumber` values; the
   predicate type remains `https://cyclonedx.org/bom` and predicate bytes remain
   deterministic. The job receives read-only repository access plus only
   `id-token: write`, `attestations: write`, and the artifact-metadata permission
   required by the reviewed action. It does not receive tag, release, package, or
   pull-request write authority.
6. The same job immediately verifies the exact locally generated Sigstore
   bundles with `gh attestation verify`. Verification requires repository
   `ContextualWisdomLab/EgressWeave`, signer workflow
   `.github/workflows/release.yml`, the exact protected-main source digest and
   source ref, a GitHub-hosted runner, and predicate type
   `https://cyclonedx.org/bom`. It then compares each verified predicate to the
   generated CycloneDX 1.7 JSON, preserves both bundles, and refreshes
   `SHA256SUMS` over the complete evidence set.
7. The `publish-to-pypi` job enters the protected `pypi` environment only after
   signed SBOM verification. Its only steps download the canonical distribution
   artifact and invoke the pinned PyPA Trusted Publishing action with
   attestations enabled. It receives no repository-content write permission and
   no long-lived package-index token.
8. Only after PyPI succeeds, the final job downloads the attested evidence,
   rechecks that the tag still points to the reviewed SHA, verifies
   `SHA256SUMS`, creates a draft GitHub Release with all evidence attached, and
   then publishes that complete draft. It refuses to overwrite an existing
   public release.

## Failure and retry semantics

- A build or acceptance failure creates no tag, PyPI package, or GitHub Release.
- If `main` changes before tag creation, start a fresh release run from the new
  reviewed head rather than tagging the stale accepted artifact set.
- If exact tag creation succeeds but PyPI publication is blocked, the immutable
  tag remains at the reviewed commit. Correct the external publisher or
  environment configuration and rerun the failed jobs; do not move the tag.
- If the final GitHub Release job leaves a draft, a retry may delete and rebuild
  only that recoverable draft. An existing public release is never replaced.
- Never republish changed bytes under an existing version. Correct a release
  with a new version and a transparent changelog entry.

## Post-release verification

- Confirm PyPI shows both wheel and source distribution for the exact version.
- Inspect PyPI provenance and publish-attestation evidence.
- Download both distributions, both CycloneDX 1.7 SBOMs, the two signed SBOM
  attestation bundles, and `SHA256SUMS`; verify the complete checksum set.
- Verify each distribution against the repository SBOM attestation, for example:

  ```bash
  gh attestation verify egressweave-<version>-py3-none-any.whl \
    --bundle wheel.sbom.attestation.json \
    -R ContextualWisdomLab/EgressWeave \
    --predicate-type https://cyclonedx.org/bom \
    --signer-workflow \
      ContextualWisdomLab/EgressWeave/.github/workflows/release.yml
  ```

  Repeat for the source distribution and compare the verified predicate JSON to
  the attached `.cdx.json` document. For an air-gapped verifier, obtain a trusted
  root on an authenticated online system with `gh attestation trusted-root`, move
  that root with the checksummed evidence, and add
  `--custom-trusted-root trusted_root.jsonl` to the bundle verification command.
- Install the wheel in clean Python 3.10 and Python 3.13 environments and run a
  minimal import/version check outside the source tree.
- Confirm the GitHub Release tag resolves to the exact workflow and protected
  `main` commit.
- Restore an empty `[Unreleased]` section only in the next normal development PR.

A signed SBOM attestation is evidence binding an exact artifact digest to the
reviewed CycloneDX predicate and workflow identity. No SLSA Build level is
claimed merely because SBOMs, Sigstore bundles, PyPI attestations, or GitHub
artifact attestations exist; any future SLSA claim requires a separate mapping
to every normative requirement of the claimed level.

## Authoritative references — APA 7th

Ecma International, & OWASP Foundation. (2025). *CycloneDX specification 1.7
(ECMA-424).* https://cyclonedx.org/specification/overview/

GitHub. (n.d.). *Manually running a workflow.* GitHub Docs. Retrieved August 5,
2026, from https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow

GitHub. (n.d.). *Using artifact attestations to establish provenance for
builds.* GitHub Docs. Retrieved August 5, 2026, from
https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations

GitHub. (n.d.). *Verifying attestations offline.* GitHub Docs. Retrieved August
5, 2026, from
https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline

GitHub. (2026). *actions/attest* (Version 4) [Computer software].
https://github.com/actions/attest

in-toto Project. (n.d.). *Predicate type: CycloneDX.* Retrieved August 5, 2026,
from https://github.com/in-toto/attestation/blob/main/spec/predicates/cyclonedx.md

Python Packaging Authority. (n.d.). *Publishing with a Trusted Publisher.* PyPI
Docs. Retrieved August 5, 2026, from
https://docs.pypi.org/trusted-publishers/using-a-publisher/

Python Packaging Authority. (n.d.). *Trusted Publishing security model.* PyPI
Docs. Retrieved August 5, 2026, from
https://docs.pypi.org/trusted-publishers/security-model/
