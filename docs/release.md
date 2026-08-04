# Release runbook

EgressWeave releases use a credential-separated GitHub Actions workflow and
PyPI Trusted Publishing. The build job receives no publishing identity. A later
job may request a short-lived OIDC token only after the exact release-tag source
has produced and passed distribution acceptance.

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
4. Keep the release workflow and every third-party action pinned to reviewed
   commit SHAs.

The project cannot be published through this workflow until the PyPI project or
pending Trusted Publisher exists. That external enrollment is deliberately not
a repository-secret fallback.

## Prepare a release pull request

1. Confirm the open PR count is zero and `main` is green.
2. Choose the next SemVer version and update both `pyproject.toml` and
   `src/egressweave/__init__.py`.
3. Move all intended entries from `[Unreleased]` into a dated
   `## [<version>] - YYYY-MM-DD` section in `CHANGELOG.md`.
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
   100% statement/branch coverage, docstring checks, and review gates pass.

## Publish

1. Create and publish a GitHub Release with tag `v<version>` targeting the exact
   reviewed `main` commit. Do not use a mutable branch name as release evidence.
2. The `release.yml` workflow checks out that tag, verifies that it matches the
   project version and dated changelog section, rebuilds wheel and sdist from
   hash-locked tooling, validates both archives, writes `SHA256SUMS`, and uploads
   the package artifact.
3. The `publish-to-pypi` job downloads the reviewed artifact, verifies
   `SHA256SUMS`, enters the protected `pypi` environment, obtains an OIDC token,
   and publishes through the pinned PyPA action. PyPI publish attestations remain
   enabled.
4. A separate GitHub Release asset job attaches the wheel, source distribution,
   and `SHA256SUMS` to the already-published release. It does not possess the
   PyPI OIDC permission.

## Post-release verification

- Confirm PyPI shows both wheel and source distribution for the exact version.
- Inspect PyPI provenance and publish-attestation evidence.
- Download both artifacts and verify them against the attached `SHA256SUMS`.
- Install the wheel in a clean Python 3.10 and Python 3.13 environment and run a
  minimal import/version check outside the source tree.
- Confirm the GitHub Release points to the same commit used by the workflow.
- Restore an empty `[Unreleased]` section only in the next normal development PR.

Never republish a changed artifact under an existing version. Correct a release
with a new version and a transparent changelog entry.
