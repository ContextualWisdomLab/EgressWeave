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
   installed wheel, and uploads two immutable artifact sets:
   - canonical wheel and sdist only for PyPI;
   - wheel, sdist, and `SHA256SUMS` as complete release evidence.
4. A credential-separated tag job creates the lightweight `v<version>` tag at
   the exact reviewed SHA. If the tag already exists at another commit, the run
   fails rather than moving it.
5. The `publish-to-pypi` job enters the protected `pypi` environment. Its only
   steps download the canonical distribution artifact and invoke the pinned
   PyPA Trusted Publishing action with attestations enabled. It receives no
   repository-content write permission and no long-lived package-index token.
6. Only after PyPI succeeds, the final job rechecks that the tag still points to
   the reviewed SHA, verifies `SHA256SUMS`, creates a draft GitHub Release with
   all evidence attached, and then publishes that complete draft. It refuses to
   overwrite an existing public release.

## Failure and retry semantics

- A build or acceptance failure creates no tag, PyPI package, or GitHub Release.
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
- Download both artifacts and verify them against the attached `SHA256SUMS`.
- Install the wheel in clean Python 3.10 and Python 3.13 environments and run a
  minimal import/version check outside the source tree.
- Confirm the GitHub Release tag resolves to the exact workflow and protected
  `main` commit.
- Restore an empty `[Unreleased]` section only in the next normal development PR.

## Authoritative references

- [GitHub Docs: Manually running a workflow](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)
- [GitHub Docs: Events that trigger workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)
- [PyPI Docs: Publishing with a Trusted Publisher](https://docs.pypi.org/trusted-publishers/using-a-publisher/)
- [PyPI Docs: Trusted Publishing security model](https://docs.pypi.org/trusted-publishers/security-model/)
