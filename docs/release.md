# Release runbook

EgressWeave releases use a credential-separated GitHub Actions workflow and
PyPI Trusted Publishing. The workflow is dispatched manually from protected
`main` with an explicit `v<version>` input. The build job receives no write or
publishing identity, a separate read-only evidence job proves the exact
integrating pull request and its live governance evidence, the tag job receives
only repository-content write access, the PyPI job receives only artifact-read
and OIDC permissions, and the final GitHub Release job receives no PyPI identity.

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
   100% statement/branch coverage, docstring checks, any actually required
   independent review, and all required-workflow gates pass. A wrapper-green
   Security Scan is not sufficient when its pinned `Dependency review` action
   was skipped or otherwise did not execute successfully.

### Credential-free release-evidence preparation

After local and pull-request package acceptance, the separately documented
[release-evidence preparation control](release-evidence-preparation.md) may be
run only from a read-only, credential-free checkout detached at the exact
accepted source SHA. It requires exactly one wheel and matching source
distribution, applies compressed-byte bounds before archive parsing, and creates
the deterministic six-file evidence set plus a separately stored handoff for
independent re-verification.

This branch-local preparer is not integrated into the credential-bearing release
workflow and does not modify or weaken that workflow's tag, OIDC, publication,
release, or approval boundaries. Its output is a credential-free consistency
handoff, not hosted build provenance, publication authorization, or a SLSA Build
level claim.

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
4. In parallel, the read-only `verify-release-evidence` job binds the exact
   protected-main commit to exactly one merged integrating PR, resolves that
   PR's immutable contributor head, reads the active branch rulesets applicable
   to protected main, and paginates the exact-head required-workflow evidence.
   Every required workflow must be the repository-required workflow instance on
   that same source head and must be completed-success. Current-head non-author
   approvals are counted only when live rules require them, required review
   threads must be resolved, and governance modes the verifier cannot prove
   safely fail closed rather than being guessed.
5. The evidence job separately opens the exact Security Scan run and requires
   the `dependency-review` job plus the pinned `Dependency review` action step
   itself to have completed successfully. A successful wrapper job with that
   action absent, skipped, queued, neutral, cancelled, failed, or stale is a
   publication blocker. When Strix is an active ruleset-required workflow, the
   same evidence job also requires exactly one completed-successful `strix` job
   and inspects that job's check-run annotations. A `Strix backend unavailable`
   annotation is a publication blocker even when the wrapper job is green. Strix
   evidence is enforced only when the active ruleset requires Strix. These
   checks verify central evidence; they do not copy or replace centrally owned
   scanners or reviewers.
6. A credential-separated tag job waits for both build acceptance and the
   evidence verifier, rechecks that the live protected `main` head still equals
   the accepted workflow SHA, then creates the lightweight `v<version>` tag at
   that exact reviewed commit. If `main` advanced after acceptance, or the tag
   already exists at another commit, the run fails rather than publishing stale
   evidence or moving the tag.
7. The `publish-to-pypi` job also depends directly on the evidence verifier and
   enters the protected `pypi` environment. Its only steps download the
   canonical distribution artifact and invoke the pinned PyPA Trusted Publishing
   action with attestations enabled. It receives no repository-content write
   permission and no long-lived package-index token.
8. Only after PyPI succeeds, the final job rechecks that the tag still points to
   the reviewed SHA, verifies `SHA256SUMS`, creates a draft GitHub Release with
   all evidence attached, and then publishes that complete draft. It refuses to
   overwrite an existing public release and also depends directly on the same
   release-evidence gate.

## Failure and retry semantics

- A build, evidence-admission, or acceptance failure creates no tag, PyPI
  package, or GitHub Release.
- Missing, stale, skipped, non-successful, or ambiguous required-workflow
  evidence fails closed. Repair or regenerate the authoritative PR evidence;
  never substitute a local scanner or aggregate status for the missing gate.
- If protected-main governance changes to a review mode the verifier cannot
  prove safely, publication stops until a narrow evidence proof is implemented
  and reviewed.
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
- Download both artifacts and verify them against the attached `SHA256SUMS`.
- Inspect the released source commit's integrating PR and confirm the exact-head
  required-workflow set is still attributable, including an actually executed
  successful `Dependency review` action in Security Scan and, when required by
  the active ruleset, substantive completed-successful Strix evidence without a
  backend-unavailable annotation.
- Install the wheel in clean Python 3.10 and Python 3.13 environments and run a
  minimal import/version check outside the source tree.
- Confirm the GitHub Release tag resolves to the exact workflow and protected
  `main` commit.
- Restore an empty `[Unreleased]` section only in the next normal development PR.

## Authoritative references

- [GitHub Docs: Manually running a workflow](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)
- [GitHub Docs: Events that trigger workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)
- [GitHub Docs: REST API endpoints for rules](https://docs.github.com/en/rest/repos/rules)
- [GitHub Docs: REST API endpoints for commits](https://docs.github.com/en/rest/commits/commits)
- [PyPI Docs: Publishing with a Trusted Publisher](https://docs.pypi.org/trusted-publishers/using-a-publisher/)
- [PyPI Docs: Trusted Publishing security model](https://docs.pypi.org/trusted-publishers/security-model/)
