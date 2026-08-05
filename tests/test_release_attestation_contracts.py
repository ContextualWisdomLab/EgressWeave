"""Contracts for signed, artifact-bound SBOM release evidence."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "release.yml"
SBOM_DOCUMENTATION_PATH = REPOSITORY_ROOT / "docs" / "sbom-release-evidence.md"
ATTEST_ACTION = "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26"
CYCLONEDX_PREDICATE_TYPE = "https://cyclonedx.org/bom"


def _workflow() -> str:
    """Return the exact protected release workflow source as UTF-8 text."""
    return RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")


def _job(workflow: str, start: str, end: str | None) -> str:
    """Return one top-level release job without neighbouring permission scopes."""
    remainder = workflow.split(start, maxsplit=1)[1]
    return remainder if end is None else remainder.split(end, maxsplit=1)[0]


def test_release_build_generates_two_sboms_and_complete_checksums() -> None:
    """Bind each canonical distribution and SBOM into one deterministic evidence set."""
    workflow = _workflow()
    build_job = _job(workflow, "  build-distributions:", "  create-release-tag:")

    assert build_job.count("python scripts/ci/generate_release_sbom.py") == 2
    assert "--manifest scripts/ci/release_runtime_dependencies.json" in build_job
    assert "--lock requirements-ci.txt" in build_job
    assert ".whl.cdx.json" in build_job
    assert ".tar.gz.cdx.json" in build_job
    assert "Finalize complete release evidence checksums" in build_job
    assert "expected_evidence_count = 4" in build_job
    assert "sha256sum --check SHA256SUMS" in build_job


def test_attestation_job_has_only_required_signing_permissions() -> None:
    """Keep untrusted project execution outside the OIDC-enabled signer."""
    workflow = _workflow()
    attest_job = _job(
        workflow,
        "  attest-release-evidence:",
        "  verify-release-attestations:",
    )

    assert "actions: read" in attest_job
    assert "contents: read" in attest_job
    assert "id-token: write" in attest_job
    assert "attestations: write" in attest_job
    assert "artifact-metadata: write" in attest_job
    assert "contents: write" not in attest_job
    assert "packages: write" not in attest_job
    assert "actions/checkout@" not in attest_job
    assert attest_job.count(ATTEST_ACTION) == 2
    assert attest_job.count("subject-path:") == 2
    assert attest_job.count("sbom-path:") == 2
    assert "release-attestations-${{ github.sha }}" in attest_job


def test_read_only_verifier_enforces_exact_sbom_attestation_identity() -> None:
    """Verify subject, predicate, workflow, commit, ref, and predicate bytes."""
    workflow = _workflow()
    verify_job = _job(
        workflow,
        "  verify-release-attestations:",
        "  publish-to-pypi:",
    )

    assert "actions: read" in verify_job
    assert "contents: read" in verify_job
    assert "contents: write" not in verify_job
    assert "id-token: write" not in verify_job
    assert "attestations: write" not in verify_job
    assert "gh attestation verify" in verify_job
    assert f"--predicate-type {CYCLONEDX_PREDICATE_TYPE}" in verify_job
    assert '--signer-workflow "${GITHUB_REPOSITORY}/.github/workflows/release.yml"' in verify_job
    assert '--source-digest "$RELEASE_SHA"' in verify_job
    assert "--source-ref refs/heads/main" in verify_job
    assert "--deny-self-hosted-runners" in verify_job
    assert "verificationResult.statement.predicate" in verify_job
    assert "verified-release-attestations-${{ github.sha }}" in verify_job


def test_publication_waits_for_verified_attestations() -> None:
    """Publish neither PyPI nor GitHub Release before attestation verification."""
    workflow = _workflow()
    publish_job = _job(workflow, "  publish-to-pypi:", "  publish-github-release:")
    release_job = _job(workflow, "  publish-github-release:", None)

    assert "- verify-release-attestations" in publish_job
    assert "- verify-release-attestations" in release_job
    assert "verified-release-attestations-${{ github.sha }}" in release_job
    assert "sha256sum --check ATTESTATION_SHA256SUMS" in release_job
    assert 'release-evidence/* attestation-evidence/*' in release_job


def test_operator_guidance_supports_exact_offline_verification() -> None:
    """Document bundle-based offline verification without overstating SLSA."""
    guidance = SBOM_DOCUMENTATION_PATH.read_text(encoding="utf-8")

    assert "gh attestation trusted-root" in guidance
    assert "--bundle" in guidance
    assert "--custom-trusted-root" in guidance
    assert f"--predicate-type {CYCLONEDX_PREDICATE_TYPE}" in guidance
    assert "--signer-workflow" in guidance
    assert "No SLSA Build level is claimed" in guidance
