"""Contracts for signed, artifact-bound CycloneDX release evidence."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "release.yml"
RELEASE_DOCUMENTATION_PATH = REPOSITORY_ROOT / "docs" / "release.md"
ATTEST_ACTION = "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"
CYCLONEDX_PREDICATE_TYPE = "https://cyclonedx.org/bom"


def _workflow() -> str:
    """Return the protected release workflow as UTF-8 text."""
    return RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")


def test_build_job_generates_exact_artifact_sboms_before_evidence_upload() -> None:
    """Bind one deterministic CycloneDX document to each accepted distribution."""
    workflow = _workflow()
    build_job = workflow.split("  build-distributions:", maxsplit=1)[1].split(
        "  create-release-tag:", maxsplit=1
    )[0]

    assert "Generate deterministic CycloneDX SBOMs" in build_job
    assert build_job.count("scripts/ci/generate_release_sbom.py") == 2
    assert build_job.count("scripts/ci/release_runtime_dependencies.json") == 2
    assert build_job.count("requirements-ci.txt") >= 3
    assert "*.whl.cdx.json" in build_job
    assert "*.tar.gz.cdx.json" in build_job
    assert "sha256sum --check SHA256SUMS" in build_job
    assert build_job.index("Generate deterministic CycloneDX SBOMs") < build_job.index(
        "Upload complete checksummed release evidence"
    )


def test_attestation_job_has_only_the_required_signing_identity() -> None:
    """Keep signing separate from tag, PyPI, and GitHub Release write identities."""
    workflow = _workflow()
    attestation_job = workflow.split("  attest-release-evidence:", maxsplit=1)[1].split(
        "  publish-to-pypi:", maxsplit=1
    )[0]

    assert "- build-distributions" in attestation_job
    assert "- create-release-tag" in attestation_job
    assert "actions: read" in attestation_job
    assert "contents: read" in attestation_job
    assert "id-token: write" in attestation_job
    assert "attestations: write" in attestation_job
    assert "contents: write" not in attestation_job
    assert "packages: write" not in attestation_job
    assert "pull-requests: write" not in attestation_job
    assert attestation_job.count(ATTEST_ACTION) == 2
    assert attestation_job.count("subject-path:") == 2
    assert attestation_job.count("sbom-path:") == 2


def test_attestations_are_verified_and_preserved_before_public_release() -> None:
    """Reject release publication unless exact subjects and predicates verify."""
    workflow = _workflow()
    attestation_job = workflow.split("  attest-release-evidence:", maxsplit=1)[1].split(
        "  publish-to-pypi:", maxsplit=1
    )[0]
    release_job = workflow.split("  publish-github-release:", maxsplit=1)[1]

    assert attestation_job.count("gh attestation verify") == 2
    assert attestation_job.count(f"--predicate-type {CYCLONEDX_PREDICATE_TYPE}") == 2
    assert "attested-release-evidence-${{ github.sha }}" in attestation_job
    assert "attest-release-evidence" in release_job
    assert "attested-release-evidence-${{ github.sha }}" in release_job
    assert "sha256sum --check SHA256SUMS" in release_job


def test_operator_runbook_documents_signed_sbom_verification() -> None:
    """Give buyers and operators an offline-verifiable evidence procedure."""
    documentation = RELEASE_DOCUMENTATION_PATH.read_text(encoding="utf-8")

    assert "CycloneDX 1.7" in documentation
    assert "signed SBOM attestation" in documentation
    assert "gh attestation verify" in documentation
    assert CYCLONEDX_PREDICATE_TYPE in documentation
    assert "No SLSA Build level" in documentation
