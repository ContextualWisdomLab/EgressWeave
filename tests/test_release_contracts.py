"""Repository contracts for reproducible builds and Trusted Publishing."""

from __future__ import annotations

from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT_PATH = REPOSITORY_ROOT / "pyproject.toml"
README_PATH = REPOSITORY_ROOT / "README.md"
CI_WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "release.yml"
RELEASE_REQUIREMENTS_PATH = REPOSITORY_ROOT / "requirements-release.txt"
RUNTIME_LOCK_PATH = REPOSITORY_ROOT / "requirements-ci.txt"
RELEASE_DOCUMENTATION_PATH = REPOSITORY_ROOT / "docs" / "release.md"
SBOM_DOCUMENTATION_PATH = REPOSITORY_ROOT / "docs" / "sbom-release-evidence.md"
SBOM_GENERATOR_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "generate_release_sbom.py"
SBOM_MANIFEST_PATH = (
    REPOSITORY_ROOT / "scripts" / "ci" / "release_runtime_dependencies.json"
)
DISTRIBUTION_VERIFIER_PATH = (
    REPOSITORY_ROOT / "scripts" / "ci" / "verify_distribution.py"
)
PYPI_PUBLISH_ACTION = (
    "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33"
)
UPLOAD_ARTIFACT_ACTION = (
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
)
DOWNLOAD_ARTIFACT_ACTION = (
    "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
)


def _load_pyproject() -> dict[str, object]:
    """Return the parsed package and tool configuration."""
    with PYPROJECT_PATH.open("rb") as pyproject_file:
        return tomllib.load(pyproject_file)


def test_package_metadata_uses_spdx_and_ships_the_license_file() -> None:
    """Publish unambiguous license metadata and the legal text in distributions."""
    project = _load_pyproject()["project"]

    assert project["license"] == "Apache-2.0"
    assert project["license-files"] == ["LICENSE"]


def test_release_build_dependencies_are_hash_locked() -> None:
    """Prevent mutable release tooling from entering the build runner."""
    requirements = RELEASE_REQUIREMENTS_PATH.read_text(encoding="utf-8")

    required_artifacts = {
        "hatchling-1.31.0-py3-none-any.whl": (
            "aac80bec8b6fe35e8480f1c335be8910fa210a0e6f735a139be205dadcacb544"
        ),
        "pathspec-1.1.1-py3-none-any.whl": (
            "a00ce642f577bf7f473932318056212bc4f8bfdf53128c78bbd5af0b9b20b189"
        ),
        "trove_classifiers-2026.6.1.19-py3-none-any.whl": (
            "ab4c4ec93cc4a4e7815fa759906e05e6bb3f2fbd92ea0f897288c6a43efd15b3"
        ),
    }
    for filename, sha256 in required_artifacts.items():
        assert filename in requirements
        assert f"--hash=sha256:{sha256}" in requirements

    assert "packaging==26.3" in requirements
    assert (
        "--hash=sha256:d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c"
        in requirements
    )
    assert "pluggy==1.6.0" in requirements
    assert "tomli==2.4.1 ; python_version < \"3.11\"" in requirements


def test_ci_builds_and_validates_wheel_and_sdist() -> None:
    """Make package acceptance a pull-request gate rather than a release surprise."""
    workflow = CI_WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "package-acceptance:" in workflow
    assert "python -m hatchling build" in workflow
    assert "python scripts/ci/verify_distribution.py" in workflow
    assert UPLOAD_ARTIFACT_ACTION in workflow


def test_release_workflow_uses_credential_separated_trusted_publishing() -> None:
    """Keep build, tag, OIDC publication, and GitHub Release identities separate."""
    workflow = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "workflow_dispatch:" in workflow
    assert "release_tag:" in workflow
    assert "types: [published]" not in workflow
    assert "build-distributions:" in workflow
    assert "create-release-tag:" in workflow
    assert "publish-to-pypi:" in workflow
    assert "publish-github-release:" in workflow
    assert "environment:" in workflow
    assert "name: pypi" in workflow
    assert "id-token: write" in workflow
    assert PYPI_PUBLISH_ACTION in workflow
    assert UPLOAD_ARTIFACT_ACTION in workflow
    assert DOWNLOAD_ARTIFACT_ACTION in workflow
    assert "python scripts/ci/verify_distribution.py --release-ref" in workflow
    assert "sha256sum --check SHA256SUMS" in workflow


def test_release_source_is_bound_to_manual_input_and_protected_main_head() -> None:
    """Reject mutable, stale, off-branch, or malformed publication targets."""
    workflow = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "name: Verify stable release input and exact reviewed commit" in workflow
    assert "EXPECTED_RELEASE_SHA: ${{ github.sha }}" in workflow
    assert "RELEASE_REF: ${{ github.ref }}" in workflow
    assert "RELEASE_TAG: ${{ inputs.release_tag }}" in workflow
    assert '"$RELEASE_REF" != "refs/heads/main"' in workflow
    assert "git fetch --no-tags origin main" in workflow
    assert 'checked_sha="$(git rev-parse HEAD)"' in workflow
    assert 'main_sha="$(git rev-parse origin/main)"' in workflow
    assert '"$checked_sha" != "$EXPECTED_RELEASE_SHA"' in workflow
    assert '"$checked_sha" != "$main_sha"' in workflow


def test_release_tag_creation_rechecks_the_current_main_head() -> None:
    """Close the race between read-only acceptance and privileged tag creation."""
    workflow = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")
    tag_job = workflow.split("  create-release-tag:", maxsplit=1)[1].split(
        "  publish-to-pypi:", maxsplit=1
    )[0]

    assert 'repos/${GITHUB_REPOSITORY}/commits/main' in tag_job
    assert "current_main_sha" in tag_job
    assert '"$current_main_sha" != "$RELEASE_SHA"' in tag_job
    assert "Protected main moved after artifact verification" in tag_job


def test_pypi_job_receives_only_canonical_distribution_artifacts() -> None:
    """Limit the OIDC-enabled job to immutable artifact retrieval and publication."""
    workflow = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")
    publish_job = workflow.split("  publish-to-pypi:", maxsplit=1)[1].split(
        "  publish-github-release:", maxsplit=1
    )[0]

    assert "name: pypi-distributions-${{ github.sha }}" in publish_job
    assert "path: dist" in publish_job
    assert "packages-dir: dist" in publish_job
    assert PYPI_PUBLISH_ACTION in publish_job
    assert "run:" not in publish_job
    assert "SHA256SUMS" not in publish_job


def test_github_release_is_created_only_after_pypi_publication() -> None:
    """Do not expose a public GitHub Release before exact artifacts reach PyPI."""
    workflow = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")
    release_job = workflow.split("  publish-github-release:", maxsplit=1)[1]

    assert "needs:" in release_job
    assert "- build-distributions" in release_job
    assert "- create-release-tag" in release_job
    assert "- publish-to-pypi" in release_job
    assert "Verify the immutable release tag" in release_job
    assert "gh release create" in release_job
    assert "--verify-tag" in release_job
    assert "sha256sum --check SHA256SUMS" in release_job


def test_readme_distinguishes_release_readiness_from_pypi_availability() -> None:
    """Do not present a future publishing path as evidence of current availability."""
    readme = README_PATH.read_text(encoding="utf-8")

    assert "## Publication status" in readme
    assert "A bare `pip install egressweave` command is authoritative only" in readme
    assert "verified PyPI project page" in readme
    assert "install from a reviewed source checkout" in readme


def test_distribution_verifier_and_release_runbook_are_present() -> None:
    """Require executable acceptance checks and operator-facing release guidance."""
    assert DISTRIBUTION_VERIFIER_PATH.is_file()
    assert RELEASE_DOCUMENTATION_PATH.is_file()

    runbook = RELEASE_DOCUMENTATION_PATH.read_text(encoding="utf-8")
    assert "Trusted Publisher" in runbook
    assert "environment named `pypi`" in runbook
    assert "v<version>" in runbook
    assert "SHA256SUMS" in runbook
    assert "Run workflow" in runbook
    assert "only after PyPI publication succeeds" in runbook


def test_sbom_foundation_is_deterministic_and_keeps_write_identity_separate() -> None:
    """Require reviewed SBOM tooling without weakening the release trust boundary."""
    assert SBOM_GENERATOR_PATH.is_file()
    assert SBOM_MANIFEST_PATH.is_file()
    assert SBOM_DOCUMENTATION_PATH.is_file()
    assert RUNTIME_LOCK_PATH.is_file()

    generator = SBOM_GENERATOR_PATH.read_text(encoding="utf-8")
    assert 'CYCLONEDX_SPEC_VERSION = "1.7"' in generator
    assert "serialNumber" not in generator
    assert '"timestamp"' not in generator
    assert "_sha256_file" in generator
    assert "validate_runtime_lock" in generator
    assert 'for flag in ("artifact", "manifest", "lock", "output")' in generator
    assert "runtime dependency manifest contains unreachable components" in generator
    assert "does not match the hash-locked runtime subset" in generator

    guidance = SBOM_DOCUMENTATION_PATH.read_text(encoding="utf-8")
    assert "exact distribution bytes by SHA-256" in guidance
    assert "--lock requirements-ci.txt" in guidance
    assert "executable hash-locked subset" in guidance
    assert "protected-main or organization-level reusable workflow" in guidance
    assert "No SLSA Build level is claimed" in guidance
    assert "must never add a temporary job" in guidance
