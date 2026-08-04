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
RELEASE_DOCUMENTATION_PATH = REPOSITORY_ROOT / "docs" / "release.md"
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

    assert "packaging==26.2" in requirements
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
    """Keep build execution separate from the OIDC-enabled publishing job."""
    workflow = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "release:" in workflow
    assert "types: [published]" in workflow
    assert "build-distributions:" in workflow
    assert "publish-to-pypi:" in workflow
    assert "environment:" in workflow
    assert "name: pypi" in workflow
    assert "id-token: write" in workflow
    assert PYPI_PUBLISH_ACTION in workflow
    assert UPLOAD_ARTIFACT_ACTION in workflow
    assert DOWNLOAD_ARTIFACT_ACTION in workflow
    assert "python scripts/ci/verify_distribution.py --release-ref" in workflow
    assert "sha256sum --check SHA256SUMS" in workflow


def test_release_tag_is_bound_to_the_event_and_protected_main_head() -> None:
    """Reject mutable, stale, off-branch, or prerelease publication targets."""
    workflow = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "name: Verify stable release and exact reviewed commit" in workflow
    assert "EXPECTED_RELEASE_SHA: ${{ github.sha }}" in workflow
    assert "RELEASE_IS_PRERELEASE: ${{ github.event.release.prerelease }}" in workflow
    assert "git fetch --no-tags origin main" in workflow
    assert 'tagged_sha="$(git rev-parse HEAD)"' in workflow
    assert 'main_sha="$(git rev-parse origin/main)"' in workflow
    assert '"$tagged_sha" != "$EXPECTED_RELEASE_SHA"' in workflow
    assert '"$tagged_sha" != "$main_sha"' in workflow


def test_pypi_job_uploads_only_distribution_archives() -> None:
    """Keep checksum evidence available without presenting it as a PyPI package."""
    workflow = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "path: release-evidence" in workflow
    assert "working-directory: release-evidence" in workflow
    assert "name: Prepare publish-only directory" in workflow
    assert "cp release-evidence/*.whl release-evidence/*.tar.gz dist/" in workflow
    assert "packages-dir: dist" in workflow
    assert "cp release-evidence/SHA256SUMS dist/" not in workflow


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
