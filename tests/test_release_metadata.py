"""Release metadata consistency checks."""

from pathlib import Path

from packaging.version import Version

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_declared_version_has_a_dated_changelog_section() -> None:
    """Keep package metadata and the buyer-visible release history aligned."""
    project_metadata = tomllib.loads(
        (REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    version = project_metadata["project"]["version"]
    Version(version)

    changelog = (REPOSITORY_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    release_heading = f"## [{version}] - "

    assert release_heading in changelog
    assert changelog.index("## [Unreleased]") < changelog.index(release_heading)
