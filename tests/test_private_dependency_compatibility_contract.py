"""Contracts for the private HTTPX/HTTPCore compatibility boundary."""

from __future__ import annotations

from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised only on Python 3.10
    import tomli as tomllib

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _REPOSITORY_ROOT / "pyproject.toml"
_CI_REQUIREMENTS = _REPOSITORY_ROOT / "requirements-ci.txt"
_COMPATIBILITY_GUIDE = (
    _REPOSITORY_ROOT / "docs" / "research" / "private-http-dependency-compatibility.md"
)
_PRIVATE_DEPENDENCY_VERSIONS = {
    "httpx": "0.28.1",
    "httpcore": "1.0.9",
}


def _project_runtime_dependencies() -> tuple[str, ...]:
    """Return the declared runtime dependency requirements from project metadata."""
    project = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["project"]
    return tuple(project["dependencies"])


def test_private_http_dependencies_advertise_only_the_ci_proven_pair() -> None:
    """Do not advertise private-API compatibility beyond the exact pair CI executes."""
    dependencies = _project_runtime_dependencies()

    for package_name, version in _PRIVATE_DEPENDENCY_VERSIONS.items():
        matches = tuple(
            requirement
            for requirement in dependencies
            if requirement.startswith(package_name)
        )
        assert matches == (f"{package_name}=={version}",)


def test_private_http_dependency_identity_matches_the_hash_locked_ci_pair() -> None:
    """Keep package metadata aligned with the exact dependency identities CI proves."""
    requirements = _CI_REQUIREMENTS.read_text(encoding="utf-8")

    for package_name, version in _PRIVATE_DEPENDENCY_VERSIONS.items():
        assert f"{package_name}=={version} \\\n" in requirements


def test_private_http_compatibility_guide_preserves_upgrade_and_host_impact_rules() -> None:
    """Keep the exact-pin trade-off and widening procedure explicit and reviewable."""
    guide = _COMPATIBILITY_GUIDE.read_text(encoding="utf-8")

    for package_name, version in _PRIVATE_DEPENDENCY_VERSIONS.items():
        assert f"`{package_name}=={version}`" in guide
    assert "conflict with a host application" in guide
    assert "explicit compatibility matrix" in guide
    assert "before changing the advertised pair" in guide
    assert "private surface and behavior" in guide
    assert "fail dependency resolution" in guide
