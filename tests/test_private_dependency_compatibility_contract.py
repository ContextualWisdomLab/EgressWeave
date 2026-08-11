"""Contracts for the private HTTPX/HTTPCore compatibility boundary."""

from __future__ import annotations

from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
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
_TEST_TOMLI_REQUIREMENT = "tomli>=2.4.1,<3; python_version < '3.11'"


def _project_metadata() -> dict[str, object]:
    """Return parsed project metadata for compatibility-contract assertions."""
    return tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))


def _project_runtime_dependencies() -> tuple[str, ...]:
    """Return the declared runtime dependency requirements from project metadata."""
    project = _project_metadata()["project"]
    assert isinstance(project, dict)
    return tuple(project["dependencies"])


def _project_test_dependencies() -> tuple[str, ...]:
    """Return the declared test-extra requirements from project metadata."""
    project = _project_metadata()["project"]
    assert isinstance(project, dict)
    optional_dependencies = project["optional-dependencies"]
    assert isinstance(optional_dependencies, dict)
    return tuple(optional_dependencies["test"])


def _active_lock_records(requirements: str, package_name: str) -> tuple[tuple[str, ...], ...]:
    """Return active hash-lock records whose requirement starts with ``package_name``."""
    lines = requirements.splitlines()
    records: list[tuple[str, ...]] = []
    index = 0
    prefix = f"{package_name}=="

    while index < len(lines):
        line = lines[index]
        if not line.startswith(prefix):
            index += 1
            continue

        record = [line]
        index += 1
        while index < len(lines) and lines[index][:1].isspace():
            record.append(lines[index])
            index += 1
        records.append(tuple(record))

    return tuple(records)


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


def test_python_310_test_extra_installs_tomli_fallback() -> None:
    """Keep editable test installs collectible on Python 3.10 without ``tomllib``."""
    assert _TEST_TOMLI_REQUIREMENT in _project_test_dependencies()


def test_private_http_dependency_identity_matches_the_hash_locked_ci_pair() -> None:
    """Require one active exact-version lock record with an associated artifact hash."""
    requirements = _CI_REQUIREMENTS.read_text(encoding="utf-8")

    for package_name, version in _PRIVATE_DEPENDENCY_VERSIONS.items():
        records = _active_lock_records(requirements, package_name)
        assert len(records) == 1
        header, *continuations = records[0]
        assert header == f"{package_name}=={version} \\"
        assert any("--hash=" in line for line in continuations)


def test_private_http_compatibility_guide_preserves_upgrade_and_host_impact_rules() -> None:
    """Keep the exact-pin trade-off and widening procedure explicit and reviewable."""
    guide = _COMPATIBILITY_GUIDE.read_text(encoding="utf-8")

    for package_name, version in _PRIVATE_DEPENDENCY_VERSIONS.items():
        assert f"`{package_name}=={version}`" in guide
    assert "conflict with a host application" in guide
    assert "explicit compatibility matrix" in guide
    assert "before changing the advertised pair" in guide
    assert "record the observed failing contract" in guide
    assert "private surface and behavior" in guide
    assert "fail dependency resolution" in guide
