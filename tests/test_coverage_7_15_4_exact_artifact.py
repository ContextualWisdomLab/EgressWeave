"""Regression contract for the reviewed coverage.py 7.15.4 artifact."""

from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT_PATH = REPOSITORY_ROOT / "pyproject.toml"
CI_LOCK_PATH = REPOSITORY_ROOT / "requirements-ci.txt"
COVERAGE_WHEEL_URL = (
    "https://files.pythonhosted.org/packages/b4/d9/"
    "e70c286c979378f061d8266e279b686ab0b0b688e1fe0af864684f23a77d/"
    "coverage-7.15.4-py3-none-any.whl"
)
COVERAGE_WHEEL_SHA256 = (
    "964730a1e9de9c0cf11be6a1a3c79ce419c34882842abd256086ba4698705e84"
)


def test_coverage_7_15_4_metadata_and_executable_artifact_move_together() -> None:
    """Advertise 7.15.4 only when CI executes its exact reviewed universal wheel."""
    with PYPROJECT_PATH.open("rb") as pyproject_file:
        pyproject = tomllib.load(pyproject_file)
    test_dependencies = pyproject["project"]["optional-dependencies"]["test"]
    lock = CI_LOCK_PATH.read_text(encoding="utf-8")

    assert "coverage>=7.15.4,<8" in test_dependencies
    assert f"coverage @ {COVERAGE_WHEEL_URL}" in lock
    assert f"--hash=sha256:{COVERAGE_WHEEL_SHA256}" in lock
    assert "coverage-7.15.3-py3-none-any.whl" not in lock
