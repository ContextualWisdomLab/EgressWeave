"""Documentation contracts for validated-result integrity boundaries."""

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SECURITY_MODEL_PATH = REPOSITORY_ROOT / "docs" / "security-model.md"
CHANGELOG_PATH = REPOSITORY_ROOT / "CHANGELOG.md"


def _normalized(path: Path) -> str:
    """Return repository text with whitespace normalized for contract assertions."""
    return " ".join(path.read_text(encoding="utf-8").split())


def test_security_model_requires_exact_factory_issued_validation_result_type() -> None:
    """Document rejection before subclass-controlled attribute access."""
    security_model = _normalized(SECURITY_MODEL_PATH)

    assert "exact factory-issued `ValidatedEgressURL` type" in security_model
    assert "before reading caller-controlled validation-result attributes" in security_model


def test_changelog_records_exact_validation_result_type_boundary() -> None:
    """Keep the security tightening visible in release-facing history."""
    changelog = _normalized(CHANGELOG_PATH)

    assert "`ValidatedEgressURL` subclasses" in changelog
    assert "before attribute access" in changelog
