"""Documentation contracts for response-stream policy-denial cleanup."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RESPONSE_RESOURCE_DOC = (
    REPOSITORY_ROOT / "docs" / "research" / "response-body-resource-limits.md"
)
CHANGELOG_PATH = REPOSITORY_ROOT / "CHANGELOG.md"


def test_cleanup_guidance_distinguishes_child_failures_from_control_flow() -> None:
    """Require docs to preserve direct interpreter control-flow propagation."""
    documentation = " ".join(
        RESPONSE_RESOURCE_DOC.read_text(encoding="utf-8").split()
    )

    assert "custom `BaseException`" in documentation
    assert "`KeyboardInterrupt`, `SystemExit`, and `GeneratorExit`" in documentation
    assert "propagate" in documentation
    assert "all cleanup exceptions" not in documentation


def test_changelog_qualifies_cleanup_failure_containment() -> None:
    """Keep release history precise about interpreter control-flow propagation."""
    changelog = " ".join(CHANGELOG_PATH.read_text(encoding="utf-8").split())

    assert "except direct `KeyboardInterrupt`, `SystemExit`, and `GeneratorExit`" in changelog
