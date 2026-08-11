"""Documentation contracts for exact request-timeout policy configuration."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TIMEOUT_GUIDE_PATH = REPOSITORY_ROOT / "docs" / "research" / "request-timeout-boundaries.md"
CHANGELOG_PATH = REPOSITORY_ROOT / "CHANGELOG.md"


def _read(path: Path) -> str:
    """Return one repository text file as normalized UTF-8 prose."""
    return " ".join(path.read_text(encoding="utf-8").split())


def test_timeout_guide_requires_exact_reviewed_policy_type() -> None:
    """Explain why timeout-policy subclass polymorphism is not a supported boundary."""
    guide = _read(TIMEOUT_GUIDE_PATH)

    for fragment in (
        "exact `EgressTimeoutPolicy` type",
        "subclass",
        "trusted policy construction",
        "`as_httpcore_timeout()`",
    ):
        assert fragment in guide


def test_changelog_records_timeout_policy_type_hardening() -> None:
    """Expose the pre-1.0 policy-integrity tightening to integrators."""
    changelog = _read(CHANGELOG_PATH)

    for fragment in (
        "request timeout policy",
        "exact `EgressTimeoutPolicy`",
        "subclass",
    ):
        assert fragment in changelog


def test_changelog_keeps_security_heading_and_entries_at_markdown_root() -> None:
    """Prevent whitespace drift from turning release-history structure into code."""
    changelog = CHANGELOG_PATH.read_text(encoding="utf-8")

    assert "\n### Security\n" in changelog
    assert "\n- Require the request timeout policy" in changelog
    assert "\n ### Security\n" not in changelog
    assert "\n - Require the request timeout policy" not in changelog
