"""Documentation contracts for bounded same-authority DNS single-flight work."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RESEARCH_PATH = REPOSITORY_ROOT / "docs" / "research" / "dns-resolution-resource-bounds.md"
CHANGELOG_PATH = REPOSITORY_ROOT / "CHANGELOG.md"


def _normalized(path: Path) -> str:
    """Return one repository document with whitespace normalized for assertions."""
    return " ".join(path.read_text(encoding="utf-8").split())


def test_dns_singleflight_operator_guidance_records_the_exact_boundary() -> None:
    """Require operator guidance for live-only sharing and per-caller validation."""
    guidance = _normalized(RESEARCH_PATH)

    required = (
        "in-flight",
        "(hostname, port)",
        "never caches a completed DNS result",
        "each caller retains its own",
        "max_resolved_addresses",
        "socket.getaddrinfo",
        "cannot safely cancel",
        "DNS rebinding",
    )
    missing = [fragment for fragment in required if fragment not in guidance]
    assert not missing, f"DNS single-flight guidance is missing: {missing}"


def test_changelog_records_same_authority_dns_worker_deduplication() -> None:
    """Keep the buyer-facing release history aligned with the resolver repair."""
    changelog = _normalized(CHANGELOG_PATH)

    assert "same-authority DNS" in changelog
    assert "in-flight" in changelog
    assert "completed DNS results" in changelog
