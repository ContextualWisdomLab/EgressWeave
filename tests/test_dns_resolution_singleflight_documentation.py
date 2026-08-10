"""Documentation contracts for bounded same-authority DNS single-flight work."""

from __future__ import annotations

import re
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RESEARCH_PATH = REPOSITORY_ROOT / "docs" / "research" / "dns-resolution-resource-bounds.md"
CHANGELOG_PATH = REPOSITORY_ROOT / "CHANGELOG.md"


def _normalized_section(path: Path, heading: str) -> str:
    """Return one named Markdown section with whitespace normalized."""
    text = path.read_text(encoding="utf-8")
    marker = f"{heading}\n"
    section = text.split(marker, 1)[1]
    level = len(heading) - len(heading.lstrip("#"))
    next_heading = re.search(rf"\n#{{1,{level}}} ", section)
    if next_heading is not None:
        section = section[: next_heading.start()]
    return " ".join(section.split())


def test_dns_singleflight_operator_guidance_records_the_exact_boundary() -> None:
    """Require operator guidance for live-only sharing and per-caller validation."""
    guidance = _normalized_section(RESEARCH_PATH, "## Implemented boundary")

    required = (
        "in-flight",
        "(hostname, port)",
        "never caches a completed DNS result",
        "each caller retains its own",
        "max_resolved_addresses",
        "before executor scheduling",
    )
    missing = [fragment for fragment in required if fragment not in guidance]
    assert not missing, f"DNS single-flight implemented boundary is missing: {missing}"


def test_dns_singleflight_operator_guidance_records_residual_platform_limits() -> None:
    """Keep non-cancellable platform-resolver limits in their canonical section."""
    guidance = _normalized_section(RESEARCH_PATH, "## Residual platform limitation")

    required = ("socket.getaddrinfo", "cannot safely cancel", "DNS rebinding")
    missing = [fragment for fragment in required if fragment not in guidance]
    assert not missing, f"DNS residual platform guidance is missing: {missing}"


def test_changelog_records_same_authority_dns_worker_deduplication() -> None:
    """Keep the buyer-facing release history aligned with the resolver repair."""
    changelog = _normalized_section(CHANGELOG_PATH, "### Security")

    assert "same-authority DNS" in changelog
    assert "in-flight" in changelog
    assert "completed DNS results" in changelog


def test_operator_guidance_counts_async_executor_scheduling_inside_deadline() -> None:
    """State that async timeout accounting starts before executor scheduling."""
    guidance = _normalized_section(RESEARCH_PATH, "## Implemented boundary")

    assert "before executor scheduling" in guidance


def test_changelog_records_async_executor_scheduling_deadline() -> None:
    """Keep the async DNS deadline tightening visible in release history."""
    changelog = _normalized_section(CHANGELOG_PATH, "### Security")

    assert "executor scheduling" in changelog
