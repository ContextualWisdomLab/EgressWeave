"""Documentation contracts for caller-visible response extension capabilities."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ARCHITECTURE_PATH = REPOSITORY_ROOT / "ARCHITECTURE.md"
CHANGELOG_PATH = REPOSITORY_ROOT / "CHANGELOG.md"
RESPONSE_GUIDE_PATH = (
    REPOSITORY_ROOT / "docs" / "research" / "response-body-resource-limits.md"
)


def _read(path: Path) -> str:
    """Return one repository text file as UTF-8."""
    return path.read_text(encoding="utf-8")


def test_response_guide_defines_caller_visible_extension_allowlist() -> None:
    """Document inert response metadata and hidden raw transport capability."""
    guide = _read(RESPONSE_GUIDE_PATH)

    for fragment in (
        "Caller-visible response extensions",
        "`http_version`",
        "`reason_phrase`",
        "`network_stream`",
        "raw transport capability",
        "future response extensions",
    ):
        assert fragment in guide


def test_architecture_hides_raw_response_transport_capabilities() -> None:
    """Keep the normative transport architecture aligned with response filtering."""
    architecture = _read(ARCHITECTURE_PATH)

    for fragment in (
        "response-extension allowlist",
        "`http_version`",
        "`reason_phrase`",
        "`network_stream`",
    ):
        assert fragment in architecture


def test_changelog_records_response_extension_capability_hardening() -> None:
    """Expose the pre-1.0 compatibility tightening to downstream integrators."""
    changelog = " ".join(_read(CHANGELOG_PATH).split()).lower()

    for fragment in (
        "response extensions",
        "`network_stream`",
        "`http_version`",
        "`reason_phrase`",
        "raw transport",
    ):
        assert fragment in changelog
