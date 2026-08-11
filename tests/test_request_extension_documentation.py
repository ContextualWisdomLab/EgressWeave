"""Documentation contracts for the reviewed HTTPCore request-extension boundary."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ARCHITECTURE_PATH = REPOSITORY_ROOT / "ARCHITECTURE.md"
RESEARCH_INDEX_PATH = REPOSITORY_ROOT / "docs" / "research" / "README.md"
REQUEST_EXTENSION_GUIDE_PATH = (
    REPOSITORY_ROOT / "docs" / "research" / "request-extension-capabilities.md"
)
CHANGELOG_PATH = REPOSITORY_ROOT / "CHANGELOG.md"


def _read(path: Path) -> str:
    """Return one repository documentation file as UTF-8 text."""
    return path.read_text(encoding="utf-8")


def test_request_extension_capability_boundary_is_documented() -> None:
    """Explain the fail-closed allowlist and the rejected HTTPCore capabilities."""
    guide = _read(REQUEST_EXTENSION_GUIDE_PATH)

    for fragment in (
        "HTTPCore",
        "`timeout`",
        "`sni_hostname`",
        "exact built-in `bytes`",
        "exact built-in `str`",
        "Subclasses of `bytes` and `str` are rejected",
        "`target`",
        "`trace`",
        "fail closed",
        "NetworkStream",
    ):
        assert fragment in guide


def test_architecture_names_the_positive_request_extension_allowlist() -> None:
    """Keep the authoritative transport architecture aligned with capability policy."""
    architecture = _read(ARCHITECTURE_PATH)

    for fragment in (
        "positive request-extension allowlist",
        "`timeout`",
        "`sni_hostname`",
        "`target`",
        "`trace`",
    ):
        assert fragment in architecture


def test_request_extension_guide_is_discoverable_from_research_index() -> None:
    """Keep the request-extension capability boundary reachable from the index."""
    research_index = _read(RESEARCH_INDEX_PATH)

    assert (
        "[HTTPCore request-extension capability boundary]"
        "(request-extension-capabilities.md)"
    ) in research_index


def test_changelog_records_request_extension_capability_hardening() -> None:
    """Keep the compatibility-tightening security change visible to integrators."""
    changelog = " ".join(_read(CHANGELOG_PATH).split()).lower()

    for fragment in (
        "restrict low-level httpcore request extensions",
        "`timeout`",
        "`sni_hostname`",
        "`trace`",
        "`target`",
        "unknown extension keys",
        "non-string keys",
        "hostile extension mappings",
        "fail closed before pool dispatch",
    ):
        assert fragment in changelog
