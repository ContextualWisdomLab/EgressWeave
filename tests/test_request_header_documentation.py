"""Contracts for the exact outbound request-header byte boundary."""

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
HTTP_FIELD_GUIDE = REPOSITORY_ROOT / "docs" / "research" / "http-field-syntax.md"
CHANGELOG = REPOSITORY_ROOT / "CHANGELOG.md"


def _read(path: Path) -> str:
    """Return one repository text file as UTF-8."""
    return path.read_text(encoding="utf-8")


def _normalized_text(path: Path) -> str:
    """Return whitespace-normalized case-insensitive prose for semantic checks."""
    return " ".join(_read(path).split()).casefold()


def test_http_field_guide_documents_exact_builtin_bytes_only() -> None:
    """Keep the protocol guide aligned with the request-header trust boundary."""
    guide = _normalized_text(HTTP_FIELD_GUIDE)

    assert "exact built-in `bytes`" in guide
    assert "byte subclasses" in guide
    assert "before field parsing" in guide


def test_changelog_records_exact_request_header_byte_hardening() -> None:
    """Keep the compatibility-tightening boundary visible in release history."""
    changelog = _normalized_text(CHANGELOG)

    assert "request-header names and values" in changelog
    assert "exact built-in `bytes`" in changelog
    assert "byte subclasses" in changelog
