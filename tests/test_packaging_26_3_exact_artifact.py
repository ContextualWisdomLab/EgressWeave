"""Regression contract for the reviewed packaging 26.3 toolchain artifact."""

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CI_LOCK_PATH = REPOSITORY_ROOT / "requirements-ci.txt"
RELEASE_LOCK_PATH = REPOSITORY_ROOT / "requirements-release.txt"
PACKAGING_WHEEL_SHA256 = (
    "d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c"
)
PACKAGING_SDIST_SHA256 = (
    "94edc256424af38762eb31306eed28beb9f0efc50a8837492c9d6fd6004aed79"
)


def test_packaging_26_3_uses_one_reviewed_wheel_in_both_toolchain_locks() -> None:
    """Pin one exact packaging wheel rather than widening execution to the sdist."""
    for lock_path in (CI_LOCK_PATH, RELEASE_LOCK_PATH):
        lock = lock_path.read_text(encoding="utf-8")
        packaging_entry = lock.split("packaging==", maxsplit=1)[1].split("\n", maxsplit=2)
        entry_text = "\n".join(packaging_entry[:2])

        assert entry_text.startswith("26.3 \\")
        assert entry_text.count("--hash=sha256:") == 1
        assert f"--hash=sha256:{PACKAGING_WHEEL_SHA256}" in entry_text
        assert PACKAGING_SDIST_SHA256 not in entry_text
