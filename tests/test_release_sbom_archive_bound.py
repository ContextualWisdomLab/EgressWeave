"""Regression tests for the direct release-SBOM archive-size boundary."""

from __future__ import annotations

import importlib.util
import io
import os
import tarfile
import zipfile
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "generate_release_sbom.py"
MANIFEST_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "release_runtime_dependencies.json"
EXPECTED_MAX_ARTIFACT_BYTES = 256 * 1024 * 1024


def _load_generator() -> ModuleType:
    """Load the standalone generator without importing the package under test."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_generate_release_sbom_archive_bound",
        GENERATOR_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _write_sparse_oversized_file(path: Path) -> None:
    """Create one cheap sparse fixture just above the accepted compressed bound."""
    with path.open("wb") as stream:
        stream.truncate(EXPECTED_MAX_ARTIFACT_BYTES + 1)


def _write_minimal_archive(path: Path) -> None:
    """Write one parseable wheel or source archive for live-growth regressions."""
    metadata = (
        b"Metadata-Version: 2.4\n"
        b"Name: egressweave\n"
        b"Version: 0.3.0\n"
        b"License-Expression: Apache-2.0\n\n"
    )
    if path.name.endswith(".whl"):
        with zipfile.ZipFile(path, mode="w") as archive:
            archive.writestr("egressweave-0.3.0.dist-info/METADATA", metadata)
        return
    with tarfile.open(path, mode="w:gz") as archive:
        member = tarfile.TarInfo("egressweave-0.3.0/PKG-INFO")
        member.size = len(metadata)
        archive.addfile(member, io.BytesIO(metadata))


def test_generator_uses_the_reviewed_compressed_archive_limit() -> None:
    """Keep the standalone parser preflight aligned with release verification."""
    generator = _load_generator()

    assert generator.MAX_RELEASE_ARTIFACT_BYTES == EXPECTED_MAX_ARTIFACT_BYTES


def test_oversized_wheel_fails_before_zip_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject an oversized wheel before ZIP parser CPU or memory can be spent."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    _write_sparse_oversized_file(wheel_path)

    def unexpected_parser(*args, **kwargs):
        pytest.fail("ZIP parser ran before the compressed-byte bound")

    monkeypatch.setattr(generator.zipfile, "ZipFile", unexpected_parser)

    with pytest.raises(SystemExit, match="compressed-byte safety bound"):
        generator.build_sbom(wheel_path, MANIFEST_PATH)


def test_oversized_sdist_fails_before_tar_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject an oversized source archive before gzip/tar parsing begins."""
    generator = _load_generator()
    sdist_path = tmp_path / "egressweave-0.3.0.tar.gz"
    _write_sparse_oversized_file(sdist_path)

    def unexpected_parser(*args, **kwargs):
        pytest.fail("tar parser ran before the compressed-byte bound")

    monkeypatch.setattr(generator.tarfile, "open", unexpected_parser)

    with pytest.raises(SystemExit, match="compressed-byte safety bound"):
        generator.build_sbom(sdist_path, MANIFEST_PATH)


def test_symlinked_archive_fails_before_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a direct archive symlink instead of following it into a parser."""
    generator = _load_generator()
    target = tmp_path / "target.whl"
    with zipfile.ZipFile(target, mode="w") as archive:
        archive.writestr("egressweave-0.3.0.dist-info/METADATA", b"invalid")
    alias = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    try:
        alias.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable on this platform")

    def unexpected_parser(*args, **kwargs):
        pytest.fail("ZIP parser followed an unsafe archive link")

    monkeypatch.setattr(generator.zipfile, "ZipFile", unexpected_parser)

    with pytest.raises(SystemExit, match="missing or unsafe"):
        generator.build_sbom(alias, MANIFEST_PATH)


def test_cli_rejects_symlinked_archive_before_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep the CLI from resolving away the caller-supplied final symlink."""
    generator = _load_generator()
    target = tmp_path / "target.whl"
    _write_minimal_archive(target)
    alias = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    try:
        alias.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable on this platform")

    monkeypatch.setattr(
        generator,
        "_parse_arguments",
        lambda: SimpleNamespace(
            artifact=alias,
            manifest=MANIFEST_PATH,
            lock=tmp_path / "runtime.lock",
            output=tmp_path / "sbom.json",
        ),
    )
    monkeypatch.setattr(generator, "validate_runtime_lock", lambda *args: None)

    def unexpected_parser(*args, **kwargs):
        pytest.fail("CLI resolved an unsafe archive link before validation")

    monkeypatch.setattr(generator.zipfile, "ZipFile", unexpected_parser)

    with pytest.raises(SystemExit, match="missing or unsafe"):
        generator.main()


def test_archive_lstat_failure_is_normalized_before_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Normalize filesystem inspection failure without exposing local details."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel_path, mode="w") as archive:
        archive.writestr("egressweave-0.3.0.dist-info/METADATA", b"invalid")
    original_lstat = Path.lstat

    def fail_artifact_lstat(path: Path, *args, **kwargs):
        if path == wheel_path:
            raise OSError("sensitive local filesystem detail")
        return original_lstat(path, *args, **kwargs)

    def unexpected_parser(*args, **kwargs):
        pytest.fail("ZIP parser ran after archive inspection failed")

    monkeypatch.setattr(Path, "lstat", fail_artifact_lstat)
    monkeypatch.setattr(generator.zipfile, "ZipFile", unexpected_parser)

    with pytest.raises(SystemExit, match="missing or unsafe"):
        generator.build_sbom(wheel_path, MANIFEST_PATH)


def test_directory_archive_is_rejected_as_unsafe(tmp_path: Path) -> None:
    """Reject a non-regular artifact with the same stable public failure."""
    generator = _load_generator()
    directory = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    directory.mkdir()

    with pytest.raises(SystemExit, match="missing or unsafe"):
        generator.build_sbom(directory, MANIFEST_PATH)


def test_path_replacement_after_lstat_fails_before_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bind parser input to the file identity accepted by the path preflight."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    replacement = tmp_path / "replacement.whl"
    with zipfile.ZipFile(wheel_path, mode="w") as archive:
        archive.writestr("egressweave-0.3.0.dist-info/METADATA", b"original")
    with zipfile.ZipFile(replacement, mode="w") as archive:
        archive.writestr("egressweave-0.3.0.dist-info/METADATA", b"replacement")
    original_lstat = Path.lstat
    replaced = False

    def replace_after_artifact_lstat(path: Path, *args, **kwargs):
        nonlocal replaced
        metadata = original_lstat(path, *args, **kwargs)
        if path == wheel_path and not replaced:
            wheel_path.unlink()
            replacement.replace(wheel_path)
            replaced = True
        return metadata

    def unexpected_parser(*args, **kwargs):
        pytest.fail("parser opened a pathname replacement after preflight")

    monkeypatch.setattr(Path, "lstat", replace_after_artifact_lstat)
    monkeypatch.setattr(generator.zipfile, "ZipFile", unexpected_parser)

    with pytest.raises(SystemExit, match="missing or unsafe"):
        generator.build_sbom(wheel_path, MANIFEST_PATH)


@pytest.mark.parametrize(
    "artifact_name",
    ("egressweave-0.3.0-py3-none-any.whl", "egressweave-0.3.0.tar.gz"),
)
def test_archive_growth_after_initial_hash_is_bounded_inside_parser(
    artifact_name: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a live archive that grows past the ceiling before parser reads."""
    generator = _load_generator()
    artifact_path = tmp_path / artifact_name
    _write_minimal_archive(artifact_path)
    original_hash = generator._sha256_file
    hash_calls = 0

    def grow_after_initial_hash(stream):
        nonlocal hash_calls
        digest = original_hash(stream)
        hash_calls += 1
        if hash_calls == 1:
            with artifact_path.open("r+b") as mutable_artifact:
                mutable_artifact.truncate(EXPECTED_MAX_ARTIFACT_BYTES + 1)
        return digest

    monkeypatch.setattr(generator, "_sha256_file", grow_after_initial_hash)

    with pytest.raises(SystemExit, match="compressed-byte safety bound"):
        generator.build_sbom(artifact_path, MANIFEST_PATH)

    assert hash_calls == 1


def test_archive_mutation_during_metadata_parse_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject metadata evidence when the bound archive bytes change mid-read."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    metadata = (
        "Metadata-Version: 2.4\n"
        "Name: egressweave\n"
        "Version: 0.3.0\n"
        "License-Expression: Apache-2.0\n"
        "Requires-Dist: httpcore==1.0.9\n"
        "Requires-Dist: httpx==0.28.1\n"
        "Requires-Dist: idna==3.10\n"
        "Requires-Dist: sniffio==1.3.1\n\n"
    )
    with zipfile.ZipFile(wheel_path, mode="w") as archive:
        archive.writestr("egressweave-0.3.0.dist-info/METADATA", metadata)
    original_metadata = generator._artifact_metadata

    def mutate_after_metadata(*args, **kwargs):
        result = original_metadata(*args, **kwargs)
        with wheel_path.open("ab") as stream:
            stream.write(b"mutated")
        return result

    monkeypatch.setattr(generator, "_artifact_metadata", mutate_after_metadata)

    with pytest.raises(SystemExit, match="changed during verification"):
        generator.build_sbom(wheel_path, MANIFEST_PATH)


def test_parser_read_all_is_capped_to_remaining_bytes_plus_tripwire(
    tmp_path: Path,
) -> None:
    """Never pass an unbounded parser read through to the artifact descriptor."""
    generator = _load_generator()
    artifact_path = tmp_path / "artifact.whl"
    artifact_path.write_bytes(b"abcdef")
    requested_sizes: list[int] = []

    with artifact_path.open("rb") as artifact_stream:
        artifact_stream.seek(2)

        class RecordingStream:
            """Record descriptor read sizes while delegating file operations."""

            def fileno(self) -> int:
                return artifact_stream.fileno()

            def tell(self) -> int:
                return artifact_stream.tell()

            def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
                return artifact_stream.seek(offset, whence)

            def read(self, size: int = -1) -> bytes:
                requested_sizes.append(size)
                return artifact_stream.read(size)

        reader = generator._LiveBoundedArtifactReader(RecordingStream())
        assert reader.read() == b"cdef"

    assert requested_sizes == [EXPECTED_MAX_ARTIFACT_BYTES - 2 + 1]


def test_growth_after_parser_seek_fails_before_the_next_read(tmp_path: Path) -> None:
    """Recheck the live descriptor after a parser seek and before later reads."""
    generator = _load_generator()
    artifact_path = tmp_path / "artifact.whl"
    artifact_path.write_bytes(b"abcdef")

    with artifact_path.open("rb") as artifact_stream:
        reader = generator._LiveBoundedArtifactReader(artifact_stream)
        assert reader.seek(1) == 1
        with artifact_path.open("r+b") as mutable_artifact:
            mutable_artifact.truncate(EXPECTED_MAX_ARTIFACT_BYTES + 1)
        with pytest.raises(SystemExit, match="compressed-byte safety bound"):
            reader.read(1)
