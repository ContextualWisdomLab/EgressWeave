"""Exercise checkout-free publication without network or release authority."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_REPOSITORY = "ContextualWisdomLab/EgressWeave"
_TAG = "v0.3.0"
_RELEASE_SHA = "a" * 40
_ASSETS = ("SHA256SUMS", "egressweave-0.3.0.whl", "egressweave-0.3.0.tar.gz")
_GH = r'''
import json
import os
import sys
from pathlib import Path

path = Path(os.environ["FAKE_RELEASE_STATE"])
state = json.loads(path.read_text())
args = sys.argv[1:]
state["calls"].append(args)

def save():
    path.write_text(json.dumps(state))

def fail(message):
    save()
    print(message, file=sys.stderr)
    raise SystemExit(1)

if args[0] == "release":
    if "--repo" not in args or args[args.index("--repo") + 1] != os.environ["GITHUB_REPOSITORY"]:
        fail("no local git repository; explicit repository selection required")
    if len(args) < 3 or args[2] != os.environ["RELEASE_TAG"]:
        fail("release command tag did not match the requested tag")
    if args[1] == "create":
        if "--draft" not in args or "--verify-tag" not in args:
            fail("draft and verified tag are mandatory")
        first_option = next(
            (index for index, value in enumerate(args[3:], start=3) if value.startswith("--")),
            len(args),
        )
        uploaded_assets = [Path(value).name for value in args[3:first_option]]
        expected_assets = json.loads(os.environ["EXPECTED_RELEASE_ASSETS"])
        if sorted(uploaded_assets) != sorted(expected_assets):
            fail("release create asset inventory did not match reviewed evidence")
        state["created"] = True
        state["created_tag"] = args[2]
        state["uploaded_assets"] = uploaded_assets
    elif args[1] == "edit":
        draft_flags = [value for value in args[3:] if value.startswith("--draft")]
        if draft_flags != ["--draft=false"]:
            fail("release edit must clear draft state exactly once")
        if not state["created"] or state.get("created_tag") != args[2]:
            fail("release edit must follow draft creation for the requested tag")
        state["published"] = True
    elif args[1] == "verify":
        if not state["published"]:
            fail("release attestation is unavailable before publication")
        if state.get("release_failure"):
            fail("release attestation failed")
    elif args[1] == "verify-asset":
        if not state["published"]:
            fail("asset attestation is unavailable before publication")
        asset = Path(args[3])
        if not asset.is_file() or asset.name == state.get("asset_failure"):
            fail("asset attestation failed")
        state["verified_assets"].append(asset.name)
    else:
        fail("unexpected release command")
elif args[0] == "api":
    release_endpoint = (
        "repos/" + os.environ["GITHUB_REPOSITORY"] + "/releases/tags/" + os.environ["RELEASE_TAG"]
    )
    tag_endpoint = (
        "repos/" + os.environ["GITHUB_REPOSITORY"] + "/git/ref/tags/" + os.environ["RELEASE_TAG"]
    )
    if args[1] == release_endpoint:
        if not state["created"] and not state["published"]:
            fail("HTTP 404")
        if state.get("metadata_failure"):
            fail("HTTP 503")
        metadata = dict(state["metadata"])
        metadata["draft"] = (
            state["metadata_draft_override"]
            if state["metadata_draft_override_present"]
            else not state["published"]
        )
        metadata["assets"] = [{"name": name} for name in state["uploaded_assets"]]
        state["release_metadata_read"] = True
        print(json.dumps(metadata))
    elif args[1] == tag_endpoint:
        if not state["release_metadata_read"]:
            fail("published tag identity must be checked after immutable release metadata")
        if state.get("tag_metadata_failure"):
            fail("HTTP 503")
        print(json.dumps({"object": {"sha": state["tag_sha"]}}))
    else:
        fail("metadata request not bound to repository and tag")
else:
    fail("unexpected command")
save()
'''


def _script() -> str:
    """Read the actual final workflow step, not a copy of its commands."""
    workflow = (_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    step = workflow.split("      - name: Create a complete draft and publish it atomically\n", 1)[1]
    script = step.split("        run: |\n", 1)[1]
    return "\n".join(line[10:] for line in script.splitlines() if line.startswith("          "))


def _run(
    tmp_path: Path, *, script: str | None = None, **changes: object
) -> tuple[subprocess.CompletedProcess[str], dict]:
    """Execute shell in a non-repository workspace with an observable CLI boundary."""
    metadata_changes = dict(changes.pop("metadata", {}))
    metadata_draft_override_present = "draft" in metadata_changes
    metadata_draft_override = metadata_changes.pop("draft", None)
    metadata = {"tag_name": _TAG, "prerelease": False, "immutable": True}
    metadata.update(metadata_changes)
    state = {
        "metadata": metadata,
        "metadata_draft_override_present": metadata_draft_override_present,
        "metadata_draft_override": metadata_draft_override,
        "calls": [],
        "uploaded_assets": [],
        "verified_assets": [],
        "created": False,
        "published": False,
        "release_metadata_read": False,
        "tag_sha": _RELEASE_SHA,
        **changes,
    }
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    gh.write_text(f"#!{sys.executable} -S\n" + _GH, encoding="utf-8")
    gh.chmod(0o700)
    evidence = tmp_path / "release-evidence"
    evidence.mkdir()
    for name in _ASSETS:
        (evidence / name).write_text("reviewed fixture\n", encoding="utf-8")
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"GH_REPO", "GH_TOKEN", "GITHUB_TOKEN", "GIT_DIR", "GIT_WORK_TREE"}
    }
    env.update(
        {
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "FAKE_RELEASE_STATE": str(state_path),
            "GITHUB_REPOSITORY": _REPOSITORY,
            "RELEASE_SHA": _RELEASE_SHA,
            "RELEASE_TAG": _TAG,
            "EXPECTED_RELEASE_ASSETS": json.dumps(_ASSETS),
        }
    )
    result = subprocess.run(
        ["bash", "-c", _script() if script is None else script],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    return result, json.loads(state_path.read_text(encoding="utf-8"))


def test_checkout_free_publish_verifies_release_and_every_asset(tmp_path: Path) -> None:
    """Explicit repository selection must work without a checkout or ambient GH_REPO."""
    result, state = _run(tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    assert state["created"] and state["published"]
    release_calls = [call for call in state["calls"] if call[:1] == ["release"]]
    assert release_calls
    assert all(call[2] == _TAG for call in release_calls)
    assert state["created_tag"] == _TAG
    assert sorted(state["uploaded_assets"]) == sorted(_ASSETS)
    release_endpoint = f"repos/{_REPOSITORY}/releases/tags/{_TAG}"
    tag_endpoint = f"repos/{_REPOSITORY}/git/ref/tags/{_TAG}"
    call_prefixes = [call[:2] for call in state["calls"]]
    assert call_prefixes.index(["api", release_endpoint]) < call_prefixes.index(
        ["api", tag_endpoint]
    )
    assert call_prefixes.index(["api", tag_endpoint]) < call_prefixes.index(
        ["release", "verify"]
    )
    assert sorted(state["verified_assets"]) == sorted(_ASSETS)


@pytest.mark.parametrize("command", ["create", "edit", "verify", "verify-asset"])
def test_every_release_command_is_bound_to_requested_tag(
    tmp_path: Path, command: str
) -> None:
    """A release subcommand using another tag must fail the publication contract."""
    script = _script()
    expected = f'gh release {command} "$RELEASE_TAG"'
    assert expected in script
    mutated = script.replace(expected, f'gh release {command} "v9.9.9"', 1)
    result, _ = _run(tmp_path, script=mutated)
    assert result.returncode != 0


def test_release_create_must_upload_every_locally_verified_asset(tmp_path: Path) -> None:
    """Local verification cannot certify an artifact omitted from the published release."""
    script = _script()
    assert "release-evidence/*" in script
    mutated = script.replace(
        "release-evidence/*",
        "release-evidence/SHA256SUMS release-evidence/egressweave-0.3.0.whl",
        1,
    )
    result, _ = _run(tmp_path, script=mutated)
    assert result.returncode != 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("immutable", False),
        ("immutable", None),
        ("immutable", "true"),
        ("draft", True),
        ("draft", "false"),
        ("prerelease", True),
        ("tag_name", "v9.9.9"),
    ],
)
def test_unverified_inventory_is_rejected(tmp_path: Path, field: str, value: object) -> None:
    """Published existence cannot stand in for typed, exact immutable identity."""
    result, state = _run(tmp_path, metadata={field: value})
    assert state["published"], result.stderr
    assert result.returncode != 0
    assert not state["verified_assets"]


@pytest.mark.parametrize("failure", ["metadata_failure", "release_failure"])
def test_verification_outage_is_not_success(tmp_path: Path, failure: str) -> None:
    """Read failure or invalid attestation must fail the publication result."""
    result, state = _run(tmp_path, **{failure: True})
    assert state["published"], result.stderr
    assert result.returncode != 0
    assert not state["verified_assets"]


def test_published_tag_lookup_outage_is_not_success(tmp_path: Path) -> None:
    """Post-publication tag identity must be observable before attestations are accepted."""
    result, state = _run(tmp_path, tag_metadata_failure=True)
    assert state["published"], result.stderr
    assert result.returncode != 0
    assert not state["verified_assets"]


@pytest.mark.parametrize("asset", _ASSETS)
def test_any_asset_verification_failure_is_fatal(tmp_path: Path, asset: str) -> None:
    """Check every artifact, including the checksum manifest, not only one wheel."""
    result, state = _run(tmp_path, asset_failure=asset)
    assert state["published"], result.stderr
    assert result.returncode != 0
    assert asset not in state["verified_assets"]
