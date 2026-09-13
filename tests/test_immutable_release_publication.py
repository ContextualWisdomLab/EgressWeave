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
    if args[1] == "create":
        if "--draft" not in args or "--verify-tag" not in args:
            fail("draft and verified tag are mandatory")
        state["created"] = True
    elif args[1] == "edit":
        state["published"] = True
    elif args[1] == "verify":
        if state.get("release_failure"):
            fail("release attestation failed")
    elif args[1] == "verify-asset":
        asset = Path(args[3])
        if not asset.is_file() or asset.name == state.get("asset_failure"):
            fail("asset attestation failed")
        state["verified_assets"].append(asset.name)
    else:
        fail("unexpected release command")
elif args[0] == "api":
    if state.get("metadata_failure"):
        fail("HTTP 503")
    if args[1] != "repos/" + os.environ["GITHUB_REPOSITORY"] + "/releases/tags/" + os.environ["RELEASE_TAG"]:
        fail("metadata request not bound to repository and tag")
    print(json.dumps(state["metadata"]))
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


def _run(tmp_path: Path, **changes: object) -> tuple[subprocess.CompletedProcess[str], dict]:
    """Execute shell in a non-repository workspace with an observable CLI boundary."""
    metadata = {"tag_name": _TAG, "draft": False, "prerelease": False, "immutable": True}
    metadata.update(changes.pop("metadata", {}))
    state = {
        "metadata": metadata, "calls": [], "verified_assets": [],
        "created": False, "published": False, **changes,
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
        key: value for key, value in os.environ.items()
        if key not in {"GH_REPO", "GH_TOKEN", "GITHUB_TOKEN", "GIT_DIR", "GIT_WORK_TREE"}
    }
    env.update({
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "FAKE_RELEASE_STATE": str(state_path),
        "GITHUB_REPOSITORY": _REPOSITORY,
        "RELEASE_TAG": _TAG,
    })
    result = subprocess.run(
        ["bash", "-c", _script()], cwd=tmp_path, env=env,
        text=True, capture_output=True, timeout=15,
    )
    return result, json.loads(state_path.read_text(encoding="utf-8"))


def test_checkout_free_publish_verifies_release_and_every_asset(tmp_path: Path) -> None:
    """Explicit repository selection must work without a checkout or ambient GH_REPO."""
    result, state = _run(tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    assert state["created"] and state["published"]
    assert ["release", "verify"] in [call[:2] for call in state["calls"]]
    assert sorted(state["verified_assets"]) == sorted(_ASSETS)


@pytest.mark.parametrize("field,value", [
    ("immutable", False), ("immutable", None), ("immutable", "true"),
    ("draft", True), ("draft", "false"), ("prerelease", True),
    ("tag_name", "v9.9.9"),
])
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


@pytest.mark.parametrize("asset", _ASSETS)
def test_any_asset_verification_failure_is_fatal(tmp_path: Path, asset: str) -> None:
    """Check every artifact, including the checksum manifest, not only one wheel."""
    result, state = _run(tmp_path, asset_failure=asset)
    assert state["published"], result.stderr
    assert result.returncode != 0
    assert asset not in state["verified_assets"]
