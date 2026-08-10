"""Supply-chain contracts for the credential-free autonomous verifier image."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PRODUCT_WORKFLOW_PATH = (
    REPOSITORY_ROOT / ".github" / "workflows" / "hourly-product-development.yml"
)
VERIFIER_BASE_IMAGE = (
    "python@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91"
)


def _read_workflow() -> str:
    """Return the autonomous product workflow as UTF-8 text."""
    return PRODUCT_WORKFLOW_PATH.read_text(encoding="utf-8")


def _verifier_build_step(workflow: str) -> str:
    """Return only the credential-free verifier image build step."""
    return workflow.split("Build the credential-free verifier image", 1)[1].split(
        "Test only inside the offline least-privilege verifier container",
        1,
    )[0]


def test_verifier_uses_one_reviewed_immutable_python_image_digest() -> None:
    """Require an explicit reviewed digest instead of trusting a mutable tag."""
    workflow = _read_workflow()
    verifier = _verifier_build_step(workflow)

    assert f'VERIFIER_BASE_IMAGE: "{VERIFIER_BASE_IMAGE}"' in workflow
    assert 'docker pull "$VERIFIER_BASE_IMAGE"' in verifier
    assert "docker pull python:3.13-slim" not in verifier
    assert "RepoDigests" not in verifier
    assert 'FROM ${VERIFIER_BASE_IMAGE}' in verifier


def test_verifier_rejects_non_digest_base_image_configuration() -> None:
    """Keep the reviewed image contract fail closed before Docker executes it."""
    verifier = _verifier_build_step(_read_workflow())

    assert (
        '[[ ! "$VERIFIER_BASE_IMAGE" =~ ^python@sha256:[0-9a-f]{64}$ ]]'
        in verifier
    )
    assert "The verifier base image is not an immutable reviewed Python digest" in verifier
