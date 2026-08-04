"""Contracts for the NVIDIA-backed OpenCode autonomous development scheduler."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PRODUCT_WORKFLOW_PATH = (
    REPOSITORY_ROOT / ".github" / "workflows" / "hourly-product-development.yml"
)
REVIEW_WORKFLOW_PATH = (
    REPOSITORY_ROOT / ".github" / "workflows" / "hourly-pr-maintenance.yml"
)
MAINTENANCE_DOCUMENTATION_PATH = (
    REPOSITORY_ROOT / "docs" / "hourly-autonomous-maintenance.md"
)
OPENCODE_VERSION = "1.18.13"
OPENCODE_LINUX_X64_SHA256 = (
    "8d500b20fed2d26e537e221895b1a575476571b4f0089bb29fb13eeb8eb9e937"
)
NVIDIA_MODEL = "nvidia/nemotron-3-super-120b-a12b"
NVIDIA_API_HOST_LABELS = ("integrate", "api", "nvidia", "com")
NVIDIA_API_ENDPOINT = f"{'.'.join(NVIDIA_API_HOST_LABELS)}:443"


def _read(path: Path) -> str:
    """Return one repository text file as UTF-8."""
    return path.read_text(encoding="utf-8")


def test_product_scheduler_uses_pinned_opencode_with_nvidia_nim() -> None:
    """Replace the Codex scheduler model step without mutable agent tooling."""
    workflow = _read(PRODUCT_WORKFLOW_PATH)

    assert "openai/codex-action@" not in workflow
    assert "OPENAI_API_KEY" not in workflow
    assert "NVIDIA_API_KEY: ${{ secrets.NVIDIA_NIM_API_KEY }}" in workflow
    assert f'OPENCODE_VERSION: "{OPENCODE_VERSION}"' in workflow
    assert f'OPENCODE_SHA256: "{OPENCODE_LINUX_X64_SHA256}"' in workflow
    assert (
        "https://github.com/anomalyco/opencode/releases/download/"
        "v${OPENCODE_VERSION}/opencode-linux-x64.tar.gz"
    ) in workflow
    assert "sha256sum --check" in workflow
    assert "opencode run --auto" in workflow
    assert f'OPENCODE_MODEL: "{NVIDIA_MODEL}"' in workflow


def test_model_execution_keeps_a_fail_closed_permission_and_secret_boundary() -> None:
    """Deny unneeded tools and reject model output containing its credential."""
    workflow = _read(PRODUCT_WORKFLOW_PATH)

    assert "egress-policy: block" in workflow
    assert NVIDIA_API_ENDPOINT in {line.strip() for line in workflow.splitlines()}
    assert 'OPENCODE_DISABLE_AUTOUPDATE: "true"' in workflow
    assert 'OPENCODE_DISABLE_MODELS_FETCH: "true"' in workflow
    assert 'OPENCODE_DISABLE_DEFAULT_PLUGINS: "true"' in workflow
    assert 'OPENCODE_DISABLE_LSP_DOWNLOAD: "true"' in workflow
    assert '"external_directory":"deny"' in workflow
    assert '"webfetch":"deny"' in workflow
    assert '"websearch":"deny"' in workflow
    assert '"question":"deny"' in workflow
    assert '"task":"deny"' in workflow
    assert '"skill":"deny"' in workflow
    assert "Reject model credential disclosure" in workflow
    assert 'grep -R -F -l -- "$NVIDIA_API_KEY"' in workflow
    assert 'grep -R -F -- "$NVIDIA_API_KEY"' not in workflow


def test_review_scheduler_keeps_its_existing_identity_contract() -> None:
    """Do not repurpose the centrally managed review-agent credential path."""
    review_workflow = _read(REVIEW_WORKFLOW_PATH)

    assert "NVIDIA_NIM_API_KEY" not in review_workflow
    assert "OPENAI_API_KEY" not in review_workflow
    assert "pr-review-fix-scheduler.yml@" in review_workflow
    assert "pr-review-merge-scheduler.yml@" in review_workflow
    assert review_workflow.count("secrets: inherit") == 2


def test_operator_documentation_records_the_pinned_agent_and_secret_mapping() -> None:
    """Make the autonomous execution supply chain understandable to operators."""
    documentation = _read(MAINTENANCE_DOCUMENTATION_PATH)

    assert f"OpenCode {OPENCODE_VERSION}" in documentation
    assert "`NVIDIA_NIM_API_KEY`" in documentation
    assert "`NVIDIA_API_KEY`" in documentation
    assert NVIDIA_MODEL in documentation
    assert OPENCODE_LINUX_X64_SHA256 in documentation
    assert "OpenAI Codex Action" not in documentation
