"""Regression contracts for the hourly gateway credential boundary."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "hourly-product-development.yml"
PROVIDER_SECRETS = (
    "BYTEZ_API_KEY",
    "NVIDIA_NIM_API_KEY",
    "NVIDIA_NIM_API_KEY_SUB",
    "OPENROUTER_API_KEY",
    "OPENAI_API_KEY",
)


def _workflow_step(workflow: str, start: str, end: str) -> str:
    """Return one named workflow-step slice between exact reviewed markers."""
    assert workflow.count(start) == 1
    assert workflow.count(end) == 1
    return workflow.split(start, 1)[1].split(end, 1)[0]


def test_opencode_receives_only_loopback_gateway_credentials() -> None:
    """Keep provider secrets outside the model-running OpenCode process."""
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    opencode_step = _workflow_step(
        workflow,
        "      - name: Run the bounded OpenCode autonomous maintainer\n",
        "      - name: Reject model credential disclosure\n",
    )

    for secret_name in PROVIDER_SECRETS:
        assert secret_name not in opencode_step
    assert '"baseURL":"{env:CONTEXTUAL_ORCHESTRATOR_BASE_URL}"' in opencode_step
    assert '"apiKey":"{env:CONTEXTUAL_ORCHESTRATOR_TOKEN}"' in opencode_step


def test_disclosure_scan_includes_gateway_bearer_and_provider_secrets() -> None:
    """Fail closed if either bootstrap credentials or the bearer reach output."""
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    disclosure_step = _workflow_step(
        workflow,
        "      - name: Reject model credential disclosure\n",
        "      - name: Preserve the OpenCode result outside the source tree\n",
    )

    for secret_name in (*PROVIDER_SECRETS, "CONTEXTUAL_ORCHESTRATOR_TOKEN"):
        assert secret_name in disclosure_step
    assert (
        "OPENROUTER_API_KEY OPENAI_API_KEY CONTEXTUAL_ORCHESTRATOR_TOKEN; do"
        in disclosure_step
    )
