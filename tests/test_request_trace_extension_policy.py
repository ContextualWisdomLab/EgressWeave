"""Regression contracts for request-extension transport capability isolation."""

from __future__ import annotations

import pytest

from egressweave.request_safety import _bind_validated_tls_server_name
from egressweave.validation import EgressNotAllowedError


def test_trace_extension_is_rejected_before_httpcore_dispatch() -> None:
    """Do not expose HTTPCore's raw transport lifecycle through caller trace hooks."""

    def trace_callback(event_name: str, info: object) -> None:
        """Represent a caller-controlled HTTPCore trace callback."""
        del event_name, info

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        _bind_validated_tls_server_name(
            {"trace": trace_callback},
            "api.example.com",
        )
