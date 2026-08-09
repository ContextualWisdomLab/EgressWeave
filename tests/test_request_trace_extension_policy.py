"""Regression contracts for request-extension transport capability isolation."""

from __future__ import annotations

from collections.abc import Iterator, Mapping

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


def test_unreviewed_request_extension_is_rejected_before_httpcore_dispatch() -> None:
    """Fail closed instead of forwarding a future capability-bearing extension."""
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        _bind_validated_tls_server_name(
            {"future_transport_capability": object()},
            "api.example.com",
        )


def test_hostile_extension_mapping_is_masked_by_generic_denial() -> None:
    """Do not leak caller-controlled mapping failures while inspecting capabilities."""

    class HostileExtensions(Mapping[str, object]):
        """Raise while request-extension keys are enumerated."""

        def __getitem__(self, key: str) -> object:
            """Provide no readable entry."""
            raise KeyError(key)

        def __iter__(self) -> Iterator[str]:
            """Fail when the policy boundary enumerates request capabilities."""
            raise RuntimeError("private mapping failure")

        def __len__(self) -> int:
            """Advertise one entry so callers attempt enumeration."""
            return 1

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$") as error:
        _bind_validated_tls_server_name(HostileExtensions(), "api.example.com")

    assert error.value.__cause__ is None


@pytest.mark.parametrize("value_kind", ["bytes", "text"])
def test_subclassed_sni_values_fail_before_attacker_methods_run(value_kind: str) -> None:
    """Require exact built-in SNI value types instead of invoking subclass methods."""

    class HostileBytes(bytes):
        """Raise if the policy boundary invokes a subclass-controlled decoder."""

        def decode(self, *args: object, **kwargs: object) -> str:
            """Expose an unsafe subclass method call if it occurs."""
            del args, kwargs
            raise RuntimeError("private bytes decode")

    class HostileText(str):
        """Raise if hostname normalization invokes a subclass-controlled method."""

        def strip(self, *args: object, **kwargs: object) -> str:
            """Expose an unsafe subclass method call if it occurs."""
            del args, kwargs
            raise RuntimeError("private text strip")

    value: object
    if value_kind == "bytes":
        value = HostileBytes(b"api.example.com")
    else:
        value = HostileText("api.example.com")

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$") as error:
        _bind_validated_tls_server_name(
            {"sni_hostname": value},
            "api.example.com",
        )

    assert error.value.__cause__ is None
