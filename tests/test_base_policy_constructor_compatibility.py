"""Coverage contracts for the packaged base-policy constructor surface.

The response-header policy extends the original immutable policy class so
pre-1.0 positional construction remains stable. The original classmethods are
still executable production code in the packaged inheritance hierarchy and
must retain their documented string and iterable normalization behavior.
"""

from __future__ import annotations

from egressweave.response_header_policy import _BaseEgressPolicy


def test_base_from_hosts_preserves_string_and_iterable_input_forms() -> None:
    """Exercise every normalization branch in the inherited host constructor."""
    from_strings = _BaseEgressPolicy.from_hosts(
        "api.example.com",
        allowed_ports="443",
        allowed_methods="GET,HEAD",
    )
    from_iterables = _BaseEgressPolicy.from_hosts(
        ["api.example.com"],
        allowed_ports=[443],
        allowed_methods=["GET", "HEAD"],
    )

    assert from_strings == from_iterables
    assert from_strings.allowed_hosts == frozenset({"api.example.com"})
    assert from_strings.allowed_ports == frozenset({443})
    assert from_strings.allowed_methods == frozenset({"GET", "HEAD"})


def test_base_from_authorities_preserves_method_input_forms() -> None:
    """Exercise both method-normalization branches in the authority constructor."""
    from_string = _BaseEgressPolicy.from_authorities(
        [("api.example.com", "443")],
        allowed_methods="GET,HEAD",
    )
    from_iterable = _BaseEgressPolicy.from_authorities(
        (("api.example.com", 443),),
        allowed_methods=("GET", "HEAD"),
    )

    assert from_string == from_iterable
    assert from_string.allowed_authorities == frozenset(
        {("api.example.com", 443)}
    )
    assert from_string.allowed_hosts == frozenset({"api.example.com"})
    assert from_string.allowed_ports == frozenset({443})
    assert from_string.allowed_methods == frozenset({"GET", "HEAD"})
