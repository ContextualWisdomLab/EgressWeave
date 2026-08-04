"""Response-body resource limits shared by synchronous and async transports.

An allowlisted authority can still be attacker-controlled or compromised. Without
an explicit consumption budget, a valid outbound request can therefore return an
unbounded response and exhaust process memory, disk-backed buffers, or worker
capacity. This module enforces one policy budget twice: declared oversized bodies
are rejected before they are exposed to callers, while unknown-size or dishonest
responses are counted as their decoded body chunks are consumed.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable, Iterator

import httpx

from egressweave.validation import EGRESS_NOT_ALLOWED, EgressNotAllowedError

_BODYLESS_RESPONSE_STATUS_CODES = frozenset({204, 304})


def _enforce_declared_response_size(
    request_method: str,
    status_code: int,
    headers: Iterable[tuple[bytes, bytes]],
    max_response_bytes: int,
) -> None:
    """Reject unsafe declared response lengths before caller-visible delivery.

    RFC 9112 defines responses to ``HEAD`` and responses with informational,
    204, or 304 status codes as bodyless regardless of their fields. For every
    response that can carry a body, exactly one canonical decimal
    ``Content-Length`` is accepted. Duplicate, comma-joined, signed, malformed,
    or over-budget values fail behind EgressWeave's generic rejection boundary.

    This preflight is an optimization and early-failure control, not the sole
    resource limit. A server can omit ``Content-Length`` or use chunked framing,
    and a dishonest peer can declare a smaller value. The bounded stream wrappers
    below therefore count every decoded chunk as the authoritative enforcement.
    """
    if (
        request_method == "HEAD"
        or 100 <= status_code < 200
        or status_code in _BODYLESS_RESPONSE_STATUS_CODES
    ):
        return

    content_length_values = [
        value for name, value in headers if name.lower() == b"content-length"
    ]
    if not content_length_values:
        return
    if len(content_length_values) != 1:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    content_length = content_length_values[0]
    if not content_length or any(
        octet < ord("0") or octet > ord("9") for octet in content_length
    ):
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
    if int(content_length) > max_response_bytes:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)


class _BoundedSyncResponseStream(httpx.SyncByteStream):
    """Count decoded sync response bytes and close on the first overrun."""

    def __init__(
        self, stream: httpx.SyncByteStream, max_response_bytes: int
    ) -> None:
        """Store the wrapped HTTPX stream and its positive policy budget."""
        self._stream = stream
        self._max_response_bytes = max_response_bytes

    def __iter__(self) -> Iterator[bytes]:
        """Yield chunks until the next complete chunk would exceed the budget."""
        consumed_bytes = 0
        for chunk in self._stream:
            consumed_bytes += len(chunk)
            if consumed_bytes > self._max_response_bytes:
                try:
                    self._stream.close()
                finally:
                    raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
            yield chunk

    def close(self) -> None:
        """Release the wrapped response stream and its pooled connection."""
        self._stream.close()


class _BoundedAsyncResponseStream(httpx.AsyncByteStream):
    """Count decoded async response bytes and close on the first overrun."""

    def __init__(
        self, stream: httpx.AsyncByteStream, max_response_bytes: int
    ) -> None:
        """Store the wrapped HTTPX stream and its positive policy budget."""
        self._stream = stream
        self._max_response_bytes = max_response_bytes

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield chunks until the next complete chunk would exceed the budget."""
        consumed_bytes = 0
        async for chunk in self._stream:
            consumed_bytes += len(chunk)
            if consumed_bytes > self._max_response_bytes:
                try:
                    await self._stream.aclose()
                finally:
                    raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
            yield chunk

    async def aclose(self) -> None:
        """Release the wrapped async stream and its pooled connection."""
        await self._stream.aclose()
