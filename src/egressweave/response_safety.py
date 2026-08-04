"""Response-body resource limits shared by synchronous and async transports.

An allowlisted authority can still be attacker-controlled or compromised. Without
an explicit consumption budget, a valid outbound request can therefore return an
unbounded response and exhaust process memory, disk-backed buffers, or worker
capacity. This module enforces one policy budget at three boundaries: declared
oversized bodies are rejected before caller-visible delivery, raw transport bytes
are bounded during transfer, and HTTPX-decoded bytes are bounded after content
coding so compressed responses cannot amplify past the policy limit.
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
    resource limit. A server can omit ``Content-Length``, use chunked framing,
    lie about the declared size, or apply a content coding whose decoded output
    is much larger. The bounded raw streams and response subclass below provide
    the authoritative transfer and decoded-consumption enforcement.
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
    """Count raw sync response bytes and close on the first overrun."""

    def __init__(
        self, stream: httpx.SyncByteStream, max_response_bytes: int
    ) -> None:
        """Store the wrapped HTTPX stream and its positive policy budget."""
        self._stream = stream
        self._max_response_bytes = max_response_bytes

    def __iter__(self) -> Iterator[bytes]:
        """Yield raw chunks until the next complete chunk exceeds the budget."""
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
    """Count raw async response bytes and close on the first overrun."""

    def __init__(
        self, stream: httpx.AsyncByteStream, max_response_bytes: int
    ) -> None:
        """Store the wrapped HTTPX stream and its positive policy budget."""
        self._stream = stream
        self._max_response_bytes = max_response_bytes

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield raw chunks until the next complete chunk exceeds the budget."""
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


class _BoundedHTTPXResponse(httpx.Response):
    """Apply the policy budget after HTTPX content decoding as well as before it."""

    def __init__(
        self, status_code: int, *, max_response_bytes: int, **kwargs
    ) -> None:
        """Initialize a normal HTTPX response with a decoded-byte budget."""
        self._max_response_bytes = max_response_bytes
        super().__init__(status_code, **kwargs)

    def iter_bytes(self, chunk_size: int | None = None) -> Iterator[bytes]:
        """Yield decoded sync chunks without allowing decompression amplification."""
        consumed_bytes = 0
        for chunk in super().iter_bytes(chunk_size=chunk_size):
            consumed_bytes += len(chunk)
            if consumed_bytes > self._max_response_bytes:
                try:
                    self.close()
                finally:
                    raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
            yield chunk

    async def aiter_bytes(
        self, chunk_size: int | None = None
    ) -> AsyncIterator[bytes]:
        """Yield decoded async chunks without allowing decompression amplification."""
        consumed_bytes = 0
        async for chunk in super().aiter_bytes(chunk_size=chunk_size):
            consumed_bytes += len(chunk)
            if consumed_bytes > self._max_response_bytes:
                try:
                    await self.aclose()
                finally:
                    raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
            yield chunk
