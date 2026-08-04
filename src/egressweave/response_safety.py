"""Response-body resource limits shared by synchronous and async transports.

An allowlisted authority can still be attacker-controlled or compromised. Without
an explicit consumption budget, a valid outbound request can therefore return an
unbounded response and exhaust process memory, disk-backed buffers, or worker
capacity. EgressWeave requests identity coding, rejects a body-bearing response
that nevertheless applies a content coding, rejects unsafe declared lengths
before caller-visible delivery, and counts every transfer-decoded body byte while
it is consumed. The identity-coding invariant prevents decompression expansion
from occurring outside the byte budget.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable, Iterator

import httpx

from egressweave.validation import EGRESS_NOT_ALLOWED, EgressNotAllowedError

_BODYLESS_RESPONSE_STATUS_CODES = frozenset({204, 304})


def _force_identity_accept_encoding(
    headers: Iterable[tuple[bytes, bytes]],
) -> list[tuple[bytes, bytes]]:
    """Replace caller compression preferences with one trusted identity request.

    The safe request-header builder has already validated every field and placed
    the trusted ``Host`` field last. This function removes all caller-supplied
    ``Accept-Encoding`` fields, adds ``identity``, and preserves ``Host`` as the
    final field. A server that ignores the request and returns a content-coded
    body is rejected by :func:`_enforce_declared_response_size` before HTTPX can
    allocate decompressed output outside the policy byte budget.
    """
    safe_headers: list[tuple[bytes, bytes]] = []
    trusted_host: tuple[bytes, bytes] | None = None
    for name, value in headers:
        normalized_name = name.lower()
        if normalized_name == b"accept-encoding":
            continue
        if normalized_name == b"host":
            trusted_host = (name, value)
            continue
        safe_headers.append((name, value))

    safe_headers.append((b"accept-encoding", b"identity"))
    if trusted_host is not None:
        safe_headers.append(trusted_host)
    return safe_headers


def _enforce_declared_response_size(
    request_method: str,
    status_code: int,
    headers: Iterable[tuple[bytes, bytes]],
    max_response_bytes: int,
) -> None:
    """Reject content coding or unsafe lengths before caller-visible delivery.

    RFC 9112 defines responses to ``HEAD`` and responses with informational,
    204, or 304 status codes as bodyless regardless of their fields. Their
    representation metadata is therefore not interpreted as transferred bytes.

    Every body-bearing response must be identity-coded: an absent
    ``Content-Encoding`` or exactly one canonical ``identity`` value is allowed.
    This pairs with the trusted ``Accept-Encoding: identity`` request field and
    prevents a compressed chunk from expanding beyond the policy limit before a
    post-decompression check can run. Exactly one canonical decimal
    ``Content-Length`` is accepted when present. Duplicate, comma-joined, signed,
    malformed, or over-budget values fail behind EgressWeave's generic rejection
    boundary.

    This metadata preflight is not the sole length control. A peer can omit or
    under-declare ``Content-Length`` or use chunked framing, so the bounded stream
    wrappers below count every transfer-decoded identity body chunk.
    """
    if (
        request_method == "HEAD"
        or 100 <= status_code < 200
        or status_code in _BODYLESS_RESPONSE_STATUS_CODES
    ):
        return

    header_items = tuple(headers)
    content_encoding_values = [
        value for name, value in header_items if name.lower() == b"content-encoding"
    ]
    if len(content_encoding_values) > 1:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
    if content_encoding_values:
        content_encoding = content_encoding_values[0]
        if content_encoding != b"identity":
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    content_length_values = [
        value for name, value in header_items if name.lower() == b"content-length"
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
    """Count identity-coded sync response bytes and close on first overrun."""

    def __init__(
        self, stream: httpx.SyncByteStream, max_response_bytes: int
    ) -> None:
        """Store the wrapped HTTPX stream and its positive policy budget."""
        self._stream = stream
        self._max_response_bytes = max_response_bytes

    def __iter__(self) -> Iterator[bytes]:
        """Yield chunks until the next complete chunk exceeds the budget."""
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
    """Count identity-coded async response bytes and close on first overrun."""

    def __init__(
        self, stream: httpx.AsyncByteStream, max_response_bytes: int
    ) -> None:
        """Store the wrapped HTTPX stream and its positive policy budget."""
        self._stream = stream
        self._max_response_bytes = max_response_bytes

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield chunks until the next complete chunk exceeds the budget."""
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
