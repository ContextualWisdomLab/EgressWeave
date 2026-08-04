"""Outbound request-body resource limits shared by both pinned transports.

An application can accidentally or adversarially provide an unbounded request
stream even after the destination authority has passed egress validation. This
module applies a finite byte budget twice: it rejects an oversized declared
``Content-Length`` before connection-pool dispatch and counts the actual bytes
produced by synchronous and asynchronous streams. The stream that would exceed
the budget is closed before its over-budget chunk can be sent, while callers
continue to receive EgressWeave's generic non-leaking denial error.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable, Iterator

import httpx

from egressweave.validation import EGRESS_NOT_ALLOWED, EgressNotAllowedError


def _enforce_declared_request_size(
    headers: Iterable[tuple[bytes, bytes]], max_request_bytes: int
) -> None:
    """Reject unsafe or over-budget declared request content lengths.

    Request-header syntax and framing have already been normalized by the
    shared request-safety layer. This function nevertheless remains fail closed
    when called independently: no more than one ``Content-Length`` is accepted,
    and its value must be a non-empty sequence of ASCII decimal digits. The
    comparison is performed by decimal text length and lexical order instead of
    converting attacker-influenced arbitrarily long text to an integer.

    A missing ``Content-Length`` is valid because streaming requests can use
    chunked framing. Actual bytes are always constrained by the stream wrappers
    below, so this metadata check is an early rejection rather than the sole
    enforcement boundary.
    """
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

    significant_length = content_length.lstrip(b"0")
    if not significant_length:
        return
    budget_text = str(max_request_bytes).encode("ascii")
    if len(significant_length) > len(budget_text) or (
        len(significant_length) == len(budget_text)
        and significant_length > budget_text
    ):
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)


class _BoundedSyncRequestStream(httpx.SyncByteStream):
    """Forward synchronous request chunks until the finite budget is exceeded."""

    def __init__(
        self, stream: httpx.SyncByteStream, max_request_bytes: int
    ) -> None:
        """Store the caller's stream and its positive policy byte budget."""
        self._stream = stream
        self._max_request_bytes = max_request_bytes

    def __iter__(self) -> Iterator[bytes]:
        """Yield only complete chunks that keep consumption within the budget."""
        consumed_bytes = 0
        for chunk in self._stream:
            consumed_bytes += len(chunk)
            if consumed_bytes > self._max_request_bytes:
                try:
                    self._stream.close()
                finally:
                    raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
            yield chunk

    def close(self) -> None:
        """Close the caller's request stream and release any source resources."""
        self._stream.close()


class _BoundedAsyncRequestStream(httpx.AsyncByteStream):
    """Forward asynchronous request chunks within one finite byte budget."""

    def __init__(
        self, stream: httpx.AsyncByteStream, max_request_bytes: int
    ) -> None:
        """Store the caller's asynchronous stream and policy byte budget."""
        self._stream = stream
        self._max_request_bytes = max_request_bytes

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield only async chunks that keep consumption within the budget."""
        consumed_bytes = 0
        async for chunk in self._stream:
            consumed_bytes += len(chunk)
            if consumed_bytes > self._max_request_bytes:
                try:
                    await self._stream.aclose()
                finally:
                    raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
            yield chunk

    async def aclose(self) -> None:
        """Close the caller's asynchronous request stream."""
        await self._stream.aclose()
