"""HTTP wrapper. It canonicalizes the request and then calls `Client.once`."""

import base64
from dataclasses import dataclass

from agent_idempotency.canonical import http_document
from agent_idempotency.errors import NonserializableResult, NotApplied, UncertainOutcome

_DROPPED_RESPONSE_HEADERS = {"authorization", "cookie", "date", "proxy-authorization", "set-cookie"}


@dataclass
class HttpResponse:
    status: int
    headers: list[tuple[str, str]]
    body: bytes

    def contract(self) -> dict:
        kept = []
        for name, value in self.headers:
            lowered = name.lower()
            if lowered in _DROPPED_RESPONSE_HEADERS:
                continue
            kept.append([lowered, value])
        kept.sort()
        return {
            "body_base64": base64.b64encode(self.body).decode("ascii"),
            "headers": kept,
            "kind": "http_response",
            "status": self.status,
        }

    @classmethod
    def from_contract(cls, body: dict) -> "HttpResponse":
        return cls(
            int(body["status"]),
            [(name, value) for name, value in body["headers"]],
            base64.b64decode(body["body_base64"]),
        )


class HttpFailure(Exception):
    """Transport failure. `bytes_written` is 0 only when no request byte was sent."""

    def __init__(self, reason: str, *, bytes_written: int | None):
        super().__init__(reason)
        self.reason = reason
        self.bytes_written = bytes_written


def http_request(client, method: str, url: str, headers=None, body: bytes = b"", transport=None) -> HttpResponse:
    """Perform one idempotent HTTP call. A second call in the same scope returns the stored response."""
    document = http_document(method, url, headers, body or b"")
    sender = transport or client.transport or _unsupported_transport

    def run() -> dict:
        try:
            response = sender(method.upper(), document["url"], headers, body or b"")
        except NotApplied:
            raise
        except UncertainOutcome:
            raise
        except HttpFailure as exc:
            if exc.bytes_written == 0:
                raise NotApplied(exc.reason) from exc
            raise UncertainOutcome("uncertain_http_outcome") from exc
        except Exception as exc:
            raise UncertainOutcome("uncertain_http_outcome") from exc
        if not isinstance(response, HttpResponse):
            raise NonserializableResult("http transport returned a value outside the contract")
        return response.contract()

    stored = client.once(document, run)
    return HttpResponse.from_contract(stored)


def _unsupported_transport(*_args):
    raise NotApplied("no http transport is configured")
