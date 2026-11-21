"""Optional interception for urllib. Direct database drivers stay outside the guarantee."""

import urllib.request

from agent_idempotency.http import http_request


def install_urllib_enforcement(client) -> None:
    """Route `urllib.request.urlopen` through the idempotency client."""
    if getattr(urllib.request, "_idempotency_wrapped", False):
        return
    original = urllib.request.urlopen

    def urlopen(url, data=None, timeout=None, *, context=None, **_kwargs):
        request = url if isinstance(url, urllib.request.Request) else urllib.request.Request(url, data=data)
        body = request.data or b""
        headers = dict(request.header_items())
        if client.transport is None:
            client.transport = _original_transport(original, timeout, context)
        return http_request(client, request.get_method(), request.full_url, headers, body)

    urllib.request.urlopen = urlopen
    urllib.request._idempotency_original_urlopen = original
    urllib.request._idempotency_wrapped = True


def remove_urllib_enforcement() -> None:
    if not getattr(urllib.request, "_idempotency_wrapped", False):
        return
    urllib.request.urlopen = urllib.request._idempotency_original_urlopen
    urllib.request._idempotency_wrapped = False


def _original_transport(original, timeout, context):
    def send(method, url, headers, body):
        from agent_idempotency.http import HttpResponse

        request = urllib.request.Request(url, data=body or None, method=method, headers=dict(headers or {}))
        kwargs = {}
        if timeout is not None:
            kwargs["timeout"] = timeout
        if context is not None:
            kwargs["context"] = context
        with original(request, **kwargs) as response:
            payload = response.read()
            pairs = list(response.headers.items())
            return HttpResponse(response.status, pairs, payload)

    return send
