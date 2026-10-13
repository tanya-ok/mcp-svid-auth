"""Connect only to policy-checked addresses while retaining the original TLS identity."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from ssl import SSLContext

import httpx2


class PinnedTransport(httpx2.AsyncBaseTransport):
    """No proxy environment, redirects or second hostname lookup can bypass the policy.

    Pools belong to the original origin, not the numeric address. Two DNS names sharing
    an IP therefore cannot reuse a connection authenticated for the other name.
    """

    def __init__(
        self, addresses: Callable[[str], Awaitable[list[str]]], *, verify: SSLContext | bool = True
    ) -> None:
        self.addresses = addresses
        self.verify = verify
        self.pools: dict[tuple[str, str, int | None], httpx2.AsyncHTTPTransport] = {}

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        addresses = await self.addresses(str(request.url))
        origin = (request.url.scheme, request.url.host, request.url.port)
        if origin not in self.pools:
            if len(self.pools) >= 64:
                raise httpx2.ConnectError("too many request origins", request=request)
            self.pools[origin] = httpx2.AsyncHTTPTransport(
                trust_env=False,
                verify=self.verify,
                limits=httpx2.Limits(max_connections=10, max_keepalive_connections=5),
            )
        for index, address in enumerate(addresses):
            headers = httpx2.Headers(request.headers)
            headers["Host"] = request.url.netloc.decode("ascii")
            pinned = httpx2.Request(
                request.method,
                request.url.copy_with(host=address),
                headers=headers,
                stream=request.stream,
                extensions={**request.extensions, "sni_hostname": request.url.host},
            )
            try:
                return await self.pools[origin].handle_async_request(pinned)
            except (httpx2.ConnectError, httpx2.ConnectTimeout):
                if index == len(addresses) - 1:
                    raise
        raise httpx2.ConnectError("no checked address", request=request)

    async def aclose(self) -> None:
        for pool in self.pools.values():
            await pool.aclose()
