"""Usage with httpx and httpx2, checked by type checkers only (not collected),
transports should be accepted by clients of both without aliasing.
"""

import httpx
import httpx2
from typing_extensions import assert_type

from httpx_curl_cffi import AsyncCurlTransport, CurlTransport


def check_httpx(request: httpx.Request) -> None:
    with httpx.Client(transport=CurlTransport()) as client:
        assert_type(client.get("https://example.com"), httpx.Response)
    assert_type(CurlTransport().handle_request(request), httpx.Response)


async def check_httpx_async(request: httpx.Request) -> None:
    async with httpx.AsyncClient(transport=AsyncCurlTransport()) as client:
        assert_type(await client.get("https://example.com"), httpx.Response)
    transport = AsyncCurlTransport()
    assert_type(await transport.handle_async_request(request), httpx.Response)


def check_httpx2(request: httpx2.Request) -> None:
    with httpx2.Client(transport=CurlTransport()) as client:
        assert_type(client.get("https://example.com"), httpx2.Response)
    assert_type(CurlTransport().handle_request(request), httpx2.Response)


async def check_httpx2_async(request: httpx2.Request) -> None:
    async with httpx2.AsyncClient(transport=AsyncCurlTransport()) as client:
        assert_type(await client.get("https://example.com"), httpx2.Response)
    transport = AsyncCurlTransport()
    assert_type(await transport.handle_async_request(request), httpx2.Response)
