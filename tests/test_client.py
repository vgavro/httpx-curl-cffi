import gzip
import zlib
from collections.abc import Callable

import brotli  # type: ignore[import-untyped]
import httpx
import pytest
import zstandard
from httpx._client import BoundAsyncStream, BoundSyncStream
from pytest_httpserver import HTTPServer

from tests.conftest import PolymorphClient

HTTPX_USER_AGENT = httpx.Client().headers["user-agent"]


async def test_ok(httpserver: HTTPServer, client: PolymorphClient) -> None:
    httpserver.expect_request(
        "/test",
        headers={"user-agent": HTTPX_USER_AGENT},
    ).respond_with_data(
        "OK",
        200,
    )
    resp = await client.get(httpserver.url_for("/test"))
    resp.raise_for_status()
    assert resp.text == "OK"


async def test_redirect(httpserver: HTTPServer, client: PolymorphClient) -> None:
    httpserver.expect_ordered_request(
        "/redirect",
        headers={"user-agent": HTTPX_USER_AGENT},
    ).respond_with_data(
        "redirect",
        301,
        headers={"location": httpserver.url_for("/test")},
    )
    httpserver.expect_ordered_request(
        "/test",
        headers={"user-agent": HTTPX_USER_AGENT},
    ).respond_with_data(
        "OK",
        200,
    )
    resp = await client.get(httpserver.url_for("/redirect"), follow_redirects=True)
    resp.raise_for_status()
    assert resp.history[0].text == "redirect"
    assert resp.text == "OK"


async def test_404(httpserver: HTTPServer, client: PolymorphClient) -> None:
    httpserver.expect_request(
        "/test",
        headers={"user-agent": HTTPX_USER_AGENT},
    ).respond_with_data(
        "not_found",
        404,
    )
    resp = await client.get(httpserver.url_for("/test"))
    with pytest.raises(httpx.HTTPStatusError) as exc:
        resp.raise_for_status()
    assert exc.value.response.status_code == httpx.codes.NOT_FOUND
    assert resp.text == "not_found"


async def test_post(httpserver: HTTPServer, client: PolymorphClient) -> None:
    httpserver.expect_request(
        "/test",
        headers={"user-agent": HTTPX_USER_AGENT},
        json={"hello": "world"},
    ).respond_with_data(
        "OK",
        200,
    )
    resp = await client.post(httpserver.url_for("/test"), json={"hello": "world"})
    resp.raise_for_status()
    assert resp.text == "OK"


async def test_stream(httpserver: HTTPServer, client: PolymorphClient) -> None:
    httpserver.expect_request(
        "/test",
        headers={"user-agent": HTTPX_USER_AGENT},
    ).respond_with_data(
        "OK",
        200,
    )
    async with client.stream(
        "POST",
        httpserver.url_for("/test"),
    ) as resp:
        resp.raise_for_status()
        if isinstance(resp.stream, BoundSyncStream):
            assert resp.read() == b"OK"
        else:
            assert isinstance(resp.stream, BoundAsyncStream)
            assert await resp.aread() == b"OK"
        assert resp.text == "OK"


_ENCODERS: dict[str, Callable[[bytes], bytes]] = {
    "gzip": gzip.compress,
    "deflate": zlib.compress,
    "br": brotli.compress,
    "zstd": zstandard.compress,
}


@pytest.mark.parametrize("encoding", list(_ENCODERS))
async def test_encoded(
    httpserver: HTTPServer,
    client: PolymorphClient,
    encoding: str,
) -> None:
    httpserver.expect_request("/test").respond_with_data(
        _ENCODERS[encoding](b"OK"),
        200,
        headers={"content-encoding": encoding},
    )
    resp = await client.get(httpserver.url_for("/test"))
    resp.raise_for_status()
    assert resp.headers["content-encoding"] == encoding
    assert resp.text == "OK"


@pytest.mark.parametrize("encoding", list(_ENCODERS))
async def test_encoded_raw(
    httpserver: HTTPServer,
    client: PolymorphClient,
    encoding: str,
) -> None:
    # raw content isn't decoded by curl, as by httpx transports, so responses
    # may be created of it again (e.g. by transports wrapping this one)
    encoded = _ENCODERS[encoding](b"OK")
    httpserver.expect_request("/test").respond_with_data(
        encoded,
        200,
        headers={"content-encoding": encoding},
    )
    async with client.stream("GET", httpserver.url_for("/test")) as resp:
        if isinstance(resp.stream, BoundSyncStream):
            raw = b"".join(resp.iter_raw())
        else:
            raw = b"".join([chunk async for chunk in resp.aiter_raw()])
    assert raw == encoded
    assert httpx.Response(200, headers=resp.headers, content=raw).text == "OK"
