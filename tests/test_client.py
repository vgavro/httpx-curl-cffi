# noqa:INP001  # ..is part of an implicit namespace package. Add an `__init__.py`
import ssl

import httpx
import pytest
import trustme
from pytest_httpserver import HTTPServer

from httpx_curl_cffi import AsyncCurlTransport, CurlTransport

HTTPX_USER_AGENT = httpx.Client().headers["user-agent"]


@pytest.fixture(scope="session")
def ca() -> trustme.CA:
    return trustme.CA()


@pytest.fixture(scope="session")
def httpserver_ssl_context(ca: trustme.CA) -> ssl.SSLContext:
    """
    This is hardcoded (fixture name is used inside `httpserver` fixture)
    context that forces `httpserver` to start in TLS mode
    """
    # TODO: note that we're using `verify=False` on transport initialization
    # instead of passing verification context, which is not trivial
    # with curl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    localhost_cert = ca.issue_cert("localhost")
    localhost_cert.configure_cert(context)
    return context


def test_ok(httpserver: HTTPServer) -> None:
    httpserver.expect_request(
        "/test",
        headers={"user-agent": HTTPX_USER_AGENT},
    ).respond_with_data(
        "OK",
        200,
    )
    with httpx.Client(transport=CurlTransport(verify=False)) as client:
        resp = client.get(httpserver.url_for("/test"))
    resp.raise_for_status()
    assert resp.text == "OK"


async def test_async_ok(httpserver: HTTPServer) -> None:
    httpserver.expect_request(
        "/test",
        headers={"user-agent": HTTPX_USER_AGENT},
    ).respond_with_data(
        "OK",
        200,
    )
    async with httpx.AsyncClient(transport=AsyncCurlTransport(verify=False)) as client:
        resp = await client.get(httpserver.url_for("/test"))
    resp.raise_for_status()
    assert resp.text == "OK"


def test_redirect(httpserver: HTTPServer) -> None:
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
    with httpx.Client(transport=CurlTransport(verify=False)) as client:
        resp = client.get(httpserver.url_for("/redirect"), follow_redirects=True)
    resp.raise_for_status()
    assert resp.history[0].text == "redirect"
    assert resp.text == "OK"


async def test_async_redirect(httpserver: HTTPServer) -> None:
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
    async with httpx.AsyncClient(transport=AsyncCurlTransport(verify=False)) as client:
        resp = await client.get(httpserver.url_for("/redirect"), follow_redirects=True)
    resp.raise_for_status()
    assert resp.history[0].text == "redirect"
    assert resp.text == "OK"


def test_404(httpserver: HTTPServer) -> None:
    httpserver.expect_request(
        "/test",
        headers={"user-agent": HTTPX_USER_AGENT},
    ).respond_with_data(
        "not_found",
        404,
    )
    with httpx.Client(transport=CurlTransport(verify=False)) as client:
        resp = client.get(httpserver.url_for("/test"))
    with pytest.raises(httpx.HTTPStatusError) as exc:
        resp.raise_for_status()
    assert exc.value.response.status_code == httpx.codes.NOT_FOUND
    assert resp.text == "not_found"


async def test_async_404(httpserver: HTTPServer) -> None:
    httpserver.expect_request(
        "/test",
        headers={"user-agent": HTTPX_USER_AGENT},
    ).respond_with_data(
        "not_found",
        404,
    )
    async with httpx.AsyncClient(transport=AsyncCurlTransport(verify=False)) as client:
        resp = await client.get(httpserver.url_for("/test"))
    with pytest.raises(httpx.HTTPStatusError) as exc:
        resp.raise_for_status()
    assert exc.value.response.status_code == httpx.codes.NOT_FOUND
    assert resp.text == "not_found"


def test_stream(httpserver: HTTPServer) -> None:
    httpserver.expect_request(
        "/test",
        headers={"user-agent": HTTPX_USER_AGENT},
    ).respond_with_data(
        "OK",
        200,
    )
    with (
        httpx.Client(transport=CurlTransport(verify=False)) as client,
        client.stream("GET", httpserver.url_for("/test")) as resp,
    ):
        resp.raise_for_status()
        assert resp.read() == b"OK"
        assert resp.text == "OK"


async def test_async_stream(httpserver: HTTPServer) -> None:
    httpserver.expect_request(
        "/test",
        headers={"user-agent": HTTPX_USER_AGENT},
    ).respond_with_data(
        "OK",
        200,
    )
    async with (
        httpx.AsyncClient(transport=AsyncCurlTransport(verify=False)) as client,
        client.stream("GET", httpserver.url_for("/test")) as resp,
    ):
        resp.raise_for_status()
        assert await resp.aread() == b"OK"
        assert resp.text == "OK"


def test_post(httpserver: HTTPServer) -> None:
    httpserver.expect_request(
        "/test",
        headers={"user-agent": HTTPX_USER_AGENT},
        json={"hello": "world"},
    ).respond_with_data(
        "OK",
        200,
    )
    with (
        httpx.Client(transport=CurlTransport(verify=False)) as client,
        client.stream(
            "POST",
            httpserver.url_for("/test"),
            json={"hello": "world"},
        ) as resp,
    ):
        resp.raise_for_status()
        assert resp.read() == b"OK"
        assert resp.text == "OK"


async def test_async_post(httpserver: HTTPServer) -> None:
    httpserver.expect_request(
        "/test",
        headers={"user-agent": HTTPX_USER_AGENT},
        json={"hello": "world"},
    ).respond_with_data(
        "OK",
        200,
    )
    async with (
        httpx.AsyncClient(transport=AsyncCurlTransport(verify=False)) as client,
        client.stream(
            "POST",
            httpserver.url_for("/test"),
            json={"hello": "world"},
        ) as resp,
    ):
        resp.raise_for_status()
        assert await resp.aread() == b"OK"
        assert resp.text == "OK"
