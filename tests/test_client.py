import gzip
import socket
import struct
import threading
import zlib
from collections.abc import Callable, Iterator

import brotli  # type: ignore[import-untyped]
import pytest
import zstandard
from pytest_httpserver import HTTPServer

from httpx_curl_cffi.transport import _CURL_ERRORS
from tests.conftest import PolymorphClient, httpx

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
        if isinstance(resp.stream, httpx.SyncByteStream):
            assert resp.read() == b"OK"
        else:
            assert isinstance(resp.stream, httpx.AsyncByteStream)
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
        if isinstance(resp.stream, httpx.SyncByteStream):
            raw = b"".join(resp.iter_raw())
        else:
            raw = b"".join([chunk async for chunk in resp.aiter_raw()])
    assert raw == encoded
    assert httpx.Response(200, headers=resp.headers, content=raw).text == "OK"


@pytest.mark.parametrize(
    "name",
    sorted({*_CURL_ERRORS.values(), "RequestError"}),
)
def test_error_classes_exist(name: str) -> None:
    # resolved by name of the request's module, see `_create_error`
    error_cls = getattr(httpx, name)
    assert issubclass(error_cls, httpx.RequestError)


async def test_connect_error(client: PolymorphClient) -> None:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    with pytest.raises(httpx.ConnectError):
        await client.get(f"http://127.0.0.1:{port}/")


@pytest.fixture(
    params=[
        # closing connection gracefully (FIN)
        ("fin", httpx.RemoteProtocolError),
        # resetting connection (RST, by zero linger timeout)
        ("rst", httpx.ReadError),
    ],
    ids=["fin", "rst"],
)
def incomplete(
    request: pytest.FixtureRequest,
) -> Iterator[tuple[str, type[httpx.TransportError]]]:
    # responds with incomplete body, yields url and error expected,
    # the same as raised by httpx transports
    close, error_cls = request.param

    def serve(server: socket.socket) -> None:
        conn, _ = server.accept()
        with conn:
            conn.recv(65536)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nOK")
            if close == "rst":
                linger = struct.pack("ii", 1, 0)
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)

    with socket.create_server(("127.0.0.1", 0)) as server:
        threading.Thread(target=serve, args=(server,), daemon=True).start()
        yield f"http://127.0.0.1:{server.getsockname()[1]}/", error_cls


async def _stream_read(client: PolymorphClient, url: str) -> None:
    async with client.stream("GET", url) as resp:
        if isinstance(resp.stream, httpx.SyncByteStream):
            resp.read()
        else:
            await resp.aread()


async def test_incomplete_body_error(
    client: PolymorphClient,
    incomplete: tuple[str, type[httpx.TransportError]],
) -> None:
    # raised on reading body, not on sending request
    url, error_cls = incomplete
    with pytest.raises(error_cls) as exc:
        await _stream_read(client, url)
    assert exc.value.request.url == url


async def test_incomplete_body_error_not_streamed(
    client: PolymorphClient,
    incomplete: tuple[str, type[httpx.TransportError]],
) -> None:
    # transports always stream, so the same is raised on reading body by client
    url, error_cls = incomplete
    with pytest.raises(error_cls) as exc:
        await client.get(url)
    assert exc.value.request.url == url
