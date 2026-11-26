import socketserver
import threading
from collections.abc import Iterator
from typing import Any, cast

import pytest

from httpx_curl_cffi import AsyncCurlTransport, CurlOpt, CurlTransport
from tests.conftest import PolymorphClient

# libcurl reads proxies of environ on its own (only lowercase `http_proxy`),
# while transports should use only the proxy passed, see
# https://github.com/lexiforest/curl_cffi/issues/345 (fixed for trust_env=False
# in curl_cffi>=0.17 https://github.com/lexiforest/curl_cffi/pull/867)
_PROXY_ENVIRON = ("http_proxy", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY")
_NO_PROXY_ENVIRON = ("no_proxy", "NO_PROXY")


class _Server(socketserver.ThreadingTCPServer):
    # plain HTTP server answering its name, recording request lines,
    # e.g. `GET http://127.0.0.1:1234/ HTTP/1.1` when used as a proxy
    daemon_threads = True

    def __init__(self, name: str) -> None:
        self.name = name
        self.requests: list[str] = []
        super().__init__(("127.0.0.1", 0), _Handler)

    @property
    def url(self) -> str:
        host, port = self.server_address[:2]
        return f"http://{host!s}:{port}/"


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        server = cast("_Server", self.server)
        server.requests.append(self.rfile.readline().decode().strip())
        while self.rfile.readline() not in {b"\r\n", b"\n", b""}:
            pass
        body = server.name.encode()
        self.wfile.write(
            b"HTTP/1.1 200 OK\r\nConnection: close\r\n"
            b"Content-Length: %d\r\n\r\n%s" % (len(body), body),
        )


def _serve(name: str) -> Iterator[_Server]:
    with _Server(name) as server:
        thread = threading.Thread(
            target=server.serve_forever,
            args=(0.01,),
            daemon=True,
        )
        thread.start()
        yield server
        server.shutdown()


@pytest.fixture
def origin() -> Iterator[_Server]:
    yield from _serve("origin")


@pytest.fixture
def proxy() -> Iterator[_Server]:
    yield from _serve("proxy")


@pytest.fixture(params=[CurlTransport, AsyncCurlTransport])  # type: ignore[list-item]
def transport_cls(request: Any) -> type[CurlTransport | AsyncCurlTransport]:
    return request.param  # type: ignore[no-any-return]


async def test_proxy_environ_ignored(
    monkeypatch: pytest.MonkeyPatch,
    transport_cls: type[CurlTransport | AsyncCurlTransport],
    origin: _Server,
    proxy: _Server,
) -> None:
    for name in _PROXY_ENVIRON:
        monkeypatch.setenv(name, proxy.url)
    # NOTE: without curl_options, as NOPROXY was dropped without them
    async with PolymorphClient(transport=transport_cls(), trust_env=False) as client:
        resp = await client.get(origin.url)
    assert resp.text == "origin"
    assert proxy.requests == []


async def test_no_proxy_environ_ignored(
    monkeypatch: pytest.MonkeyPatch,
    transport_cls: type[CurlTransport | AsyncCurlTransport],
    origin: _Server,
    proxy: _Server,
) -> None:
    for name in _NO_PROXY_ENVIRON:
        monkeypatch.setenv(name, "*")
    transport = transport_cls(proxy=proxy.url)
    async with PolymorphClient(transport=transport, trust_env=False) as client:
        resp = await client.get(origin.url)
    assert resp.text == "proxy"
    assert proxy.requests == [f"GET {origin.url} HTTP/1.1"]
    assert origin.requests == []


async def test_curl_options_proxy_used(
    monkeypatch: pytest.MonkeyPatch,
    transport_cls: type[CurlTransport | AsyncCurlTransport],
    origin: _Server,
    proxy: _Server,
) -> None:
    # set in curl_options instead of passed, as other curl options
    for name in _NO_PROXY_ENVIRON:
        monkeypatch.setenv(name, "*")
    transport = transport_cls(curl_options={CurlOpt.PROXY: proxy.url})
    async with PolymorphClient(transport=transport, trust_env=False) as client:
        resp = await client.get(origin.url)
    assert resp.text == "proxy"
    assert proxy.requests == [f"GET {origin.url} HTTP/1.1"]
    assert origin.requests == []


def test_curl_options_not_modified(
    transport_cls: type[CurlTransport | AsyncCurlTransport],
) -> None:
    curl_options = {CurlOpt.FRESH_CONNECT: True}
    transport_cls(curl_options=curl_options)
    assert curl_options == {CurlOpt.FRESH_CONNECT: True}
