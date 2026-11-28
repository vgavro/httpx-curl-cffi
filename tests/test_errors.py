"""Errors raised by curl transports, matching errors raised by httpx transports
in the same cases, each case is checked with both (exact error class expected).
"""

import socket
import ssl
import struct
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any, NamedTuple

import pytest
import trustme

from httpx_curl_cffi import AsyncCurlTransport, CurlTransport
from httpx_curl_cffi.transport import _CURL_ERRORS
from tests.conftest import PolymorphClient, httpx

_Handler = Callable[[socket.socket], None]

_RESPONSE_HEAD = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
_CHUNKED_HEAD = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"


def _reset(conn: socket.socket) -> None:
    # closed with RST instead of FIN, by zero linger timeout
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))


def _respond(data: bytes, *, sleep: float = 0, reset: bool = False) -> _Handler:
    def handler(conn: socket.socket) -> None:
        conn.recv(65536)
        conn.sendall(data)
        time.sleep(sleep)
        if reset:
            _reset(conn)

    return handler


class _Servers:
    """Raw socket servers, handling each connection by handler and closing it"""

    def __init__(self, ca: trustme.CA) -> None:
        self._ca = ca
        self._sockets: list[socket.socket] = []

    def _socket(self) -> socket.socket:
        sock = socket.socket()
        self._sockets.append(sock)
        sock.bind(("127.0.0.1", 0))
        return sock

    def _url(self, sock: socket.socket, scheme: str = "http") -> str:
        return f"{scheme}://127.0.0.1:{sock.getsockname()[1]}/"

    def url(self, handler: _Handler, *, tls: bool = False) -> str:
        sock = self._socket()
        sock.listen()
        context = None
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._ca.issue_cert("127.0.0.1").configure_cert(context)

        def handle(conn: socket.socket) -> None:
            try:
                if context:
                    conn = context.wrap_socket(conn, server_side=True)
                handler(conn)
            except OSError:
                pass
            finally:
                conn.close()

        def serve() -> None:
            while True:
                try:
                    conn, _ = sock.accept()
                except OSError:  # closed
                    return
                threading.Thread(target=handle, args=(conn,), daemon=True).start()

        threading.Thread(target=serve, daemon=True).start()
        return self._url(sock, "https" if tls else "http")

    def closed_url(self) -> str:
        # bound, but not listening, so connection is refused
        return self._url(self._socket())

    def backlog_full_url(self) -> str:
        # connections are not accepted when backlog queue is full,
        # so connecting hangs until timeout
        sock = self._socket()
        sock.listen(0)
        for _ in range(3):
            conn = socket.socket()
            self._sockets.append(conn)
            conn.settimeout(0)  # non-blocking
            conn.connect_ex(sock.getsockname())
        return self._url(sock)

    def close(self) -> None:
        for sock in self._sockets:
            sock.close()


@pytest.fixture
def servers(ca: trustme.CA) -> Iterator[_Servers]:
    servers = _Servers(ca)
    yield servers
    servers.close()


class _Case(NamedTuple):
    # url and transport kwargs of servers
    setup: Callable[[_Servers], tuple[str, dict[str, Any]]]
    error_name: str
    request_kwargs: dict[str, Any] = {}  # noqa: RUF012


_TIMEOUT = {"timeout": 0.5}

_CASES: dict[str, _Case] = {
    "unsupported_protocol": _Case(
        lambda _: ("foo://127.0.0.1:1/", {}),
        "UnsupportedProtocol",
    ),
    "connection_refused": _Case(
        lambda s: (s.closed_url(), {}),
        "ConnectError",
    ),
    "dns_failed": _Case(
        lambda _: ("http://nonexistent.invalid/", {}),
        "ConnectError",
    ),
    "connect_timeout": _Case(
        lambda s: (s.backlog_full_url(), {}),
        "ConnectTimeout",
        _TIMEOUT,
    ),
    "tls_untrusted": _Case(
        lambda s: (s.url(_respond(_RESPONSE_HEAD), tls=True), {}),
        "ConnectError",
    ),
    "tls_to_plain": _Case(
        lambda s: (s.url(_respond(_RESPONSE_HEAD)).replace("http", "https"), {}),
        "ConnectError",
    ),
    "plain_to_tls": _Case(
        lambda s: (s.url(_respond(b""), tls=True).replace("https", "http"), {}),
        "ReadError",
    ),
    "proxy_refused": _Case(
        lambda s: ("http://example.com/", {"proxy": s.closed_url()}),
        "ConnectError",
    ),
    "proxy_dns_failed": _Case(
        lambda _: ("http://example.com/", {"proxy": "http://nonexistent.invalid"}),
        "ConnectError",
    ),
    "proxy_connect_forbidden": _Case(
        lambda s: (
            "https://example.com/",
            {"proxy": s.url(_respond(b"HTTP/1.1 403 Forbidden\r\n\r\n"))},
        ),
        "ProxyError",
    ),
    "reset_before_response": _Case(
        lambda s: (s.url(_respond(b"", reset=True)), {}),
        "ReadError",
    ),
    "empty_response": _Case(
        lambda s: (s.url(_respond(b"")), {}),
        "RemoteProtocolError",
    ),
    "invalid_response": _Case(
        lambda s: (s.url(_respond(b"invalid response\r\n\r\n")), {}),
        "RemoteProtocolError",
    ),
    "read_timeout": _Case(
        lambda s: (s.url(_respond(b"", sleep=5)), {}),
        "ReadTimeout",
        _TIMEOUT,
    ),
    "body_read_timeout": _Case(
        # NOTE: curl_cffi timeouts in stream mode are by low speed (1 byte/sec)
        # during `ceil(connect + read)` seconds, so it's longer
        lambda s: (s.url(_respond(_RESPONSE_HEAD + b"OK", sleep=5)), {}),
        "ReadTimeout",
        _TIMEOUT,
    ),
    "body_incomplete": _Case(
        lambda s: (s.url(_respond(_RESPONSE_HEAD + b"OK")), {}),
        "RemoteProtocolError",
    ),
    "body_reset": _Case(
        lambda s: (s.url(_respond(_RESPONSE_HEAD + b"OK", reset=True)), {}),
        "ReadError",
    ),
    "body_invalid_chunk_size": _Case(
        lambda s: (s.url(_respond(_CHUNKED_HEAD + b"invalid\r\n")), {}),
        "RemoteProtocolError",
    ),
    "body_invalid_chunk": _Case(
        lambda s: (s.url(_respond(_CHUNKED_HEAD + b"2\r\nOKOK\r\n0\r\n\r\n")), {}),
        "RemoteProtocolError",
    ),
}


_TRANSPORTS = {
    "httpx": lambda kwargs: httpx.HTTPTransport(**kwargs),
    "httpx_async": lambda kwargs: httpx.AsyncHTTPTransport(**kwargs),
    "curl": lambda kwargs: CurlTransport(**kwargs),
    "curl_async": lambda kwargs: AsyncCurlTransport(**kwargs),
}


@pytest.mark.parametrize("transport", list(_TRANSPORTS))
@pytest.mark.parametrize("case", list(_CASES))
async def test_error(servers: _Servers, transport: str, case: str) -> None:
    setup, error_name, request_kwargs = _CASES[case]
    url, transport_kwargs = setup(servers)
    async with PolymorphClient(
        transport=_TRANSPORTS[transport](transport_kwargs),
        trust_env=False,
    ) as client:
        with pytest.raises(httpx.RequestError) as exc:
            await client.get(url, **request_kwargs)
    assert type(exc.value).__name__ == error_name, exc.value
    assert type(exc.value) is getattr(httpx, error_name)
    assert exc.value.request.url == url


def _error_names() -> set[str]:
    return {
        name
        for names in _CURL_ERRORS.values()
        for name in (names.values() if isinstance(names, dict) else [names])
    }


@pytest.mark.parametrize("name", sorted({*_error_names(), "RequestError"}))
def test_error_class_exists(name: str) -> None:
    # resolved by name of the request's module, see `_create_error`
    error_cls = getattr(httpx, name)
    assert issubclass(error_cls, httpx.RequestError)


@pytest.mark.parametrize(
    "code",
    [code for code, names in _CURL_ERRORS.items() if isinstance(names, dict)],
)
def test_error_by_message_default(code: int) -> None:
    # "" matches any message, so it's the last, otherwise next ones never matched
    names = _CURL_ERRORS[code]
    assert isinstance(names, dict)
    assert list(names)[-1] == ""
