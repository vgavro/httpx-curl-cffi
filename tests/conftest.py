import ssl
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager
from typing import Any, TypeVar

import httpx
import pytest
import trustme

from httpx_curl_cffi import AsyncCurlTransport, CurlOpt, CurlTransport

_T = TypeVar("_T")


def _copy_type(_: _T) -> Callable[[Any], _T]:
    # https://github.com/python/typing/issues/769#issuecomment-903760354
    return lambda x: x


class PolymorphClient(httpx.AsyncClient):
    _client: httpx.Client | httpx.AsyncClient

    def __init__(
        self,
        transport: httpx.BaseTransport | httpx.AsyncBaseTransport,
        **kwargs: Any,
    ) -> None:
        if isinstance(transport, httpx.BaseTransport):
            self._client = httpx.Client(transport=transport, **kwargs)
        elif isinstance(transport, httpx.AsyncBaseTransport):
            self._client = httpx.AsyncClient(transport=transport, **kwargs)
        else:
            raise TypeError("Unexpected transport")

    async def __aenter__(self) -> "PolymorphClient":
        if isinstance(self._client, httpx.Client):
            self._client.__enter__()
        else:
            await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_args: Any) -> None:
        if isinstance(self._client, httpx.Client):
            self._client.__exit__(*exc_args)
        else:
            await self._client.__aexit__(*exc_args)

    @_copy_type(httpx.AsyncClient.request)
    async def request(self, *args: Any, **kwargs: Any) -> httpx.Response:
        if isinstance(self._client, httpx.Client):
            return self._client.request(*args, **kwargs)
        return await self._client.request(*args, **kwargs)

    @_copy_type(httpx.AsyncClient.send)
    async def send(self, *args: Any, **kwargs: Any) -> httpx.Response:
        if isinstance(self._client, httpx.Client):
            return self._client.send(*args, **kwargs)
        return await self._client.send(*args, **kwargs)

    # pyright doesn't like `@_copy_type(httpx.AsyncClient.stream)` here
    @asynccontextmanager
    async def stream(
        self,
        method: str,
        url: httpx.URL | str,
        **kwargs: Any,
    ) -> AsyncIterator[httpx.Response]:
        if isinstance(self._client, httpx.Client):
            with self._client.stream(method, url, **kwargs) as resp:
                yield resp
        else:
            async with self._client.stream(method, url, **kwargs) as resp:
                yield resp


@pytest.fixture(scope="session")
def ca() -> trustme.CA:
    return trustme.CA()


@pytest.fixture(scope="session")
def ca_cert_pem_path(ca: trustme.CA) -> Iterator[str]:
    with ca.cert_pem.tempfile() as tempfile:
        yield tempfile


@pytest.fixture(scope="session")
def httpserver_ssl_context(ca: trustme.CA) -> ssl.SSLContext:
    """
    This is hardcoded (fixture name is used inside `httpserver` fixture)
    context that forces `httpserver` to start in TLS mode
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    localhost_cert = ca.issue_cert("localhost")
    localhost_cert.configure_cert(context)
    return context


@pytest.fixture(
    params=[CurlTransport, AsyncCurlTransport],  # type: ignore[list-item]
)
async def client(
    request: Any,
    ca_cert_pem_path: str,
) -> AsyncIterator[PolymorphClient]:
    transport: CurlTransport | AsyncCurlTransport = request.param(
        curl_options={
            CurlOpt.CAINFO: ca_cert_pem_path,
        },
    )
    async with PolymorphClient(transport=transport) as client:
        yield client
