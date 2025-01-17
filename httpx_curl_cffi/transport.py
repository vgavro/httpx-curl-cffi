import ssl
from asyncio import AbstractEventLoop
from collections.abc import AsyncIterator, Iterator
from datetime import timedelta
from http.cookiejar import Cookie, CookieJar
from pathlib import PurePath
from typing import (
    TYPE_CHECKING,
    Any,
    ClassVar,
    Generic,
    TypedDict,
    TypeVar,
    Unpack,
)

import httpx
from curl_cffi import CurlECode, CurlHttpVersion, CurlInfo, CurlOpt
from curl_cffi.requests import Response as _Response
from curl_cffi.requests.impersonate import (
    ExtraFingerprints,
    ExtraFpDict,
)
from curl_cffi.requests.session import (
    AsyncCurl,
    Curl,
    ThreadType,
)
from curl_cffi.requests.session import (
    AsyncSession as _AsyncSession,
)
from curl_cffi.requests.session import (
    BaseSession as _BaseSession,
)
from curl_cffi.requests.session import (
    Session as _SyncSession,
)
from httpx._decoders import IdentityDecoder

if TYPE_CHECKING:
    from curl_cffi.requests.impersonate import (
        BrowserTypeLiteral,
    )
else:
    BrowserTypeLiteral = str

if TYPE_CHECKING:
    from curl_cffi.requests.session import (
        BaseSessionParams as _BaseSessionParams,
    )
else:
    _BaseSessionParams = dict[str, Any]

if TYPE_CHECKING:
    from curl_cffi.requests.exceptions import RequestException as _RequestError
else:
    try:
        from curl_cffi.requests.exceptions import RequestException as _RequestError
    except ImportError:
        from curl_cffi.requests.errors import RequestsError as _RequestError


_HTTPX_DEFAULT_HEADERS: list[tuple[str, str]] = list(
    httpx.Client(trust_env=False).headers.items(),
)

_CURL_ERRORS: dict[CurlECode, type[httpx.RequestError]] = {
    CurlECode.UNSUPPORTED_PROTOCOL: httpx.ProtocolError,
    CurlECode.COULDNT_CONNECT: httpx.ConnectError,
    CurlECode.COULDNT_RESOLVE_HOST: httpx.ConnectError,
    CurlECode.COULDNT_RESOLVE_PROXY: httpx.ProxyError,
    CurlECode.SSL_CONNECT_ERROR: httpx.ConnectError,
    CurlECode.READ_ERROR: httpx.ReadError,
    CurlECode.RECV_ERROR: httpx.ReadError,
    CurlECode.WRITE_ERROR: httpx.WriteError,
    CurlECode.BAD_CONTENT_ENCODING: httpx.DecodingError,
    CurlECode.OPERATION_TIMEDOUT: httpx.TimeoutException,
}


class _DummyCookieJar(CookieJar):
    def set_cookie(self, cookie: Cookie) -> None:  # noqa:ARG002
        return


class CurlAsyncByteStream(httpx.AsyncByteStream):
    _resp: _Response

    def __init__(self, resp: _Response) -> None:
        self._resp = resp

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for data in self._resp.aiter_content():
            yield data

    async def aclose(self) -> None:
        await self._resp.aclose()


class CurlSyncByteStream(httpx.SyncByteStream):
    _resp: _Response

    def __init__(self, resp: _Response) -> None:
        self._resp = resp

    def __iter__(self) -> Iterator[bytes]:
        yield from self._resp.iter_content()

    def close(self) -> None:
        self._resp.close()


def _adapt_cert(
    cert: PurePath | tuple[PurePath, PurePath] | None,
) -> str | tuple[str, str] | None:
    if not cert:
        return None
    if isinstance(cert, tuple):
        cert_len = 2
        if not all(isinstance(x, PurePath) for x in cert) or not len(cert) == cert_len:
            raise TypeError("cert expected to be `Path | tuple[Path, Path]`")
        return str(cert[0]), str(cert[1])
    if not isinstance(cert, PurePath):
        raise TypeError("cert expected to be `Path | tuple[Path, Path]`")
    return str(cert)


class CurlTransportParams(TypedDict, total=False):
    """httpx-compatible Transport parameters,
    corresponds to `curl_cffi.requests.session.BaseSessionParams`
    """

    debug: bool

    ## ---- Request arguments set on `httpx.HTTPTransport` by httpx design,
    ## still it's request parameters in `curl_cffi.requests.Session`
    ## and we may override them in `Request.extensions`

    proxy: str | httpx.Proxy | None

    verify: bool
    # Deprecated with httpx if favor of passing `verify` as `ssl.SSLContext`,
    # in `httpx` it's (certfile, keyfile=None, password=None)
    # str | tuple[str, str] | tuple[str, str, str]
    # here it's certfile, keyfile without password?
    # TODO: make this in-memory data instead of filenames
    cert: PurePath | tuple[PurePath, PurePath] | None

    ## in `httpx.HTTPTransport` it's http1=True, http2=false arguments,
    ## don't try to mimic that
    http_version: CurlHttpVersion | None

    ## name compatible with `httpx.HTTPTransport`
    ## binds to "interfrace" `curl_cffi` parameter
    local_address: str | None

    ## --- Curl-impersonate related params,
    ## should be passed in `Request.extensions`, but may be set on transport
    impersonate: BrowserTypeLiteral | None
    ja3: str | None
    akamai: str | None
    extra_fp: ExtraFingerprints | ExtraFpDict | None
    default_headers: bool

    ## --- Curl related params
    curl_options: dict[CurlOpt, Any]
    # https://curl.se/libcurl/c/curl_easy_getinfo.html
    curl_infos: list[CurlInfo]


SessionT = TypeVar("SessionT", bound=_BaseSession)


class BaseCurlTransport(Generic[SessionT]):
    _session_cls: type[SessionT]
    _session: SessionT
    _stream_wrap_cls: ClassVar[type[CurlSyncByteStream | CurlAsyncByteStream]]

    @staticmethod
    def _create_session_params(
        params: CurlTransportParams,
    ) -> _BaseSessionParams:
        if isinstance(params.get("verify"), ssl.SSLContext):
            raise TypeError(
                "verify parameter can't be `ssl.SSLContext` "
                "because OpenSSL may not be used",
            )

        # See https://github.com/lexiforest/curl_cffi/issues/345
        # curl is always using environ,
        # We're explicitly setting NOPROXY option below
        # to override proxy usage from environ.
        # With httpx it's expected that proxy environ
        # read by `httpx.Client` with trust_env=True (default),
        # and separate mounts created with separate transports.
        assert not params.get("trust_env")

        curl_options = params.get("curl_options") or {}

        proxy = params.get("proxy", None)
        if proxy:
            if isinstance(proxy, str):
                proxy = httpx.Proxy(url=proxy)

            # """
            # Setting the noproxy string to "" (an empty string)
            # explicitly enables the proxy for all hostnames,
            # even if there is an environment variable set for it.
            # """
            # https://curl.se/libcurl/c/CURLOPT_NOPROXY.html
            curl_options[CurlOpt.NOPROXY] = ""
        else:
            proxy = None
            curl_options[CurlOpt.NOPROXY] = "*"

        return {
            "debug": params.get("debug", False),
            "proxy": str(proxy.url) if proxy else None,
            "proxy_auth": proxy.auth if proxy and proxy.auth else None,
            # NOTE: proxy_headers is not currently
            # supported in Session, while it's achievable
            # in `curl-cffi` in general.
            "verify": params.get("verify", True),
            "cert": _adapt_cert(params.get("cert")),
            "http_version": params.get("http_version"),
            "interface": params.get("local_address"),
            "impersonate": params.get("impersonate"),
            "ja3": params.get("ja3"),
            "akamai": params.get("akamai"),
            "extra_fp": params.get("extra_fp"),
            "default_headers": params.get("default_headers", False),
            "curl_options": params.get("curl_options"),
            "curl_infos": params.get("curl_infos"),
            # NOTE: trust_env isn't working, see ticket above
            "trust_env": False,
            "cookies": _DummyCookieJar(),
            "allow_redirects": False,
        }

    def _create_request_params(self, req: httpx.Request) -> dict[str, Any]:
        if self._session.default_headers:
            # drop httpx default headers
            for header, value in _HTTPX_DEFAULT_HEADERS:
                if req.headers.get(header) == value:
                    req.headers.pop(header, None)

        # httpx has `pool`, `write`, `read`, `connect` timeouts
        # curl has `--connect-timeout` and overall `--max-time` timeouts.
        # TODO: `pool` timeout may be implemented with overriding
        # curl_cffi `requests.AsyncSession.pop_curl`,
        # it's using asyncio.LifoQueue underneath,
        # `LifoQueue.get` have no timeout, may be wrapped with `asyncio.timeout`
        assert "timeout" in req.extensions

        return {
            "method": req.method,
            "url": str(req.url),
            "data": req.content,  # expected `req.read` or `req.aread` was called
            "headers": req.headers.raw,
            "timeout": (
                req.extensions["timeout"]["connect"],
                # request.extensions["timeout"]["write"] is ignored,
                # make this write+read sum?
                req.extensions["timeout"]["read"],
            ),
            "interface": req.extensions.get("local_address"),
            "stream": True,
        }

    def _create_response(
        self,
        req: httpx.Request,
        _resp: _Response,
    ) -> httpx.Response:
        # TODO: curl_cffi has always empty headers in `_resp.request.headers`
        # https://github.com/lexiforest/curl_cffi/issues/368
        # especially needed for cases when `_session.default_headers` was used
        if _resp.request and _resp.request.headers:
            req.headers = httpx.Headers(_resp.request.headers.raw)

        assert _resp.queue, "request was called without stream=True"
        resp = httpx.Response(
            status_code=_resp.status_code,
            request=req,
            headers=[(k, v) for k, v in _resp.headers.raw],
            stream=self._stream_wrap_cls(_resp),
            extensions={
                "curl": {
                    "response": _resp,
                    "infos": _resp.infos,
                },
            },
        )
        # disable decompressing content based on `content-encoding` header,
        # it's already decompressed by curl and curl interfrace
        # doesn't provide raw content at all.
        # https://github.com/lexiforest/curl_cffi/issues/438
        resp._decoder = IdentityDecoder()  # noqa:SLF001

        # there is no actual reason in HTTP/2 and HTTP/3
        if _resp.reason:
            resp.extensions["reason_phrase"] = _resp.reason.encode("ascii", "ignore")

        # `response.elapsed` will be updated by `httpx.Client` one more time
        # when stream will be closed
        resp.elapsed = timedelta(seconds=_resp.elapsed)
        return resp

    def _create_error(
        self,
        req: httpx.Request,
        exc: _RequestError,
    ) -> httpx.RequestError:
        assert exc.code, "Curl error code undefined"
        # NOTE: we're loosing curl error code here
        return _CURL_ERRORS.get(exc.code, httpx.RequestError)(exc.args[0], request=req)


class CurlTransport(BaseCurlTransport[_SyncSession], httpx.BaseTransport):
    _session_cls = _SyncSession
    _stream_wrap_cls = CurlSyncByteStream

    def __init__(
        self,
        *,
        curl: Curl | None = None,
        thread: ThreadType | None = None,
        use_thread_local_curl: bool = True,
        **kwargs: Unpack[CurlTransportParams],
    ) -> None:
        self._session = self._session_cls(
            curl=curl,
            thread=thread,
            use_thread_local_curl=use_thread_local_curl,
            **self._create_session_params(kwargs),
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        request.read()
        try:
            _resp = self._session.request(
                **self._create_request_params(request),
            )
            return self._create_response(request, _resp)
        except _RequestError as _exc:
            raise self._create_error(request, _exc) from _exc

    def close(self) -> None:
        self._session.close()


class AsyncCurlTransport(BaseCurlTransport[_AsyncSession], httpx.AsyncBaseTransport):
    _session_cls = _AsyncSession
    _stream_wrap_cls = CurlAsyncByteStream

    def __init__(
        self,
        *,
        loop: AbstractEventLoop | None = None,
        async_curl: AsyncCurl | None = None,
        # try to make naming compatible with httpx,
        # while in httpx.BaseTransport it's actually limit: Limit object
        # with more granular settings
        max_connections: int = 10,
        **kwargs: Unpack[CurlTransportParams],
    ) -> None:
        self._session = self._session_cls(
            loop=loop,
            async_curl=async_curl,
            max_clients=max_connections,
            **self._create_session_params(kwargs),
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await request.aread()
        try:
            _resp = await self._session.request(
                **self._create_request_params(request),
            )
            return self._create_response(request, _resp)
        except _RequestError as _exc:
            raise self._create_error(request, _exc) from _exc

    async def aclose(self) -> None:
        await self._session.close()
