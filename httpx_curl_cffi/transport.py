import ssl
import sys
from asyncio import AbstractEventLoop
from collections.abc import AsyncIterator, Iterator, Sequence
from datetime import timedelta
from functools import cache
from http.cookiejar import Cookie, CookieJar
from pathlib import PurePath
from types import ModuleType
from typing import (
    TYPE_CHECKING,
    Any,
    ClassVar,
    Generic,
    Literal,
    TypeAlias,
    TypedDict,
    TypeVar,
    cast,
    overload,
)

if sys.version_info < (3, 11):
    from typing_extensions import Unpack
else:
    from typing import Unpack

import httpx
from curl_cffi import (
    AsyncCurl,
    Curl,
    CurlECode,
    CurlHttpVersion,
    CurlInfo,
    CurlOpt,
)
from curl_cffi.requests import Response as _CurlResponse
from curl_cffi.requests.impersonate import (
    ExtraFingerprints,
    ExtraFpDict,
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
from curl_cffi.requests.session import ThreadType

# Transports are compatible with both httpx and httpx2 (if installed),
# `httpx.Client` and `httpx2.Client` are accepted (by type checkers too)
# as transports are subclasses of both, responses and errors are created
# of the same module as request (also httpx aliased by `httpx2.alias_httpx()`).
if TYPE_CHECKING:
    import httpx2  # type: ignore[import-not-found, unused-ignore]
else:
    try:
        import httpx2
    except ImportError:
        httpx2 = None

if TYPE_CHECKING:
    from curl_cffi.requests.impersonate import (
        BrowserTypeLiteral,
    )
else:
    try:
        from curl_cffi.requests.impersonate import (
            BrowserTypeLiteral,
        )
    except ImportError:
        # marked to be removed in curl_cffi>=1.0
        from curl_cffi.requests.impersonate import BrowserType

        BrowserTypeLiteral = Literal[tuple(e.value for e in BrowserType)]

if TYPE_CHECKING:
    from curl_cffi.requests.session import (
        BaseSessionParams as _BaseSessionParams,
    )
else:
    try:
        from curl_cffi.requests.session import (
            BaseSessionParams as _BaseSessionParams,
        )
    except ImportError:
        _BaseSessionParams = dict[str, Any]

if TYPE_CHECKING:
    from curl_cffi.requests.exceptions import RequestException as _RequestError
else:
    try:
        from curl_cffi.requests.exceptions import RequestException as _RequestError
    except ImportError:
        from curl_cffi.requests.errors import RequestsError as _RequestError


_Request: TypeAlias = "httpx.Request | httpx2.Request"
_Response: TypeAlias = "httpx.Response | httpx2.Response"

if TYPE_CHECKING:
    _Proxy: TypeAlias = httpx.Proxy | httpx2.Proxy
else:
    _Proxy = httpx.Proxy | httpx2.Proxy if httpx2 else httpx.Proxy


def _bases(*bases: type | None) -> tuple[type, ...]:
    # deduplicated, as httpx is httpx2 when aliased by `httpx2.alias_httpx()`
    return tuple(dict.fromkeys(base for base in bases if base))


def _httpx_of(request: _Request) -> ModuleType:
    if httpx2 and isinstance(request, httpx2.Request):
        return httpx2
    return httpx


@cache
def _httpx_default_headers(httpx_: ModuleType) -> list[tuple[str, str]]:
    return list(httpx_.Client(trust_env=False).headers.items())


# NOTE: by int, as `CurlError.code` is `int | CurlECode` (`CurlECode` is `IntEnum`)
# names of `httpx.RequestError` subclasses, as module depends on request
_CURL_ERRORS: dict[int, str] = {
    CurlECode.UNSUPPORTED_PROTOCOL: "ProtocolError",
    CurlECode.COULDNT_CONNECT: "ConnectError",
    CurlECode.COULDNT_RESOLVE_HOST: "ConnectError",
    CurlECode.COULDNT_RESOLVE_PROXY: "ProxyError",
    CurlECode.SSL_CONNECT_ERROR: "ConnectError",
    CurlECode.READ_ERROR: "ReadError",
    CurlECode.RECV_ERROR: "ReadError",
    CurlECode.WRITE_ERROR: "WriteError",
    CurlECode.BAD_CONTENT_ENCODING: "DecodingError",
    CurlECode.OPERATION_TIMEDOUT: "TimeoutException",
}

_CURL_HTTP_VERSIONS: dict[CurlHttpVersion, bytes] = {
    # string enums compatible with native httpx transports
    CurlHttpVersion.V1_0: b"HTTP/1.0",
    CurlHttpVersion.V1_1: b"HTTP/1.1",
    CurlHttpVersion.V2_0: b"HTTP/2",
    CurlHttpVersion.V3: b"HTTP/3",
}


class _DummyCookieJar(CookieJar):
    def set_cookie(self, cookie: Cookie) -> None:  # noqa:ARG002
        return


if TYPE_CHECKING:
    # NOTE: base classes of httpx and httpx2 are not compatible for type checkers
    # (different request and response types), still methods are overloaded

    class _AsyncByteStream(httpx.AsyncByteStream, httpx2.AsyncByteStream): ...

    class _SyncByteStream(httpx.SyncByteStream, httpx2.SyncByteStream): ...

    class _BaseTransport(  # type: ignore[misc]
        httpx.BaseTransport,
        httpx2.BaseTransport,
    ): ...

    class _AsyncBaseTransport(  # type: ignore[misc]
        httpx.AsyncBaseTransport,
        httpx2.AsyncBaseTransport,
    ): ...

else:

    class _AsyncByteStream(
        *_bases(httpx.AsyncByteStream, httpx2.AsyncByteStream if httpx2 else None),
    ): ...

    class _SyncByteStream(
        *_bases(httpx.SyncByteStream, httpx2.SyncByteStream if httpx2 else None),
    ): ...

    class _BaseTransport(
        *_bases(httpx.BaseTransport, httpx2.BaseTransport if httpx2 else None),
    ): ...

    class _AsyncBaseTransport(
        *_bases(
            httpx.AsyncBaseTransport,
            httpx2.AsyncBaseTransport if httpx2 else None,
        ),
    ): ...


class CurlAsyncByteStream(_AsyncByteStream):
    _resp: _CurlResponse

    def __init__(self, resp: _CurlResponse) -> None:
        self._resp = resp

    async def __aiter__(self) -> AsyncIterator[bytes]:
        if not self._resp.queue:
            # stream mode disabled
            yield self._resp.content
            return
        async for data in self._resp.aiter_content():
            yield data

    async def aclose(self) -> None:
        await self._resp.aclose()


class CurlSyncByteStream(_SyncByteStream):
    _resp: _CurlResponse

    def __init__(self, resp: _CurlResponse) -> None:
        self._resp = resp

    def __iter__(self) -> Iterator[bytes]:
        if not self._resp.queue:
            # stream mode disabled
            yield self._resp.content
            return
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

    proxy: str | _Proxy | None

    verify: bool
    # Deprecated with httpx if favor of passing `verify` as `ssl.SSLContext`,
    # in `httpx` it's (certfile, keyfile=None, password=None)
    # `str | tuple[str, str] | tuple[str, str, str]`
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

    # Transport API should always return responses in stream mode,
    # still you may force curl-cffi not to use stream ONLY in case of bugs,
    # which should be fixed in curl-cffi anyway.
    _stream_enabled: bool = True

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
        # We're explicitly setting PROXY and NOPROXY options below
        # to override proxy usage from environ (unless set in curl_options).
        # Fixed the same way for trust_env=False in curl_cffi>=0.17
        # (still needed before) https://github.com/lexiforest/curl_cffi/pull/867
        # With httpx it's expected that proxy environ
        # read by `httpx.Client` with trust_env=True (default),
        # and separate mounts created with separate transports.
        assert not params.get("trust_env")

        curl_options = dict(params.get("curl_options") or {})
        # Content is decoded by httpx (as for its own transports) by
        # `content-encoding` header, so raw content of responses is encoded.
        # https://github.com/lexiforest/curl_cffi/issues/438
        curl_options[CurlOpt.HTTP_CONTENT_DECODING] = 0

        proxy = params.get("proxy", None)
        if proxy:
            if isinstance(proxy, str):
                proxy = httpx.Proxy(url=proxy)
        else:
            proxy = None
            # """
            # Setting the proxy string to "" (an empty string)
            # explicitly disables the use of a proxy,
            # even if there is an environment variable set for it.
            # """
            # https://curl.se/libcurl/c/CURLOPT_PROXY.html
            curl_options.setdefault(CurlOpt.PROXY, "")
        # """
        # Setting the noproxy string to "" (an empty string)
        # explicitly enables the proxy for all hostnames,
        # even if there is an environment variable set for it.
        # """
        # https://curl.se/libcurl/c/CURLOPT_NOPROXY.html
        curl_options.setdefault(CurlOpt.NOPROXY, "")

        return {
            "debug": params.get("debug", False),
            "proxy": str(proxy.url) if proxy else None,
            "proxy_auth": proxy.auth if proxy and proxy.auth else None,
            # NOTE: `proxy_headers` is not currently
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
            "curl_options": curl_options,
            "curl_infos": params.get("curl_infos"),
            # NOTE: trust_env isn't working, see ticket above
            "trust_env": False,
            "cookies": _DummyCookieJar(),
            "allow_redirects": False,
        }

    @staticmethod
    def _create_headers(
        raw_headers: Sequence[tuple[bytes, bytes | None]],
    ) -> list[tuple[bytes, bytes]]:
        return [(h, v or b"") for h, v in raw_headers]

    def _create_request_params(self, req: _Request) -> dict[str, Any]:
        if self._session.default_headers:
            # drop httpx default headers
            for header, value in _httpx_default_headers(_httpx_of(req)):
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
                # `request.extensions["timeout"]["write"]`` is ignored,
                # make this write+read sum?
                req.extensions["timeout"]["read"],
            ),
            "interface": req.extensions.get("local_address"),
            "stream": self._stream_enabled,
        }

    def _create_response(
        self,
        req: _Request,
        _resp: _CurlResponse,
    ) -> Any:
        httpx_ = _httpx_of(req)
        # TODO: curl_cffi has always empty headers in `_resp.request.headers`
        # https://github.com/lexiforest/curl_cffi/issues/368
        # especially needed for cases when `_session.default_headers` was used
        if _resp.request and _resp.request.headers:
            req.headers = httpx_.Headers(
                self._create_headers(_resp.request.headers.raw),
            )

        resp = httpx_.Response(
            status_code=_resp.status_code,
            request=req,
            headers=self._create_headers(_resp.headers.raw),
            stream=self._stream_wrap_cls(_resp),
            extensions={
                "curl": {
                    "response": _resp,
                    "infos": _resp.infos,
                },
            },
        )
        http_version = CurlHttpVersion(_resp.http_version)
        if http_version in _CURL_HTTP_VERSIONS:
            resp.extensions["http_version"] = _CURL_HTTP_VERSIONS[http_version]

        # there is no actual reason in HTTP/2 and HTTP/3
        if _resp.reason:
            resp.extensions["reason_phrase"] = _resp.reason.encode("ascii", "ignore")

        # `response.elapsed` will be updated by `httpx.Client` one more time
        # when stream will be closed
        if isinstance(_resp.elapsed, timedelta):
            resp.elapsed = _resp.elapsed
        else:
            resp.elapsed = timedelta(seconds=_resp.elapsed)
        return resp

    def _create_error(
        self,
        req: _Request,
        exc: _RequestError,
    ) -> Exception:
        assert exc.code, "Curl error code undefined"
        error_cls = getattr(_httpx_of(req), _CURL_ERRORS.get(exc.code, "RequestError"))
        # NOTE: we're loosing curl error code here
        return error_cls(exc.args[0], request=req)  # type: ignore[no-any-return]


class CurlTransport(BaseCurlTransport[_SyncSession], _BaseTransport):
    _session_cls: type[_SyncSession] = _SyncSession
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

    @overload
    def handle_request(self, request: httpx.Request) -> httpx.Response: ...
    # NOTE: never matched when httpx2 isn't installed (`Any` type)
    @overload
    def handle_request(  # type: ignore[overload-cannot-match, unused-ignore]
        self,
        request: httpx2.Request,
    ) -> httpx2.Response: ...
    def handle_request(self, request: _Request) -> _Response:
        request.read()
        try:
            # NOTE: cast as `Response | None` inferred by pyright
            # of unannotated `Session.request` in curl_cffi 0.15
            _resp = cast(
                "_CurlResponse",
                self._session.request(**self._create_request_params(request)),
            )
            return self._create_response(request, _resp)
        except _RequestError as _exc:
            raise self._create_error(request, _exc) from _exc

    def close(self) -> None:
        self._session.close()


class AsyncCurlTransport(BaseCurlTransport[_AsyncSession], _AsyncBaseTransport):
    _session_cls: type[_AsyncSession] = _AsyncSession
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

    @overload
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response: ...
    # NOTE: never matched when httpx2 isn't installed (`Any` type)
    @overload
    async def handle_async_request(  # type: ignore[overload-cannot-match, unused-ignore]
        self,
        request: httpx2.Request,
    ) -> httpx2.Response: ...
    async def handle_async_request(self, request: _Request) -> _Response:
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
