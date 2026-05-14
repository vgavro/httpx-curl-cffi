from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("httpx-curl-cffi")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

from .transport import (
    AsyncCurlTransport,
    BrowserTypeLiteral,
    CurlHttpVersion,
    CurlInfo,
    CurlOpt,
    CurlTransport,
    ExtraFingerprints,
    ExtraFpDict,
)

__all__ = [
    "AsyncCurlTransport",
    "BrowserTypeLiteral",
    "CurlHttpVersion",
    "CurlInfo",
    "CurlOpt",
    "CurlTransport",
    "ExtraFingerprints",
    "ExtraFpDict",
    "__version__",
]
