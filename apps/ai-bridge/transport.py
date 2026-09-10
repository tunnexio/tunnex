"""Locked HTTP transport, including CONNECT for plaintext custom HTTP."""

import base64
import ssl
from urllib.parse import urlsplit, unquote

import httpcore
import httpx
from httpcore._backends.auto import AutoBackend
from diagnostics import capture, record, exception_failure


class ConnectBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, proxy):
        self.proxy = urlsplit(proxy)
        self.backend = AutoBackend()
        if (
            self.proxy.scheme != "http"
            or not self.proxy.hostname
            or not self.proxy.username
            or not self.proxy.password
        ):
            raise ValueError("invalid proxy")

    async def connect_tcp(
        self, host, port, timeout=None, local_address=None, socket_options=None
    ):
        if isinstance(host, bytes):
            host = host.decode("ascii")
        authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        try:
            stream = await self.backend.connect_tcp(
                self.proxy.hostname, self.proxy.port or 80, timeout=timeout
            )
        except Exception as exc:
            record(**exception_failure(exc, "proxy"))
            raise
        try:
            auth = base64.b64encode(
                (
                    unquote(self.proxy.username) + ":" + unquote(self.proxy.password)
                ).encode()
            ).decode()
            await stream.write(
                f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Basic {auth}\r\n\r\n".encode(),
                timeout=timeout,
            )
            header = b""
            # Read exactly the header, leaving any tunnel bytes for TLS/HTTP.
            while not header.endswith(b"\r\n\r\n"):
                data = await stream.read(1, timeout=timeout)
                if not data or len(header) > 8192:
                    raise ValueError("proxy refused")
                header += data
            line = header.split(b"\r\n", 1)[0].split()
            if len(line) < 2 or line[1] != b"200":
                if len(line) >= 2 and line[1].isdigit() and 400 <= int(line[1]) <= 599:
                    record("http_error", "proxy", int(line[1]))
                else:
                    record("invalid_response", "proxy")
                raise ValueError("proxy refused")
            return stream
        except BaseException as exc:
            current = capture.get()
            if isinstance(exc, Exception) and (current is None or not current.get("failure")):
                record(**exception_failure(exc, "proxy"))
            await stream.aclose()
            raise

    async def connect_unix_socket(self, *args, **kwargs):
        raise ValueError("unix denied")

    async def sleep(self, seconds):
        await self.backend.sleep(seconds)


class BoundedStream(httpx.AsyncByteStream):
    def __init__(self, stream):
        self.stream = stream

    async def __aiter__(self):
        total = 0
        try:
            async for chunk in self.stream:
                total += len(chunk)
                if total > 1024 * 1024:
                    raise ValueError("upstream response bound")
                yield chunk
        finally:
            await self.stream.aclose()

    async def aclose(self):
        await self.stream.aclose()


class LockedTransport(httpx.AsyncBaseTransport):
    def __init__(self, origins, proxy=None):
        self.origins = frozenset(origins)
        self.transport = httpx.AsyncHTTPTransport(retries=0, trust_env=False)
        if proxy:
            self.transport._pool = httpcore.AsyncConnectionPool(
                ssl_context=ssl.create_default_context(),
                max_connections=2,
                max_keepalive_connections=0,
                retries=0,
                network_backend=ConnectBackend(proxy),
            )

    async def handle_async_request(self, request):
        origin = (
            request.url.scheme,
            request.url.host,
            request.url.port or (443 if request.url.scheme == "https" else 80),
        )
        if origin not in self.origins or request.url.username or request.url.password:
            raise ValueError("destination denied")
        request.headers["Accept-Encoding"] = "identity"
        try:
            response = await self.transport.handle_async_request(request)
        except Exception as exc:
            # Preserve a CONNECT diagnostic already captured before httpx/SDK
            # wrapping. Otherwise classify the socket failure without its text.
            current = capture.get()
            if current is None or not current.get("failure"):
                record(**exception_failure(exc))
            raise
        if 400 <= response.status_code <= 599:
            record("http_error", "provider", response.status_code)
        else:
            # A response exists. If body decoding, reading or SDK validation
            # fails, classify it here before SDK wrappers discard that fact.
            # Successful calls never return the captured failure fallback.
            record("invalid_response", "provider")
        if response.headers.get("content-encoding", "identity").lower() != "identity":
            await response.aclose()
            raise ValueError("upstream encoding denied")
        response.stream = BoundedStream(response.stream)
        return response

    async def aclose(self):
        await self.transport.aclose()
