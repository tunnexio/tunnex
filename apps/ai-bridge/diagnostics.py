"""Fixed diagnostic vocabulary; never serialize upstream exception text."""

import asyncio
import contextvars
import ssl

KINDS = frozenset({"http_error", "network_error", "timeout", "configuration_error", "invalid_response", "unknown"})
SOURCES = frozenset({"provider", "proxy", "gateway"})
capture = contextvars.ContextVar("probe_diagnostic", default=None)


def sanitized(value):
    if not isinstance(value, dict) or value.get("kind") not in KINDS or value.get("source") not in SOURCES:
        return None
    result = {"kind": value["kind"], "source": value["source"]}
    code = value.get("http_status")
    if result["kind"] == "http_error":
        if type(code) is not int or not 400 <= code <= 599:
            return None
        result["http_status"] = code
    elif code is not None:
        return None
    return result


class ProbeFailure(ValueError):
    def __init__(self, failure):
        self.failure = sanitized(failure) or {"kind": "unknown", "source": "gateway"}
        super().__init__("adapter operation failed")


def record(kind, source, http_status=None):
    current = capture.get()
    if current is not None:
        value = {"kind": kind, "source": source}
        if http_status is not None:
            value["http_status"] = http_status
        current["failure"] = sanitized(value)


def exception_failure(exc, source="provider"):
    import httpcore
    import httpx
    if isinstance(exc, ProbeFailure):
        return exc.failure
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError, httpx.TimeoutException, httpcore.TimeoutException)):
        return {"kind": "timeout", "source": source}
    if isinstance(exc, (OSError, ssl.SSLError, httpx.NetworkError, httpcore.NetworkError)):
        return {"kind": "network_error", "source": source}
    return {"kind": "unknown", "source": source}
