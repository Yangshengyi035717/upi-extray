"""Sentinel SDK 的跨平台 curl_cffi 请求桥。

Node/V8 仅负责运行 SDK；所有 SDK 网络请求固定由当前 Python venv 的
curl_cffi 发出，避免 Windows 系统 curl（Schannel）与 Linux curl
（OpenSSL/GnuTLS）产生不同的 TLS 上下文。
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

try:
    import curl_cffi
    from curl_cffi import requests as curl_requests
except Exception as exc:  # pragma: no cover - deployment dependency check
    curl_cffi = None
    curl_requests = None
    _CURL_CFFI_IMPORT_ERROR = exc
else:
    _CURL_CFFI_IMPORT_ERROR = None


def _text(value: Any) -> str:
    return str(value or "").strip()


def _redact_error(value: Any) -> str:
    """Keep bridge diagnostics actionable without returning proxy credentials."""
    text = re.sub(r"\s+", " ", _text(value))
    text = re.sub(r"([a-z][a-z0-9+.-]*://)[^/@\s]+@", r"\1***@", text, flags=re.I)
    return text[:420] or "unknown error"


def _payload_headers(payload: dict[str, Any]) -> dict[str, str]:
    values = payload.get("headers")
    if not isinstance(values, dict):
        return {}
    return {
        str(name): str(value)
        for name, value in values.items()
        if name not in (None, "") and value is not None
    }


def _request(payload: dict[str, Any]) -> dict[str, Any]:
    url = _text(payload.get("url"))
    if not url.startswith(("https://", "http://")):
        raise ValueError("invalid_url")
    impersonate = _text(payload.get("tlsImpersonate")) or "chrome136"
    proxy = _text(payload.get("proxy"))
    timeout = max(1.0, min(float(payload.get("timeout") or 120), 120.0))
    if curl_requests is None:
        raise RuntimeError(f"curl_cffi_unavailable:{_redact_error(_CURL_CFFI_IMPORT_ERROR)}")
    session = curl_requests.Session(impersonate=impersonate)
    try:
        if hasattr(session, "trust_env"):
            session.trust_env = False
        if proxy:
            session.proxies.update({"http": proxy, "https": proxy})
        response = session.request(
            _text(payload.get("method")).upper() or "GET",
            url,
            headers=_payload_headers(payload),
            data=payload.get("body") if payload.get("body") is not None else None,
            timeout=timeout,
            allow_redirects=True,
        )
        return {
            "status": int(response.status_code),
            "body": response.text,
            "transport": {
                "kind": "curl_cffi",
                "version": str(getattr(curl_cffi, "__version__", "unknown")),
                "effective_tls": impersonate,
            },
        }
    finally:
        session.close()


def main() -> None:
    try:
        raw = sys.stdin.buffer.read().decode("utf-8")
        payload = json.loads(raw or "{}")
        if not isinstance(payload, dict):
            raise ValueError("payload_must_be_object")
        result = _request(payload)
    except Exception as exc:  # bridge boundary: always return JSON to Node
        result = {"error": _redact_error(exc)}
    sys.stdout.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
