"""UPI 专用 Playwright 无头 Chromium 请求传输层。"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import RLock, get_ident
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

import requests
from requests.structures import CaseInsensitiveDict

try:  # 直接以脚本方式运行时回退到绝对导入
    from .register_profile import web_device_memory
except ImportError:  # pragma: no cover - 脚本入口
    from register_profile import web_device_memory  # type: ignore

try:
    from .playwright_proxy_guard import guard_system_proxy
except ImportError:  # pragma: no cover - 脚本入口
    from playwright_proxy_guard import guard_system_proxy  # type: ignore

try:
    import curl_cffi
    from curl_cffi import requests as curl_requests
except Exception:  # pragma: no cover - 可选依赖
    curl_cffi = None
    curl_requests = None


UPI_HEADLESS_BROWSER_UNAVAILABLE = "UPI_HEADLESS_BROWSER_UNAVAILABLE"
UPI_HEADLESS_BROWSER_LAUNCH_FAILED = "UPI_HEADLESS_BROWSER_LAUNCH_FAILED"
UPI_HEADLESS_BROWSER_PROXY_UNSUPPORTED = "UPI_HEADLESS_BROWSER_PROXY_UNSUPPORTED"
UPI_HEADLESS_BROWSER_REQUEST_FAILED = "UPI_HEADLESS_BROWSER_REQUEST_FAILED"
UPI_PROTOCOL_SESSION_UNAVAILABLE = "UPI_PROTOCOL_SESSION_UNAVAILABLE"

_FETCH_SCRIPT = """
async ({url, method, headers, body, timeoutMs, allowRedirects, referrer}) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.max(1000, timeoutMs || 30000));
  try {
    const options = {
      method,
      credentials: "include",
      mode: "cors",
      redirect: allowRedirects ? "follow" : "manual",
      signal: controller.signal,
      headers: headers || {},
    };
    if (body !== null && body !== undefined) options.body = body;
    if (referrer) options.referrer = referrer;
    const response = await fetch(url, options);
    return {
      status: response.status,
      url: response.url || url,
      headers: Object.fromEntries(response.headers.entries()),
      text: await response.text(),
    };
  } catch (error) {
    return {
      error: String(error && (error.stack || error.message || error.name) || error || "fetch failed"),
    };
  } finally {
    clearTimeout(timer);
  }
}
"""


def _text(value: Any) -> str:
    return str(value or "").strip()


def _short_error(value: Any, limit: int = 280) -> str:
    text = re.sub(r"\s+", " ", _text(value))
    return text[:limit] or "unknown error"


def _fingerprint_value(
    profile: dict[str, Any] | None,
    *keys: str,
    default: str = "",
) -> str:
    if not isinstance(profile, dict):
        return default
    for key in keys:
        value = _text(profile.get(key))
        if value:
            return value
    return default


def _browser_executable_path() -> str:
    configured = (
        os.environ.get("UPI_BROWSER_EXECUTABLE_PATH")
        or os.environ.get("PLAYWRIGHT_CHROMIUM_PATH")
        or os.environ.get("PLAYWRIGHT_BROWSER_EXECUTABLE_PATH")
        or ""
    ).strip()
    if configured and Path(configured).is_file():
        return configured

    candidates = (
        shutil.which("google-chrome"),
        shutil.which("chromium"),
        shutil.which("chromium-browser"),
        shutil.which("chrome"),
        shutil.which("msedge"),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/microsoft-edge",
    )
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    return ""


def _proxy_options(proxy_url: str) -> dict[str, str] | None:
    raw = _text(proxy_url)
    if not raw:
        return None
    parsed = urlsplit(raw)
    if not parsed.hostname or not parsed.port:
        raise RuntimeError(
            f"{UPI_HEADLESS_BROWSER_PROXY_UNSUPPORTED}: proxy 必须包含 host 和 port"
        )
    scheme = (parsed.scheme or "http").lower()
    if scheme == "socks5h":
        scheme = "socks5"
    elif scheme == "socks4a":
        scheme = "socks4"
    if scheme not in {"http", "https", "socks4", "socks5"}:
        raise RuntimeError(
            f"{UPI_HEADLESS_BROWSER_PROXY_UNSUPPORTED}: 不支持代理协议 {parsed.scheme}"
        )
    result: dict[str, str] = {
        "server": f"{scheme}://{parsed.hostname}:{parsed.port}",
    }
    if parsed.username is not None:
        result["username"] = parsed.username
    if parsed.password is not None:
        result["password"] = parsed.password
    return result


def _browser_user_agent(profile: dict[str, Any] | None, browser_version: str) -> str:
    version = _text(browser_version)
    configured = _fingerprint_value(profile, "ua", "user_agent")
    if configured and version:
        configured = re.sub(
            r"(?:HeadlessChrome|Chrome|Chromium)/[\d.]+",
            f"Chrome/{version}",
            configured,
            count=1,
            flags=re.IGNORECASE,
        )
    if configured:
        return configured.replace("HeadlessChrome/", "Chrome/")
    major = version.split(".", 1)[0] if version else "146"
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        f"Chrome/{major}.0.0.0 Safari/537.36"
    )


def _browser_profile(
    profile: dict[str, Any] | None,
    browser_version: str,
) -> dict[str, str]:
    version = _text(browser_version)
    major = version.split(".", 1)[0] or _fingerprint_value(profile, "major", default="146")
    language = _fingerprint_value(
        profile,
        "oai_language",
        "language",
        default="en-IN",
    )
    accept_language = _fingerprint_value(
        profile,
        "accept_language",
        "locale",
        default=f"{language},en;q=0.9",
    )
    timezone = _fingerprint_value(
        profile,
        "timezone",
        "timezone_id",
        default="Asia/Kolkata",
    )
    reported_full = version or _fingerprint_value(
        profile,
        "full",
        "browser_full_version",
        default=f"{major}.0.0.0",
    )
    platform = _fingerprint_value(profile, "platform", "platform_os", default="Windows")
    return {
        **{str(key): str(value) for key, value in (profile or {}).items() if value not in (None, "")},
        "ua": _browser_user_agent(profile, version),
        "major": major,
        "full": reported_full,
        "oai_language": language,
        "accept_language": accept_language,
        "timezone": timezone,
        "platform": platform,
        "sec_ch_ua": (
            f'"Not;A=Brand";v="99", "Chromium";v="{major}", '
            f'"Google Chrome";v="{major}"'
        ),
        "sec_ch_ua_full_version_list": (
            f'"Not;A=Brand";v="99.0.0.0", "Chromium";v="{reported_full}", '
            f'"Google Chrome";v="{reported_full}"'
        ),
    }


def _browser_dimensions(profile: dict[str, Any] | None) -> tuple[dict[str, int], dict[str, int]]:
    resolution = _fingerprint_value(profile, "resolution", default="1536x864").lower()
    match = re.fullmatch(r"\s*(\d{3,5})\s*x\s*(\d{3,5})\s*", resolution)
    if match:
        screen_width = max(1024, min(int(match.group(1)), 5120))
        screen_height = max(720, min(int(match.group(2)), 2880))
    else:
        screen_width, screen_height = 1536, 864
    viewport = {
        "width": screen_width,
        "height": max(600, screen_height - min(120, max(80, screen_height // 8))),
    }
    return viewport, {"width": screen_width, "height": screen_height}


def _number(
    profile: dict[str, Any] | None,
    key: str,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    try:
        value = float(_fingerprint_value(profile, key, default=str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


def _browser_init_script(profile: dict[str, Any] | None) -> str:
    platform = _fingerprint_value(profile, "platform", "platform_os", default="Windows").lower()
    navigator_platform = "MacIntel" if "mac" in platform else "Win32"
    language = _fingerprint_value(profile, "oai_language", "language", default="en-IN")
    languages = [
        language,
        language.split("-", 1)[0] if "-" in language else language,
        "en",
    ]
    config = json.dumps(
        {
            "platform": navigator_platform,
            "language": language,
            "languages": list(dict.fromkeys(languages)),
            "cores": int(_number(profile, "cores", 8, 1, 64)),
            "memory": web_device_memory(_number(profile, "device_memory", 8, 1, 64)),
            "touchPoints": int(_number(profile, "max_touch_points", 0, 0, 20)),
            "webglVendor": _fingerprint_value(profile, "webgl_vendor"),
            "webglRenderer": _fingerprint_value(profile, "webgl_renderer"),
        },
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return f"""
        (() => {{
          const fp = {config};
          const define = (target, name, value) => {{
            try {{
              Object.defineProperty(target, name, {{
                get: () => value,
                configurable: true,
              }});
            }} catch (_) {{}}
          }};
          define(Navigator.prototype, 'webdriver', undefined);
          define(Navigator.prototype, 'platform', fp.platform);
          define(Navigator.prototype, 'language', fp.language);
          define(Navigator.prototype, 'languages', fp.languages);
          define(Navigator.prototype, 'hardwareConcurrency', fp.cores);
          define(Navigator.prototype, 'deviceMemory', fp.memory);
          define(Navigator.prototype, 'maxTouchPoints', fp.touchPoints);
          const patchWebGL = (prototype) => {{
            if (!prototype || !prototype.getParameter || prototype.__upiPatched) return;
            const original = prototype.getParameter;
            Object.defineProperty(prototype, '__upiPatched', {{ value: true }});
            prototype.getParameter = function(parameter) {{
              if (parameter === 37445 && fp.webglVendor) return fp.webglVendor;
              if (parameter === 37446 && fp.webglRenderer) return fp.webglRenderer;
              return original.call(this, parameter);
            }};
          }};
          patchWebGL(globalThis.WebGLRenderingContext?.prototype);
          patchWebGL(globalThis.WebGL2RenderingContext?.prototype);
          // 无头 Chrome 的 navigator.plugins / mimeTypes 为空、window.chrome 缺失，
          // 是风控（含 hCaptcha）最容易命中的指纹差异，这里补成真实 Chrome 形状。
          try {{
            const pluginEntries = [
              ['PDF Viewer', 'internal-pdf-viewer', 'Portable Document Format'],
              ['Chrome PDF Viewer', 'internal-pdf-viewer', 'Portable Document Format'],
              ['Chromium PDF Viewer', 'internal-pdf-viewer', 'Portable Document Format'],
              ['Microsoft Edge PDF Viewer', 'internal-pdf-viewer', 'Portable Document Format'],
              ['WebKit built-in PDF', 'internal-pdf-viewer', 'Portable Document Format'],
            ];
            const makePlugin = (entry) => {{
              const plugin = {{
                name: entry[0],
                filename: entry[1],
                description: entry[2],
                length: 1,
              }};
              plugin.item = () => null;
              plugin.namedItem = () => null;
              return plugin;
            }};
            const pluginArray = pluginEntries.map(makePlugin);
            pluginArray.item = (index) => pluginArray[index] || null;
            pluginArray.namedItem = (name) => pluginArray.find((item) => item.name === name) || null;
            pluginArray.refresh = () => undefined;
            define(Navigator.prototype, 'plugins', pluginArray);
            const mimeArray = [
              {{
                type: 'application/pdf',
                suffixes: 'pdf',
                description: 'Portable Document Format',
                enabledPlugin: pluginArray[0],
              }},
            ];
            mimeArray.item = (index) => mimeArray[index] || null;
            mimeArray.namedItem = (name) => mimeArray.find((item) => item.type === name) || null;
            define(Navigator.prototype, 'mimeTypes', mimeArray);
          }} catch (_) {{}}
          try {{
            if (!globalThis.chrome) {{
              Object.defineProperty(globalThis, 'chrome', {{
                value: {{
                  app: {{ isInstalled: false }},
                  runtime: {{}},
                  csi: () => ({{}}),
                  loadTimes: () => ({{}}),
                }},
                configurable: true,
              }});
            }}
          }} catch (_) {{}}
        }})();
    """


def _cookie_header_parts(value: str) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for part in _text(value).split(";"):
        name, separator, cookie_value = part.strip().partition("=")
        if separator and name and not name.startswith("$"):
            result.append((name, cookie_value))
    return result


class BrowserResponse:
    """兼容现有提链代码所需最小 requests.Response 接口。"""

    def __init__(
        self,
        *,
        status_code: int,
        url: str,
        headers: dict[str, Any] | None,
        text: str,
    ) -> None:
        self.status_code = int(status_code or 0)
        self.url = _text(url)
        self.headers = CaseInsensitiveDict(
            {str(key): str(value) for key, value in (headers or {}).items()}
        )
        self.text = str(text or "")
        self.history: list[Any] = []

    @property
    def ok(self) -> bool:
        return self.status_code < 400

    @property
    def content(self) -> bytes:
        return self.text.encode("utf-8", errors="replace")

    def json(self, **_kwargs: Any) -> Any:
        return json.loads(self.text)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(
                f"{self.status_code} Client Error for url: {self.url}",
                response=self,
            )


class ProtocolHttpSession:
    """curl_cffi 指纹协议会话，不启动 Chromium。

    ChatGPT 请求使用真实 UA/Origin/Sentinel，Stripe 请求直接携带
    js.stripe.com Origin/Referer，因此协议模式可以完成与无头浏览器相同
    的 Checkout→Stripe→Confirm→Approve 流程，服务器资源占用低得多。
    只有官方 Checkout 页面兜底仍按需临时启动无头 Chromium。
    """

    is_browser_backed = False
    transport_name = "curl-cffi-fingerprint"

    def __init__(
        self,
        *,
        proxy: str = "",
        pre_proxy: str = "",
        fingerprint_profile: dict[str, Any] | None = None,
        timeout_ms: int = 45_000,
    ) -> None:
        if pre_proxy and proxy:
            raise RuntimeError(
                f"{UPI_HEADLESS_BROWSER_PROXY_UNSUPPORTED}: "
                "协议模式暂不支持 UPI_PRE_PROXY 与本机代理叠加"
            )
        self.headers: CaseInsensitiveDict[str] = CaseInsensitiveDict()
        self.proxies: dict[str, str] = {}
        self.trust_env = False
        self.cookies = requests.cookies.RequestsCookieJar()
        self._proxy = _text(proxy) or _text(pre_proxy)
        self._profile = dict(fingerprint_profile or {})
        self._timeout = max(8, min(int(timeout_ms or 45_000) / 1000, 120))
        self._closed = False
        self._session: Any = None
        self.requested_tls_impersonate = ""
        self.effective_tls_impersonate = ""
        self.curl_cffi_version = "unavailable"
        self._ensure_session()

    @property
    def browser_profile(self) -> dict[str, str]:
        return dict(self._profile)

    @property
    def transport_runtime(self) -> dict[str, str]:
        """Return the effective protocol runtime without exposing session data."""
        return {
            "transport": self.transport_name,
            "python": sys.version.split()[0],
            "curl_cffi": self.curl_cffi_version,
            "requested_tls": self.requested_tls_impersonate,
            "effective_tls": self.effective_tls_impersonate,
        }

    def _ensure_session(self) -> None:
        if self._session is not None:
            return
        impersonate = str(
            self._profile.get("tls_impersonate")
            or self._profile.get("tls")
            or "chrome136"
        ).strip()
        self.requested_tls_impersonate = impersonate
        if curl_requests is None:
            raise RuntimeError(
                f"{UPI_PROTOCOL_SESSION_UNAVAILABLE}: "
                "协议模式必须使用 curl_cffi，不能回退到 requests"
            )
        try:
            self._session = curl_requests.Session(impersonate=impersonate)
        except Exception as exc:
            raise RuntimeError(
                f"{UPI_PROTOCOL_SESSION_UNAVAILABLE}: "
                f"当前 curl_cffi 不支持 TLS 预设 {impersonate}：{_short_error(exc)}"
            ) from exc
        self.effective_tls_impersonate = impersonate
        self.curl_cffi_version = str(getattr(curl_cffi, "__version__", "unknown"))
        session = self._session
        if hasattr(session, "trust_env"):
            session.trust_env = False
        if self._proxy:
            session.proxies.update({"http": self._proxy, "https": self._proxy})
            self.proxies.update({"http": self._proxy, "https": self._proxy})

    def set_proxy(self, proxy: str) -> None:
        self._proxy = _text(proxy)
        if self._session is not None:
            if self._proxy:
                self._session.proxies.update({"http": self._proxy, "https": self._proxy})
                self.proxies.update({"http": self._proxy, "https": self._proxy})
            else:
                self._session.proxies.clear()
                self.proxies.clear()

    def set_fetch_page(self, page_url: str) -> None:
        """协议模式用 Origin/Referer 头表达页面来源，无需真实承载页。"""
        return

    def _merge_headers(self, headers: dict[str, Any] | None) -> dict[str, str]:
        merged: dict[str, str] = {}
        for key, value in (self.headers or {}).items():
            if value is not None:
                merged[str(key)] = str(value)
        for key, value in (headers or {}).items():
            if value is not None:
                merged[str(key)] = str(value)
        return merged

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Any = None,
        data: Any = None,
        json: Any = None,
        headers: dict[str, Any] | None = None,
        timeout: float | int | None = None,
        allow_redirects: bool = True,
        **kwargs: Any,
    ) -> Any:
        if self._closed or self._session is None:
            raise RuntimeError(f"{UPI_PROTOCOL_SESSION_UNAVAILABLE}: 会话已关闭")
        timeout_value = self._timeout
        if timeout is not None:
            timeout_value = max(1, min(float(timeout), 120))
        request_headers = self._merge_headers(headers)
        request_kwargs: dict[str, Any] = {
            "headers": request_headers,
            "timeout": timeout_value,
            "allow_redirects": bool(allow_redirects),
        }
        if params is not None:
            request_kwargs["params"] = params
        if json is not None:
            request_kwargs["json"] = json
        elif data is not None:
            request_kwargs["data"] = data
        request_kwargs.update(kwargs)
        return self._session.request(str(method or "GET").upper(), url, **request_kwargs)

    def get(self, url: str, params: Any = None, **kwargs: Any) -> Any:
        return self.request("GET", url, params=params, **kwargs)

    def post(self, url: str, data: Any = None, json: Any = None, **kwargs: Any) -> Any:
        return self.request("POST", url, data=data, json=json, **kwargs)

    def run_page_workflow(
        self,
        target_url: str,
        workflow: Any,
        *,
        timeout_ms: int | None = None,
    ) -> Any:
        raise RuntimeError(
            f"{UPI_PROTOCOL_SESSION_UNAVAILABLE}: "
            "官方 Checkout 页面兜底需要单独启用无头 Chromium"
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._session is not None:
            try:
                self._session.close()
            except Exception:
                pass
            self._session = None

    def __enter__(self) -> "ProtocolHttpSession":
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class PlaywrightBrowserSession:
    """用真实 Chromium page.fetch 承载 HTTP 请求，不回退到 requests/curl。"""

    is_browser_backed = True
    transport_name = "playwright-headless-chromium"

    def __init__(
        self,
        *,
        proxy: str = "",
        pre_proxy: str = "",
        fingerprint_profile: dict[str, Any] | None = None,
        timeout_ms: int = 45_000,
    ) -> None:
        self.headers: CaseInsensitiveDict[str] = CaseInsensitiveDict()
        self.proxies: dict[str, str] = {}
        self.trust_env = False
        self.cookies = requests.cookies.RequestsCookieJar()
        self._proxy = _text(proxy)
        self._pre_proxy = _text(pre_proxy)
        self._fingerprint = dict(fingerprint_profile or {})
        self._timeout_ms = max(8_000, min(int(timeout_ms or 45_000), 120_000))
        self._lock = RLock()
        self._runtime_executor: ThreadPoolExecutor | None = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="upi-browser",
        )
        self._runtime_thread_id: int | None = None
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._pages: dict[str, Any] = {}
        self._profile: dict[str, str] = {}
        self._host_cookies: dict[str, str] = {}
        self._fetch_page_url = ""
        self._closed = False

        if self._proxy:
            self.proxies = {"http": self._proxy, "https": self._proxy}

    @property
    def browser_profile(self) -> dict[str, str]:
        return dict(self._profile)

    def _run_on_browser_thread(
        self,
        callback: Any,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Keep every Sync Playwright call on one thread without an asyncio loop."""
        if self._runtime_thread_id == get_ident():
            return callback(*args, **kwargs)
        executor = self._runtime_executor
        if executor is None:
            raise RuntimeError(f"{UPI_HEADLESS_BROWSER_REQUEST_FAILED}: 会话执行器已关闭")

        def invoke() -> Any:
            self._runtime_thread_id = get_ident()
            return callback(*args, **kwargs)

        return executor.submit(invoke).result()

    def set_proxy(self, proxy: str) -> None:
        with self._lock:
            if self._browser is not None and _text(proxy) != self._proxy:
                raise RuntimeError(
                    f"{UPI_HEADLESS_BROWSER_PROXY_UNSUPPORTED}: "
                    "浏览器上下文启动后不能热切换代理，请新建会话"
                )
            self._proxy = _text(proxy)
            self.proxies = (
                {"http": self._proxy, "https": self._proxy}
                if self._proxy
                else {}
            )

    def set_fetch_page(self, page_url: str) -> None:
        """Set the origin page that executes cross-origin API fetches.

        Stripe accepts checkout API calls only when the browser page origin
        matches its allowed js.stripe.com origin; otherwise the API answers
        ``invalid_request_http_origin``. Setting the fetch page lets Chromium
        attach the real ``Origin`` header for cross-origin api.stripe.com calls.
        """
        value = _text(page_url)
        if value:
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise RuntimeError(
                    f"{UPI_HEADLESS_BROWSER_REQUEST_FAILED}: fetch page URL 无效：{value}"
                )
        with self._lock:
            self._fetch_page_url = value

    def _effective_proxy(self) -> str:
        if self._pre_proxy and self._proxy:
            raise RuntimeError(
                f"{UPI_HEADLESS_BROWSER_PROXY_UNSUPPORTED}: "
                "Playwright Chromium 只能配置一个代理；不能同时使用 UPI_PRE_PROXY 和提链代理"
            )
        return self._proxy or self._pre_proxy

    def _launch_browser(self, playwright: Any) -> Any:
        launch_options: dict[str, Any] = {
            "headless": True,
            "args": [
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
            ],
        }
        proxy = _proxy_options(self._effective_proxy())
        if proxy:
            launch_options["proxy"] = proxy
        # 未配置出口时必须显式关掉系统代理，否则 Chromium 会继承本机
        # Clash/V2Ray（Windows 上 ProxyEnable=1），把请求送去别的国家出口。
        guard_system_proxy(launch_options, proxy, engine="chromium")

        executable = _browser_executable_path()
        attempts: list[tuple[str, dict[str, Any]]] = []
        if executable:
            attempts.append(
                (
                    f"executable_path={executable}",
                    {**launch_options, "executable_path": executable},
                )
            )
        bundled = _text(getattr(playwright.chromium, "executable_path", ""))
        if bundled and Path(bundled).is_file() and bundled != executable:
            attempts.append(
                (
                    f"playwright-executable={bundled}",
                    {**launch_options, "executable_path": bundled},
                )
            )
        for channel in ("chrome", "msedge"):
            attempts.append((f"channel={channel}", {**launch_options, "channel": channel}))
        attempts.append(("playwright-bundled", dict(launch_options)))

        errors: list[str] = []
        for label, options in attempts:
            try:
                return playwright.chromium.launch(**options)
            except Exception as exc:
                errors.append(f"{label}: {_short_error(exc, 180)}")
        raise RuntimeError(
            f"{UPI_HEADLESS_BROWSER_LAUNCH_FAILED}: "
            + " | ".join(errors[-4:])
        )

    def _cookie_domain(self, host: str) -> str:
        lower = host.lower().lstrip(".")
        if lower == "chatgpt.com" or lower.endswith(".chatgpt.com"):
            return ".chatgpt.com"
        if lower == "openai.com" or lower.endswith(".openai.com"):
            return ".openai.com"
        # Stripe 的 m / __stripe_mid 等是跨 checkout.stripe.com 与 api.stripe.com
        # 共用的，必须落到 .stripe.com，否则托管页会被当成全新访客直接弹 hCaptcha。
        if lower == "stripe.com" or lower.endswith(".stripe.com"):
            return ".stripe.com"
        return lower

    def set_host_cookies(self, cookies: dict[str, str]) -> None:
        """Seed per-domain Cookie headers for later pages/context restarts.

        调用方用 ``{".stripe.com": "m=...; __stripe_mid=...", ".chatgpt.com": "..."}``
        的形式登记，浏览器只会把这些 Cookie 发给对应域，避免把 ChatGPT 会话
        Cookie 泄露给 Stripe，也避免托管页以全新访客身份打开。
        """
        if not isinstance(cookies, dict):
            return
        with self._lock:
            for domain, header in cookies.items():
                key = _text(domain).lower()
                value = _text(header)
                if not key or not value:
                    continue
                self._host_cookies[key] = value

    def _jar_cookie_parts(self, domain: str) -> list[tuple[str, str, str]]:
        """Return ``(cookie_domain, name, value)`` from the jar that apply to ``domain``."""
        base = _text(domain).lower().lstrip(".")
        found: list[tuple[str, str, str]] = []
        if not base:
            return found
        try:
            items = list(self.cookies)
        except Exception:
            return found
        for item in items:
            name = _text(getattr(item, "name", ""))
            value = str(getattr(item, "value") or "")
            cookie_domain = _text(getattr(item, "domain", "")).lower()
            if not name or not cookie_domain:
                continue
            scope = cookie_domain.lstrip(".")
            if base != scope and not base.endswith("." + scope):
                continue
            found.append((cookie_domain, name, value))
        return found

    def _seed_cookies(self, host: str) -> None:
        if self._context is None:
            return
        domain = self._cookie_domain(host)
        merged: dict[tuple[str, str], str] = {}
        for name, value in _cookie_header_parts(self.headers.get("Cookie", "")):
            merged[(domain, name)] = value
        for name, value in _cookie_header_parts(self._host_cookies.get(domain, "")):
            merged[(domain, name)] = value
        for cookie_domain, name, value in self._jar_cookie_parts(domain):
            merged.setdefault((cookie_domain, name), value)
        if not merged:
            return
        cookies = [
            {
                "name": name,
                "value": value,
                "domain": cookie_domain,
                "path": "/",
                "secure": True,
                "sameSite": "Lax",
            }
            for (cookie_domain, name), value in merged.items()
        ]
        try:
            self._context.add_cookies(cookies)
        except Exception as exc:
            raise RuntimeError(
                f"{UPI_HEADLESS_BROWSER_REQUEST_FAILED}: "
                f"写入浏览器 Cookie 失败：{_short_error(exc)}"
            ) from exc

    def _sync_cookie_jar(self) -> None:
        if self._context is None:
            return
        try:
            browser_cookies = self._context.cookies()
        except Exception:
            return
        for item in browser_cookies:
            name = _text(item.get("name"))
            value = str(item.get("value") or "")
            domain = _text(item.get("domain"))
            path = _text(item.get("path")) or "/"
            if not name or not domain:
                continue
            try:
                self.cookies.set(name, value, domain=domain, path=path)
            except Exception:
                continue

    def _ensure_runtime(self, target_url: str) -> None:
        if self._context is not None:
            return
        try:
            from playwright.sync_api import sync_playwright
        except Exception as exc:
            raise RuntimeError(
                f"{UPI_HEADLESS_BROWSER_UNAVAILABLE}: "
                f"Playwright Python 包不可用：{_short_error(exc)}"
            ) from exc

        try:
            self._playwright = sync_playwright().start()
            self._browser = self._launch_browser(self._playwright)
            self._profile = _browser_profile(
                self._fingerprint,
                _text(getattr(self._browser, "version", "")),
            )
            viewport, screen = _browser_dimensions(self._profile)
            max_touch_points = int(
                _number(self._profile, "max_touch_points", 0, 0, 20)
            )
            is_mobile = max_touch_points >= 5
            self._context = self._browser.new_context(
                locale=_fingerprint_value(
                    self._profile,
                    "oai_language",
                    "language",
                    default="en-IN",
                ),
                timezone_id=_fingerprint_value(
                    self._profile,
                    "timezone",
                    "timezone_id",
                    default="Asia/Kolkata",
                ),
                viewport=viewport,
                screen=screen,
                user_agent=self._profile["ua"],
                is_mobile=is_mobile,
                has_touch=is_mobile,
                device_scale_factor=1,
                color_scheme="light",
                reduced_motion="no-preference",
                extra_http_headers={
                    "accept-language": self._profile["accept_language"],
                    "oai-device-id": _fingerprint_value(self._profile, "device_id"),
                    "oai-language": self._profile["oai_language"],
                },
            )
            self._context.add_init_script(_browser_init_script(self._profile))
            host = (urlsplit(target_url).hostname or "").lower()
            self._seed_cookies(host)
        except RuntimeError:
            self._close_runtime()
            raise
        except Exception as exc:
            self._close_runtime()
            raise RuntimeError(
                f"{UPI_HEADLESS_BROWSER_LAUNCH_FAILED}: "
                f"创建浏览器上下文失败：{_short_error(exc)}"
            ) from exc

    def _page_for_url(self, target_url: str) -> Any:
        page_url = self._fetch_page_url or target_url
        parsed = urlsplit(page_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise RuntimeError(
                f"{UPI_HEADLESS_BROWSER_REQUEST_FAILED}: URL 无效：{page_url}"
            )
        origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        page = self._pages.get(origin)
        if page is not None:
            return page
        page = None
        try:
            page = self._context.new_page()
            page.set_default_timeout(self._timeout_ms)
            host = (parsed.hostname or "").lower()
            self._seed_cookies(host)
            # API 请求需要一个与目标同源的页面作为 fetch 承载页；
            # 不再强制访问 ChatGPT 首页。部分代理会主动中止首页导航，
            # 但并不影响同一出口访问 backend-api。Stripe 与 ChatGPT
            # API 都使用本地 fulfill 的空白根页面，实际请求仍由
            # Chromium 网络栈发出。
            def fulfill_blank(route: Any) -> None:
                route.fulfill(
                    status=200,
                    headers={"content-type": "text/html; charset=utf-8"},
                    body="<!doctype html><html><head></head><body></body></html>",
                )

            page.route(origin + "/", fulfill_blank)
            try:
                page.goto(
                    origin + "/",
                    wait_until="commit",
                    timeout=self._timeout_ms,
                )
            finally:
                page.unroute(origin + "/", fulfill_blank)
        except Exception as exc:
            try:
                page.close()
            except Exception:
                pass
            raise RuntimeError(
                f"{UPI_HEADLESS_BROWSER_REQUEST_FAILED}: "
                f"浏览器打开 {origin} 失败：{_short_error(exc)}"
            ) from exc
        self._pages[origin] = page
        return page

    def _request_headers(self, headers: dict[str, Any] | None) -> tuple[dict[str, str], str]:
        merged = CaseInsensitiveDict(self.headers)
        if headers:
            merged.update(headers)
        referrer = _text(merged.get("Referer") or merged.get("Referrer"))
        browser_headers: dict[str, str] = {}
        for key, value in merged.items():
            name = str(key)
            lower = name.lower()
            if lower in {
                "accept-encoding",
                "connection",
                "content-length",
                "cookie",
                "host",
                "origin",
                "referer",
                "user-agent",
            } or lower.startswith("sec-"):
                continue
            if value is not None:
                browser_headers[name] = str(value)
        return browser_headers, referrer

    def _request_on_browser_thread(
        self,
        method: str,
        url: str,
        *,
        params: Any = None,
        data: Any = None,
        json: Any = None,
        headers: dict[str, Any] | None = None,
        timeout: float | int | None = None,
        allow_redirects: bool = True,
        **_kwargs: Any,
    ) -> BrowserResponse:
        with self._lock:
            if self._closed:
                raise RuntimeError(f"{UPI_HEADLESS_BROWSER_REQUEST_FAILED}: 会话已关闭")
            parsed = urlsplit(_text(url))
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise RuntimeError(
                    f"{UPI_HEADLESS_BROWSER_REQUEST_FAILED}: URL 无效：{url}"
                )
            if params:
                query = urlencode(params, doseq=True)
                parsed = parsed._replace(
                    query=f"{parsed.query}&{query}" if parsed.query else query
                )
            request_url = urlunsplit(parsed)
            self._ensure_runtime(request_url)
            self._seed_cookies(parsed.hostname)
            page = self._page_for_url(request_url)
            browser_headers, referrer = self._request_headers(headers)
            body: str | None = None
            if json is not None:
                body = __import__("json").dumps(
                    json,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                browser_headers.setdefault("Content-Type", "application/json")
            elif data is not None:
                if isinstance(data, (dict, list, tuple)):
                    body = urlencode(data, doseq=True)
                elif isinstance(data, bytes):
                    body = data.decode("utf-8", errors="replace")
                else:
                    body = str(data)
                browser_headers.setdefault(
                    "Content-Type",
                    "application/x-www-form-urlencoded",
                )
            timeout_value = self._timeout_ms
            if timeout is not None:
                timeout_value = max(1_000, min(int(float(timeout) * 1000), 120_000))
            try:
                result = page.evaluate(
                    _FETCH_SCRIPT,
                    {
                        "url": request_url,
                        "method": str(method or "GET").upper(),
                        "headers": browser_headers,
                        "body": body,
                        "timeoutMs": timeout_value,
                        "allowRedirects": bool(allow_redirects),
                        "referrer": referrer,
                    },
                )
            except Exception as exc:
                raise RuntimeError(
                    f"{UPI_HEADLESS_BROWSER_REQUEST_FAILED}: "
                    f"{str(method or 'GET').upper()} {parsed.path or '/'} 浏览器执行失败："
                    f"{_short_error(exc)}"
                ) from exc
            if not isinstance(result, dict):
                raise RuntimeError(
                    f"{UPI_HEADLESS_BROWSER_REQUEST_FAILED}: 浏览器未返回响应对象"
                )
            if result.get("error"):
                raise RuntimeError(
                    f"{UPI_HEADLESS_BROWSER_REQUEST_FAILED}: "
                    f"{str(method or 'GET').upper()} {parsed.path or '/'}："
                    f"{_short_error(result.get('error'))}"
                )
            response = BrowserResponse(
                status_code=int(result.get("status") or 0),
                url=_text(result.get("url")) or request_url,
                headers=result.get("headers") if isinstance(result.get("headers"), dict) else {},
                text=str(result.get("text") or ""),
            )
            self._sync_cookie_jar()
            return response

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Any = None,
        data: Any = None,
        json: Any = None,
        headers: dict[str, Any] | None = None,
        timeout: float | int | None = None,
        allow_redirects: bool = True,
        **_kwargs: Any,
    ) -> BrowserResponse:
        with self._lock:
            if self._closed:
                raise RuntimeError(f"{UPI_HEADLESS_BROWSER_REQUEST_FAILED}: 会话已关闭")
        return self._run_on_browser_thread(
            self._request_on_browser_thread,
            method,
            url,
            params=params,
            data=data,
            json=json,
            headers=headers,
            timeout=timeout,
            allow_redirects=allow_redirects,
        )

    def get(self, url: str, params: Any = None, **kwargs: Any) -> BrowserResponse:
        return self.request("GET", url, params=params, **kwargs)

    def post(
        self,
        url: str,
        data: Any = None,
        json: Any = None,
        **kwargs: Any,
    ) -> BrowserResponse:
        return self.request("POST", url, data=data, json=json, **kwargs)

    def run_page_workflow(
        self,
        target_url: str,
        workflow: Any,
        *,
        timeout_ms: int | None = None,
    ) -> Any:
        """Run a page-level workflow on the session's existing headless context.

        The callback executes on the dedicated Playwright thread so callers can
        reuse the same proxy, cookies, fingerprint and browser context without
        mixing sync Playwright calls with the caller's asyncio loop.
        """

        def execute() -> Any:
            with self._lock:
                if self._closed:
                    raise RuntimeError(f"{UPI_HEADLESS_BROWSER_REQUEST_FAILED}: session 已关闭")
                parsed = urlsplit(_text(target_url))
                if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                    raise RuntimeError(
                        f"{UPI_HEADLESS_BROWSER_REQUEST_FAILED}: URL 无效 {target_url}"
                    )
                self._ensure_runtime(target_url)
                self._seed_cookies(parsed.hostname)
                page = self._page_for_url(target_url)
                page.set_default_timeout(
                    max(2_000, min(int(timeout_ms or self._timeout_ms), 120_000))
                )
                return workflow(page)

        return self._run_on_browser_thread(execute)

    def _close_runtime(self) -> None:
        for page in list(self._pages.values()):
            try:
                page.close()
            except Exception:
                pass
        self._pages.clear()
        if self._context is not None:
            try:
                self._context.close()
            except Exception:
                pass
        if self._browser is not None:
            try:
                self._browser.close()
            except Exception:
                pass
        if self._playwright is not None:
            try:
                self._playwright.stop()
            except Exception:
                pass
        self._context = None
        self._browser = None
        self._playwright = None

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            executor = self._runtime_executor
            self._runtime_executor = None
        if executor is None:
            return
        try:
            if self._runtime_thread_id == get_ident():
                self._close_runtime()
            else:
                executor.submit(self._close_runtime).result()
        finally:
            executor.shutdown(wait=True, cancel_futures=True)

    def __enter__(self) -> "PlaywrightBrowserSession":
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


__all__ = [
    "BrowserResponse",
    "PlaywrightBrowserSession",
    "ProtocolHttpSession",
    "UPI_PROTOCOL_SESSION_UNAVAILABLE",
    "UPI_HEADLESS_BROWSER_LAUNCH_FAILED",
    "UPI_HEADLESS_BROWSER_PROXY_UNSUPPORTED",
    "UPI_HEADLESS_BROWSER_REQUEST_FAILED",
    "UPI_HEADLESS_BROWSER_UNAVAILABLE",
]
