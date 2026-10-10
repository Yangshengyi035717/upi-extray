#!/usr/bin/env python3
"""通过 ChatGPT access token → Stripe → GCash 提链流程提取 GCash 支付跳转链接。

流程与 UPI 提链相同，但使用 PH/PHP 账单和 type=gcash 支付方式：
1. 用 ChatGPT access token 创建 checkout session
2. 通过 Stripe API init 获取支付页信息
3. 创建 type=gcash 的 Stripe payment_method（PH 账单资料）
4. Stripe confirm 提交支付
5. 轮询/提取 GCash redirect URL
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html as html_lib
import io
import json
import os
import random
import re
import shutil
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlsplit, urlunsplit

import requests
try:
    import qrcode
    from qrcode.image.svg import SvgPathImage
except ImportError:  # QR 输出仅 CLI 使用，服务端提链不应因此无法启动
    qrcode = None  # type: ignore[assignment]
    SvgPathImage = None  # type: ignore[assignment]

try:
    from curl_cffi.requests import Session as CurlCffiSession  # type: ignore
except ImportError:
    CurlCffiSession = None  # type: ignore

try:
    from .fingerprint_store import extractor_profile, get_account_fingerprint
    from .register_profile import random_profile
except ImportError:  # pragma: no cover - CLI 直接运行时兜底
    from fingerprint_store import extractor_profile, get_account_fingerprint  # type: ignore
    from register_profile import random_profile  # type: ignore


# ---------------------------------------------------------------------------
# 目录 & 常量
# ---------------------------------------------------------------------------

GCASH_DIR = Path(__file__).resolve().parent
LOG_DIR = GCASH_DIR / "logs"
OUTPUT_DIR = GCASH_DIR / "output"

DEFAULT_STRIPE_PK = (
    "pk_live_51HOrSwC6h1nxGoI3lTAgRjYVrz4dU3fVOabyCcKR3pbEJguCVAlqCxdxCUvoRh1XWwRac"
    "ViovU3kLKvpkjh7IqkW00iXQsjo3n"
)
STRIPE_VERSION_FULL = (
    "2025-03-31.basil; checkout_server_update_beta=v1; checkout_manual_approval_preview=v1"
)
DEFAULT_TIMEOUT = 30
CHATGPT_TIMEOUT = 45
CHATGPT_RETRY_ATTEMPTS = 5
PROVIDER_RETRY_ATTEMPTS = 3
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
)
DEFAULT_STRIPE_RUNTIME_VERSION = "6f8494a281"
PLUS_TRIAL_PROMO_ID = "plus-1-month-free"
KNOWN_GCASH_CUSTOM_PAYMENT_METHOD_IDS = {
    "cpmt_1TOgstC6h1nxGoI3WUVEY2cJ",
}

# GCash 相关域名
GCASH_HOST_SUFFIXES = ("gcash.com", "mynt.xyz", "globe.com.ph")
ADYEN_CHECKOUT_HOST_SUFFIXES = ("checkoutshopper-live.adyen.com", "checkoutshopper-test.adyen.com")


# ---------------------------------------------------------------------------
# PH 账单资料池
# ---------------------------------------------------------------------------

PH_BILLING_NAMES = [
    ("Juan", "Dela Cruz"),
    ("Maria", "Santos"),
    ("Jose", "Reyes"),
    ("Ana", "Garcia"),
    ("Miguel", "Ramos"),
    ("Sofia", "Torres"),
    ("Carlos", "Cruz"),
    ("Isabella", "Mendoza"),
    ("Rafael", "Villanueva"),
    ("Gabriela", "Lopez"),
    ("Andres", "Gonzales"),
    ("Patricia", "Aquino"),
]
PH_BILLING_STREETS = [
    ("123 Rizal Avenue", "Manila", "NCR", "1000"),
    ("456 EDSA", "Quezon City", "NCR", "1100"),
    ("789 Ayala Avenue", "Makati", "NCR", "1200"),
    ("321 Session Road", "Baguio", "CAR", "2600"),
    ("654 Osmeña Boulevard", "Cebu City", "VII", "6000"),
    ("111 Magsaysay Drive", "Davao City", "XI", "8000"),
    ("222 General Santos Avenue", "General Santos", "XII", "9500"),
    ("333 Lacson Street", "Bacolod", "VI", "6100"),
]
EMAIL_DOMAIN_POOL = ("gmail.com", "outlook.com", "icloud.com")


# ---------------------------------------------------------------------------
# 异常
# ---------------------------------------------------------------------------


class GCashExtractError(RuntimeError):
    pass


class StripeRequiresApproval(Exception):
    pass


# ---------------------------------------------------------------------------
# Sentinel Token 生成器
# ---------------------------------------------------------------------------

SENTINEL_BASE = "https://sentinel.openai.com"
SENTINEL_SDK = SENTINEL_BASE + "/sentinel/20260124ceb8/sdk.js"
SENTINEL_MAX_ATTEMPTS = 100000

def _compact_json(value) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)

class _SentinelTokenGenerator:
    def __init__(self, device_id: str, user_agent: str) -> None:
        self.device_id = device_id
        self.user_agent = user_agent
        self.sid = str(uuid.uuid4())

    def config(self) -> list:
        perf_now = 1000 + random.random() * 49000
        now = datetime.now(timezone.utc)
        weekdays = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
        months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
        now_text = (
            f"{weekdays[now.weekday()]} {months[now.month - 1]} {now.day:02d} "
            f"{now.year:04d} {now.hour:02d}:{now.minute:02d}:{now.second:02d} "
            "GMT+0000 (Coordinated Universal Time)"
        )
        return [
            "1920x1080",
            now_text,
            4294705152,
            random.random(),
            self.user_agent,
            SENTINEL_SDK,
            None,
            None,
            "en-US",
            random.random(),
            random.choice(["vendorSub-undefined", "plugins-undefined", "mimeTypes-undefined", "hardwareConcurrency-undefined"]),
            random.choice(["location", "implementation", "URL", "documentURI", "compatMode"]),
            random.choice(["Object", "Function", "Array", "Number", "parseFloat", "undefined"]),
            perf_now,
            self.sid,
            "",
            random.choice([4, 8, 12, 16]),
            int(time.time() * 1000) - perf_now,
        ]

    def generate_requirements_token(self) -> str:
        data = self.config()
        data[3] = 1
        data[9] = round(5 + random.random() * 45)
        return "gAAAAAC" + self._base64_json(data)

    def generate_token(self, seed: str, difficulty: str) -> str:
        started = time.time()
        data = self.config()
        difficulty = difficulty or "0"
        for i in range(SENTINEL_MAX_ATTEMPTS):
            data[3] = i
            data[9] = round((time.time() - started) * 1000)
            payload = self._base64_json(data)
            hashed = self._fnv1a32(seed + payload)
            prefix_len = min(len(difficulty), len(hashed))
            if hashed[:prefix_len] <= difficulty[:prefix_len]:
                return "gAAAAAB" + payload + "~S"
        return "gAAAAAB" + "ERROR_" + self._base64_json("None")

    @staticmethod
    def _base64_json(value) -> str:
        return base64.b64encode(_compact_json(value).encode("utf-8")).decode("ascii")

    @staticmethod
    def _fnv1a32(text: str) -> str:
        value = 2166136261
        for ch in text:
            value ^= ord(ch)
            value = (value * 16777619) & 0xFFFFFFFF
        value ^= value >> 16
        value = (value * 2246822507) & 0xFFFFFFFF
        value ^= value >> 13
        value = (value * 3266489909) & 0xFFFFFFFF
        value ^= value >> 16
        return f"{value & 0xFFFFFFFF:08x}"

def _session_cookie_header(session: Any) -> str:
    """Return non-empty ChatGPT/OpenAI cookies without exposing their values."""
    jar = getattr(session, "cookies", None)
    if jar is None:
        return ""
    pairs: list[tuple[str, str]] = []
    try:
        for cookie in jar:
            name = _text(getattr(cookie, "name", ""))
            value = _text(getattr(cookie, "value", ""))
            domain = _text(getattr(cookie, "domain", "")).lower()
            if name and value and (
                not domain or "chatgpt.com" in domain or "openai.com" in domain
            ):
                pairs.append((name, value))
    except Exception:
        try:
            values = jar.get_dict()
        except Exception:
            values = {}
        if isinstance(values, dict):
            pairs.extend(
                (_text(name), _text(value))
                for name, value in values.items()
                if _text(name) and _text(value)
            )
    unique: dict[str, str] = {}
    for name, value in pairs:
        unique[name] = value
    return "; ".join(f"{name}={value}" for name, value in unique.items())


def _sync_session_cookie_header(session: Any) -> None:
    """Refresh the explicit Cookie header after a page warm-up response."""
    cookie_header = _session_cookie_header(session)
    if cookie_header:
        try:
            session.headers["Cookie"] = cookie_header
        except Exception:
            pass


def _browser_executable_path() -> str:
    """Locate a system browser when Playwright's bundled browser is absent."""
    configured = (
        os.environ.get("GCASH_BROWSER_EXECUTABLE_PATH")
        or os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    )
    if configured and os.path.isfile(configured):
        return configured

    candidates = (
        shutil.which("google-chrome"),
        shutil.which("chromium"),
        shutil.which("chromium-browser"),
        shutil.which("chrome"),
        shutil.which("msedge"),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/microsoft-edge",
    )
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return ""


def _playwright_browser_engine(playwright: Any) -> Any:
    """Return the configured Playwright engine, falling back to Chromium."""
    requested = str(os.environ.get("GCASH_BROWSER_ENGINE") or "chromium").strip().lower()
    if requested not in {"chromium", "webkit", "firefox"}:
        requested = "chromium"
    return getattr(playwright, requested, playwright.chromium)


def _launch_gcash_browser(playwright: Any, proxy_config: dict[str, str] | None) -> Any:
    """Launch a headless browser using system Chrome when available."""
    engine = _playwright_browser_engine(playwright)
    launch_options: dict[str, Any] = {
        "headless": True,
        "proxy": proxy_config,
    }
    # 未配置出口时关掉浏览器继承的系统代理（Windows 上的 Clash/V2Ray），
    # 避免请求从错误的出口国家发出。
    try:
        from .playwright_proxy_guard import guard_system_proxy
    except ImportError:  # pragma: no cover - CLI 直跑
        from playwright_proxy_guard import guard_system_proxy  # type: ignore
    engine_name = str(getattr(engine, "name", "") or "").strip().lower() or "chromium"
    guard_system_proxy(launch_options, proxy_config, engine=engine_name)
    executable_path = _browser_executable_path()
    if executable_path:
        launch_options["executable_path"] = executable_path
    try:
        return engine.launch(**launch_options)
    except Exception:
        # A system Chrome executable cannot be used by WebKit/Firefox. Retry
        # without it so the normal Playwright-managed browser can still work.
        if executable_path:
            launch_options.pop("executable_path", None)
            return engine.launch(**launch_options)
        raise


def _sync_browser_cookies(session: Any, cookies: list[dict[str, Any]]) -> int:
    """Copy ChatGPT/OpenAI cookies from a browser context into the HTTP session."""
    copied = 0
    jar = getattr(session, "cookies", None)
    if jar is None or not hasattr(jar, "set"):
        return copied
    for item in cookies:
        name = str(item.get("name") or "").strip()
        value = str(item.get("value") or "")
        domain = str(item.get("domain") or "").strip()
        path = str(item.get("path") or "/").strip() or "/"
        if not name or not value or not domain:
            continue
        if "chatgpt.com" not in domain.lower() and "openai.com" not in domain.lower():
            continue
        try:
            jar.set(name, value, domain=domain, path=path)
            copied += 1
        except Exception:
            continue
    if copied:
        _sync_session_cookie_header(session)
    return copied


def _warmup_gcash_browser_page(
    session: Any,
    access_token: str,
    *,
    device_id: str,
    page_url: str = "https://chatgpt.com/",
    log: Any | None = None,
) -> tuple[bool, str]:
    """Load ChatGPT in a real browser context before the API checkout flow.

    This is intentionally a compatibility warm-up, not a synthetic mouse/typing
    simulator. The browser gets the same proxy, UA, device ID and existing
    cookies, then returns first-party cookies to the HTTP session.
    """
    if str(os.environ.get("GCASH_BROWSER_WARMUP", "1")).strip().lower() in {
        "0", "false", "no", "off",
    }:
        return False, "disabled"
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except Exception:
        return False, "playwright_unavailable"

    timeout_seconds = max(
        5,
        min(int(os.environ.get("GCASH_BROWSER_WARMUP_TIMEOUT", "20") or "20"), 60),
    )
    user_agent = str(getattr(session, "headers", {}).get("User-Agent") or DEFAULT_USER_AGENT)
    proxy_config = _playwright_proxy(_session_proxy_url(session))
    session_headers = dict(getattr(session, "headers", {}) or {})
    authorization = str(session_headers.get("Authorization") or "").strip()
    browser_headers = {
        "oai-device-id": str(device_id or "").strip(),
        "oai-language": str(session_headers.get("oai-language") or "en-PH"),
        "oai-session-id": str(session_headers.get("oai-session-id") or ""),
    }
    browser_headers = {key: value for key, value in browser_headers.items() if value}
    source_cookies = _playwright_cookies(session)

    def emit(message: str) -> None:
        if log:
            log(message)

    try:
        with sync_playwright() as playwright:
            browser = _launch_gcash_browser(playwright, proxy_config)
            try:
                context = browser.new_context(
                    user_agent=user_agent,
                    locale="en-PH",
                    timezone_id="Asia/Manila",
                    viewport={"width": 1536, "height": 864},
                )
                if source_cookies:
                    context.add_cookies(source_cookies)
                if browser_headers:
                    context.set_extra_http_headers(browser_headers)

                def route_handler(route: Any) -> None:
                    request = route.request
                    headers = dict(request.headers)
                    host = str(urlsplit(request.url).hostname or "").lower()
                    if authorization and (
                        host == "chatgpt.com"
                        or host.endswith(".chatgpt.com")
                        or host == "openai.com"
                        or host.endswith(".openai.com")
                    ):
                        headers["authorization"] = authorization
                    route.continue_(headers=headers)

                context.route("**/*", route_handler)
                page = context.new_page()
                try:
                    response = page.goto(
                        page_url or "https://chatgpt.com/",
                        wait_until="domcontentloaded",
                        timeout=timeout_seconds * 1000,
                    )
                    status = int(getattr(response, "status", 0) or 0) if response else 0
                    if status >= 400:
                        emit(f"GCash 阶段[浏览器暖身]: ChatGPT 页面 HTTP {status}，继续 API 流程.")
                    try:
                        page.wait_for_load_state("networkidle", timeout=5000)
                    except PlaywrightTimeoutError:
                        pass
                    page.wait_for_timeout(500)
                except PlaywrightTimeoutError:
                    emit("GCash 阶段[浏览器暖身]: 页面加载超时，继续 API 流程.")
                copied = _sync_browser_cookies(session, context.cookies())
                return True, f"ok:cookies={copied}"
            finally:
                browser.close()
    except Exception as exc:
        return False, f"browser_error:{short_error(str(exc), 160)}"


def _warmup_gcash_chatgpt_page(
    session: Any,
    *,
    device_id: str,
    page_url: str = "https://chatgpt.com/",
    log: Any | None = None,
) -> None:
    """Warm the ChatGPT page on the same sticky proxy/session before checkout."""
    try:
        from .linkpp_handoff.protocol.stripe_checkout import _warmup_chatgpt_page
    except ImportError:  # pragma: no cover - CLI 直接运行时兜底
        from linkpp_handoff.protocol.stripe_checkout import _warmup_chatgpt_page  # type: ignore

    def emit(message: str) -> None:
        if log:
            log(message)

    _warmup_chatgpt_page(
        session,
        page_url=page_url or "https://chatgpt.com/",
        country="PH",
        device_id=device_id,
        log=emit,
    )
    _sync_session_cookie_header(session)


def _mint_full_sentinel_token(
    *,
    flow: str,
    device_id: str,
    user_agent: str,
    session: Any,
    page_url: str,
    language: str = "en-PH",
    timezone: str = "Asia/Manila",
    cores: int = 16,
    tls_impersonate: str = "chrome136",
) -> str:
    """Use the bundled Sentinel SDK bridge and keep its SO token on the session."""
    try:
        from .linkpp_handoff.protocol.sentinel import mint_sentinel_sync
    except ImportError:  # pragma: no cover - CLI 直接运行时兜底
        from linkpp_handoff.protocol.sentinel import mint_sentinel_sync  # type: ignore

    main_token, so_token = mint_sentinel_sync(
        flow=flow,
        device_id=device_id,
        user_agent=user_agent,
        proxy=_session_proxy_url(session),
        page_url=page_url,
        language=str(language or "en-PH"),
        timezone=str(timezone or "Asia/Manila"),
        cores=max(1, int(cores or 16)),
        cookie_header=_session_cookie_header(session),
        tls_impersonate=_text(tls_impersonate) or "chrome136",
    )
    try:
        setattr(session, "_gcash_sentinel_so_token", str(so_token or ""))
        setattr(session, "_gcash_sentinel_mode", "sdk")
    except Exception:
        pass
    return str(main_token or "")


def build_sentinel_token(
    access_token: str,
    device_id: str,
    user_agent: str,
    session: Any,
    *,
    flow: str = "checkout_session_approval",
    page_url: str = "",
    language: str = "en-PH",
    timezone: str = "Asia/Manila",
    cores: int = 16,
    tls_impersonate: str = "chrome136",
) -> str:
    # 优先使用 bundled Sentinel SDK：它可以生成真实的 t/so 字段，并把
    # 当前页面 Cookie、代理、UA、device_id 一起纳入证明上下文。
    try:
        full_token = _mint_full_sentinel_token(
            flow=flow,
            device_id=device_id,
            user_agent=user_agent,
            session=session,
            page_url=page_url or "https://chatgpt.com/",
            language=language,
            timezone=timezone,
            cores=cores,
            tls_impersonate=tls_impersonate,
        )
        if full_token:
            return full_token
    except Exception:
        try:
            setattr(session, "_gcash_sentinel_mode", "fallback")
            setattr(session, "_gcash_sentinel_so_token", "")
        except Exception:
            pass

    generator = _SentinelTokenGenerator(device_id, user_agent)
    req_payload = {
        "p": generator.generate_requirements_token(),
        "id": device_id,
        "flow": flow,
    }

    headers = {
        "x-openai-target-path": "/backend-api/sentinel/req",
        "x-openai-target-route": "/backend-api/sentinel/req",
    }

    resp = session.post(
        "https://chatgpt.com/backend-api/sentinel/req",
        json=req_payload,
        headers=headers,
        timeout=30
    )

    if resp.status_code != 200:
        raise GCashExtractError(f"Sentinel Token 获取失败 HTTP {resp.status_code}: {resp.text}")

    payload = resp.json() or {}
    challenge_token = payload.get("token")
    if not challenge_token:
        raise GCashExtractError(f"Sentinel Token 响应中缺少 token: {payload}")

    proof = payload.get("proofofwork") or {}
    if proof.get("required") and proof.get("seed"):
        p_value = generator.generate_token(proof.get("seed"), str(proof.get("difficulty") or "0"))
    else:
        p_value = generator.generate_requirements_token()

    return _compact_json({
        "p": p_value,
        "t": "",
        "c": challenge_token,
        "id": device_id,
        "flow": flow,
    })


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------


def _text(value: Any) -> str:
    return str(value or "").strip()


def new_session(use_curl_cffi: bool = True, impersonate: str = "chrome136", log: Any | None = None) -> Any:
    impersonate = _text(impersonate) or "chrome136"
    if use_curl_cffi and CurlCffiSession is not None:
        try:
            session = CurlCffiSession(impersonate=impersonate)
        except Exception as exc:
            if impersonate != "chrome136":
                if log:
                    try:
                        log(
                            "GCash 指纹 TLS 预设不可用，"
                            f"已从 {impersonate} 回退 chrome136：{short_error(str(exc))}"
                        )
                    except Exception:
                        pass
                session = CurlCffiSession(impersonate="chrome136")
            else:
                raise
    else:
        session = requests.Session()
    if hasattr(session, "trust_env"):
        session.trust_env = False
    return session


def _fingerprint_header_value(profile: dict[str, Any] | None, *keys: str, default: str = "") -> str:
    if not isinstance(profile, dict):
        return default
    for key in keys:
        value = _text(profile.get(key))
        if value:
            return value
    return default


def _gcash_fingerprint_label(profile: dict[str, Any] | None, device_id: str = "") -> str:
    if not isinstance(profile, dict) or not profile:
        return "默认 Chrome/chrome136 · en-US · device=random"
    name = _fingerprint_header_value(profile, "summary", "name", default="fingerprint")
    tls = _fingerprint_header_value(profile, "tls_impersonate", default="chrome136")
    locale = _fingerprint_header_value(profile, "oai_language", "language", "accept_language", default="en-PH")
    timezone = _fingerprint_header_value(profile, "timezone", "timezone_id", default="Asia/Manila")
    region = _fingerprint_header_value(profile, "region", default="PH")
    fp_id = _fingerprint_header_value(profile, "fingerprint_id")
    short_device = _text(device_id)[:8] or "random"
    id_part = f" id={fp_id}" if fp_id else ""
    return f"{name}{id_part} TLS={tls} 语言={locale} 时区={timezone} 建单国={region} device={short_device}"


def resolve_gcash_fingerprint(
    access_token: str = "",
    *,
    account_id: str = "",
    mode: str = "sticky",
    attempt: int = 1,
) -> dict[str, str]:
    """Return a PH browser fingerprint for GCash extraction."""
    normalized_mode = _text(mode).lower()
    if normalized_mode not in {"sticky", "rotate"}:
        normalized_mode = "sticky"
    resolved_account = _text(account_id)
    if not resolved_account:
        try:
            from .session_login import account_context_from_access_token
        except ImportError:  # pragma: no cover - CLI 直接运行时兜底
            from session_login import account_context_from_access_token  # type: ignore
        resolved_account, email = account_context_from_access_token(access_token)
        resolved_account = resolved_account or email
    resolved_account = resolved_account or f"gcash-token:{hashlib.sha256(_text(access_token).encode('utf-8')).hexdigest()}"
    if normalized_mode == "rotate":
        profile = random_profile(
            region="PH",
            diversify=True,
            include_mobile=str(os.environ.get("GCASH_MOBILE_FINGERPRINTS", "")).strip().lower()
            in {"1", "true", "yes"},
        )
        device_id = str(uuid.uuid4())
        adapted = extractor_profile(profile, device_id)
    else:
        profile, device_id = get_account_fingerprint(resolved_account, region="PH")
        adapted = extractor_profile(profile, device_id)
    adapted["device_id"] = device_id
    adapted["mode"] = normalized_mode
    adapted["account_id"] = resolved_account
    adapted["attempt"] = str(max(1, int(attempt or 1)))
    return adapted


def normalize_proxy_url(proxy: str) -> str:
    proxy = str(proxy or "").strip()
    if not proxy:
        return ""
    if "://" not in proxy:
        return f"socks5h://{proxy}"
    if proxy.lower().startswith("socks5://"):
        return "socks5h://" + proxy.split("://", 1)[1]
    return proxy


def set_proxy_url(session: Any, proxy: str) -> None:
    proxy = normalize_proxy_url(proxy)
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    elif hasattr(session, "proxies"):
        session.proxies = {}


def short_error(detail: str, limit: int = 260) -> str:
    text = re.sub(r"\s+", " ", str(detail or "")).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


_DIAG_KEYS = {
    "success", "status", "result", "state", "payment_status", "checkout_status",
    "can_confirm", "canConfirm", "amount_total", "amount", "currency",
    "error", "code", "message", "reason", "failure_reason", "decline_code",
    "checkout_provider", "processor_entity",
    "promo_campaign_id", "promoCampaignId", "payment_method_type", "selected_payment_method_type",
}


def _compact_identifier(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) <= 18:
        return text
    return f"{text[:10]}...{text[-6:]}"


def _diagnostic_find(payload: Any, wanted: set[str], found: dict[str, str], limit: int = 14) -> None:
    if len(found) >= limit:
        return
    if isinstance(payload, dict):
        for key, value in payload.items():
            normalized = str(key or "").strip()
            if normalized in wanted and normalized not in found:
                if isinstance(value, (str, int, float, bool)) or value is None:
                    found[normalized] = short_error(str(value), 90)
                elif isinstance(value, dict):
                    nested = value.get("message") or value.get("code") or value.get("status") or value.get("type")
                    if nested is not None:
                        found[normalized] = short_error(str(nested), 90)
            if normalized in {"checkout_session_id", "session_id", "id"} and "id" not in found:
                if isinstance(value, (str, int, float)):
                    found["id"] = _compact_identifier(value)
            _diagnostic_find(value, wanted, found, limit=limit)
            if len(found) >= limit:
                return
    elif isinstance(payload, list):
        for item in payload[:10]:
            _diagnostic_find(item, wanted, found, limit=limit)
            if len(found) >= limit:
                return


def diagnostic_summary(label: str, payload: Any = None, *, status_code: int | None = None) -> str:
    parts = [str(label)]
    if status_code is not None:
        parts.append(f"http={status_code}")
    found: dict[str, str] = {}
    _diagnostic_find(payload, _DIAG_KEYS, found)
    for key in sorted(found):
        value = found[key]
        if value:
            parts.append(f"{key}={value}")
    if isinstance(payload, dict):
        for key in (
            "custom_payment_methods",
            "custom_payment_method_data",
            "payment_method_types",
            "payment_method_options",
        ):
            value = payload.get(key)
            if isinstance(value, list):
                parts.append(f"{key}.count={len(value)}")
    promo_ok, _promo_source = _promo_qualification_evidence(payload)
    if promo_ok:
        parts.append(f"promo={PLUS_TRIAL_PROMO_ID}")
    if _payload_has_gcash_payment_method(payload):
        parts.append("gcash_method=present")
    return "; ".join(parts)


def build_email(first_name: str, last_name: str) -> str:
    first = (first_name or "").lower()
    last = (last_name or "").lower()
    suffix = str(random.randint(10000, 999999))
    domain = random.choice(EMAIL_DOMAIN_POOL)
    return f"{first}.{last}{suffix}@{domain}"


def billing_for_ph() -> dict[str, str]:
    first_name, last_name = random.choice(PH_BILLING_NAMES)
    line1, city, state, postal_code = random.choice(PH_BILLING_STREETS)
    return {
        "name": f"{first_name} {last_name}",
        "email": build_email(first_name, last_name),
        "country": "PH",
        "line1": line1,
        "city": city,
        "state": state,
        "postal_code": postal_code,
    }


def locale_parts(locale: str) -> tuple[str, str]:
    mapping: dict[str, tuple[str, str]] = {
        "en-PH": ("en-PH", "en-PH"),
        "en-US": ("en-US", "en"),
        "en": ("en-US", "en"),
    }
    return mapping.get(str(locale or "").strip(), ("en-PH", "en-PH"))


# ---------------------------------------------------------------------------
# GCash URL 识别
# ---------------------------------------------------------------------------


def is_gcash_redirect_url(value: str) -> bool:
    """识别 GCash 授权/支付页面 URL。"""
    try:
        parsed = urlsplit(str(value or "").strip())
    except Exception:
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    for suffix in GCASH_HOST_SUFFIXES:
        if host == suffix or host.endswith(f".{suffix}"):
            return True
    return False


def is_stripe_pm_redirect_url(value: str) -> bool:
    parsed = urlsplit(str(value or ""))
    host = (parsed.netloc or "").lower()
    path = parsed.path or ""
    return host == "pm-redirects.stripe.com" and path.startswith("/authorize/")


def is_gcash_or_redirect_url(value: str) -> bool:
    """GCash 直接跳转或 Stripe pm-redirects 中间跳转。"""
    return is_gcash_redirect_url(value) or is_stripe_pm_redirect_url(value)


def is_external_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except Exception:
        return False
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def is_ignored_resource_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except Exception:
        return False
    host = (parsed.netloc or "").lower()
    path = (parsed.path or "").lower()
    ignored_hosts = {
        "stripe-camo.global.ssl.fastly.net",
        "files.stripe.com",
        "q.stripe.com",
        "js.stripe.com",
        "m.stripe.network",
    }
    ignored_suffixes = (
        ".png", ".jpg", ".jpeg", ".svg", ".webp", ".gif", ".ico",
        ".css", ".js", ".woff", ".woff2",
    )
    if host in ignored_hosts or any(host.endswith(f".{h}") for h in ignored_hosts):
        return True
    if path.endswith(ignored_suffixes):
        return True
    return False


# ---------------------------------------------------------------------------
# URL 收集 & redirect 提取 (镜像 UPI app.py 逻辑)
# ---------------------------------------------------------------------------


def collect_urls(payload: Any, urls: list[str] | None = None) -> list[str]:
    found = urls if urls is not None else []
    if isinstance(payload, str):
        source = html_lib.unescape(payload.replace("\\u0026", "&"))
        for match in re.findall(r"https?://[^\s\"'<>]+", source):
            found.append(match.rstrip("),.;]"))
    elif isinstance(payload, dict):
        for key, value in payload.items():
            if (
                key in ("url", "return_url", "redirect_url", "redirect_to_url")
                and isinstance(value, str)
                and is_external_url(value)
            ):
                found.append(value)
            else:
                collect_urls(value, found)
    elif isinstance(payload, list):
        for item in payload:
            collect_urls(item, found)
    return found


def _is_adyen_checkout_redirect_url(value: str) -> bool:
    try:
        parsed = urlsplit(str(value or "").strip())
    except Exception:
        return False
    host = (parsed.hostname or "").lower()
    path = (parsed.path or "").rstrip("/").lower()
    if not host:
        return False
    for suffix in ADYEN_CHECKOUT_HOST_SUFFIXES:
        if host == suffix or host.endswith(f".{suffix}"):
            return path.endswith("/checkoutpaymentredirect")
    return False


def _pick_preferred_redirect_url(urls: list[str]) -> str:
    cleaned = [str(item or "").strip() for item in urls if str(item or "").strip()]
    if not cleaned:
        return ""
    for predicate in (
        _is_adyen_checkout_redirect_url,
        is_stripe_pm_redirect_url,
        is_gcash_redirect_url,
        is_external_url,
    ):
        for item in cleaned:
            if predicate(item):
                return item
    return cleaned[0]


def extract_redirect_to_url(payload: Any) -> str:
    if not isinstance(payload, dict):
        urls = collect_urls(payload)
        return next(
            (item for item in urls if is_gcash_or_redirect_url(item)),
            "",
        )
    next_action = payload.get("next_action")
    if isinstance(next_action, dict) and next_action.get("type") == "redirect_to_url":
        redirect_to_url = next_action.get("redirect_to_url") or {}
        if isinstance(redirect_to_url, dict):
            url = str(redirect_to_url.get("url") or "").strip()
            if url:
                return url
    for key in ("setup_intent", "payment_intent"):
        nested = payload.get(key)
        if isinstance(nested, dict):
            found = extract_redirect_to_url(nested)
            if found:
                return found
    return _pick_preferred_redirect_url(collect_urls(payload))


def find_submission_attempt(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        item = payload.get("submission_attempt")
        if isinstance(item, dict):
            return item
        for value in payload.values():
            found = find_submission_attempt(value)
            if found:
                return found
    elif isinstance(payload, list):
        for value in payload:
            found = find_submission_attempt(value)
            if found:
                return found
    return {}


def submission_attempt_failure_fields(submission: Any) -> dict[str, str]:
    wanted = {
        "error", "code", "message", "reason", "failure_reason",
        "decline_code", "failure_code", "failure_message",
    }
    found: dict[str, str] = {}

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                normalized = str(key or "").strip()
                if normalized in wanted and normalized not in found:
                    if isinstance(item, (str, int, float, bool)):
                        text = str(item).strip()
                    elif isinstance(item, dict):
                        text = str(
                            item.get("message") or item.get("code")
                            or item.get("reason") or item.get("type") or ""
                        ).strip()
                    else:
                        text = ""
                    if text:
                        found[normalized] = text[:240]
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    if isinstance(submission, dict):
        walk(submission)
    return found


def first_non_empty(values: dict[str, str], *keys: str) -> str:
    for key in keys:
        value = str(values.get(key) or "").strip()
        if value:
            return value
    return ""


def submission_attempt_summary(submission: dict[str, Any]) -> str:
    if not submission:
        return "未找到 submission_attempt"
    fields = submission_attempt_failure_fields(submission)
    state = str(submission.get("state") or "未知").strip()
    reason = first_non_empty(fields, "reason", "failure_reason", "decline_code", "failure_code", "code")
    code = first_non_empty(fields, "code", "decline_code", "failure_code")
    message = first_non_empty(fields, "message", "failure_message", "error")
    parts = [f"state={state}"]
    if reason:
        parts.append(f"reason={reason}")
    if code:
        parts.append(f"code={code}")
    if message:
        parts.append(f"message={message}")
    return "，".join(parts)


def is_terminal_submission_failure(submission: dict[str, Any]) -> bool:
    if not submission or str(submission.get("state") or "").lower() != "failed":
        return False
    fields = submission_attempt_failure_fields(submission)
    reason = first_non_empty(fields, "reason", "failure_reason", "decline_code", "failure_code", "code").lower()
    code = first_non_empty(fields, "code", "decline_code", "failure_code").lower()
    message = first_non_empty(fields, "message", "failure_message", "error").lower()
    combined = " ".join(item for item in (reason, code, message) if item)
    if not combined:
        return False
    terminal_markers = (
        "generic_decline", "checkout_approval_payment_failure", "payment_failure",
        "payment_error", "decline", "declined", "blocked", "canceled", "cancelled", "failed",
    )
    return any(marker in combined for marker in terminal_markers)


# ---------------------------------------------------------------------------
# ChatGPT 交互
# ---------------------------------------------------------------------------


def build_chatgpt_session(
    access_token: str,
    proxy: str = "",
    device_id: str = "",
    user_agent: str = "",
    fingerprint_profile: dict[str, Any] | None = None,
    log: Any | None = None,
) -> Any:
    fingerprint = dict(fingerprint_profile or {}) if isinstance(fingerprint_profile, dict) else {}
    device_id = _text(device_id) or _fingerprint_header_value(fingerprint, "device_id") or str(uuid.uuid4())
    user_agent = _text(user_agent) or _fingerprint_header_value(fingerprint, "ua", "user_agent") or DEFAULT_USER_AGENT
    ua_lower = str(user_agent or "").lower()
    omit_ua_ch = (
        "firefox/" in ua_lower
        or "iphone" in ua_lower
        or _text(fingerprint.get("browser")).lower() in {"firefox", "safari"}
    )
    accept_language = _fingerprint_header_value(fingerprint, "accept_language", "locale", default="en-US,en;q=0.9")
    oai_language = _fingerprint_header_value(fingerprint, "oai_language", "language", default="en-US")
    sec_ch_ua = _fingerprint_header_value(
        fingerprint,
        "sec_ch_ua",
        default='"Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"',
    )
    sec_ch_ua_platform = _fingerprint_header_value(fingerprint, "sec_ch_ua_platform", "platform", default='"Windows"')
    if omit_ua_ch:
        sec_ch_ua = ""
        sec_ch_ua_platform = ""
    if sec_ch_ua_platform and not sec_ch_ua_platform.startswith('"'):
        sec_ch_ua_platform = f'"{sec_ch_ua_platform}"'
    # curl_cffi 支持 HTTP/SOCKS 代理；优先使用它，避免 requests 在
    # SOCKS5 节点上缺少 PySocks 依赖而直接失败。
    session = new_session(
        use_curl_cffi=True,
        impersonate=_fingerprint_header_value(fingerprint, "tls_impersonate", default="chrome136"),
        log=log,
    )
    session.headers.update({
        "User-Agent": user_agent,
        "Accept": "*/*",
        "Accept-Language": accept_language,
        "Authorization": f"Bearer {access_token}",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/",
        "Content-Type": "application/json",
        "oai-device-id": device_id,
        "oai-language": oai_language,
        "sec-ch-ua": sec_ch_ua,
        "sec-ch-ua-mobile": _fingerprint_header_value(fingerprint, "mobile", default="?0"),
        "sec-ch-ua-platform": sec_ch_ua_platform,
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "priority": "u=1, i",
        "Cookie": f"oai-did={device_id}",
    })
    if omit_ua_ch:
        for header_key in ("sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"):
            session.headers.pop(header_key, None)
    else:
        for header_key in ("sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"):
            if not _text(session.headers.get(header_key)):
                session.headers.pop(header_key, None)
    # 与官网页面请求保持同一客户端上下文；这些值不替代 Sentinel，
    # 但可避免 checkout 被识别成脱离页面的裸 API 请求。
    try:
        from .linkpp_handoff.protocol.stripe_checkout import oai_session_id_for_device
        session.headers["oai-session-id"] = oai_session_id_for_device(device_id)
        session.headers["oai-client-version"] = "prod-8b282ae6b2e95fa180d7bde7b664e1446691fac0"
        session.headers["oai-client-build-number"] = "10379027"
    except Exception:
        pass
    try:
        from .session_login import account_context_from_access_token as _gcash_account_context
    except ImportError:  # pragma: no cover - CLI 直接运行时兜底
        try:
            from standalone_core.session_login import (  # type: ignore
                account_context_from_access_token as _gcash_account_context,
            )
        except Exception:
            _gcash_account_context = None
    if _gcash_account_context is not None:
        try:
            _gcash_account_id, _gcash_account_email = _gcash_account_context(access_token)
            if _gcash_account_id:
                session.headers["chatgpt-account-id"] = str(_gcash_account_id)
        except Exception:
            pass
    try:
        if hasattr(session, "cookies") and hasattr(session.cookies, "set"):
            session.cookies.set("oai-did", device_id, domain="chatgpt.com", path="/")
    except Exception:
        pass
    if not omit_ua_ch:
        for source_key, header_key in (
            ("arch", "sec-ch-ua-arch"),
            ("bitness", "sec-ch-ua-bitness"),
            ("sec_ch_ua_full_version_list", "sec-ch-ua-full-version-list"),
            ("platform_version", "sec-ch-ua-platform-version"),
        ):
            value = _fingerprint_header_value(fingerprint, source_key)
            if value:
                if header_key in {"sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-platform-version"} and not value.startswith('"'):
                    value = f'"{value}"'
                session.headers[header_key] = value
    if not omit_ua_ch:
        full_version = _fingerprint_header_value(fingerprint, "full", "browser_full_version")
        if full_version:
            session.headers["sec-ch-ua-full-version"] = full_version if full_version.startswith('"') else f'"{full_version}"'
    set_proxy_url(session, proxy)
    return session


_GCASH_AT_INVALID_MARKERS = (
    "token_invalidated",
    "authentication token has been invalidated",
    "your authentication token has been invalidated",
    "token expired",
    "token_expired",
    "invalid access token",
    "jwt expired",
)


def _response_text(response: Any, limit: int = 500) -> str:
    text = str(getattr(response, "text", "") or "")
    if text:
        return text[:limit]
    try:
        payload = response.json()
    except Exception:
        return ""
    try:
        return json.dumps(payload, ensure_ascii=False)[:limit]
    except Exception:
        return str(payload)[:limit]


def _is_gcash_at_invalid_response(status_code: int, body_text: str) -> bool:
    text = re.sub(r"\s+", " ", str(body_text or "")).strip().lower()
    if int(status_code or 0) == 401:
        return True
    return any(marker in text for marker in _GCASH_AT_INVALID_MARKERS)


def preflight_gcash_access_token(chatgpt: Any, log: Any | None = None) -> dict[str, Any]:
    """Check AT health without mistaking proxy failures for invalid credentials.

    Only an explicit authentication failure is terminal. A 400/403 or transport
    error can come from the proxy gateway, Cloudflare, or an incomplete browser
    context, so the caller is allowed to continue to the authoritative Checkout
    request and classify the failure there.
    """

    def emit(message: str) -> None:
        if log:
            log(message)

    path = "/backend-api/me"
    headers = dict(getattr(chatgpt, "headers", {}) or {})
    device_id = str(
        headers.get("oai-device-id")
        or headers.get("OAI-Device-Id")
        or ""
    ).strip()
    emit("GCash 阶段[页面暖身]: 使用同一 PH 代理预热 ChatGPT 页面与 Cookie.")
    try:
        _warmup_gcash_chatgpt_page(chatgpt, device_id=device_id, log=emit)
    except Exception as exc:
        # 页面暖身是增强项，失败时仍继续做 /me 预检；真正的 checkout
        # 失败仍由上游响应决定，不能把暖身失败伪装成成功。
        emit(f"GCash 阶段[页面暖身]: 预热失败，继续预检：{short_error(str(exc))}")
    headers.update({
        "Accept": "application/json",
        "Referer": "https://chatgpt.com/",
        "x-openai-target-path": path,
        "x-openai-target-route": path,
    })
    emit("GCash 阶段[Token预检]: 校验 ChatGPT access token 是否有效.")
    try:
        response = chatgpt.get(
            "https://chatgpt.com/backend-api/me",
            headers=headers,
            timeout=min(CHATGPT_TIMEOUT, 20),
        )
    except Exception as exc:
        detail = short_error(str(exc))
        emit(
            "GCash 阶段[Token预检]: /me 网络失败，"
            f"不判定 AT 失效，继续尝试 Checkout：{detail}"
        )
        return {
            "ok": False,
            "kind": "transport_error",
            "http_status": 0,
            "error": detail,
        }

    status_code = int(getattr(response, "status_code", 0) or 0)
    body_text = _response_text(response)
    if _is_gcash_at_invalid_response(status_code, body_text):
        raise GCashExtractError(
            f"GCASH_AT_INVALID: /me HTTP {status_code}: {short_error(body_text)}"
        )
    if status_code >= 400:
        detail = short_error(body_text)
        emit(
            "GCash 阶段[Token预检]: "
            f"/me HTTP {status_code} 非明确认证失败，不提前终止，继续尝试 Checkout：{detail}"
        )
        return {
            "ok": False,
            "kind": "upstream_or_proxy_error",
            "http_status": status_code,
            "error": detail,
        }
    emit("GCash 阶段[Token预检]: ChatGPT access token 有效.")
    return {
        "ok": True,
        "kind": "authenticated",
        "http_status": status_code,
    }


def _should_fallback_direct_promo_checkout(exc: Exception) -> bool:
    """Use the older split update path only when direct promo checkout failed at checkout shape/HTTP level."""
    text = re.sub(r"\s+", " ", str(exc or "")).strip().lower()
    if not text:
        return False
    if (
        "http 401" in text
        or "gcash_at_invalid" in text
        or "token_invalidated" in text
        or "unusual activity" in text
        or "try again later" in text
    ):
        return False
    return (
        "checkout 创建失败" in text
        or "checkout 响应缺少 cs_id" in text
        or "checkout response missing" in text
    )


def create_checkout(
    chatgpt: Any,
    promo_mode: str = "campaign",
) -> dict[str, Any]:
    """创建 ChatGPT checkout session，PH/PHP。"""
    body: dict[str, Any] = {
        "entry_point": "all_plans_pricing_modal",
        "plan_name": "chatgptplusplan",
        "billing_details": {
            "country": "PH",
            "currency": "PHP",
        },
        "cancel_url": "https://chatgpt.com/",
        "checkout_ui_mode": "custom",
        "check_card_proxy": True,
    }
    if promo_mode in {"query", "campaign"}:
        body["promo_campaign"] = {
            "promo_campaign_id": PLUS_TRIAL_PROMO_ID,
            "is_coupon_from_query_param": promo_mode == "query",
        }
    elif promo_mode == "coupon":
        body["coupon"] = PLUS_TRIAL_PROMO_ID
    elif promo_mode == "code":
        body["promotion_code"] = PLUS_TRIAL_PROMO_ID
    elif promo_mode == "none":
        # GCash 分流流程需要先用 Pool 1 创建纯 PH/PHP 订单，再由
        # Pool 2 独立执行 checkout/update。避免在 Pool 1 出口提前做优惠
        # 判定，导致 PH 出口无优惠或 TR 出口账单国家不一致。
        pass
    elif promo_mode == "off":
        trial_days = os.environ.get("PP_TRIAL_DAYS", "30").strip()
        if trial_days and trial_days != "0":
            body["subscription_data"] = {"trial_period_days": int(trial_days)}
    # 官网 checkout 首次建单不显式提交 payment_method_types；
    # GCash 可用性以后续 checkout_state/taxes 返回的 custom_payment_methods 为准。
    referer = (
        f"https://chatgpt.com/?promo_campaign={PLUS_TRIAL_PROMO_ID}"
        if "promo_campaign" in body
        else "https://chatgpt.com/"
    )
    headers = {
        "Referer": referer,
        "Origin": "https://chatgpt.com",
        "Accept": "*/*",
        "Content-Type": "application/json",
        "priority": "u=1, i",
        "x-openai-target-path": "/backend-api/payments/checkout",
        "x-openai-target-route": "/backend-api/payments/checkout",
    }
    session_headers = getattr(chatgpt, "headers", {}) or {}
    device_id = str(
        session_headers.get("oai-device-id")
        or session_headers.get("OAI-Device-Id")
        or ""
    ).strip()
    user_agent = str(session_headers.get("User-Agent") or DEFAULT_USER_AGENT).strip()
    if device_id and _session_bearer_token(chatgpt):
        try:
            sentinel_token = build_sentinel_token(
                _session_bearer_token(chatgpt),
                device_id,
                user_agent,
                chatgpt,
                flow="chatgpt_checkout",
                page_url=referer,
            )
            if sentinel_token:
                headers["openai-sentinel-token"] = sentinel_token
                so_token = str(getattr(chatgpt, "_gcash_sentinel_so_token", "") or "")
                if so_token:
                    headers["openai-sentinel-so-token"] = so_token
        except Exception:
            # 保留原有 checkout 路径；若本地 Node/SDK 不可用，不能把
            # “证明生成失败”误报成账号失效。
            pass
    response = chatgpt.post(
        "https://chatgpt.com/backend-api/payments/checkout",
        json=body,
        headers=headers,
        timeout=CHATGPT_TIMEOUT,
    )
    if response.status_code >= 400:
        body_text = response.text[:500] if response.text else ""
        raise GCashExtractError(f"checkout 创建失败: HTTP {response.status_code}: {body_text}")

    data = response.json() or {}
    cs_id = data.get("checkout_session_id") or data.get("session_id") or data.get("id")
    cs_id = str(cs_id or "").strip()
    if not cs_id:
        raise GCashExtractError(f"checkout 响应缺少 cs_id: {data}")

    # 提取 processor_entity 和 stripe publishable key
    processor_entity = _extract_processor_entity(data)
    stripe_pk = _extract_stripe_publishable_key(data)
    customer_session_secret = _extract_customer_session_client_secret(data)
    return {
        "cs_id": str(cs_id),
        "processor_entity": processor_entity,
        "stripe_publishable_key": stripe_pk,
        "publishable_key": stripe_pk,
        "customer_session_client_secret": customer_session_secret,
        "billing_country": "PH",
        "currency": "PHP",
        "checkout_provider": data.get("checkout_provider"),
        "promo_campaign": data.get("promo_campaign"),
        "payment_method_types": data.get("payment_method_types"),
        "custom_payment_methods": data.get("custom_payment_methods"),
        "custom_payment_method_data": data.get("custom_payment_method_data"),
        "billing_details": data.get("billing_details"),
        "checkout_state": data.get("checkout_state"),
        "raw_checkout": data,
    }



def apply_gcash_promotion_update(
    promo_update_chatgpt: Any,
    *,
    cs_id: str,
    processor_entity: str,
    promo_mode: str,
    emit: Callable[[str], None],
) -> dict[str, Any]:
    """Apply the GCash trial promotion through Pool 2 checkout/update only."""

    if promo_mode == "off":
        return {}

    emit("GCash 阶段[优惠更新]: 使用代理池 2 请求 payments/checkout/update.")
    update_url = "https://chatgpt.com/backend-api/payments/checkout/update"
    promo_update_chatgpt.headers["x-openai-target-path"] = "/backend-api/payments/checkout/update"
    promo_update_chatgpt.headers["x-openai-target-route"] = "/backend-api/payments/checkout/update"
    promo_update_chatgpt.headers["Referer"] = f"https://chatgpt.com/checkout/{processor_entity}/{cs_id}"
    update_body = {
        "checkout_session_id": cs_id,
        "processor_entity": processor_entity,
        "plan_name": "chatgptplusplan",
        "price_interval": "month",
        "seat_quantity": 1,
        "promo_campaign": {
            "promo_campaign_id": PLUS_TRIAL_PROMO_ID,
            "is_coupon_from_query_param": promo_mode == "query",
        },
    }
    resp_update = promo_update_chatgpt.post(update_url, json=update_body, timeout=CHATGPT_TIMEOUT)
    emit(diagnostic_summary("GCash DIAG[promo_update_response]", None, status_code=resp_update.status_code))
    try:
        update_payload = resp_update.json() or {}
    except Exception:
        update_payload = {}

    if resp_update.status_code >= 400:
        detail = resp_update.text[:500] if resp_update.text else ""
        emit(f"GCash 阶段[优惠更新]: checkout/update 未确认成功: {detail}")
        emit(
            "GCash 自动优惠兼容：不再仅因 checkout/update 未成功失败；"
            "继续由后续 taxes/final 的明确 0 金额 + GCash method + verify 短链 + 有效授权跳转严格判定。"
        )
        return update_payload if isinstance(update_payload, dict) else {}

    failure_detail = _payload_failure_detail(update_payload)
    if failure_detail:
        emit(f"GCash 阶段[优惠更新]: checkout/update 返回未成功状态: {failure_detail}")
        emit(
            "GCash 自动优惠兼容：账号可能已自带优惠，继续执行最终严格校验；"
            "若后续金额不是 0 或证据不足仍会失败。"
        )
        return update_payload if isinstance(update_payload, dict) else {}

    emit("GCash 阶段[优惠更新]: checkout/update 成功.")
    emit(diagnostic_summary("GCash DIAG[promo_update_data]", update_payload, status_code=resp_update.status_code))
    amount, amount_source = _explicit_openai_amount(update_payload)
    if _amount_is_nonzero(amount):
        raise GCashExtractError(
            "GCASH_PROMO_AMOUNT_NONZERO: checkout/update 已返回成功，"
            f"但应付金额仍非 0：amount={amount}, source={amount_source}"
        )
    return update_payload

def _extract_processor_entity(data: Any) -> str:
    if not isinstance(data, dict):
        return ""
    direct = data.get("processor_entity") or data.get("processorEntity")
    if direct:
        return str(direct).strip()
    for key in ("checkout_session", "session", "checkout", "data"):
        nested = data.get(key)
        if isinstance(nested, dict):
            found = _extract_processor_entity(nested)
            if found:
                return found
    return ""


def _extract_stripe_publishable_key(data: Any) -> str:
    if isinstance(data, str):
        match = re.search(r"pk_live_[A-Za-z0-9]+", data)
        return match.group(0) if match else ""
    if isinstance(data, dict):
        for key in ("stripe_publishable_key", "publishable_key", "publishableKey", "stripePublishableKey", "key"):
            found = _extract_stripe_publishable_key(data.get(key))
            if found:
                return found
        for item in data.values():
            found = _extract_stripe_publishable_key(item)
            if found:
                return found
    if isinstance(data, list):
        for item in data:
            found = _extract_stripe_publishable_key(item)
            if found:
                return found
    return ""


def _extract_customer_session_client_secret(data: Any) -> str:
    if isinstance(data, str):
        match = re.search(r"cuss_secret_[A-Za-z0-9_=-]+", data)
        return match.group(0) if match else ""
    if isinstance(data, dict):
        for key in (
            "customer_session_client_secret",
            "customerSessionClientSecret",
            "customer_session_secret",
            "customerSessionSecret",
        ):
            found = _extract_customer_session_client_secret(data.get(key))
            if found:
                return found
        for item in data.values():
            found = _extract_customer_session_client_secret(item)
            if found:
                return found
    if isinstance(data, list):
        for item in data:
            found = _extract_customer_session_client_secret(item)
            if found:
                return found
    return ""


# ---------------------------------------------------------------------------
# Stripe 交互
# ---------------------------------------------------------------------------


def stripe_init(
    cs_id: str,
    stripe_pk: str,
    proxy: str = "",
    user_agent: str = "",
    customer_session_client_secret: str = "",
    fingerprint_profile: dict[str, Any] | None = None,
    log: Any | None = None,
) -> tuple[Any, dict[str, Any]]:
    """初始化 Stripe payment page。返回 (stripe_session, init_payload)。"""
    fingerprint = dict(fingerprint_profile or {}) if isinstance(fingerprint_profile, dict) else {}
    browser_locale, elements_locale = locale_parts(
        _fingerprint_header_value(fingerprint, "oai_language", "language", default="en-PH")
    )
    client_stripe_js_id = str(uuid.uuid4())
    client_elements_session_id = f"elements_session_{uuid.uuid4().hex[:11]}"
    stripe = new_session(
        impersonate=_fingerprint_header_value(fingerprint, "tls_impersonate", default="chrome136"),
        log=log,
    )
    stripe.headers.update({
        "User-Agent": user_agent or _fingerprint_header_value(fingerprint, "ua", "user_agent") or DEFAULT_USER_AGENT,
        "Accept-Language": _fingerprint_header_value(fingerprint, "accept_language", "locale", default="en-PH,en;q=0.9"),
    })
    set_proxy_url(stripe, proxy)
    body = {
        "browser_locale": browser_locale,
        "browser_timezone": _fingerprint_header_value(fingerprint, "timezone", "timezone_id", default="Asia/Manila"),
        "elements_session_client[client_betas][0]": "custom_checkout_server_updates_1",
        "elements_session_client[client_betas][1]": "custom_checkout_manual_approval_1",
        "elements_session_client[elements_init_source]": "custom_checkout",
        "elements_session_client[referrer_host]": "chatgpt.com",
        "elements_session_client[stripe_js_id]": client_stripe_js_id,
        "elements_session_client[session_id]": client_elements_session_id,
        "elements_session_client[locale]": elements_locale,
        "elements_session_client[is_aggregation_expected]": "false",
        "elements_options_client[saved_payment_method][enable_save]": "never",
        "elements_options_client[saved_payment_method][enable_redisplay]": "never",
        "key": stripe_pk,
        "_stripe_version": STRIPE_VERSION_FULL,
    }
    init_url = f"https://api.stripe.com/v1/payment_pages/{cs_id}/init"
    response = stripe.post(init_url, data=body, timeout=DEFAULT_TIMEOUT)
    if response.status_code >= 400:
        raise GCashExtractError(f"Stripe init 失败: HTTP {response.status_code}: {response.text[:500]}")
    payload = response.json() or {}
    payload["client_stripe_js_id"] = client_stripe_js_id
    payload["client_elements_session_id"] = client_elements_session_id
    customer_secret = str(customer_session_client_secret or "").strip()
    if customer_secret:
        payload["customer_session_client_secret"] = customer_secret
        elements_payload = stripe_elements_session(
            stripe,
            cs_id,
            stripe_pk,
            customer_secret,
            payload,
            stripe_js_id=client_stripe_js_id,
            elements_locale=elements_locale,
        )
        payload["elements_session"] = elements_payload
        real_session_id = str(elements_payload.get("session_id") or elements_payload.get("id") or "").strip()
        if real_session_id:
            payload["client_elements_session_id"] = real_session_id
        config_id = str(elements_payload.get("config_id") or "").strip()
        if config_id:
            payload["client_elements_session_config_id"] = config_id
        method_types = [
            str(item.get("type") or "").strip()
            for item in elements_payload.get("payment_method_specs", [])
            if isinstance(item, dict) and str(item.get("type") or "").strip()
        ]
        if method_types:
            payload["payment_method_types"] = method_types
    return stripe, payload


def stripe_elements_session(
    stripe: Any,
    cs_id: str,
    stripe_pk: str,
    customer_session_client_secret: str,
    init_payload: dict[str, Any],
    *,
    stripe_js_id: str,
    elements_locale: str,
    custom_payment_method_type_id: str = "",
) -> dict[str, Any]:
    """Best-effort Stripe Elements Session handshake used by custom wallets."""
    amount = expected_amount(init_payload)
    currency = str(init_payload.get("currency") or "php").lower()
    custom_payment_method_type_id = str(custom_payment_method_type_id or "").strip()
    params = {
        "customer_session_client_secret": str(customer_session_client_secret or "").strip(),
        "client_betas[0]": "custom_checkout_server_updates_1",
        "client_betas[1]": "custom_checkout_manual_approval_1",
        "deferred_intent[mode]": "subscription",
        "deferred_intent[amount]": str(amount or "0"),
        "deferred_intent[currency]": currency,
        # GCash 是 OpenAI/Stripe 的 custom payment method，不是 Stripe 原生
        # payment_method_types 中的 gcash。官网 Elements 请求仍以 link/card
        # 作为 deferred intent 类型，并通过 custom_payment_methods 单独传入 cpmt_*。
        "deferred_intent[payment_method_types][0]": "link",
        "deferred_intent[payment_method_types][1]": "card",
        "currency": currency,
        "key": stripe_pk,
        "_stripe_version": STRIPE_VERSION_FULL,
        "elements_init_source": "stripe.elements",
        "referrer_host": "chatgpt.com",
        "stripe_js_id": stripe_js_id,
        "locale": elements_locale,
        "type": "deferred_intent",
    }
    if custom_payment_method_type_id:
        params["custom_payment_methods[0]"] = custom_payment_method_type_id
    setup_future_usage = os.environ.get("GCASH_STRIPE_ELEMENTS_SETUP_FUTURE_USAGE", "").strip()
    if custom_payment_method_type_id:
        params["deferred_intent[setup_future_usage]"] = setup_future_usage or "off_session"
    elif setup_future_usage:
        params["deferred_intent[setup_future_usage]"] = setup_future_usage
    try:
        response = stripe.get(
            "https://api.stripe.com/v1/elements/sessions",
            params=params,
            timeout=DEFAULT_TIMEOUT,
        )
    except Exception as exc:
        return {"_error": short_error(str(exc))}
    try:
        payload = response.json() or {}
    except Exception:
        payload = {"_raw": str(getattr(response, "text", "") or "")[:500]}
    if not isinstance(payload, dict):
        payload = {"payload": payload}
    payload["_http_status"] = int(getattr(response, "status_code", 0) or 0)
    return payload


def stripe_context(cs_id: str, init_payload: dict[str, Any]) -> dict[str, Any]:
    _, elements_locale = locale_parts("en-PH")
    return {
        "stripe_js_id": str(
            init_payload.get("client_stripe_js_id")
            or init_payload.get("stripe_js_id")
            or uuid.uuid4()
        ),
        "elements_session_id": str(
            init_payload.get("client_elements_session_id")
            or init_payload.get("elements_session_id")
            or f"elements_session_{uuid.uuid4().hex[:11]}"
        ),
        "elements_session_config_id": str(
            init_payload.get("client_elements_session_config_id")
            or init_payload.get("elements_session_config_id")
            or init_payload.get("config_id")
            or uuid.uuid4()
        ),
        "config_id": init_payload.get("config_id") or "",
        "init_checksum": init_payload.get("init_checksum") or "",
        "currency": str(init_payload.get("currency") or "php").lower(),
        "checkout_amount": expected_amount(init_payload),
        "locale": elements_locale,
    }


def expected_amount(init_payload: Any) -> str:
    if not isinstance(init_payload, dict):
        return "0"
    total_summary = init_payload.get("total_summary")
    if isinstance(total_summary, dict) and total_summary.get("due") is not None:
        return str(total_summary.get("due"))
    invoice = init_payload.get("invoice")
    if isinstance(invoice, dict) and invoice.get("amount_due") is not None:
        return str(invoice.get("amount_due"))
    line_items = init_payload.get("line_items")
    if isinstance(line_items, list):
        total = 0
        found = False
        for item in line_items:
            if isinstance(item, dict) and item.get("amount") is not None:
                try:
                    total += int(item.get("amount") or 0)
                    found = True
                except Exception:
                    pass
        if found:
            return str(total)
    return "0"


def ensure_zero_amount(init_payload: dict[str, Any]) -> None:
    amount = expected_amount(init_payload)
    try:
        amount_int = int(str(amount or "0"))
    except Exception:
        amount_int = 0
    if amount_int != 0:
        currency = str(init_payload.get("currency") or "PHP").upper()
        raise GCashExtractError(f"checkout 金额非零: {currency} {amount_int / 100:.2f}")


def stripe_create_payment_method(
    stripe: Any,
    cs_id: str,
    stripe_pk: str,
    billing: dict[str, str],
    ctx: dict[str, Any],
    custom_payment_method_type_id: str = "",
) -> str:
    """创建 Stripe payment method；GCash custom flow 优先使用 type=custom。"""
    runtime_version = DEFAULT_STRIPE_RUNTIME_VERSION
    cpm_id = str(custom_payment_method_type_id or "").strip()
    body = {
        "billing_details[name]": billing.get("name") or "Juan Dela Cruz",
        "billing_details[email]": billing.get("email") or "buyer@example.com",
        "billing_details[address][country]": billing.get("country") or "PH",
        "billing_details[address][line1]": billing.get("line1") or "123 Rizal Avenue",
        "billing_details[address][city]": billing.get("city") or "Manila",
        "billing_details[address][postal_code]": billing.get("postal_code") or "1000",
        "billing_details[address][state]": billing.get("state") or "NCR",
        "type": "custom" if cpm_id else "gcash",
        "payment_user_agent": f"stripe.js/{runtime_version}; stripe-js-v3/{runtime_version}; payment-element; deferred-intent",
        "referrer": "https://chatgpt.com",
        "time_on_page": str(random.randint(25000, 55000)),
        "client_attribution_metadata[checkout_session_id]": cs_id,
        "client_attribution_metadata[client_session_id]": ctx["stripe_js_id"],
        "client_attribution_metadata[checkout_config_id]": ctx.get("config_id") or "",
        "client_attribution_metadata[elements_session_id]": ctx["elements_session_id"],
        "client_attribution_metadata[elements_session_config_id]": ctx["elements_session_config_id"],
        "client_attribution_metadata[merchant_integration_source]": "elements",
        "client_attribution_metadata[merchant_integration_subtype]": "payment-element",
        "client_attribution_metadata[merchant_integration_version]": "2021",
        "client_attribution_metadata[payment_intent_creation_flow]": "deferred",
        "client_attribution_metadata[payment_method_selection_flow]": "automatic",
        "client_attribution_metadata[merchant_integration_additional_elements][0]": "payment",
        "client_attribution_metadata[merchant_integration_additional_elements][1]": "address",
        "key": stripe_pk,
        "_stripe_version": STRIPE_VERSION_FULL,
    }
    if cpm_id:
        body["custom[type]"] = cpm_id
    response = stripe.post(
        "https://api.stripe.com/v1/payment_methods",
        data=body,
        timeout=DEFAULT_TIMEOUT,
    )
    if response.status_code >= 400:
        raise GCashExtractError(f"Stripe payment_methods 失败: HTTP {response.status_code}: {response.text[:500]}")
    pm_id = str((response.json() or {}).get("id") or "")
    if not pm_id.startswith("pm_"):
        raise GCashExtractError(f"Stripe payment_methods 响应异常: {response.text[:300]}")
    return pm_id


def stripe_context_from_elements(
    cs_id: str,
    elements_payload: dict[str, Any],
    *,
    stripe_js_id: str,
) -> dict[str, Any]:
    _, elements_locale = locale_parts("en-PH")
    return {
        "stripe_js_id": stripe_js_id,
        "elements_session_id": str(
            elements_payload.get("session_id")
            or elements_payload.get("id")
            or f"elements_session_{uuid.uuid4().hex[:11]}"
        ),
        "elements_session_config_id": str(
            elements_payload.get("config_id")
            or elements_payload.get("elements_session_config_id")
            or uuid.uuid4()
        ),
        "config_id": str(elements_payload.get("config_id") or ""),
        "init_checksum": "",
        "currency": "php",
        "checkout_amount": "0",
        "locale": elements_locale,
    }


def _openai_elements_session(
    cs_id: str,
    stripe_pk: str,
    customer_session_client_secret: str,
    *,
    custom_payment_method_type_id: str = "",
    proxy: str = "",
    user_agent: str = "",
    fingerprint_profile: dict[str, Any] | None = None,
    log: Any | None = None,
) -> tuple[Any, dict[str, Any], str]:
    """Create a Stripe Elements session using the browser-compatible request shape."""
    fingerprint = dict(fingerprint_profile or {}) if isinstance(fingerprint_profile, dict) else {}
    stripe_js_id = str(uuid.uuid4())
    _, elements_locale = locale_parts(
        _fingerprint_header_value(fingerprint, "oai_language", "language", default="en-PH")
    )
    stripe = new_session(
        impersonate=_fingerprint_header_value(fingerprint, "tls_impersonate", default="chrome136"),
        log=log,
    )
    stripe.headers.update({
        "User-Agent": user_agent or _fingerprint_header_value(fingerprint, "ua", "user_agent") or DEFAULT_USER_AGENT,
        "Accept-Language": _fingerprint_header_value(
            fingerprint,
            "accept_language",
            "locale",
            default="en-PH,en;q=0.9",
        ),
        "Origin": "https://js.stripe.com",
        "Referer": "https://js.stripe.com/",
    })
    set_proxy_url(stripe, proxy)
    elements_payload = stripe_elements_session(
        stripe,
        cs_id,
        stripe_pk,
        customer_session_client_secret,
        {"currency": "php", "total_summary": {"due": 0}},
        stripe_js_id=stripe_js_id,
        elements_locale=elements_locale,
        custom_payment_method_type_id=custom_payment_method_type_id,
    )
    status = int(elements_payload.get("_http_status") or 0)
    if status and status >= 400:
        raise GCashExtractError(
            f"Stripe elements/sessions 失败: HTTP {status}: {short_error(str(elements_payload), 500)}"
        )
    if elements_payload.get("_error"):
        raise GCashExtractError(f"Stripe elements/sessions 异常: {elements_payload.get('_error')}")
    return stripe, elements_payload, stripe_js_id


def stripe_create_openai_custom_payment_method(
    cs_id: str,
    stripe_pk: str,
    customer_session_client_secret: str,
    custom_payment_method_type_id: str,
    billing: dict[str, str],
    *,
    proxy: str = "",
    user_agent: str = "",
    fingerprint_profile: dict[str, Any] | None = None,
    log: Any | None = None,
) -> str:
    """Create pm_* for OpenAI custom checkout through Stripe custom[type]=cpmt_*."""
    fingerprint = dict(fingerprint_profile or {}) if isinstance(fingerprint_profile, dict) else {}
    stripe, elements_payload, stripe_js_id = _openai_elements_session(
        cs_id,
        stripe_pk,
        customer_session_client_secret,
        custom_payment_method_type_id=custom_payment_method_type_id,
        proxy=proxy,
        user_agent=user_agent,
        fingerprint_profile=fingerprint,
        log=log,
    )
    ctx = stripe_context_from_elements(cs_id, elements_payload, stripe_js_id=stripe_js_id)
    return stripe_create_payment_method(
        stripe,
        cs_id,
        stripe_pk,
        billing,
        ctx,
        custom_payment_method_type_id=custom_payment_method_type_id,
    )


def stripe_confirm(
    stripe: Any,
    cs_id: str,
    pm_id: str,
    stripe_pk: str,
    init_payload: dict[str, Any],
    ctx: dict[str, Any],
    checkout: dict[str, Any],
    stripe_hosted_url: str,
) -> dict[str, Any]:
    """Stripe confirm 提交支付。"""
    return_url = _stripe_confirm_return_url(cs_id, checkout, stripe_hosted_url)
    runtime_version = DEFAULT_STRIPE_RUNTIME_VERSION
    body = {
        "guid": uuid.uuid4().hex,
        "muid": uuid.uuid4().hex,
        "sid": uuid.uuid4().hex,
        "payment_method": pm_id,
        "init_checksum": str(init_payload.get("init_checksum") or ctx.get("init_checksum") or ""),
        "version": runtime_version,
        "expected_amount": str(ctx.get("checkout_amount") or expected_amount(init_payload)),
        "expected_payment_method_type": "gcash",
        "return_url": return_url,
        "elements_session_client[session_id]": ctx["elements_session_id"],
        "elements_session_client[locale]": str(ctx.get("locale") or "en-PH"),
        "elements_session_client[referrer_host]": "chatgpt.com",
        "elements_session_client[is_aggregation_expected]": "false",
        "elements_session_client[elements_init_source]": "custom_checkout",
        "elements_session_client[stripe_js_id]": ctx["stripe_js_id"],
        "elements_session_client[client_betas][0]": "custom_checkout_server_updates_1",
        "elements_session_client[client_betas][1]": "custom_checkout_manual_approval_1",
        "elements_options_client[saved_payment_method][enable_save]": "never",
        "elements_options_client[saved_payment_method][enable_redisplay]": "never",
        "client_attribution_metadata[client_session_id]": ctx["stripe_js_id"],
        "client_attribution_metadata[checkout_session_id]": cs_id,
        "client_attribution_metadata[checkout_config_id]": ctx.get("config_id") or "",
        "client_attribution_metadata[elements_session_id]": ctx["elements_session_id"],
        "client_attribution_metadata[elements_session_config_id]": ctx["elements_session_config_id"],
        "client_attribution_metadata[merchant_integration_source]": "checkout",
        "client_attribution_metadata[merchant_integration_subtype]": "payment-element",
        "client_attribution_metadata[merchant_integration_version]": "custom",
        "client_attribution_metadata[payment_intent_creation_flow]": "deferred",
        "client_attribution_metadata[payment_method_selection_flow]": "automatic",
        "client_attribution_metadata[merchant_integration_additional_elements][0]": "payment",
        "client_attribution_metadata[merchant_integration_additional_elements][1]": "address",
        "consent[terms_of_service]": "accepted",
        "key": stripe_pk,
        "_stripe_version": STRIPE_VERSION_FULL,
    }
    confirm_url = f"https://api.stripe.com/v1/payment_pages/{cs_id}/confirm"
    response = stripe.post(confirm_url, data=body, timeout=DEFAULT_TIMEOUT)
    if response.status_code >= 400:
        detail = response.text[:500]
        try:
            payload = response.json() or {}
            error = payload.get("error") if isinstance(payload, dict) else {}
            if isinstance(error, dict):
                summary = {
                    "code": error.get("code") or "",
                    "type": error.get("type") or "",
                    "message": error.get("message") or "",
                    "confirm_error_reason": error.get("confirm_error_reason") or "",
                }
                useful = ", ".join(f"{k}={v}" for k, v in summary.items() if str(v or "").strip())
                if useful:
                    detail = f"{useful}; raw={detail}"
        except Exception:
            pass
        raise GCashExtractError(f"Stripe confirm 失败: {detail}")
    return response.json() or {}


def _processor_entity_for_country(country: str, processor_entity: str = "") -> str:
    entity = str(processor_entity or "").strip()
    if entity:
        return entity
    return "openai_ie"  # PH → openai_ie


def _chatgpt_success_return_url(cs_id: str, processor_entity: str = "") -> str:
    entity = _processor_entity_for_country("PH", processor_entity)
    return f"https://chatgpt.com/checkout/verify?stripe_session_id={cs_id}&processor_entity={entity}&plan_type=plus"


def _stripe_confirm_return_url(
    cs_id: str, checkout: dict[str, Any], stripe_hosted_url: str,
) -> str:
    processor_entity = str(checkout.get("processor_entity") or "").strip() or "openai_ie"
    hosted_url = _to_openai_pay_url(stripe_hosted_url) or (
        f"https://checkout.stripe.com/c/pay/{cs_id}"
        f"?returned_from_redirect=true&ui_mode=custom&return_url="
        f"{quote(_chatgpt_success_return_url(cs_id, processor_entity), safe='')}"
    )
    if "pay.openai.com/" in hosted_url or "checkout.stripe.com/" in hosted_url:
        parsed = urlsplit(hosted_url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query.setdefault(
            "success_return_url",
            _chatgpt_success_return_url(cs_id, processor_entity),
        )
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment))
    return hosted_url


def _to_openai_pay_url(stripe_hosted_url: str) -> str:
    url = str(stripe_hosted_url or "").strip()
    if not url:
        return ""
    if url.startswith("https://checkout.stripe.com"):
        return "https://pay.openai.com" + url[len("https://checkout.stripe.com"):]
    parsed = urlsplit(url)
    if parsed.netloc.lower() == "checkout.stripe.com":
        return urlunsplit((parsed.scheme or "https", "pay.openai.com", parsed.path, parsed.query, parsed.fragment))
    return url


# ---------------------------------------------------------------------------
# ChatGPT approve
# ---------------------------------------------------------------------------


def _session_bearer_token(session: Any) -> str:
    authorization = str((getattr(session, "headers", {}) or {}).get("Authorization") or "").strip()
    if authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return ""


def _response_header_summary(response: Any) -> str:
    headers = getattr(response, "headers", {}) or {}
    wanted = (
        "x-request-id",
        "openai-processing-ms",
        "cf-ray",
        "server",
        "date",
        "content-type",
    )
    parts: list[str] = []
    for key in wanted:
        try:
            value = str(headers.get(key) or headers.get(key.title()) or "").strip()
        except Exception:
            value = ""
        if value:
            parts.append(f"{key}={short_error(value, 120)}")
    return "; ".join(parts)


def _checkout_page_route_headers(
    processor_entity: str,
    cs_id: str,
    *,
    accept: str = "application/json",
) -> dict[str, str]:
    """Headers matching the signed-in ChatGPT checkout page route.

    The OpenAI custom checkout endpoints are normally called while the browser
    is on ``/checkout/[processorEntity]/[checkoutSessionId]``.  Keeping this
    route identity consistent across state/confirm/start/approve makes the
    protocol closer to the working web flow and avoids classifying backend API
    calls as detached automation.
    """

    entity = str(processor_entity or "openai_llc").strip() or "openai_llc"
    checkout_page = f"https://chatgpt.com/checkout/{entity}/{cs_id}"
    return {
        "Accept": accept,
        "Referer": checkout_page,
        "x-openai-target-path": f"/checkout/{entity}/{cs_id}",
        "x-openai-target-route": "/checkout/[processorEntity]/[checkoutSessionId]",
        "OAI-Chat-Web-Route": "/checkout/[processorEntity]/[checkoutSessionId]",
    }


def _decode_response_payload(response: Any) -> dict[str, Any]:
    try:
        payload = response.json() or {}
    except Exception:
        payload = {"raw": str(getattr(response, "text", "") or "")[:1000]}
    return payload if isinstance(payload, dict) else {"payload": payload}


def chatgpt_approve(
    chatgpt: Any,
    cs_id: str,
    checkout: dict[str, Any],
    log: Any | None = None,
) -> None:
    processor_entity = str(checkout.get("processor_entity") or "").strip() or "openai_ie"
    session_headers = getattr(chatgpt, "headers", {}) or {}
    access_token = _session_bearer_token(chatgpt)
    device_id = str(
        session_headers.get("oai-device-id")
        or session_headers.get("OAI-Device-Id")
        or uuid.uuid4()
    ).strip()
    user_agent = str(session_headers.get("User-Agent") or DEFAULT_USER_AGENT).strip() or DEFAULT_USER_AGENT

    def emit(message: str) -> None:
        if log:
            log(message)

    try:
        _warmup_gcash_chatgpt_page(
            chatgpt,
            device_id=device_id,
            page_url=f"https://chatgpt.com/checkout/{processor_entity}/{cs_id}",
            log=emit,
        )
    except Exception as exc:
        emit(f"ChatGPT checkout 页面暖身失败，继续 approve：{short_error(str(exc))}")

    try:
        chatgpt.post(
            "https://chatgpt.com/backend-api/sentinel/ping",
            json={},
            headers={
                "Referer": "https://chatgpt.com/",
                "x-openai-target-path": "/backend-api/sentinel/ping",
                "x-openai-target-route": "/backend-api/sentinel/ping",
            },
            timeout=CHATGPT_TIMEOUT,
        )
    except Exception:
        pass
    approve_url = "https://chatgpt.com/backend-api/payments/checkout/approve"
    approve_body = {"checkout_session_id": cs_id, "processor_entity": processor_entity}
    base_approve_headers = {
        "OAI-Device-Id": device_id,
        "oai-device-id": device_id,
        "User-Agent": user_agent,
        "OAI-Telemetry": "[1,null]",
        "x-openai-target-path": "/backend-api/payments/checkout/approve",
        "x-openai-target-route": "/backend-api/payments/checkout/approve",
    }
    base_approve_headers.update(_checkout_page_route_headers(processor_entity, cs_id))
    # approve 本身仍然是 backend-api 动作，但保留 checkout 页面路由。
    base_approve_headers["x-openai-target-path"] = "/backend-api/payments/checkout/approve"
    base_approve_headers["x-openai-target-route"] = "/backend-api/payments/checkout/approve"
    if access_token:
        emit("ChatGPT approve 将按工作流刷新 Sentinel token 后提交。")
    else:
        emit("ChatGPT approve Sentinel token 跳过：session 缺少 Authorization Bearer。")
    max_attempts_raw = os.environ.get("GCASH_APPROVE_RETRY_MAX", "8").strip() or "8"
    try:
        max_attempts = int(max_attempts_raw)
    except ValueError:
        max_attempts = 8
    max_attempts = max(1, min(max_attempts, 8))
    last_response: Any | None = None
    last_payload: dict[str, Any] = {}
    last_result = ""
    for attempt in range(1, max_attempts + 1):
        approve_headers = dict(base_approve_headers)
        if access_token:
            try:
                token_value = build_sentinel_token(access_token, device_id, user_agent, chatgpt)
                approve_headers["openai-sentinel-token"] = token_value
                approve_headers["OpenAI-Sentinel-Token"] = token_value
                so_token = str(getattr(chatgpt, "_gcash_sentinel_so_token", "") or "")
                if so_token:
                    approve_headers["openai-sentinel-so-token"] = so_token
                    approve_headers["OpenAI-Sentinel-SO-Token"] = so_token
                emit(f"ChatGPT approve Sentinel token 已生成（{attempt}/{max_attempts}）。")
            except Exception as exc:
                emit(f"ChatGPT approve Sentinel token 生成失败，继续提交以保留上游错误：{short_error(str(exc))}")
        response = chatgpt.post(
            approve_url, json=approve_body, headers=approve_headers, timeout=CHATGPT_TIMEOUT,
        )
        last_response = response
        last_payload = _decode_response_payload(response)
        last_result = str(
            last_payload.get("result")
            or last_payload.get("status")
            or ""
        ).strip().lower()
        if response.status_code < 400 and last_result == "approved":
            if attempt > 1:
                emit(f"ChatGPT approve 第 {attempt}/{max_attempts} 次通过。")
            return
        emit(
            "ChatGPT approve "
            f"第 {attempt}/{max_attempts} 次未通过："
            f"http={response.status_code}, result={last_result or 'empty'}"
        )
        if attempt < max_attempts:
            time.sleep(0.25)

    response = last_response
    status_code = int(getattr(response, "status_code", 0) or 0) if response is not None else 0
    if status_code >= 400:
        headers_summary = _response_header_summary(response)
        try:
            state_summary = diagnostic_summary(
                "GCash DIAG[approve_checkout_state]",
                fetch_openai_checkout_state(chatgpt, cs_id, processor_entity),
            )
        except Exception as exc:
            state_summary = f"checkout_state_error={short_error(str(exc), 180)}"
        detail = _response_text(response) if response is not None else short_error(str(last_payload), 500)
        raise GCashExtractError(
            f"ChatGPT approve 失败: HTTP {status_code}: {detail}; "
            f"headers: {headers_summary or 'none'}; state: {state_summary or 'none'}"
        )
    raise GCashExtractError(
        f"ChatGPT approve 结果异常: {last_result!r}; "
        f"{diagnostic_summary('GCash DIAG[approve_data]', last_payload, status_code=status_code)}"
    )


# ---------------------------------------------------------------------------
# 轮询 redirect URL
# ---------------------------------------------------------------------------


def stripe_payment_page_redirect_url(
    stripe: Any,
    cs_id: str,
    stripe_pk: str,
    ctx: dict[str, Any],
    timeout_seconds: float = 30,
    raise_on_requires_approval: bool = True,
    log: Any | None = None,
) -> str:
    deadline = time.time() + max(1.0, float(timeout_seconds or 30))
    last_err = ""
    params = {
        "elements_session_client[client_betas][0]": "custom_checkout_server_updates_1",
        "elements_session_client[client_betas][1]": "custom_checkout_manual_approval_1",
        "elements_session_client[elements_init_source]": "custom_checkout",
        "elements_session_client[referrer_host]": "chatgpt.com",
        "elements_session_client[session_id]": ctx["elements_session_id"],
        "elements_session_client[stripe_js_id]": ctx["stripe_js_id"],
        "elements_session_client[locale]": str(ctx.get("locale") or "en-PH"),
        "elements_session_client[is_aggregation_expected]": "false",
        "elements_options_client[saved_payment_method][enable_save]": "never",
        "elements_options_client[saved_payment_method][enable_redisplay]": "never",
        "key": stripe_pk,
        "_stripe_version": STRIPE_VERSION_FULL,
    }
    while time.time() < deadline:
        payment_page_url = f"https://api.stripe.com/v1/payment_pages/{cs_id}"
        response = stripe.get(payment_page_url, params=params, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            payload = response.json() or {}
            redirect_url = extract_redirect_to_url(payload)
            if redirect_url:
                return redirect_url
            submission = find_submission_attempt(payload)
            if submission.get("state") == "requires_approval":
                if raise_on_requires_approval:
                    raise StripeRequiresApproval("payment page requires ChatGPT approval")
                time.sleep(1)
                continue
            if submission.get("state") == "failed":
                summary = submission_attempt_summary(submission)
                if is_terminal_submission_failure(submission):
                    raise GCashExtractError(f"Stripe submission 终态失败: {summary}")
        else:
            last_err = f"http {response.status_code}: {response.text[:120]}"
        time.sleep(1)
    raise GCashExtractError(f"轮询 redirect URL 超时: {last_err}")


def redirect_url_after_confirm(
    chatgpt: Any,
    stripe: Any,
    confirm_payload: dict[str, Any],
    cs_id: str,
    stripe_pk: str,
    ctx: dict[str, Any],
    checkout: dict[str, Any],
    log: Any | None = None,
) -> str:
    redirect_url = extract_redirect_to_url(confirm_payload)
    if redirect_url:
        return redirect_url
    submission = find_submission_attempt(confirm_payload)
    if submission.get("state") == "requires_approval":
        if log:
            log("Stripe 要求 ChatGPT approve，正在提交 approve。")
        chatgpt_approve(chatgpt, cs_id, checkout, log=log)
        if log:
            log("ChatGPT approve 已通过，继续轮询 GCash redirect。")
        return stripe_payment_page_redirect_url(
            stripe, cs_id, stripe_pk, ctx,
            timeout_seconds=45, raise_on_requires_approval=False, log=log,
        )
    if submission.get("state") == "failed":
        summary = submission_attempt_summary(submission)
        if is_terminal_submission_failure(submission):
            raise GCashExtractError(f"Stripe submission 终态失败: {summary}")
    try:
        return stripe_payment_page_redirect_url(
            stripe, cs_id, stripe_pk, ctx, timeout_seconds=30, log=log,
        )
    except StripeRequiresApproval:
        if log:
            log("轮询发现 requires_approval，正在提交 ChatGPT approve。")
        chatgpt_approve(chatgpt, cs_id, checkout, log=log)
        if log:
            log("ChatGPT approve 已通过，继续轮询 GCash redirect。")
        return stripe_payment_page_redirect_url(
            stripe, cs_id, stripe_pk, ctx,
            timeout_seconds=45, raise_on_requires_approval=False, log=log,
        )


def resolve_external_redirect(
    stripe: Any,
    redirect_url: str,
    max_hops: int = 5,
) -> str:
    """跟随重定向链直到找到 GCash URL 或到达最大跳数。"""
    current = str(redirect_url or "").strip()
    for _ in range(max(1, int(max_hops or 1))):
        if not current:
            return ""
        if is_gcash_redirect_url(current):
            return current
        try:
            response = stripe.get(current, allow_redirects=False, timeout=DEFAULT_TIMEOUT)
        except Exception:
            return current
        location = str(response.headers.get("Location") or "").strip()
        if location:
            candidate = urljoin(current, location)
            if is_gcash_redirect_url(candidate):
                return candidate
            current = candidate
            continue
        body_urls = collect_urls(getattr(response, "text", "") or "")
        gcash_url = next((item for item in body_urls if is_gcash_redirect_url(item)), "")
        if gcash_url:
            return gcash_url
        meta_url = extract_meta_refresh_url(getattr(response, "text", "") or "", current)
        if meta_url:
            if is_gcash_redirect_url(meta_url):
                return meta_url
            current = meta_url
            continue
        if response.status_code not in (301, 302, 303, 307, 308):
            return current
    return current


def resolve_gcash_verification_redirect(
    chatgpt: Any,
    verification_url: str,
    max_hops: int = 8,
) -> str:
    """Follow ChatGPT verify short link and retain the signed Adyen/GCash URL."""

    current = str(verification_url or "").strip()
    visited: set[str] = set()
    for _ in range(max(1, int(max_hops or 1))):
        if not current or current in visited:
            break
        visited.add(current)
        if _is_valid_openai_gcash_redirect(current):
            return current
        try:
            response = chatgpt.get(
                current,
                headers={"Referer": "https://chatgpt.com/"},
                allow_redirects=False,
                timeout=CHATGPT_TIMEOUT,
            )
        except Exception:
            return ""
        body_url = _pick_preferred_redirect_url(collect_urls(getattr(response, "text", "") or ""))
        if _is_valid_openai_gcash_redirect(body_url):
            return body_url
        location = str(getattr(response, "headers", {}).get("Location") or "").strip()
        if not location:
            break
        current = urljoin(current, location)
    return ""


def extract_redirect_url_from_json(data: Any) -> str:
    return _pick_preferred_redirect_url(collect_urls(data))


def extract_meta_refresh_url(html: str, base_url: str = "") -> str:
    """Extract URL from HTML meta refresh without executing page scripts."""
    source = str(html or "")
    if not source:
        return ""
    meta_re = re.compile(
        r"<meta\b[^>]*http-equiv\s*=\s*['\"]?refresh['\"]?[^>]*>",
        re.IGNORECASE,
    )
    content_re = re.compile(
        r"\bcontent\s*=\s*(['\"])(.*?)\1|\bcontent\s*=\s*([^'\"\s>]+)",
        re.IGNORECASE | re.DOTALL,
    )
    url_re = re.compile(r"(?:^|;)\s*url\s*=\s*([^;]+)", re.IGNORECASE)
    for meta in meta_re.finditer(source):
        content_match = content_re.search(meta.group(0))
        if not content_match:
            continue
        content = html_lib.unescape(content_match.group(2) or content_match.group(3) or "").strip()
        url_match = url_re.search(content)
        if not url_match:
            continue
        candidate = url_match.group(1).strip().strip("'\"")
        if candidate:
            return urljoin(base_url, candidate) if base_url else candidate
    return ""


def _valid_qr_image_data_url(value: str) -> str:
    text = re.sub(r"\s+", "", str(value or "").strip())
    if re.fullmatch(r"data:image/(?:png|jpe?g|webp|gif);base64,[A-Za-z0-9+/=]+", text, re.IGNORECASE):
        return text
    return ""


def _extract_qr_image_from_html(html: str, base_url: str = "") -> tuple[str, str]:
    """Extract a QR-looking image from static HTML without decoding QR contents."""
    source = str(html or "")
    if not source:
        return "", ""
    marker_re = re.compile(r"(?:qr|qrcode|qr-code|gcash)", re.IGNORECASE)
    data_re = re.compile(
        r"data:image/(?:png|jpe?g|webp|gif);base64,[A-Za-z0-9+/=\s]+",
        re.IGNORECASE,
    )
    for match in data_re.finditer(source):
        window = source[max(0, match.start() - 240): match.end() + 240]
        if marker_re.search(window):
            data_url = _valid_qr_image_data_url(match.group(0))
            if data_url:
                return data_url, "html_data_url"

    tag_re = re.compile(r"<(?:img|source)\b[^>]*(?:src|srcset)\s*=\s*(['\"])(.*?)\1[^>]*>", re.IGNORECASE | re.DOTALL)
    for match in tag_re.finditer(source):
        tag = match.group(0)
        if not marker_re.search(tag):
            continue
        raw_src = html_lib.unescape(match.group(2)).strip()
        if not raw_src:
            continue
        first_src = raw_src.split(",", 1)[0].strip().split()[0]
        data_url = _valid_qr_image_data_url(first_src)
        if data_url:
            return data_url, "html_img_data_url"
        if first_src and not first_src.startswith("data:"):
            return urljoin(base_url, first_src) if base_url else first_src, "html_img_url"
    return "", ""


def fetch_gcash_qr_image_data_url(
    session: Any,
    gcash_url: str,
    *,
    referer: str = "",
    log: Callable[[str], None] | None = None,
) -> tuple[str, str]:
    """Best-effort QR image capture using the same HTTP session/proxy/cookies.

    This intentionally returns only image bytes as a data URL.  It never decodes
    QR content and never fabricates a QR from the authorization link.
    """
    target = str(gcash_url or "").strip()
    if not target or not is_gcash_redirect_url(target):
        return "", "skipped:not_gcash_url"
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Referer": referer or "https://checkoutshopper-live.adyen.com/",
    }
    try:
        response = session.get(target, headers=headers, allow_redirects=True, timeout=DEFAULT_TIMEOUT)
    except Exception as exc:
        return "", f"page_error:{short_error(str(exc), 120)}"
    html = str(getattr(response, "text", "") or "")
    candidate, source = _extract_qr_image_from_html(html, target)
    data_url = _valid_qr_image_data_url(candidate)
    if data_url:
        return data_url, source
    if not candidate or not is_external_url(candidate):
        browser_image, browser_status = _capture_qr_with_playwright(session, target, log=log)
        if browser_image:
            return browser_image, browser_status
        return "", browser_status if browser_status != "browser_unavailable" else "not_found"
    try:
        image_response = session.get(
            candidate,
            headers={"Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8", "Referer": target},
            allow_redirects=True,
            timeout=DEFAULT_TIMEOUT,
        )
    except Exception as exc:
        return "", f"image_error:{short_error(str(exc), 120)}"
    content_type = str(getattr(image_response, "headers", {}).get("Content-Type") or "").split(";", 1)[0].strip().lower()
    mime = content_type if content_type in {"image/png", "image/jpeg", "image/webp", "image/gif"} else ""
    content = getattr(image_response, "content", b"") or b""
    if not mime or len(content) < 100:
        return "", "image_invalid"
    encoded = base64.b64encode(content).decode("ascii")
    return f"data:{mime};base64,{encoded}", source or "html_img_url"


def _session_proxy_url(session: Any) -> str:
    proxies = getattr(session, "proxies", {}) or {}
    if isinstance(proxies, dict):
        return str(proxies.get("https") or proxies.get("http") or "").strip()
    return ""


def _playwright_proxy(proxy_url: str) -> dict[str, str] | None:
    proxy = normalize_proxy_url(proxy_url)
    if not proxy:
        return None
    try:
        parsed = urlsplit(proxy)
    except Exception:
        return {"server": proxy}
    host = parsed.hostname or ""
    if not host:
        return {"server": proxy}
    server_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    server = f"{parsed.scheme}://{server_host}"
    if parsed.port:
        server = f"{server}:{parsed.port}"
    config: dict[str, str] = {"server": server}
    if parsed.username:
        config["username"] = unquote(parsed.username)
    if parsed.password:
        config["password"] = unquote(parsed.password)
    return config


def _playwright_cookies(session: Any) -> list[dict[str, Any]]:
    jar = getattr(session, "cookies", None)
    output: list[dict[str, Any]] = []
    if not jar:
        return output
    try:
        items = list(jar)
    except Exception:
        return output
    for cookie in items:
        name = str(getattr(cookie, "name", "") or "")
        value = str(getattr(cookie, "value", "") or "")
        domain = str(getattr(cookie, "domain", "") or "")
        if not name or not domain:
            continue
        item: dict[str, Any] = {
            "name": name,
            "value": value,
            "domain": domain,
            "path": str(getattr(cookie, "path", "/") or "/"),
            "secure": bool(getattr(cookie, "secure", True)),
            "httpOnly": False,
        }
        output.append(item)
    return output


def _capture_qr_with_playwright(
    session: Any,
    gcash_url: str,
    *,
    log: Callable[[str], None] | None = None,
) -> tuple[str, str]:
    """Optional browser fallback for async GCash QR rendering."""
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except Exception:
        return "", "browser_unavailable"

    timeout_seconds = int(os.environ.get("GCASH_QR_BROWSER_TIMEOUT", "45") or "45")
    if timeout_seconds <= 0:
        return "", "browser_disabled"
    user_agent = str(getattr(session, "headers", {}).get("User-Agent") or DEFAULT_USER_AGENT)
    proxy_config = _playwright_proxy(_session_proxy_url(session))
    deadline = time.time() + timeout_seconds

    def emit(message: str) -> None:
        if log:
            log(message)

    try:
        with sync_playwright() as playwright:
            browser = _launch_gcash_browser(playwright, proxy_config)
            try:
                context = browser.new_context(
                    user_agent=user_agent,
                    locale="en-PH",
                    timezone_id="Asia/Manila",
                    viewport={"width": 420, "height": 820},
                )
                cookies = _playwright_cookies(session)
                if cookies:
                    context.add_cookies(cookies)
                page = context.new_page()
                try:
                    page.goto(gcash_url, wait_until="domcontentloaded", timeout=min(timeout_seconds, 20) * 1000)
                except PlaywrightTimeoutError:
                    emit("GCash 阶段[二维码]: Playwright 页面初始加载超时，继续扫描已渲染内容.")

                excluded = ("option1", "ins_photo1", "instruction", "guide", "sample", "logo")
                selector = "canvas,img,svg,[style*='background-image']"
                last_diag = 0.0
                while time.time() < deadline:
                    candidate_count = 0
                    for frame in page.frames:
                        try:
                            handles = frame.query_selector_all(selector)
                        except Exception:
                            continue
                        for handle in handles:
                            try:
                                box = handle.bounding_box()
                                if not box:
                                    continue
                                width = float(box.get("width") or 0)
                                height = float(box.get("height") or 0)
                                if width < 100 or height < 100:
                                    continue
                                if abs(width - height) / max(width, height) > 0.25:
                                    continue
                                marker = str(handle.evaluate(
                                    "(el) => [el.id, el.className, el.alt, el.src, el.getAttribute('aria-label')].join(' ').toLowerCase()"
                                ) or "")
                                if any(item in marker for item in excluded):
                                    continue
                                candidate_count += 1
                                png = handle.screenshot(type="png")
                                if png and len(png) > 500:
                                    return "data:image/png;base64," + base64.b64encode(png).decode("ascii"), "browser_screenshot"
                            except Exception:
                                continue
                    now = time.time()
                    if now - last_diag >= 10:
                        last_diag = now
                        emit(
                            "GCash 阶段[二维码]: Playwright 等待二维码渲染，"
                            f"url={urlsplit(page.url).path or '/'} candidates={candidate_count} frames={len(page.frames)}"
                        )
                    page.wait_for_timeout(800)
                return "", "browser_timeout"
            finally:
                browser.close()
    except Exception as exc:
        return "", f"browser_error:{short_error(str(exc), 120)}"


def fetch_openai_checkout_state(chatgpt: Any, cs_id: str, processor_entity: str) -> dict[str, Any]:
    """Read the current OpenAI custom checkout state."""
    entity = str(processor_entity or "openai_llc").strip() or "openai_llc"
    headers = _checkout_page_route_headers(entity, cs_id, accept="application/json")
    response = chatgpt.get(
        f"https://chatgpt.com/backend-api/payments/checkout/{entity}/{cs_id}",
        headers=headers,
        timeout=CHATGPT_TIMEOUT,
    )
    if response.status_code >= 400:
        raise GCashExtractError(f"读取 Open_AI checkout 状态失败 HTTP {response.status_code}: {response.text[:500]}")
    data = response.json() or {}
    return data if isinstance(data, dict) else {"payload": data}


def _jwt_text(value: Any) -> str:
    return str(value or "").strip()


def _decode_gcash_claims(token: str) -> dict[str, Any]:
    parts = _jwt_text(token).split(".")
    if len(parts) < 2:
        return {}
    raw = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(raw.encode("ascii")))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _gcash_account_context(token: str) -> tuple[str, str]:
    claims = _decode_gcash_claims(token)
    auth = claims.get("https://api.openai.com/auth")
    profile = claims.get("https://api.openai.com/profile")
    account_id = ""
    email = ""
    if isinstance(auth, dict):
        account_id = _jwt_text(auth.get("chatgpt_account_id") or auth.get("account_id"))
    account_id = account_id or _jwt_text(claims.get("chatgpt_account_id") or claims.get("account_id"))
    if isinstance(profile, dict):
        email = _jwt_text(profile.get("email"))
    email = email or _jwt_text(claims.get("email"))
    return account_id, email


def _subscription_plan_from_payload(payload: Any) -> str:
    seen: set[int] = set()

    def walk(value: Any, depth: int = 0) -> str:
        if depth > 6:
            return ""
        if isinstance(value, dict):
            marker = id(value)
            if marker in seen:
                return ""
            seen.add(marker)
            for key in ("plan_type", "planType", "chatgpt_plan_type", "subscription_plan", "plan"):
                candidate = _jwt_text(value.get(key))
                if candidate:
                    return candidate
            for child in value.values():
                found = walk(child, depth + 1)
                if found:
                    return found
        elif isinstance(value, list):
            marker = id(value)
            if marker in seen:
                return ""
            seen.add(marker)
            for child in value[:80]:
                found = walk(child, depth + 1)
                if found:
                    return found
        return ""

    return walk(payload)


def fetch_gcash_subscription_state(chatgpt: Any, account_id: str) -> dict[str, Any]:
    """Read ChatGPT subscription state; final success requires plan_type=plus."""
    account_id = _jwt_text(account_id)
    if not account_id:
        raise GCashExtractError("GCASH_SUBSCRIPTION_ACCOUNT_ID_MISSING")
    headers = {
        "Accept": "application/json",
        "Referer": "https://chatgpt.com/",
        "x-openai-target-path": "/backend-api/subscriptions",
        "x-openai-target-route": "/backend-api/subscriptions",
    }
    response = chatgpt.get(
        "https://chatgpt.com/backend-api/subscriptions",
        params={"account_id": account_id},
        headers=headers,
        timeout=CHATGPT_TIMEOUT,
    )
    if response.status_code >= 400:
        raise GCashExtractError(
            f"GCASH_SUBSCRIPTION_STATUS_FAILED HTTP {response.status_code}: {_response_text(response)}"
        )
    try:
        payload = response.json() or {}
    except Exception as exc:
        raise GCashExtractError("GCASH_SUBSCRIPTION_STATUS_INVALID_JSON") from exc
    data = payload if isinstance(payload, dict) else {"payload": payload}
    data["_subscription_http_status"] = int(getattr(response, "status_code", 0) or 0)
    data["_subscription_plan"] = _subscription_plan_from_payload(payload)
    return data


_PROMO_CAMPAIGN_KEYS = {
    "promo_campaign_id",
    "promocampaignid",
    "promo_campaign",
    "promoCampaign",
    "campaign_id",
    "campaignId",
    "coupon",
    "promotion_code",
    "promotionCode",
}

_GCASH_METHOD_CONTAINER_KEYS = {
    "payment_method_types",
    "paymentMethodTypes",
    "custom_payment_methods",
    "customPaymentMethods",
    "custom_payment_method_data",
    "customPaymentMethodData",
    "payment_method_options",
    "paymentMethodOptions",
    "available_payment_method_types",
    "availablePaymentMethodTypes",
    "selected_payment_method_type",
    "selectedPaymentMethodType",
}

_GCASH_METHOD_VALUE_KEYS = {
    "type",
    "name",
    "display_name",
    "displayName",
    "label",
    "payment_method_type",
    "paymentMethodType",
    "payment_method",
    "paymentMethod",
    "custom_payment_method_type",
    "customPaymentMethodType",
    "custom_payment_method_type_id",
    "customPaymentMethodTypeId",
}


def _normalized_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").strip().lower())


_PROMO_CAMPAIGN_NORMALIZED_KEYS = {_normalized_key(item) for item in _PROMO_CAMPAIGN_KEYS}
_GCASH_METHOD_CONTAINER_NORMALIZED_KEYS = {_normalized_key(item) for item in _GCASH_METHOD_CONTAINER_KEYS}
_GCASH_METHOD_VALUE_NORMALIZED_KEYS = {_normalized_key(item) for item in _GCASH_METHOD_VALUE_KEYS}


def _known_gcash_custom_payment_method_id(value: Any) -> str:
    text = str(value or "")
    for method_id in KNOWN_GCASH_CUSTOM_PAYMENT_METHOD_IDS:
        if method_id in text:
            return method_id
    return ""


def _is_gcash_text(value: Any) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    normalized = re.sub(r"[^a-z0-9]", "", text)
    return normalized == "gcash" or "gcash" in normalized


def _promo_qualification_evidence(*payloads: Any) -> tuple[bool, str]:
    """Detect plus trial qualification markers without treating them as final success."""

    seen: set[int] = set()
    wanted = PLUS_TRIAL_PROMO_ID.lower()

    def walk(value: Any, path: str = "") -> str:
        if isinstance(value, (dict, list, tuple)):
            marker = id(value)
            if marker in seen:
                return ""
            seen.add(marker)
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else str(key)
                normalized_key = _normalized_key(key)
                if normalized_key in _PROMO_CAMPAIGN_NORMALIZED_KEYS:
                    if isinstance(child, (str, int, float, bool)) and str(child).strip().lower() == wanted:
                        return child_path
                    if isinstance(child, dict):
                        candidate = str(
                            child.get("promo_campaign_id")
                            or child.get("promoCampaignId")
                            or child.get("campaign_id")
                            or child.get("campaignId")
                            or ""
                        ).strip().lower()
                        if candidate == wanted:
                            return f"{child_path}.promo_campaign_id"
                if normalized_key in {"promocampaignid", "campaignid", "coupon", "promotioncode"}:
                    if str(child or "").strip().lower() == wanted:
                        return child_path
                found = walk(child, child_path)
                if found:
                    return found
        elif isinstance(value, (list, tuple)):
            for index, child in enumerate(value[:100]):
                found = walk(child, f"{path}[{index}]" if path else f"[{index}]")
                if found:
                    return found
        elif isinstance(value, str) and value.lstrip().startswith(("{", "[")):
            try:
                found = walk(json.loads(value), path)
                if found:
                    return found
            except Exception:
                return ""
        return ""

    for payload in payloads:
        source = walk(payload)
        if source:
            return True, source
    return False, ""


def _gcash_payment_method_evidence(*payloads: Any) -> tuple[bool, str]:
    """Detect whether checkout payload explicitly exposes GCash as a payment type."""

    seen: set[int] = set()
    def walk(value: Any, path: str = "", in_method_context: bool = False) -> str:
        if isinstance(value, str) and value.lstrip().startswith(("{", "[")):
            try:
                found = walk(json.loads(value), path, in_method_context)
                if found:
                    return found
            except Exception:
                pass
        if isinstance(value, str):
            known_method_id = _known_gcash_custom_payment_method_id(value)
            if known_method_id:
                return path or known_method_id
        if isinstance(value, (dict, list, tuple)):
            marker = id(value)
            if marker in seen:
                return ""
            seen.add(marker)
        if isinstance(value, dict):
            for key, child in value.items():
                key_text = str(key)
                normalized_key = _normalized_key(key_text)
                child_path = f"{path}.{key_text}" if path else key_text
                child_method_context = in_method_context or normalized_key in _GCASH_METHOD_CONTAINER_NORMALIZED_KEYS
                if normalized_key == "gcash" and isinstance(child, (dict, list, tuple, str, int, float, bool, type(None))):
                    return child_path
                known_method_id = _known_gcash_custom_payment_method_id(child)
                if known_method_id:
                    return child_path
                if child_method_context and isinstance(child, str) and _is_gcash_text(child):
                    return child_path
                if normalized_key in _GCASH_METHOD_VALUE_NORMALIZED_KEYS and _is_gcash_text(child):
                    return child_path
                found = walk(child, child_path, child_method_context)
                if found:
                    return found
        elif isinstance(value, (list, tuple)):
            for index, child in enumerate(value[:100]):
                child_path = f"{path}[{index}]" if path else f"[{index}]"
                if in_method_context and isinstance(child, str) and _is_gcash_text(child):
                    return child_path
                found = walk(child, child_path, in_method_context)
                if found:
                    return found
        return ""

    for payload in payloads:
        source = walk(payload)
        if source:
            return True, source
    return False, ""


def _payload_has_gcash_payment_method(*payloads: Any) -> bool:
    return _gcash_payment_method_evidence(*payloads)[0]


def extract_custom_payment_method_id(
    *payloads: Any,
    require_gcash_context: bool = False,
) -> str:
    """Find the cpmt_* id for GCash from checkout/update/taxes/state payloads.

    ``require_gcash_context`` is used by the strict OpenAI flow.  A lone
    ``cpmt_*`` value is not enough evidence that the selected method is GCash;
    the surrounding payload must also mention GCash.
    """
    contextual: list[str] = []
    candidates: list[str] = []
    seen: set[int] = set()

    def remember(value: Any, gcash_context: bool = False) -> None:
        match = re.search(r"\bcpmt_[A-Za-z0-9_-]+", str(value or ""))
        if not match:
            return
        item = match.group(0)
        if _known_gcash_custom_payment_method_id(item):
            gcash_context = True
        if item not in candidates:
            candidates.append(item)
        if gcash_context and item not in contextual:
            contextual.append(item)

    def text_context(value: Any, depth: int = 0) -> str:
        if depth > 4:
            return ""
        if isinstance(value, str):
            return value.lower()
        if isinstance(value, dict):
            return " ".join([str(k).lower() + " " + text_context(v, depth + 1) for k, v in list(value.items())[:80]])
        if isinstance(value, (list, tuple)):
            return " ".join(text_context(item, depth + 1) for item in list(value)[:80])
        return ""

    def has_gcash_context(value: Any) -> bool:
        if _gcash_payment_method_evidence(value)[0]:
            return True
        return "gcash" in text_context(value)

    def visit(value: Any, inherited_context: bool = False) -> None:
        if isinstance(value, str):
            remember(value, inherited_context or "gcash" in value.lower())
            if value.lstrip().startswith(("{", "[")):
                try:
                    visit(json.loads(value), inherited_context)
                except Exception:
                    pass
            return
        if not isinstance(value, (dict, list, tuple)):
            return
        marker = id(value)
        if marker in seen:
            return
        seen.add(marker)
        current_context = inherited_context or has_gcash_context(value)
        if isinstance(value, dict):
            for key in (
                "id",
                "type",
                "custom_payment_method_type_id",
                "customPaymentMethodTypeId",
                "payment_method_type_id",
                "paymentMethodTypeId",
                "type_id",
                "value",
            ):
                remember(value.get(key), current_context)
            for child in value.values():
                visit(child, current_context)
        else:
            for child in value:
                visit(child, current_context)

    for payload in payloads:
        visit(payload)
    if contextual:
        return contextual[0]
    if require_gcash_context:
        return ""
    if len(candidates) == 1:
        return candidates[0]
    return ""




def _deep_get(payload: Any, *path: str) -> Any:
    current = payload
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


_DUE_AMOUNT_PATHS = (
    ("checkout_session", "total_summary", "due"),
    ("checkout_session", "totalSummary", "due"),
    ("checkout_session", "due_today"),
    ("checkout_session", "dueToday"),
    ("checkout_session", "amount_due"),
    ("checkoutSession", "total_summary", "due"),
    ("checkoutSession", "totalSummary", "due"),
    ("checkoutSession", "due_today"),
    ("checkoutSession", "dueToday"),
    ("checkoutSession", "amount_due"),
    ("checkout_state", "total_summary", "due"),
    ("checkout_state", "totalSummary", "due"),
    ("checkout_state", "due_today"),
    ("checkout_state", "dueToday"),
    ("checkout_state", "amount_due"),
    ("checkoutState", "total_summary", "due"),
    ("checkoutState", "totalSummary", "due"),
    ("checkoutState", "due_today"),
    ("checkoutState", "dueToday"),
    ("checkoutState", "amount_due"),
    ("total_summary", "due"),
    ("totalSummary", "due"),
    ("due_today",),
    ("dueToday",),
    ("total_due",),
    ("totalDue",),
    ("invoice", "amount_due"),
    ("amount_due",),
)

_FALLBACK_AMOUNT_PATHS = (
    ("checkout_session", "amount_total"),
    ("checkoutSession", "amount_total"),
    ("checkout_state", "amount_total"),
    ("checkoutState", "amount_total"),
    ("amount_total",),
)


def _amount_text_from_path(payload: dict[str, Any], path: tuple[str, ...]) -> str:
    value = _deep_get(payload, *path)
    if isinstance(value, dict):
        for key in ("value", "amount", "total"):
            if key in value and value.get(key) is not None:
                value = value.get(key)
                break
    if value is None:
        return ""
    text = str(value).strip()
    if not text or text.lower() in {"unknown", "none", "null"}:
        return ""
    return text


def _explicit_openai_amount_candidates(payloads: Any) -> list[tuple[str, str, str]]:
    """Return explicit amount candidates as ``(amount, source, kind)``.

    ``kind=due`` means this field represents the actual amount due today.
    ``kind=fallback`` is a legacy/ambiguous total field and is only used when
    no due-today field exists anywhere in the payload set.
    """

    candidates: list[tuple[str, str, str]] = []
    inputs = payloads if isinstance(payloads, (list, tuple)) else (payloads,)
    for payload in inputs:
        if not isinstance(payload, dict):
            continue
        for path in _DUE_AMOUNT_PATHS:
            text = _amount_text_from_path(payload, path)
            if text:
                candidates.append((text, ".".join(path), "due"))
        for path in _FALLBACK_AMOUNT_PATHS:
            text = _amount_text_from_path(payload, path)
            if text:
                candidates.append((text, ".".join(path), "fallback"))
    return candidates


def _explicit_openai_amount(payloads: Any) -> tuple[str, str]:
    """读取 OpenAI checkout 中明确的应付金额。

    OpenAI 内部 checkout 的金额字段在不同响应中可能位于
    ``total_summary.due``、``amount_due`` 或 ``amount_total``。
    注意：网页右侧会同时展示「Monthly subscription ₱982.14」和
    「Due today ₱0.00」；上游 JSON 里的通用 ``amount`` 很多时候是
    原价/展示价，不是本次应付金额。这里不再把 ``checkout_state.amount``
    或顶层 ``amount`` 当作 0 元资格的失败依据，避免把有 GCash 且
    Due today 为 0 的账号误判为非 0。
    返回 ``(金额文本, 字段路径)``，没有明确金额时返回空字符串。
    """

    candidates = _explicit_openai_amount_candidates(payloads)
    for amount, source, kind in candidates:
        if kind == "due":
            return amount, source
    for amount, source, _kind in candidates:
        return amount, source
    return "", ""


def _amount_is_nonzero(value: str) -> bool:
    text = str(value or "").strip()
    if not text or text.lower() in {"unknown", "none", "null"}:
        return False
    compact = re.sub(r"[\s,]", "", text)
    numeric_parts = re.findall(r"[-+]?\d+(?:\.\d+)?", compact)
    if not numeric_parts:
        return False
    for part in numeric_parts:
        try:
            if float(part) != 0:
                return True
        except (TypeError, ValueError):
            continue
    return False


def _reject_explicit_nonzero_amount(*payloads: Any, stage: str) -> tuple[str, str]:
    """Reject as soon as any authoritative checkout payload exposes a non-zero amount."""

    candidates = _explicit_openai_amount_candidates(payloads)
    due_candidates = [(amount, source) for amount, source, kind in candidates if kind == "due"]
    for amount, source in due_candidates:
        if _amount_is_nonzero(amount):
            raise GCashExtractError(
                f"GCASH_{stage}_AMOUNT_NONZERO: 优惠/0 金额未生效，"
                f"当前 checkout 应付金额非 0：amount={amount}, source={source}；"
                "已停止 confirm/approve，避免返回无法最终订阅的 GCash 链。"
            )
    if due_candidates:
        return "", ""
    for amount, source, _kind in candidates:
        if _amount_is_nonzero(amount):
            raise GCashExtractError(
                f"GCASH_{stage}_AMOUNT_NONZERO: 优惠/0 金额未生效，"
                f"当前 checkout 应付金额非 0：amount={amount}, source={source}；"
                "已停止 confirm/approve，避免返回无法最终订阅的 GCash 链。"
            )
    return "", ""


def _reject_observed_nonzero_checkout_amount(payload: Any, *, stage: str) -> tuple[str, str]:
    amount, source = _observed_nonzero_checkout_amount(payload)
    if amount:
        raise GCashExtractError(
            f"GCASH_{stage}_AMOUNT_NONZERO: 优惠/0 金额未生效，"
            f"当前 checkout 应付金额非 0：amount={amount}, source={source}；"
            "已停止 confirm/approve，避免把不可确认订单误判为账号 Block。"
        )
    return "", ""


def _find_checkout_scalar(payload: Any, *keys: str) -> str:
    wanted = {str(key or "").strip() for key in keys if str(key or "").strip()}
    seen: set[int] = set()

    def walk(value: Any) -> str:
        if isinstance(value, (dict, list, tuple)):
            marker = id(value)
            if marker in seen:
                return ""
            seen.add(marker)
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = str(key or "").strip()
                if normalized in wanted and isinstance(child, (str, int, float, bool)):
                    text = str(child).strip()
                    if text:
                        return text
                found = walk(child)
                if found:
                    return found
        elif isinstance(value, (list, tuple)):
            for child in value:
                found = walk(child)
                if found:
                    return found
        return ""

    return walk(payload)


def _checkout_allows_approve(state: Any) -> bool:
    can_confirm = _find_checkout_scalar(state, "canConfirm", "can_confirm")
    if can_confirm.lower() in {"true", "1", "yes"}:
        return True
    submission = find_submission_attempt(state)
    submission_state = str(submission.get("state") or submission.get("status") or "").strip().lower()
    return submission_state == "requires_approval"


def _observed_nonzero_checkout_amount(payload: Any) -> tuple[str, str]:
    amount, source = _explicit_openai_amount(payload)
    if amount and _amount_is_nonzero(amount):
        return amount, source
    return "", ""


def _diagnostic_amount(payload: Any) -> tuple[str, str]:
    amount, source = _explicit_openai_amount(payload)
    if amount:
        return amount, source
    for key in ("amount_total", "amount_due", "amount"):
        value = _find_checkout_scalar(payload, key)
        if value:
            return value, f"diagnostic.{key}"
    return "", ""


def _gcash_account_blocked_error(
    confirm_data: Any,
    checkout_state: Any,
    *,
    approve_error: str = "",
) -> GCashExtractError:
    amount, amount_source = _diagnostic_amount(checkout_state)
    can_confirm = _find_checkout_scalar(checkout_state, "canConfirm", "can_confirm") or "unknown"
    payment_status = _find_checkout_scalar(checkout_state, "payment_status") or "unknown"
    parts = [
        "GCASH_ACCOUNT_BLOCKED: 账号 Block 异常：GCash confirm returned blocked，已停止重试",
        f"canConfirm={can_confirm}",
        f"payment_status={payment_status}",
    ]
    if amount:
        parts.append(f"amount={amount}")
        parts.append(f"amount_source={amount_source}")
    parts.append(diagnostic_summary("GCash DIAG[blocked_confirm]", confirm_data))
    if checkout_state:
        parts.append(diagnostic_summary("GCash DIAG[blocked_state]", checkout_state))
    if approve_error:
        parts.append(f"approve_error={short_error(approve_error, 240)}")
    return GCashExtractError("；".join(part for part in parts if part))


def _gcash_attempt_blocked_error(
    confirm_data: Any,
    checkout_state: Any,
    *,
    approve_error: str = "",
) -> GCashExtractError:
    """Mark a single confirm block as retryable session/IP risk.

    A blocked response is emitted after a checkout and payment method already
    exist. The current checkout context must be discarded; retrying approve or
    confirm on the same objects is not a valid recovery path. The outer runner
    decides whether independent retries are exhausted.
    """
    amount, amount_source = _diagnostic_amount(checkout_state)
    can_confirm = _find_checkout_scalar(checkout_state, "canConfirm", "can_confirm") or "unknown"
    payment_status = _find_checkout_scalar(checkout_state, "payment_status") or "unknown"
    parts = [
        "GCASH_ATTEMPT_BLOCKED: 本次 Checkout confirm returned blocked；当前代理/IP/会话/指纹组合触发风控，"
        "已丢弃当前 Checkout、PaymentMethod 和跳转链，交由外层更换代理与指纹后重建",
        f"canConfirm={can_confirm}",
        f"payment_status={payment_status}",
    ]
    if amount:
        parts.append(f"amount={amount}")
        parts.append(f"amount_source={amount_source}")
    parts.append(diagnostic_summary("GCash DIAG[blocked_confirm]", confirm_data))
    if checkout_state:
        parts.append(diagnostic_summary("GCash DIAG[blocked_state]", checkout_state))
    if approve_error:
        parts.append(f"approve_error={short_error(approve_error, 240)}")
    return GCashExtractError("；".join(part for part in parts if part))


def _gcash_confirm_blocked_precondition_error(
    confirm_data: Any,
    checkout_state: Any,
    *,
    approve_error: str = "",
) -> GCashExtractError:
    amount, amount_source = _diagnostic_amount(checkout_state)
    can_confirm = _find_checkout_scalar(checkout_state, "canConfirm", "can_confirm") or "unknown"
    payment_status = _find_checkout_scalar(checkout_state, "payment_status") or "unknown"
    parts = [
        "GCASH_CONFIRM_BLOCKED_PRECONDITION: confirm 返回 blocked，但 checkout 前置状态未达成：优惠/0 金额未生效或 checkout 不可确认",
        f"canConfirm={can_confirm}",
        f"payment_status={payment_status}",
    ]
    if amount:
        parts.append(f"amount={amount}")
        parts.append(f"amount_source={amount_source}")
    parts.append(diagnostic_summary("GCash DIAG[blocked_confirm]", confirm_data))
    if checkout_state:
        parts.append(diagnostic_summary("GCash DIAG[blocked_state]", checkout_state))
    if approve_error:
        parts.append(f"approve_error={short_error(approve_error, 240)}")
    return GCashExtractError("；".join(part for part in parts if part))


_OPENAI_FAILURE_STATES = {
    "error",
    "failed",
    "failure",
    "declined",
    "rejected",
    "blocked",
    "canceled",
    "cancelled",
    "invalid",
}


def _payload_failure_detail(payload: Any) -> str:
    """Return an explicit upstream failure marker, if present.

    OpenAI checkout endpoints sometimes return HTTP 200 with ``ok=false`` or
    an embedded ``error``/``status=failed`` object.  Treat those responses as
    failures instead of allowing the flow to continue to ``start``.
    """

    failure_message_markers = (
        "not available",
        "billing country must match",
        "payment failed",
        "payment error",
        "declined",
        "invalid",
        "failed",
        "error",
        "blocked",
        "canceled",
        "cancelled",
    )
    seen: set[int] = set()

    def walk(value: Any) -> str:
        if isinstance(value, (dict, list, tuple)):
            marker = id(value)
            if marker in seen:
                return ""
            seen.add(marker)
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = str(key or "").strip().lower()
                if normalized in {"ok", "success"} and child is False:
                    return f"{key}=false"
                if normalized in {
                    "error",
                    "failure",
                    "failure_reason",
                    "failure_code",
                    "decline_code",
                    "error_code",
                }:
                    text = str(child or "").strip()
                    if isinstance(child, dict):
                        text = str(
                            child.get("message")
                            or child.get("code")
                            or child.get("reason")
                            or child.get("type")
                            or ""
                        ).strip()
                    if text:
                        return f"{key}={short_error(text, 220)}"
                if normalized in {"status", "state", "result"}:
                    text = str(child or "").strip().lower()
                    if text in _OPENAI_FAILURE_STATES:
                        return f"{key}={text}"
                if normalized in {"message", "reason"} and isinstance(child, str):
                    text = child.strip()
                    lower = text.lower()
                    if any(marker in lower for marker in failure_message_markers):
                        return f"{key}={short_error(text, 220)}"
                found = walk(child)
                if found:
                    return found
        elif isinstance(value, (list, tuple)):
            for child in value:
                found = walk(child)
                if found:
                    return found
        return ""

    return walk(payload)


def _require_openai_payload_ok(payload: Any, stage: str) -> None:
    if not isinstance(payload, dict) or not payload:
        raise GCashExtractError(f"GCASH_{stage}_EMPTY: 上游未返回有效 JSON")
    detail = _payload_failure_detail(payload)
    if detail:
        raise GCashExtractError(f"GCASH_{stage}_FAILED: {detail}")


def _validate_zero_amount_evidence(*payloads: Any, stage: str) -> tuple[str, str]:
    """Require at least one explicit zero-amount field and reject any non-zero.

    Returning a payment URL is not considered success unless the checkout
    response proves that the amount is zero.  Unknown amount is fail-closed.
    ``promo_campaign=plus-1-month-free`` is only qualification evidence; it is
    not accepted as final zero-amount proof to avoid returning fake links.
    """

    observed: list[tuple[str, str]] = []
    candidates = _explicit_openai_amount_candidates(payloads)
    due_candidates = [(amount, source) for amount, source, kind in candidates if kind == "due"]
    effective_candidates = due_candidates or [
        (amount, source) for amount, source, _kind in candidates
    ]
    for amount, source in effective_candidates:
        observed.append((amount, source))
        if _amount_is_nonzero(amount):
            raise GCashExtractError(
                f"GCASH_{stage}_AMOUNT_NONZERO: 应付金额仍非 0："
                f"amount={amount}, source={source}"
            )
    if not observed:
        promo_ok, promo_source = _promo_qualification_evidence(*payloads)
        if promo_ok:
            raise GCashExtractError(
                f"GCASH_{stage}_AMOUNT_UNKNOWN: 已识别 {PLUS_TRIAL_PROMO_ID} 优惠资格"
                f"（source={promo_source}），但未找到明确的 0 金额字段，拒绝返回支付链"
            )
        raise GCashExtractError(
            f"GCASH_{stage}_AMOUNT_UNKNOWN: 未找到明确的 0 金额字段，拒绝返回支付链"
        )
    return observed[0]


def _is_valid_openai_gcash_redirect(value: str) -> bool:
    candidate = str(value or "").strip()
    return bool(
        _is_adyen_checkout_redirect_url(candidate)
        or is_gcash_redirect_url(candidate)
        or is_stripe_pm_redirect_url(candidate)
    )


def _find_chatgpt_confirm_return_url(*payloads: Any) -> str:
    """提取 ChatGPT verify 短链，避免误把 Adyen action URL 当作 verification_url。"""

    preferred_keys = (
        "confirm_return_url", "confirmReturnUrl", "success_return_url",
        "successReturnUrl", "verification_url", "verificationUrl",
    )
    seen: set[int] = set()

    def walk(value: Any) -> str:
        marker = id(value)
        if isinstance(value, (dict, list, tuple)):
            if marker in seen:
                return ""
            seen.add(marker)
        if isinstance(value, dict):
            for key in preferred_keys:
                candidate = str(value.get(key) or "").strip()
                if "chatgpt.com/checkout/verify" in candidate:
                    return candidate
            for child in value.values():
                found = walk(child)
                if found:
                    return found
        elif isinstance(value, (list, tuple)):
            for child in value:
                found = walk(child)
                if found:
                    return found
        elif isinstance(value, str) and "chatgpt.com/checkout/verify" in value:
            return value.strip()
        return ""

    for payload in payloads:
        found = walk(payload)
        if found:
            return found
    return ""


def checkout_state_from_html(html: str) -> dict[str, Any]:
    """Best-effort extraction of the embedded checkout state from HTML."""
    source = str(html or "")
    patterns = [
        re.compile(r'window\.__reactRouterContext\.streamController\.enqueue\(("(?:\\.|[^"\\])*")\)', re.DOTALL),
        re.compile(r'<script\b[^>]*\btype=([\'\"])application/json\1[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL),
    ]

    def decode_serialized(serialized: str) -> dict[str, Any]:
        try:
            decoded: Any = json.loads(serialized)
        except Exception:
            return {}
        if isinstance(decoded, list):
            try:
                decoded = _decode_react_router_payload(decoded)
            except Exception:
                pass
        if isinstance(decoded, dict):
            for key in ("checkout_state", "checkoutState"):
                candidate = decoded.get(key)
                if isinstance(candidate, dict):
                    return candidate
            return decoded
        return {}

    for pattern in patterns:
        for match in pattern.finditer(source):
            try:
                raw = json.loads(match.group(1) if pattern is patterns[0] else match.group(2))
            except Exception:
                continue
            if not isinstance(raw, str):
                continue
            state = decode_serialized(raw.strip())
            if state:
                return state
    return {}


def _decode_react_router_payload(payload: list[Any]) -> Any:
    resolved: dict[int, Any] = {}

    def resolve(reference: Any) -> Any:
        if not isinstance(reference, int):
            return reference
        if reference < 0 or reference >= len(payload):
            return None
        if reference in resolved:
            return resolved[reference]
        value = payload[reference]
        if isinstance(value, dict):
            output: dict[str, Any] = {}
            resolved[reference] = output
            for encoded_key, encoded_value in value.items():
                key_text = str(encoded_key)
                if not key_text.startswith("_") or not key_text[1:].isdigit():
                    continue
                key = resolve(int(key_text[1:]))
                if key is not None:
                    output[str(key)] = resolve(encoded_value)
            return output
        if isinstance(value, list):
            output_list: list[Any] = []
            resolved[reference] = output_list
            output_list.extend(resolve(item) for item in value)
            return output_list
        resolved[reference] = value
        return value

    return resolve(0)


def summarize_gcash_checkout_state(payload: Any, *, cs_id: str = "", processor_entity: str = "") -> dict[str, Any]:
    state = payload if isinstance(payload, dict) else {}
    checkout_state = state.get("checkout_state") if isinstance(state.get("checkout_state"), dict) else state.get("checkoutState") if isinstance(state.get("checkoutState"), dict) else {}
    payment_intent = state.get("payment_intent") if isinstance(state.get("payment_intent"), dict) else state.get("paymentIntent") if isinstance(state.get("paymentIntent"), dict) else {}
    submission = find_submission_attempt(state)
    redirect_url = extract_redirect_to_url(state)
    status = str(_deep_get(checkout_state, "status") or state.get("status") or "").strip().lower()
    payment_status = str(_deep_get(state, "payment_status") or _deep_get(payment_intent, "status") or "").strip().lower()
    submission_state = str(submission.get("state") or submission.get("status") or "").strip().lower()
    can_confirm = bool(_deep_get(checkout_state, "canConfirm") if isinstance(checkout_state, dict) else False)
    if payment_status in {"paid", "succeeded"} or status in {"complete", "paid", "succeeded"}:
        stage = "paid"
        hint = "支付已完成，等待页面状态同步"
    elif payment_status == "processing":
        stage = "processing"
        hint = "支付正在处理中"
    elif submission_state == "requires_approval" or can_confirm:
        stage = "approval_required"
        hint = "需要 ChatGPT 侧确认"
    elif redirect_url:
        stage = "redirect_ready"
        hint = "已生成可跳转的支付链接"
    elif payment_status in {"requires_payment_method", "requires_action"}:
        stage = "pending_action"
        hint = "等待支付方式继续处理"
    else:
        stage = "pending"
        hint = "等待支付状态同步"
    return {
        "checkout_status": status or str(_deep_get(state, "checkout_status") or "").strip().lower(),
        "payment_status": payment_status,
        "submission_state": submission_state,
        "can_confirm": can_confirm,
        "stage": stage,
        "hint": hint,
        "status_label": {
            "paid": "已到账",
            "processing": "处理中",
            "approval_required": "待确认",
            "redirect_ready": "可跳转",
            "pending_action": "待处理",
            "pending": "处理中",
        }.get(stage, "处理中"),
        "checkout_url": f"https://chatgpt.com/checkout/{processor_entity}/{cs_id}" if cs_id else "",
        "verification_url": f"https://chatgpt.com/checkout/{processor_entity}/{cs_id}" if cs_id else "",
        "redirect_url": redirect_url,
        "amount": expected_amount(state),
        "currency": str(_deep_get(state, "currency") or _deep_get(checkout_state, "currency") or "PHP").upper(),
        "custom_payment_method_id": extract_custom_payment_method_id(state),
    }


def check_account_gcash(
    token: str,
    proxy: str | None = None,
    *,
    log: Any | None = None,
    fingerprint_profile: dict[str, Any] | None = None,
    device_id: str = "",
    promo_mode: str = "none",
) -> dict[str, Any]:
    """Probe whether PH/PHP custom checkout exposes the GCash cpmt_* method.

    This is an eligibility probe, not a full extraction flow: it only creates
    one PH/PHP custom checkout and reads the authoritative checkout state.
    """

    def emit(message: str) -> None:
        if log:
            log(message)

    access_token = _text(token)
    if not access_token:
        raise GCashExtractError("GCASH_AT_INVALID: missing access token")
    fingerprint = dict(fingerprint_profile or {}) if isinstance(fingerprint_profile, dict) else {}
    runtime_device_id = _text(device_id) or _fingerprint_header_value(fingerprint, "device_id")
    chatgpt = build_chatgpt_session(
        access_token,
        proxy=_text(proxy),
        device_id=runtime_device_id,
        fingerprint_profile=fingerprint,
        log=emit,
    )
    preflight_gcash_access_token(chatgpt, log=emit)
    checkout = create_checkout(chatgpt, promo_mode=promo_mode or "campaign")
    cs_id = _text(checkout.get("cs_id"))
    provider = _text(checkout.get("checkout_provider")).lower()
    processor_entity = _text(checkout.get("processor_entity")) or "openai_llc"
    promo_ok, promo_source = _promo_qualification_evidence(checkout)
    result: dict[str, Any] = {
        "ok": True,
        "available": False,
        "gcash_available": False,
        "status": "unavailable",
        "reason": "",
        "checkout_session_id": cs_id,
        "checkout_provider": provider,
        "processor_entity": processor_entity,
        "custom_payment_method_id": "",
        "method_source": "",
        "promo_qualified": bool(promo_ok),
        "promo_source": promo_source,
    }
    if provider != "open_ai" or not cs_id.startswith("oaics_"):
        result["reason"] = "checkout_not_oaics"
        result["message"] = "GCash 不可用：PH checkout 未返回 oaics_* OpenAI 自定义 Checkout。"
        emit(
            "GCash 资格探针: "
            f"provider={provider or 'unknown'} cs_id={cs_id or '-'}，非 oaics_*，判定无 GCash."
        )
        return result

    state = fetch_openai_checkout_state(chatgpt, cs_id, processor_entity)
    method_id = extract_custom_payment_method_id(
        checkout,
        state,
        require_gcash_context=True,
    )
    method_ok, method_source = _gcash_payment_method_evidence(checkout, state)
    result["method_source"] = method_source
    result["custom_payment_method_id"] = method_id
    if method_id:
        result.update(
            {
                "available": True,
                "gcash_available": True,
                "status": "available",
                "reason": "custom_payment_method_found",
                "message": "GCash 可用：checkout state 已返回 GCash custom_payment_methods。",
            }
        )
        emit(f"GCash 资格探针: 可用，method={method_id} source={method_source or 'cpmt'}")
        return result
    if method_ok:
        result["reason"] = "gcash_type_without_cpmt"
        result["message"] = "GCash 可能可用：响应暴露 GCash 类型，但未返回可确认的 cpmt_*。"
    else:
        result["reason"] = "custom_payment_method_missing"
        result["message"] = "PH checkout 未发布 GCash custom_payment_methods。"
    emit(f"GCash 资格探针: 不可用，reason={result['reason']} source={method_source or '-'}")
    return result


def verify_gcash_checkout_status(
    access_token: str,
    cs_id: str,
    processor_entity: str = "",
    proxy: str = "",
    log: Any | None = None,
) -> dict[str, Any]:
    """Re-read the checkout state to infer whether the GCash flow is still pending or has progressed."""
    def emit(message: str) -> None:
        if log:
            log(message)
    entity = str(processor_entity or "openai_llc").strip() or "openai_llc"
    if not str(cs_id or "").strip():
        raise GCashExtractError("GCASH_VERIFY_MISSING_CHECKOUT_ID")
    chatgpt = build_chatgpt_session(access_token, proxy=proxy)
    emit(f"GCash 状态校验开始：{entity}/{cs_id}")
    state: dict[str, Any] = {}
    last_error = ""
    try:
        state = fetch_openai_checkout_state(chatgpt, cs_id, entity)
    except Exception as exc:
        last_error = short_error(str(exc))
        emit(f"Checkout JSON state read failed, fallback to HTML: {last_error}")
        try:
            response = chatgpt.get(
                f"https://chatgpt.com/checkout/{entity}/{cs_id}",
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": f"https://chatgpt.com/checkout/{entity}/{cs_id}",
                },
                timeout=CHATGPT_TIMEOUT,
            )
            if response.status_code < 400:
                state = checkout_state_from_html(response.text or "")
            else:
                last_error = f"http {response.status_code}: {response.text[:120]}"
        except Exception as html_exc:
            last_error = short_error(str(html_exc))
    summary = summarize_gcash_checkout_state(state, cs_id=cs_id, processor_entity=entity)
    summary["checked_at"] = int(time.time())
    summary["last_error"] = last_error
    account_id, email = _gcash_account_context(access_token)
    summary["account_id"] = account_id
    summary["email"] = email
    summary["subscription_plan"] = ""
    summary["subscription_status"] = 0
    summary["subscription_error"] = ""
    summary["monitor_success"] = False
    if account_id:
        try:
            subscription_state = fetch_gcash_subscription_state(chatgpt, account_id)
            subscription_plan = _jwt_text(subscription_state.get("_subscription_plan"))
            summary["subscription_plan"] = subscription_plan
            summary["subscription_status"] = int(subscription_state.get("_subscription_http_status") or 0)
            if subscription_plan.lower() == "plus":
                summary.update(
                    {
                        "stage": "paid",
                        "hint": "订阅接口已确认 Plus 到账",
                        "status_label": "订阅到账成功",
                        "payment_status": "paid",
                        "checkout_status": summary.get("checkout_status") or "subscription_plus",
                        "monitor_success": True,
                    }
                )
                emit(f"GCash 订阅校验成功：account_id={account_id} plan_type=plus")
            else:
                emit(f"GCash 订阅校验未到账：account_id={account_id} plan_type={subscription_plan or 'unknown'}")
        except Exception as exc:
            subscription_error = short_error(str(exc))
            summary["subscription_error"] = subscription_error
            emit(f"GCash 订阅状态读取失败：{subscription_error}")
    else:
        summary["subscription_error"] = "AT does not contain account_id"
        emit("GCash 订阅状态跳过：AT 中缺少 account_id")
    return summary


def poll_gcash_subscription_status(
    access_token: str,
    cs_id: str,
    processor_entity: str = "",
    proxy: str = "",
    timeout_seconds: int = 600,
    interval_seconds: float = 3.0,
    log: Any | None = None,
    stop_event: Any | None = None,
) -> dict[str, Any]:
    """Poll checkout + subscription state until ChatGPT reports plan_type=plus."""

    def emit(message: str) -> None:
        if log:
            log(message)

    deadline = time.time() + max(1, int(timeout_seconds or 600))
    interval = max(0.5, float(interval_seconds or 3.0))
    attempt = 0
    last_summary: dict[str, Any] = {}
    while time.time() <= deadline:
        if stop_event is not None and getattr(stop_event, "is_set", lambda: False)():
            last_summary = {
                **last_summary,
                "stage": "stopped",
                "payment_status": "monitor_stopped",
                "status_label": "订阅轮询已停止",
                "monitor_status": "stopped",
            }
            return last_summary
        attempt += 1
        try:
            last_summary = verify_gcash_checkout_status(
                access_token,
                cs_id,
                processor_entity,
                proxy=proxy,
                log=emit,
            )
        except Exception as exc:
            last_summary = {
                **last_summary,
                "last_error": short_error(str(exc)),
                "stage": "pending",
                "payment_status": "pending",
                "status_label": "等待订阅到账",
            }
            emit(f"GCash 订阅轮询第 {attempt} 次读取失败：{last_summary['last_error']}")
        last_summary["monitor_attempt"] = attempt
        last_summary["monitor_status"] = "success" if last_summary.get("monitor_success") else "running"
        last_summary["monitor_deadline_at"] = int(deadline)
        if last_summary.get("monitor_success") or str(last_summary.get("subscription_plan") or "").lower() == "plus":
            return {
                **last_summary,
                "monitor_status": "success",
                "payment_status": "paid",
                "stage": "paid",
                "status_label": "订阅到账成功",
            }
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        time.sleep(min(interval, max(0.1, remaining)))
    return {
        **last_summary,
        "stage": "monitor_timeout",
        "hint": "订阅轮询超时，未确认 Plus 到账",
        "status_label": "订阅轮询超时，未确认到账",
        "payment_status": "monitor_timeout",
        "checkout_status": last_summary.get("checkout_status") or "monitor_timeout",
        "monitor_status": "timeout",
        "monitor_success": False,
        "monitor_deadline_at": int(deadline),
    }
def extract_gcash_link(
    access_token: str,
    checkout_proxy: str = "",
    provider_proxy: str = "",
    stripe_pk: str = "",
    promo_mode: str = "campaign",
    require_zero: bool = True,
    log: Any | None = None,
    fingerprint_profile: dict[str, Any] | None = None,
    device_id: str = "",
) -> dict[str, Any]:
    """
    完整的 GCash 提链流程：
    ChatGPT checkout → Stripe init → create GCash PM → confirm → 提取 redirect URL。

    返回字典包含 gcash_url、pm_id 等。
    """

    def emit(message: str) -> None:
        if log:
            log(message)

    effective_stripe_pk = stripe_pk.strip() or DEFAULT_STRIPE_PK
    fingerprint = dict(fingerprint_profile or {}) if isinstance(fingerprint_profile, dict) else {}
    runtime_device_id = _text(device_id) or _fingerprint_header_value(fingerprint, "device_id")
    if fingerprint:
        emit(f"GCash 指纹：{_gcash_fingerprint_label(fingerprint, runtime_device_id)}")
    if not require_zero:
        # 原价链：不建优惠单、不做优惠更新，金额按账号当前资格结算。
        if str(promo_mode or "").strip().lower() != "none":
            emit(f"GCash 原价链：忽略 promo_mode={promo_mode}，改用无优惠建单（promo_mode=none）。")
        promo_mode = "none"
        emit(f"GCash 提链类型=原价链：不应用 {PLUS_TRIAL_PROMO_ID} 优惠。")

    # Step 1: 先校验 AT，再创建 ChatGPT checkout。
    # 1key 的 GCash 成功路径是“PH 优惠代理直接创建 Checkout”，所以默认优先
    # 在首次 PH/PHP checkout 就带上优惠；只有创建阶段明确失败时才回退到旧的
    # “纯 PH 建单 + Pool 2 checkout/update”分流路径。
    chatgpt = build_chatgpt_session(
        access_token,
        proxy=checkout_proxy,
        device_id=runtime_device_id,
        fingerprint_profile=fingerprint,
        log=emit,
    )
    browser_ok, browser_detail = _warmup_gcash_browser_page(
        chatgpt,
        access_token,
        device_id=str(chatgpt.headers.get("oai-device-id") or runtime_device_id or ""),
        page_url="https://chatgpt.com/",
        log=emit,
    )
    if browser_ok:
        emit(f"GCash 阶段[浏览器暖身]: 成功，{browser_detail}.")
    elif browser_detail != "disabled":
        emit(f"GCash 阶段[浏览器暖身]: 未完成，继续 HTTP 流程：{browser_detail}")
    preflight_gcash_access_token(chatgpt, log=emit)
    promo_applied_in_checkout = False
    if not require_zero:
        emit("GCash 阶段[Checkout]: 使用代理池 1 创建 PH/PHP 原价 checkout（不带 promo_campaign）.")
        checkout = create_checkout(chatgpt, promo_mode="none")
    elif promo_mode == "off":
        emit("GCash 阶段[Checkout]: 使用代理池 1 创建 PH/PHP checkout session（promo_mode=off）.")
        checkout = create_checkout(chatgpt, promo_mode="off")
    else:
        try:
            emit("GCash 阶段[Checkout]: 使用代理池 1 直接创建 PH/PHP 优惠 checkout（对齐 1key）.")
            checkout = create_checkout(chatgpt, promo_mode=promo_mode)
            promo_applied_in_checkout = True
            emit("GCash 阶段[Checkout]: 优惠 Checkout 已创建.")
        except GCashExtractError as exc:
            if not _should_fallback_direct_promo_checkout(exc):
                raise
            emit(
                "GCash 阶段[Checkout]: PH 优惠 Checkout 创建失败，"
                f"回退为纯 PH 建单 + Pool 2 优惠更新：{short_error(str(exc))}"
            )
            checkout = create_checkout(chatgpt, promo_mode="none")
    cs_id = checkout["cs_id"]
    emit(f"GCash 阶段[Checkout]: checkout 创建成功: {cs_id}, PH/PHP.")
    emit(diagnostic_summary("GCash DIAG[checkout]", checkout))
    promo_ok, promo_source = _promo_qualification_evidence(checkout)
    if promo_ok:
        emit(f"GCash 资格[优惠]: checkout 已命中 {PLUS_TRIAL_PROMO_ID}（source={promo_source}），后续仍以明确 0 金额为准.")
    else:
        emit(f"GCash 资格[优惠]: checkout 未返回 {PLUS_TRIAL_PROMO_ID}，继续检查 taxes/final 是否已有自动 0 元.")
    method_ok, method_source = _gcash_payment_method_evidence(checkout)
    if method_ok:
        emit(f"GCash 资格[方法]: checkout 已暴露 GCash payment method（source={method_source}）.")
    checkout_provider = str(checkout.get("checkout_provider") or "").strip().lower()
    if checkout_provider != "open_ai" or not cs_id.startswith("oaics_"):
        if method_ok:
            emit(
                "GCash 资格[方法]: checkout 虽然暴露了 GCash 相关字段，"
                f"但 provider={checkout_provider or 'unknown'} / cs_id={cs_id} 不是 oaics_*，直接判定 GCash 不可用."
            )
        else:
            emit(
                "GCash 资格[方法]: checkout 未返回 OpenAI 自定义 GCash 入口，"
                f"provider={checkout_provider or 'unknown'} / cs_id={cs_id}，直接判定 GCash 不可用."
            )
        raise GCashExtractError(
            "GCASH_METHOD_UNAVAILABLE: PH checkout did not return an oaics_* OpenAI custom checkout; "
            f"provider={checkout_provider or 'unknown'}; cs_id={cs_id}"
        )
    main_chatgpt = chatgpt
    promo_update_chatgpt = chatgpt
    if promo_applied_in_checkout:
        emit("GCash 路由: 代理池 1=PH 优惠 Checkout/Taxes/Confirm/Start; 代理池 2=checkout/update 兜底未启用.")
    elif normalize_proxy_url(provider_proxy) and normalize_proxy_url(provider_proxy) != normalize_proxy_url(checkout_proxy):
        promo_update_chatgpt = build_chatgpt_session(
            access_token,
            proxy=provider_proxy,
            device_id=str(chatgpt.headers.get("oai-device-id") or ""),
            user_agent=str(chatgpt.headers.get("User-Agent") or DEFAULT_USER_AGENT),
            fingerprint_profile=fingerprint,
            log=emit,
        )
        emit("GCash 路由: 代理池 1=Checkout/Taxes/Confirm/Start; 代理池 2=仅优惠 checkout/update.")

    if checkout.get("stripe_publishable_key"):
        effective_stripe_pk = str(checkout["stripe_publishable_key"]).strip() or effective_stripe_pk
        emit("使用 checkout 响应中的 Stripe publishable key。")

    # 如果是 OpenAI 的自研 Adyen 渠道，执行 OpenAI / Adyen 专属流程
    if checkout_provider == "open_ai":
        emit("检测到 OpenAI 内部支付渠道，切换 GCash 专用流程。")
        if not cs_id.startswith("oaics_"):
            raise GCashExtractError(
                f"GCASH_CHECKOUT_ID_INVALID: OpenAI checkout_session_id 不是 oaics_*：{cs_id[:80]}"
            )
        processor_entity = str(checkout.get("processor_entity") or "openai_llc").strip() or "openai_llc"
        checkout_state: dict[str, Any] = {}
        update_payload: dict[str, Any] = {}
        taxes_payload: dict[str, Any] = {}

        billing = billing_for_ph()
        emit(f"PH billing generated: {billing['name']} / {billing['city']} / {billing['email']}")
        try:
            checkout_state = fetch_openai_checkout_state(main_chatgpt, cs_id, processor_entity)
            emit(diagnostic_summary("GCash DIAG[initial_state]", checkout_state))
            promo_ok, promo_source = _promo_qualification_evidence(checkout_state)
            if promo_ok:
                emit(f"GCash 资格[优惠]: initial_state 已命中 {PLUS_TRIAL_PROMO_ID}（source={promo_source}）.")
            method_ok, method_source = _gcash_payment_method_evidence(checkout_state)
            if method_ok:
                emit(f"GCash 资格[方法]: initial_state 已暴露 GCash payment method（source={method_source}）.")
        except Exception as exc:
            emit(f"Initial checkout state read failed; will retry after taxes: {short_error(str(exc))}")

        if not require_zero:
            emit("GCash 阶段[优惠更新]: 原价链跳过 Pool 2 checkout/update，保持正价金额.")
            update_payload = {}
        elif promo_applied_in_checkout:
            emit("GCash 阶段[优惠更新]: 已在 PH 优惠 Checkout 创建阶段触发优惠，跳过 Pool 2 checkout/update.")
            update_payload = {}
        else:
            update_payload = apply_gcash_promotion_update(
                promo_update_chatgpt,
                cs_id=cs_id,
                processor_entity=processor_entity,
                promo_mode=promo_mode,
                emit=emit,
            )

        emit("GCash 阶段[确认准备]: 使用代理池 1 提交 taxes, 账单 PH/PHP.")
        taxes_url = "https://chatgpt.com/backend-api/payments/checkout/taxes"
        main_chatgpt.headers["x-openai-target-path"] = "/backend-api/payments/checkout/taxes"
        main_chatgpt.headers["x-openai-target-route"] = "/backend-api/payments/checkout/taxes"
        main_chatgpt.headers["Referer"] = f"https://chatgpt.com/checkout/{processor_entity}/{cs_id}"
        billing_address = {
            "line1": billing["line1"],
            "city": billing["city"],
            "country": "PH",
            "postal_code": billing["postal_code"],
        }
        if billing.get("state"):
            billing_address["state"] = billing["state"]
        taxes_body = {
            "checkout_session_id": cs_id,
            "checkout_email": billing["email"],
            "billing_country": "PH",
            "billing_name": billing["name"],
            "currency": "PHP",
            "tax_id": None,
            "processor_entity": processor_entity,
            "billing_address": billing_address,
        }
        resp_taxes = main_chatgpt.post(taxes_url, json=taxes_body, timeout=CHATGPT_TIMEOUT)
        emit(diagnostic_summary("GCash DIAG[taxes_response]", None, status_code=resp_taxes.status_code))
        if resp_taxes.status_code >= 400:
            raise GCashExtractError(f"Taxes submit failed HTTP {resp_taxes.status_code}: {resp_taxes.text[:500]}")
        try:
            taxes_payload = resp_taxes.json() or {}
        except Exception:
            taxes_payload = {}
        _require_openai_payload_ok(taxes_payload, "TAXES")
        emit("GCash 阶段[确认准备]: taxes 成功, 读取 GCash payment method.")
        promo_ok, promo_source = _promo_qualification_evidence(taxes_payload)
        if promo_ok:
            emit(f"GCash 资格[优惠]: taxes 已命中 {PLUS_TRIAL_PROMO_ID}（source={promo_source}）.")
        method_ok, method_source = _gcash_payment_method_evidence(taxes_payload)
        if method_ok:
            emit(f"GCash 资格[方法]: taxes 已暴露 GCash payment method（source={method_source}）.")
        amount, amount_source = _explicit_openai_amount((taxes_payload, taxes_payload.get("checkout_session") if isinstance(taxes_payload, dict) else {}))
        if _amount_is_nonzero(amount):
            raise GCashExtractError(
                "GCASH_TAXES_AMOUNT_NONZERO: taxes 已返回成功，但应付金额仍非 0："
                f"amount={amount}, source={amount_source}"
            )

        elements_payload: dict[str, Any] = {}
        customer_session_client_secret = (
            _extract_customer_session_client_secret(checkout)
            or _extract_customer_session_client_secret(checkout_state)
            or _extract_customer_session_client_secret(update_payload)
            or _extract_customer_session_client_secret(taxes_payload)
        )
        stripe_pk_for_custom = (
            _extract_stripe_publishable_key(checkout)
            or _extract_stripe_publishable_key(checkout_state)
            or _extract_stripe_publishable_key(update_payload)
            or _extract_stripe_publishable_key(taxes_payload)
            or effective_stripe_pk
        )
        cpm_id = extract_custom_payment_method_id(
            checkout,
            checkout_state,
            update_payload,
            taxes_payload,
            taxes_payload.get("checkout_session") if isinstance(taxes_payload, dict) else {},
            require_gcash_context=True,
        )
        if customer_session_client_secret and stripe_pk_for_custom:
            try:
                emit(
                    "GCash 阶段[Elements]: 先按浏览器流程请求 Stripe "
                    "v1/elements/sessions，确认 custom_payment_method_data."
                )
                _elements_stripe, elements_payload, _elements_js_id = _openai_elements_session(
                    cs_id,
                    stripe_pk_for_custom,
                    customer_session_client_secret,
                    custom_payment_method_type_id=cpm_id,
                    proxy=checkout_proxy,
                    user_agent=str(main_chatgpt.headers.get("User-Agent") or DEFAULT_USER_AGENT),
                    fingerprint_profile=fingerprint,
                    log=emit,
                )
                emit(diagnostic_summary("GCash DIAG[elements_session]", elements_payload))
                elements_cpm_id = extract_custom_payment_method_id(
                    elements_payload,
                    require_gcash_context=True,
                )
                if elements_cpm_id:
                    cpm_id = elements_cpm_id
                    emit(f"GCash 资格[方法]: Elements custom_payment_method_data 已发现 {cpm_id}.")
                elif _payload_has_gcash_payment_method(elements_payload):
                    emit("GCash 资格[方法]: Elements 响应暴露 GCash，但暂未返回可用 cpmt_*.")
            except Exception as exc:
                emit(f"GCash 阶段[Elements]: Stripe Elements 探测失败，继续现有状态轮询：{short_error(str(exc))}")
        for method_poll in range(1, 4):
            if cpm_id:
                break
            time.sleep(0.8 * method_poll)
            try:
                checkout_state = fetch_openai_checkout_state(main_chatgpt, cs_id, processor_entity)
                emit(diagnostic_summary(f"GCash DIAG[method_sync_{method_poll}]", checkout_state))
                cpm_id = extract_custom_payment_method_id(
                    elements_payload,
                    checkout,
                    checkout_state,
                    update_payload,
                    taxes_payload,
                    require_gcash_context=True,
                )
                method_ok, method_source = _gcash_payment_method_evidence(
                    elements_payload,
                    checkout,
                    checkout_state,
                    update_payload,
                    taxes_payload,
                )
                status_text = "found" if cpm_id else ("gcash-type-no-cpmt" if method_ok else "pending")
                detail = f", source={method_source}" if method_ok and method_source else ""
                emit(f"GCash method sync check {method_poll}/3: {status_text}{detail}")
            except Exception as exc:
                emit(f"GCash method sync check {method_poll}/3 failed: {short_error(str(exc))}")
        if require_zero:
            _reject_explicit_nonzero_amount(
                update_payload,
                taxes_payload,
                taxes_payload.get("checkout_session") if isinstance(taxes_payload, dict) else {},
                checkout_state,
                stage="CONFIRM_PRECHECK",
            )
            _reject_observed_nonzero_checkout_amount(checkout_state, stage="CONFIRM_PRECHECK")
        else:
            amount, amount_source = _diagnostic_amount(checkout_state)
            if not amount:
                amount, amount_source = _diagnostic_amount(taxes_payload)
            emit(
                f"GCash 原价链[金额]: amount={amount or 'unknown'}, "
                f"source={amount_source or '-'}；不拦截非 0 金额."
            )
        if not cpm_id:
            method_ok, method_source = _gcash_payment_method_evidence(
                checkout,
                checkout_state,
                elements_payload,
                update_payload,
                taxes_payload,
                taxes_payload.get("checkout_session") if isinstance(taxes_payload, dict) else {},
            )
            if method_ok:
                raise GCashExtractError(
                    "GCASH_METHOD_ID_UNAVAILABLE: checkout 已暴露 GCash payment_method_types/"
                    f"custom_payment_methods（source={method_source}），但未同步可用于确认的 cpmt_*；"
                    "已停止 confirm/start，避免返回不可支付链。请重试或更换代理。"
                )
            raise GCashExtractError(
                "GCASH_METHOD_UNAVAILABLE: PH checkout did not expose a GCash payment method. "
                "Usually the account lacks GCash/zero-amount eligibility, the PH exit is unstable, "
                "or upstream hid GCash for this proxy; retry with another PH/US-quality proxy or account."
            )
        emit(f"GCash payment method found: {cpm_id}")
        stripe_payment_method_id = ""
        device_id = main_chatgpt.headers.get("oai-device-id") or str(uuid.uuid4())
        user_agent = main_chatgpt.headers.get("User-Agent") or DEFAULT_USER_AGENT
        if customer_session_client_secret and stripe_pk_for_custom:
            try:
                emit("GCash 阶段[PaymentMethod]: 按文档初始化 Stripe Elements 并创建 custom PaymentMethod.")
                stripe_payment_method_id = stripe_create_openai_custom_payment_method(
                    cs_id,
                    stripe_pk_for_custom,
                    customer_session_client_secret,
                    cpm_id,
                    billing,
                    proxy=checkout_proxy,
                    user_agent=str(user_agent),
                    fingerprint_profile=fingerprint,
                    log=emit,
                )
                emit(f"GCash 阶段[PaymentMethod]: Stripe custom PaymentMethod 创建成功: {stripe_payment_method_id}.")
            except Exception as exc:
                emit(
                    "GCash 阶段[PaymentMethod]: Stripe custom PaymentMethod 创建失败，"
                    f"回退 cpmt_* OpenAI custom 路径：{short_error(str(exc))}"
                )
        else:
            emit("GCash 阶段[PaymentMethod]: checkout 未返回完整 Stripe customer session，沿用 cpmt_* OpenAI custom 路径.")
        emit("GCash 阶段[确认]: 使用代理池 1 请求 payments/checkout/confirm（保持 checkout 页面路由）.")
        confirm_url = "https://chatgpt.com/backend-api/payments/checkout/confirm"
        confirm_headers = _checkout_page_route_headers(processor_entity, cs_id)
        confirm_body = {
            "checkout_session_id": cs_id,
            "selected_payment_method_type": cpm_id,
        }
        if stripe_payment_method_id:
            confirm_body["payment_method"] = stripe_payment_method_id

        def post_confirm() -> Any:
            token_value = build_sentinel_token(access_token, device_id, user_agent, main_chatgpt)
            headers = dict(confirm_headers)
            headers["openai-sentinel-token"] = token_value
            headers["OpenAI-Sentinel-Token"] = token_value
            headers["OAI-Telemetry"] = "[1,null]"
            return main_chatgpt.post(
                confirm_url,
                json=confirm_body,
                headers=headers,
                timeout=CHATGPT_TIMEOUT,
            )

        resp_confirm = post_confirm()
        emit(diagnostic_summary("GCash DIAG[confirm_response]", None, status_code=resp_confirm.status_code))
        emit(f"Confirm Response: {resp_confirm.status_code} - {resp_confirm.text[:500]}")
        if resp_confirm.status_code >= 400:
            raise GCashExtractError(f"Confirm failed HTTP {resp_confirm.status_code}: {resp_confirm.text[:500]}")
        try:
            confirm_data = resp_confirm.json() or {}
        except Exception:
            confirm_data = {}
        emit(diagnostic_summary("GCash DIAG[confirm_data]", confirm_data, status_code=resp_confirm.status_code))
        confirm_state = str(confirm_data.get("status") or confirm_data.get("result") or "").strip().lower()
        if confirm_state == "blocked":
            emit(
                "GCash confirm returned blocked；丢弃当前 Checkout/PaymentMethod/跳转链，"
                "由外层切换 PH 代理与指纹后重建完整流程。"
            )
            raise _gcash_attempt_blocked_error(confirm_data, checkout_state)
        else:
            _require_openai_payload_ok(confirm_data, "CONFIRM")
        emit("GCash 阶段[确认]: checkout/confirm 成功.")
        confirm_return_url = (
            _find_chatgpt_confirm_return_url(confirm_data)
            or _chatgpt_success_return_url(cs_id, processor_entity)
        )
        if "chatgpt.com/checkout/verify" not in confirm_return_url:
            raise GCashExtractError(
                "GCASH_CONFIRM_RETURN_URL_MISSING: confirm 未返回有效 ChatGPT verify 短链"
            )

        emit("GCash 阶段[确认]: 使用代理池 1 请求 custom_payment_method/start（保持 checkout 页面路由）.")
        start_url = "https://chatgpt.com/backend-api/payments/checkout/custom_payment_method/start"
        start_headers = _checkout_page_route_headers(processor_entity, cs_id)
        start_body = {
            "checkout_session_id": cs_id,
            "custom_payment_method_type_id": cpm_id,
        }
        if stripe_payment_method_id:
            start_body["payment_method"] = stripe_payment_method_id
        resp_start = main_chatgpt.post(
            start_url,
            json=start_body,
            headers=start_headers,
            timeout=CHATGPT_TIMEOUT,
        )
        emit(diagnostic_summary("GCash DIAG[start_response]", None, status_code=resp_start.status_code))
        if resp_start.status_code >= 400:
            raise GCashExtractError(f"Start failed HTTP {resp_start.status_code}: {resp_start.text[:500]}")
        try:
            start_data = resp_start.json() or {}
        except Exception as exc:
            raise GCashExtractError(
                f"GCASH_START_INVALID_JSON: {short_error(str(exc))}"
            ) from exc
        _require_openai_payload_ok(start_data, "START")
        emit(diagnostic_summary("GCash DIAG[start_data]", start_data, status_code=resp_start.status_code))
        adyen_url = extract_redirect_url_from_json(start_data)
        if not adyen_url:
            adyen_url = extract_redirect_url_from_json(confirm_data)
        if not adyen_url and confirm_return_url:
            emit("GCash 阶段[确认]: start 未直接返回跳转，尝试解析 ChatGPT verify 短链。")
            try:
                adyen_url = resolve_gcash_verification_redirect(main_chatgpt, confirm_return_url)
            except Exception as exc:
                emit(f"GCash verify 短链解析失败：{short_error(str(exc))}")
        if not adyen_url:
            raise GCashExtractError(f"Could not extract redirect URL from start response: {str(start_data)[:700]}")
        if not _is_valid_openai_gcash_redirect(adyen_url):
            raise GCashExtractError(
                f"GCASH_REDIRECT_URL_INVALID: start 未返回 Adyen/GCash 跳转地址：{adyen_url[:240]}"
            )
        emit(f"GCash redirect extracted: {adyen_url}")
        gcash_url = adyen_url
        try:
            final_gcash = resolve_external_redirect(main_chatgpt, adyen_url)
            if final_gcash:
                gcash_url = final_gcash
        except Exception as exc:
            emit(f"Redirect follow failed; using original redirect URL: {short_error(str(exc))}")
        qr_image, qr_image_status = fetch_gcash_qr_image_data_url(
            main_chatgpt,
            gcash_url,
            referer=adyen_url,
            log=emit,
        )
        if qr_image:
            emit("GCash 阶段[二维码]: 已从最终授权页提取二维码图片 Data URL.")
        else:
            emit(f"GCash 阶段[二维码]: 未提取到页面二维码图片（{qr_image_status}），保留授权链接返回.")
        final_checkout_state = fetch_openai_checkout_state(
            main_chatgpt,
            cs_id,
            processor_entity,
        )
        _require_openai_payload_ok(final_checkout_state, "FINAL_STATE")
        emit(diagnostic_summary("GCash DIAG[final_state]", final_checkout_state))
        if require_zero:
            _validate_zero_amount_evidence(
                update_payload,
                taxes_payload,
                checkout_state,
                confirm_data,
                start_data,
                final_checkout_state,
                stage="FINAL",
            )
        else:
            amount, amount_source = _diagnostic_amount(final_checkout_state)
            if not amount:
                amount, amount_source = _diagnostic_amount(start_data)
            emit(
                f"GCash 原价链[金额]: amount={amount or 'unknown'}, "
                f"source={amount_source or '-'}；正价链不做 0 金额校验."
            )
        primary_url = adyen_url or gcash_url
        emit(f"GCash extraction completed: shopper={primary_url}; gcash={gcash_url}")
        return {
            "ok": True,
            "gcash_url": gcash_url,
            "link": gcash_url or primary_url,
            "checkout_link": primary_url,
            "checkout_url": primary_url,
            "url": primary_url,
            "cs_id": cs_id,
            "pm_id": cpm_id,
            "custom_payment_method_id": cpm_id,
            "stripe_payment_method_id": stripe_payment_method_id,
            "stripe_redirect_url": adyen_url,
            "shopper_redirect_url": primary_url,
            "gcash_auth_url": gcash_url if gcash_url and gcash_url != primary_url else "",
            "stripe_hosted_url": "",
            "billing_country": "PH",
            "currency": "PHP",
            "payment_method": "gcash",
            "payment_method_type": "gcash",
            "zero": bool(require_zero),
            "require_zero": bool(require_zero),
            "link_type": "gcash_protocol",
            "checkout_ui_mode": "custom",
            "qr_image": qr_image,
            "qr_image_status": qr_image_status,
            "extra": {
                "payment_method": "gcash",
                "payment_method_type": "gcash",
                "link_type": "gcash_protocol",
                "checkout_ui_mode": "custom",
                "qr_image": qr_image,
                "qr_image_status": qr_image_status,
            },
            "processor_entity": processor_entity,
            "checkout_provider": "open_ai",
            "short_link": confirm_return_url,
            "confirm_return_url": confirm_return_url,
            "verification_url": confirm_return_url,
            "checkout_page_url": f"https://chatgpt.com/checkout/{processor_entity}/{cs_id}",
            "checkout_status": "open_ai_pending",
            "payment_status": "pending",
            "fingerprint": {
                "mode": _fingerprint_header_value(fingerprint, "mode"),
                "fingerprint_id": _fingerprint_header_value(fingerprint, "fingerprint_id"),
                "device_id": str(main_chatgpt.headers.get("oai-device-id") or runtime_device_id or ""),
                "tls_impersonate": _fingerprint_header_value(fingerprint, "tls_impersonate"),
                "language": _fingerprint_header_value(fingerprint, "oai_language", "language"),
                "timezone": _fingerprint_header_value(fingerprint, "timezone", "timezone_id"),
                "region": _fingerprint_header_value(fingerprint, "region", default="PH"),
            },
        }

    processor_entity = str(checkout.get("processor_entity") or "openai_llc").strip() or "openai_llc"
    if not require_zero:
        emit("GCash 阶段[优惠更新]: 原价链跳过 Pool 2 checkout/update，保持正价金额.")
    elif promo_applied_in_checkout:
        emit("GCash 阶段[优惠更新]: 已在 PH 优惠 Checkout 创建阶段触发优惠，跳过 Pool 2 checkout/update.")
    else:
        apply_gcash_promotion_update(
            promo_update_chatgpt,
            cs_id=cs_id,
            processor_entity=processor_entity,
            promo_mode=promo_mode,
            emit=emit,
        )

    # Step 2: Stripe init
    emit("步骤 2/5: 使用确认/支付代理请求 Stripe init.")
    stripe, init_payload = stripe_init(
        cs_id,
        effective_stripe_pk,
        proxy=provider_proxy,
        user_agent=str(main_chatgpt.headers.get("User-Agent") or DEFAULT_USER_AGENT),
        customer_session_client_secret=str(checkout.get("customer_session_client_secret") or ""),
        fingerprint_profile=fingerprint,
        log=emit,
    )
    stripe_hosted_url = str(init_payload.get("stripe_hosted_url") or "").strip()
    if not stripe_hosted_url:
        raise GCashExtractError(
            f"Stripe init 响应缺少 stripe_hosted_url，keys={sorted(init_payload.keys())}"
        )
    emit("Stripe init 成功。")

    # 检查金额
    if require_zero:
        ensure_zero_amount(init_payload)
        emit("金额检查通过：PHP 0.00。")
    else:
        amount, amount_source = _diagnostic_amount(init_payload)
        emit(
            f"GCash 原价链[金额]: amount={amount or 'unknown'}, "
            f"source={amount_source or '-'}；正价链不做 0 金额校验."
        )

    # Step 3: 创建 GCash payment method
    emit("步骤 3/5：创建 GCash payment_method（PH 账单资料）。")
    ctx = stripe_context(cs_id, init_payload)
    billing = billing_for_ph()
    emit(f"PH 账单资料：{billing['name']} / {billing['city']}。")
    pm_id = stripe_create_payment_method(stripe, cs_id, effective_stripe_pk, billing, ctx)
    emit(f"GCash payment_method 创建成功：{pm_id}。")

    # Step 4: Stripe confirm
    emit("步骤 4/5：请求 Stripe confirm。")
    confirm_payload = stripe_confirm(
        stripe, cs_id, pm_id, effective_stripe_pk,
        init_payload, ctx, checkout, stripe_hosted_url,
    )
    emit("Stripe confirm 已返回，正在解析 GCash redirect。")

    # Step 5: 提取 GCash redirect URL
    emit("步骤 5/5：解析/轮询 GCash redirect URL。")
    # 使用 checkout 代理构建 approve 用的 chatgpt session
    chatgpt_for_approve = build_chatgpt_session(
        access_token,
        proxy=checkout_proxy,
        device_id=str(main_chatgpt.headers.get("oai-device-id") or runtime_device_id),
        user_agent=str(main_chatgpt.headers.get("User-Agent") or DEFAULT_USER_AGENT),
        fingerprint_profile=fingerprint,
        log=emit,
    )
    stripe_redirect_url = redirect_url_after_confirm(
        chatgpt_for_approve, stripe, confirm_payload,
        cs_id, effective_stripe_pk, ctx, checkout, log=emit,
    )

    # 跟随重定向到最终 GCash URL
    gcash_url = (
        stripe_redirect_url
        if is_gcash_redirect_url(stripe_redirect_url)
        else resolve_external_redirect(stripe, stripe_redirect_url)
    )

    if not is_gcash_redirect_url(gcash_url) and not is_stripe_pm_redirect_url(gcash_url):
        emit(f"警告：未提取到 GCash 跳转链接，当前结果: {gcash_url or stripe_redirect_url}")

    final_url = stripe_redirect_url or gcash_url
    emit(f"✅ 提链完成：shopper={final_url}; gcash={gcash_url}")

    return {
        "gcash_url": gcash_url,
        "checkout_link": final_url,
        "checkout_url": final_url,
        "url": final_url,
        "cs_id": cs_id,
        "pm_id": pm_id,
        "custom_payment_method_id": pm_id,
        "stripe_redirect_url": stripe_redirect_url,
        "shopper_redirect_url": final_url,
        "gcash_auth_url": gcash_url if gcash_url and gcash_url != final_url else "",
        "stripe_hosted_url": stripe_hosted_url,
        "billing_country": "PH",
        "currency": "PHP",
        "processor_entity": checkout.get("processor_entity") or "openai_ie",
        "verification_url": final_url or f"https://chatgpt.com/checkout/{checkout.get('processor_entity') or 'openai_ie'}/{cs_id}",
        "checkout_status": "pending",
        "payment_status": "pending",
        "fingerprint": {
            "mode": _fingerprint_header_value(fingerprint, "mode"),
            "fingerprint_id": _fingerprint_header_value(fingerprint, "fingerprint_id"),
            "device_id": str(chatgpt_for_approve.headers.get("oai-device-id") or runtime_device_id or ""),
            "tls_impersonate": _fingerprint_header_value(fingerprint, "tls_impersonate"),
            "language": _fingerprint_header_value(fingerprint, "oai_language", "language"),
            "timezone": _fingerprint_header_value(fingerprint, "timezone", "timezone_id"),
            "region": _fingerprint_header_value(fingerprint, "region", default="PH"),
        },
    }


# ---------------------------------------------------------------------------
# QR 码生成
# ---------------------------------------------------------------------------


def render_qr_png(url: str, output_path: Path) -> None:
    if qrcode is None:
        raise RuntimeError("qrcode dependency is required for CLI QR output")
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)
    qr.make_image(fill_color="black", back_color="white").save(output_path)


def render_qr_svg(url: str, output_path: Path) -> None:
    if qrcode is None or SvgPathImage is None:
        raise RuntimeError("qrcode dependency is required for CLI QR output")
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)
    qr.make_image(image_factory=SvgPathImage).save(output_path)


def render_qr_png_data_uri(url: str) -> str:
    if qrcode is None:
        return ""
    value = str(url or "").strip()
    if not value:
        return ""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=12,
        border=4,
    )
    qr.add_data(value)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def write_outputs(result: dict[str, Any], output_dir: Path = OUTPUT_DIR) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    cs_id = str(result.get("cs_id") or "gcash")[:24]
    stem = f"gcash_{stamp}_{cs_id}"
    paths = {
        "json": output_dir / f"{stem}.json",
        "txt": output_dir / f"{stem}.txt",
        "png": output_dir / f"{stem}.png",
        "svg": output_dir / f"{stem}.svg",
    }
    gcash_url = str(result.get("gcash_url") or "")
    render_qr_png(gcash_url, paths["png"])
    render_qr_svg(gcash_url, paths["svg"])

    saved = dict(result)
    saved["generated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    saved["local_qr_png"] = str(paths["png"].resolve())
    saved["local_qr_svg"] = str(paths["svg"].resolve())
    paths["json"].write_text(
        json.dumps(saved, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    paths["txt"].write_text(
        "\n".join([
            f"GCash 跳转链接: {gcash_url}",
            f"checkout session: {result.get('cs_id') or ''}",
            f"payment method: {result.get('pm_id') or ''}",
            f"国家/货币: PH / PHP",
            f"processor_entity: {result.get('processor_entity') or ''}",
            "使用 ChatGPT → Stripe → GCash 提链流程提取。",
        ]),
        encoding="utf-8",
    )
    return paths


# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------


def configure_log() -> Path:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    return LOG_DIR / time.strftime("gcash_%Y%m%d-%H%M%S.log")


def emit_to_log(log_path: Path, message: str) -> None:
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}"
    try:
        print(line, flush=True)
    except UnicodeEncodeError:
        enc = sys.stdout.encoding or "gbk"
        try:
            print(line.encode(enc, errors="replace").decode(enc, errors="replace"), flush=True)
        except Exception:
            # Absolute fallback: strip out non-ascii
            print(line.encode("ascii", errors="replace").decode("ascii", errors="replace"), flush=True)
    with log_path.open("a", encoding="utf-8") as stream:
        stream.write(line + "\n")


# ---------------------------------------------------------------------------
# CLI 入口
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="通过 ChatGPT access token → Stripe → GCash 提链流程提取 GCash 支付跳转链接"
    )
    parser.add_argument("--access-token", default="", help="ChatGPT access token")
    parser.add_argument("--token-file", default="", help="从文件读取 access token")
    parser.add_argument("--checkout-proxy", default="", help="Checkout 阶段代理")
    parser.add_argument("--provider-proxy", default="", help="优惠更新阶段代理 (仅 checkout/update)")
    parser.add_argument("--stripe-pk", default="", help="Stripe publishable key（可选）")
    parser.add_argument(
        "--promo-mode", default="campaign",
        choices=["query", "campaign", "coupon", "code", "off"],
        help="促销模式",
    )
    return parser


def read_access_token(args: argparse.Namespace) -> str:
    token = str(args.access_token or "").strip()
    if token:
        return token
    token_file = str(args.token_file or "").strip()
    if not token_file:
        token_file = str(GCASH_DIR / "token.txt")
    token_path = Path(token_file)
    if token_path.is_file():
        token = token_path.read_text(encoding="utf-8", errors="ignore").strip()
    if not token:
        token = os.environ.get("PP_ACCESS_TOKEN", "").strip()
    if not token:
        token = os.environ.get("PP_TOKEN", "").strip()
    return token


def load_checkout_proxy() -> str:
    # 查找可能的 Checkout .json 位置
    paths = [
        Path("Checkout .json"),
        Path("Checkout.json"),
        Path(__file__).resolve().parent / "Checkout .json",
        Path(__file__).resolve().parent.parent / "脚本" / "Checkout .json",
        Path(__file__).resolve().parent.parent / "Checkout .json",
    ]
    for p in paths:
        if p.is_file():
            try:
                content = p.read_text(encoding="utf-8", errors="ignore").strip()
                if content.startswith("["):
                    proxies = json.loads(content)
                else:
                    proxies = [line.strip() for line in content.splitlines() if line.strip()]
                # 过滤注释或无效行
                proxies = [item for item in proxies if item and not item.startswith("#")]
                if proxies:
                    # 随机打乱以获得均匀分布，并测试可用性
                    random.shuffle(proxies)
                    for p_str in proxies[:15]:
                        p_str = p_str.strip()
                        if not p_str or p_str.startswith("#"):
                            continue
                        if p_str.startswith("socks5://"):
                            p_url = "socks5h://" + p_str.split("://", 1)[1]
                        else:
                            p_url = p_str
                        try:
                            # 快速测试连通性
                            resp = requests.get(
                                "https://httpbin.org/ip",
                                proxies={"http": p_url, "https": p_url},
                                timeout=2.5
                            )
                            if resp.status_code == 200:
                                return p_str
                        except Exception:
                            pass
            except Exception:
                pass
    return ""


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
    args = build_parser().parse_args(argv)
    log_path = configure_log()

    def log(message: str) -> None:
        emit_to_log(log_path, message)

    try:
        access_token = read_access_token(args)
        if not access_token:
            raise GCashExtractError(
                "请提供 access token：--access-token 参数、token.txt 文件或 PP_ACCESS_TOKEN 环境变量"
            )

        # 默认自动从 Checkout .json 加载代理
        default_proxy = load_checkout_proxy()

        checkout_proxy = normalize_proxy_url(
            args.checkout_proxy or os.environ.get("PP_CHECKOUT_PROXY", "") or default_proxy
        )
        provider_proxy = normalize_proxy_url(
            args.provider_proxy or os.environ.get("PP_PROVIDER_PROXY", "") or default_proxy
        )
        if not provider_proxy:
            provider_proxy = checkout_proxy

        log("开始执行 GCash 提链流程：ChatGPT → Stripe → GCash，PH/PHP。")
        if checkout_proxy:
            log(f"Checkout 代理：{checkout_proxy[:40]}...")
        if provider_proxy:
            log(f"优惠更新代理: {provider_proxy[:40]}...")

        result = extract_gcash_link(
            access_token,
            checkout_proxy=checkout_proxy,
            provider_proxy=provider_proxy,
            stripe_pk=args.stripe_pk,
            promo_mode=args.promo_mode,
            log=log,
        )

        paths = write_outputs(result)
        log("GCash 跳转链接与 QR 码已保存。")
        log(f"日志: {log_path.resolve()}")

        print("\n========== GCash 提链结果 ==========", flush=True)
        print(f"GCash URL: {result['gcash_url']}", flush=True)
        for label, path in paths.items():
            print(f"{label.upper()}: {path.resolve()}", flush=True)
        return 0
    except Exception as exc:
        log(f"[ERROR] {exc}")
        print(f"日志: {log_path.resolve()}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
