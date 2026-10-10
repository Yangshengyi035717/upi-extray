from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Any

import requests

try:
    from curl_cffi.requests import Session as CurlCffiSession  # type: ignore
except ImportError:  # pragma: no cover - optional runtime dependency
    CurlCffiSession = None  # type: ignore

SESSION_URL = "https://chatgpt.com/api/auth/session"
COOKIE_NAME = "__Secure-next-auth.session-token"
MAX_COOKIE_CHUNK_SIZE = 3900
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
)


@dataclass(frozen=True)
class SessionCredential:
    session_token: str
    access_token: str
    account_id: str = ""
    email: str = ""
    name: str = ""
    expires: str = ""


def _text(value: Any) -> str:
    return str(value or "").strip()


def _compact_error(value: Any, limit: int = 260) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _decode_claims(token: str) -> dict[str, Any]:
    parts = _text(token).split(".")
    if len(parts) < 2 or not parts[1]:
        return {}
    raw = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(raw.encode("ascii")))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def account_context_from_access_token(token: str) -> tuple[str, str]:
    claims = _decode_claims(token)
    auth = claims.get("https://api.openai.com/auth")
    profile = claims.get("https://api.openai.com/profile")
    account_id = ""
    email = ""
    if isinstance(auth, dict):
        account_id = _text(auth.get("chatgpt_account_id") or auth.get("account_id"))
    account_id = account_id or _text(claims.get("chatgpt_account_id") or claims.get("account_id"))
    if isinstance(profile, dict):
        email = _text(profile.get("email"))
    email = email or _text(claims.get("email"))
    return account_id, email


def _claim_number(claims: dict[str, Any], key: str) -> float:
    """把 JWT 数值声明读成 float；缺失或非法一律返回 0。"""
    try:
        return float(claims.get(key) or 0)
    except (TypeError, ValueError):
        return 0.0


def access_token_inspect(token: str) -> dict[str, Any]:
    """纯本地解析 AT 的身份与有效期，不发任何网络请求。

    ChatGPT access token 是 RS256 JWT，``exp`` 由签发方固定为 iat+10 天。
    OpenAI 在 checkout 第一步就会用 ``token_expired`` 拒绝过期 AT，因此过期
    账号在提链链路里 100% 失败——但失败发生在「已经分配好代理 Seed、已经占住
    并发槽」之后，等于纯烧代理。这里把有效期前置成可本地判定的元数据。
    """
    claims = _decode_claims(token)
    if not claims:
        return {"ok": False, "reason": "AT_NOT_JWT", "exp": 0.0, "iat": 0.0}
    auth = claims.get("https://api.openai.com/auth")
    auth = auth if isinstance(auth, dict) else {}
    account_id, email = account_context_from_access_token(token)
    exp = _claim_number(claims, "exp")
    iat = _claim_number(claims, "iat")
    return {
        "ok": bool(exp),
        "reason": "" if exp else "AT_NO_EXP_CLAIM",
        "exp": exp,
        "iat": iat,
        "email": email,
        "account_id": account_id,
        "plan": _text(auth.get("chatgpt_plan_type")),
    }


def access_token_expiry(token: str) -> float:
    """返回 AT 的 ``exp``（Unix 秒）；无法判定时返回 0（调用方应放行）。"""
    return float(access_token_inspect(token).get("exp") or 0.0)


def _find_key(payload: Any, keys: set[str]) -> str:
    seen: set[int] = set()

    def walk(value: Any, depth: int = 0) -> str:
        if depth > 8:
            return ""
        if isinstance(value, dict):
            marker = id(value)
            if marker in seen:
                return ""
            seen.add(marker)
            for key, item in value.items():
                if str(key or "").strip() in keys and isinstance(item, str) and item.strip():
                    return item.strip()
            for item in value.values():
                found = walk(item, depth + 1)
                if found:
                    return found
        elif isinstance(value, list):
            marker = id(value)
            if marker in seen:
                return ""
            seen.add(marker)
            for item in value[:100]:
                found = walk(item, depth + 1)
                if found:
                    return found
        return ""

    return walk(payload)


def clean_session_token(raw: Any) -> str:
    """Extract a ChatGPT NextAuth session token from gptsession-style input."""
    text = _text(raw)
    if not text:
        return ""
    if text.lstrip().startswith(("{", "[")):
        try:
            payload = json.loads(text)
        except Exception:
            payload = None
        if payload is not None:
            found = _find_key(payload, {"sessionToken", "session_token"})
            if found:
                return clean_session_token(found)
    text = text.strip().strip('"\'`')
    chunk_matches = re.findall(
        r"__Secure-next-auth\.session-token\.(\d+)\s*=\s*([^;\s]+)",
        text,
        flags=re.I,
    )
    if chunk_matches:
        chunks = sorted((int(index), value.strip().strip('"\'`')) for index, value in chunk_matches)
        if chunks and chunks[0][0] == 0:
            return "".join(value for _index, value in chunks)
    single_cookie = re.search(
        r"__Secure-next-auth\.session-token\s*=\s*([^;\s]+)",
        text,
        flags=re.I,
    )
    if single_cookie:
        return single_cookie.group(1).strip().strip('"\'`')
    text = re.sub(r"^__Secure-next-auth\.session-token(?:\.\d+)?\s*=\s*", "", text, flags=re.I)
    text = text.split(";", 1)[0].strip()
    match = re.search(r"eyJ[A-Za-z0-9_.-]+", text)
    return match.group(0).strip() if match else text


def is_probable_session_token(value: Any) -> bool:
    """Return True for the NextAuth JWE/JWT shapes accepted by gptsession."""
    token = clean_session_token(value)
    if len(token) < 20 or not token.startswith("eyJ"):
        return False
    parts = token.split(".")
    if len(parts) not in {3, 5}:
        return False
    # JWE used by ChatGPT has an empty encrypted-key segment:
    # eyJ... .. iv . ciphertext . tag.  Three-part access tokens are treated as
    # access tokens unless their payload is not decodable like a normal JWT.
    if len(parts) == 3:
        return all(parts) and not account_context_from_access_token(token)[0]
    return bool(parts[0] and parts[2] and parts[3] and parts[4])


def clean_access_token(raw: Any) -> str:
    text = _text(raw)
    if not text:
        return ""
    if text.lstrip().startswith(("{", "[")):
        try:
            payload = json.loads(text)
        except Exception:
            payload = None
        if payload is not None:
            found = _find_key(payload, {"accessToken", "access_token"})
            if found:
                return found
    return text.strip().strip('"\'`')


def session_cookie_header(session_token: str) -> str:
    token = clean_session_token(session_token)
    if not token:
        return ""
    chunks = [token[index : index + MAX_COOKIE_CHUNK_SIZE] for index in range(0, len(token), MAX_COOKIE_CHUNK_SIZE)]
    if len(chunks) <= 1:
        return f"{COOKIE_NAME}={token}"
    return "; ".join(f"{COOKIE_NAME}.{index}={chunk}" for index, chunk in enumerate(chunks))


def _new_session() -> Any:
    if CurlCffiSession is not None:
        try:
            session = CurlCffiSession(impersonate="chrome136")
        except Exception:
            try:
                session = CurlCffiSession(impersonate="chrome124")
            except Exception:
                session = requests.Session()
    else:
        session = requests.Session()
    if hasattr(session, "trust_env"):
        session.trust_env = False
    return session


def _set_proxy(session: Any, proxy: str) -> None:
    value = _text(proxy)
    if not value:
        return
    if "://" not in value:
        value = "http://" + value
    if value.lower().startswith("socks5://"):
        value = "socks5h://" + value.split("://", 1)[1]
    session.proxies = {"http": value, "https": value}


def resolve_chatgpt_session_token(
    session_token: str,
    *,
    proxy: str = "",
    user_agent: str = DEFAULT_USER_AGENT,
    timeout: int = 30,
) -> SessionCredential:
    token = clean_session_token(session_token)
    if not token:
        raise ValueError("SESSION_TOKEN_REQUIRED")
    if not is_probable_session_token(token):
        raise ValueError("SESSION_TOKEN_INVALID_FORMAT")
    cookie = session_cookie_header(token)
    session = _new_session()
    _set_proxy(session, proxy)
    headers = {
        "User-Agent": _text(user_agent) or DEFAULT_USER_AGENT,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://chatgpt.com/",
        "Origin": "https://chatgpt.com",
        "Cookie": cookie,
    }
    response = session.get(SESSION_URL, headers=headers, timeout=max(5, int(timeout or 30)))
    status = int(getattr(response, "status_code", 0) or 0)
    body = _text(getattr(response, "text", ""))
    if status >= 400:
        raise ValueError(f"SESSION_RESOLVE_FAILED HTTP {status}: {_compact_error(body)}")
    try:
        payload = response.json() or {}
    except Exception as exc:
        raise ValueError("SESSION_RESOLVE_INVALID_JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("SESSION_RESOLVE_INVALID_JSON")
    access_token = clean_access_token(
        payload.get("accessToken")
        or payload.get("access_token")
        or _find_key(payload, {"accessToken", "access_token"})
    )
    if not access_token:
        raise ValueError("SESSION_ACCESS_TOKEN_MISSING")
    account_id, token_email = account_context_from_access_token(access_token)
    user = payload.get("user") if isinstance(payload.get("user"), dict) else {}
    email = _text(user.get("email") if isinstance(user, dict) else "") or token_email
    name = _text(user.get("name") if isinstance(user, dict) else "")
    return SessionCredential(
        session_token=token,
        access_token=access_token,
        account_id=account_id,
        email=email,
        name=name,
        expires=_text(payload.get("expires")),
    )


def resolve_many_session_tokens(session_tokens: list[Any], *, proxy: str = "", limit: int = 100) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(session_tokens[: max(1, min(500, int(limit or 100))) ]):
        token = clean_session_token(raw)
        if not token or token in seen:
            continue
        seen.add(token)
        try:
            resolved = resolve_chatgpt_session_token(token, proxy=proxy)
            output.append({
                "ok": True,
                "index": index,
                "session_token": resolved.session_token,
                "access_token": resolved.access_token,
                "account_id": resolved.account_id,
                "email": resolved.email,
                "name": resolved.name,
                "expires": resolved.expires,
            })
        except Exception as exc:  # noqa: BLE001 - keep one bad token from blocking the batch
            output.append({
                "ok": False,
                "index": index,
                "session_token": token,
                "error": _compact_error(exc),
            })
    return output
