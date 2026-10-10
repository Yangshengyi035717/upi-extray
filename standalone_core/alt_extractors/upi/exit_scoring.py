"""出口 ASN 画像与「提链优先挑非移动段」打分。

背景与实测修正（2026-10-09）：
    本模块最初假设「0 元链 blocked 高度集中在移动运营商段（Jio/Airtel
    Mobility/Vi）」。**该假设经 ABBA 配对对照实验未被证实**：同一批账号、
    同一 latin 账单、每任务 1 条独占出口，家宽组 blocked 14/16=87.5%，
    移动组 16/18=88.9%，Fisher p=1.0（无差异）。网络层也无差异：
    两组连通率均 100%、独立 IP 率 98.9% vs 98.4%、/24 复用率 7% vs 5%。

    结论：0 元链的 approve blocked 由 OpenAI 侧「0 元订阅授权」风控决定，
    与出口是家宽还是移动段基本无关；原价链（PaymentIntent）实测 blocked
    为 0，出链率与账单脚本强相关（latin 69.6% / hindi 0%）。

    因此 ASN 打分**不再作为提升出链率的手段**，仅保留为运维观测工具：
    用于看清池子构成（家宽/移动/未知占比、ASN 分布），以及在需要时
    把某一类出口排到前面做定向对比。分数常量保持原值，便于复现实验。

设计原则（KISS / 安全默认）：
    * 只做**排序降权**，绝不静默剔除任何出口——最差情况只是排到后面。
    * ASN 查询只在「预热」时联网，提链路径**只读本地缓存**，不增加延迟。
    * 缓存缺失的出口按中性分处理，不影响现有行为。
    * 整个模块可被关掉（开关默认关闭），关掉后行为与改动前完全一致。
    * 缓存是「换池后必须重跑预热」的产物：命中率不足时调用方会明确告警，
      不再静默把全部出口判成 unknown（那等于打分没生效却看不出来）。

数据结构：``exit_asn_cache.json``
    {
      "1.2.3.4": {"asn": "AS55836", "asname": "RELIANCEJIO-IN", "isp": "...",
                   "category": "mobile", "ts": 1791000000},
      ...
    }
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent

# ASN / 运营商名称里出现以下关键字 → 判定为「移动蜂窝」段（高风控权重）。
_MOBILE_MARKERS = (
    "reliancejio",
    "reliance jio",
    "jio",
    "bharti-mobility",
    "bharti mobility",
    "airtel-mobility",
    "airtel mobility",
    "airtel mobility ap",
    "vil-as",
    "vodafone idea",
    "vodafoneidea",
    "cellular",
    "mobile",
    "wireless",
    "gsm",
    "lte",
)

# 宽带 / 固网 ISP → 相对干净，加分。
_BROADBAND_MARKERS = (
    "broadband",
    "bsnl",
    "fiber",
    "fibre",
    "cable",
    "netplus",
    "excitel",
    "gtpl",
    "gtpl",
    "hathway",
    "den networks",
    "tata communications",
    "tata teleservices",
    "act fibernet",
)

CATEGORY_MOBILE = "mobile"
CATEGORY_BROADBAND = "broadband"
CATEGORY_UNKNOWN = "unknown"

# 打分：分数越高越优先。移动段低分，宽带段高分，未知中性。
SCORE_MOBILE = -100
SCORE_BROADBAND = 50
SCORE_UNKNOWN = 0


def cache_path() -> Path:
    raw = str(os.environ.get("UPI_EXIT_ASN_CACHE", "") or "").strip()
    return Path(raw).expanduser() if raw else SCRIPT_DIR / "exit_asn_cache.json"


def scoring_enabled() -> bool:
    raw = str(os.environ.get("UPI_ASN_SCORING", "0") or "").strip().lower()
    return raw in {"1", "true", "yes", "on", "启用", "开启"}


def _classify(asname: str, isp: str) -> str:
    haystack = f"{asname} {isp}".lower()
    if any(marker in haystack for marker in _BROADBAND_MARKERS):
        return CATEGORY_BROADBAND
    if any(marker in haystack for marker in _MOBILE_MARKERS):
        return CATEGORY_MOBILE
    return CATEGORY_UNKNOWN


def category_score(category: str) -> int:
    if category == CATEGORY_BROADBAND:
        return SCORE_BROADBAND
    if category == CATEGORY_MOBILE:
        return SCORE_MOBILE
    return SCORE_UNKNOWN


def load_cache() -> dict[str, dict[str, Any]]:
    path = cache_path()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_cache(cache: dict[str, dict[str, Any]]) -> None:
    path = cache_path()
    tmp = path.with_suffix(".json.tmp")
    try:
        tmp.write_text(json.dumps(cache, ensure_ascii=False, indent=0, sort_keys=True), encoding="utf-8")
        tmp.replace(path)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass


def record_asn(ip: str, asn: str, asname: str, isp: str = "") -> dict[str, Any]:
    """写入一条 ASN 记录并返回它（含 category / ts）。"""
    entry = {
        "asn": str(asn or ""),
        "asname": str(asname or ""),
        "isp": str(isp or ""),
        "category": _classify(str(asname or ""), str(isp or "")),
        "ts": int(time.time()),
    }
    cache = load_cache()
    cache[str(ip or "").strip()] = entry
    save_cache(cache)
    return entry


def lookup(ip: str, cache: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """只读查询某 IP 的 ASN 画像；缓存缺失返回空 dict（不联网）。"""
    data = cache if cache is not None else load_cache()
    entry = data.get(str(ip or "").strip())
    return entry if isinstance(entry, dict) else {}


def score_proxy_by_ip(ip: str, cache: dict[str, dict[str, Any]] | None = None) -> tuple[int, str]:
    """返回 (分数, 分类)。缓存缺失 → (0, unknown)。"""
    entry = lookup(ip, cache)
    category = str(entry.get("category") or CATEGORY_UNKNOWN)
    return category_score(category), category


def enrich_with_asn(ips: Iterable[str], *, timeout: int = 20, batch: int = 100) -> dict[str, dict[str, Any]]:
    """联网批量查询 ASN 并写入缓存（仅预热/CLI 使用，提链路径不调用）。

    使用 ip-api.com 免费批量接口（无需 key，约 45 请求/分钟）。
    """
    import urllib.request

    wanted = [str(ip or "").strip() for ip in ips]
    wanted = [ip for ip in wanted if ip]
    if not wanted:
        return {}
    cache = load_cache()
    pending = [ip for ip in wanted if ip not in cache]
    if not pending:
        return cache
    for start in range(0, len(pending), batch):
        chunk = pending[start : start + batch]
        payload = json.dumps(
            [{"query": ip, "fields": "query,country,isp,org,as,asname"} for ip in chunk]
        ).encode("utf-8")
        request = urllib.request.Request(
            "http://ip-api.com/batch",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            response = json.loads(urllib.request.urlopen(request, timeout=timeout).read().decode("utf-8"))
        except Exception:
            break
        for item in response:
            ip = str(item.get("query") or "").strip()
            if not ip:
                continue
            cache[ip] = {
                "asn": str(item.get("as") or ""),
                "asname": str(item.get("asname") or ""),
                "isp": str(item.get("isp") or ""),
                "category": _classify(str(item.get("asname") or ""), str(item.get("isp") or "")),
                "ts": int(time.time()),
            }
        save_cache(cache)
    return cache


def summarize_cache(cache: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """缓存画像汇总：各类别数量 + ASN 分布 Top。"""
    data = cache if cache is not None else load_cache()
    by_category: dict[str, int] = {}
    by_asn: dict[str, int] = {}
    for entry in data.values():
        if not isinstance(entry, dict):
            continue
        category = str(entry.get("category") or CATEGORY_UNKNOWN)
        by_category[category] = by_category.get(category, 0) + 1
        name = str(entry.get("asname") or entry.get("asn") or "?")
        by_asn[name] = by_asn.get(name, 0) + 1
    ranked = sorted(by_asn.items(), key=lambda kv: -kv[1])
    return {
        "total": len(data),
        "by_category": by_category,
        "top_asn": [{"asname": name, "count": count} for name, count in ranked[:15]],
    }


def order_by_exit_score(
    proxies: list[str],
    *,
    ip_of: dict[str, str],
    cache: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[str], dict[str, int]]:
    """按出口 ASN 分数稳定排序（高分在前），返回 (排序后列表, 分类计数)。

    ``ip_of`` 是 ``proxy -> egress_ip`` 映射；缺失映射的代理按中性分处理。
    排序保持稳定，同分保持原相对顺序。
    """
    data = cache if cache is not None else load_cache()
    counts = {CATEGORY_BROADBAND: 0, CATEGORY_MOBILE: 0, CATEGORY_UNKNOWN: 0}
    decorated: list[tuple[int, int, str]] = []
    for index, proxy in enumerate(proxies):
        ip = ip_of.get(proxy, "")
        if ip:
            score, category = score_proxy_by_ip(ip, data)
        else:
            score, category = SCORE_UNKNOWN, CATEGORY_UNKNOWN
        counts[category] = counts.get(category, 0) + 1
        decorated.append((score, index, proxy))
    decorated.sort(key=lambda item: (-item[0], item[1]))
    return [item[2] for item in decorated], counts


def build_ip_map(seeds: Iterable[str], cache: dict[str, dict[str, Any]] | None = None) -> dict[str, str]:
    """从 ``egress_cache.json``（probe 脚本产物）反查 seed → egress_ip。

    该缓存的键是 ``sha256(normalize(seed))[:10]``，与 upi_extract.proxy_short
    一致；这里复用同一 hash 以便把池子里的 Seed 映射到真实出口 IP。
    """
    import hashlib

    from .upi_extract import normalize_proxy_url  # 延迟导入，避免循环依赖

    raw_map: dict[str, str] = {}
    path = Path(str(os.environ.get("UPI_EGRESS_CACHE", "") or "").strip() or (SCRIPT_DIR / "egress_cache.json"))
    if path.is_file():
        try:
            raw_map = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            raw_map = {}
    result: dict[str, str] = {}
    for seed in seeds:
        normalized = normalize_proxy_url(seed)
        if not normalized:
            continue
        digest = hashlib.sha256(normalized.encode()).hexdigest()[:10]
        ip = str(raw_map.get(digest) or "").strip()
        if ip:
            result[seed] = ip
    return result


def preview_order(proxies: list[str], limit: int = 20) -> dict[str, Any]:
    """给看板用：展示当前池子按 ASN 打分后的头部出口（只读）。"""
    ip_of = build_ip_map(proxies)
    cache = load_cache()
    ordered, counts = order_by_exit_score(proxies, ip_of=ip_of, cache=cache)
    head = []
    for proxy in ordered[: max(1, limit)]:
        ip = ip_of.get(proxy, "")
        entry = lookup(ip, cache) if ip else {}
        head.append(
            {
                "proxy": proxy,
                "egress_ip": ip,
                "asname": str(entry.get("asname") or ""),
                "category": str(entry.get("category") or CATEGORY_UNKNOWN),
            }
        )
    return {
        "enabled": scoring_enabled(),
        "counts": counts,
        "ordered_head": head,
        "cache": summarize_cache(cache),
    }
