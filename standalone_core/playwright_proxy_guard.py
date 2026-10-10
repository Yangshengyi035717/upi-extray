"""Playwright 启动防护：未显式配置出口时，禁止浏览器继承操作系统代理。

背景（实测取证）：

* Windows 上 Clash/V2Ray 常驻并把系统代理打开
  （``ProxyEnable=1`` → ``127.0.0.1:7890``）。
* Chromium 在**没有** ``--proxy-server`` 时默认使用操作系统代理，
  Firefox/WebKit 同理走系统设置。
* 于是本该直连、或本该走任务出口的请求被送到另一个国家的节点，
  「出口国家 ≠ 账号/账单地区」，这是最典型的"环境污染"型 block 来源。
* 同一份配置在 Ubuntu 服务器上 7890 是关闭的，不会静默走错出口 ——
  这正是「Windows 上 block 多、Ubuntu 版就好了」的真实原因。

因此：只要没有显式代理，就显式关掉浏览器自身的系统代理。
"""

from __future__ import annotations

from typing import Any

NO_PROXY_ARG = "--no-proxy-server"


def guard_system_proxy(
    launch_options: dict[str, Any],
    proxy: Any,
    *,
    engine: str = "chromium",
) -> dict[str, Any]:
    """没有显式代理时，关掉浏览器继承的系统代理。

    有显式代理时原样返回（Playwright 的 ``proxy`` 参数已能覆盖系统设置），
    避免影响既有链路。
    """
    if proxy:
        return launch_options
    name = str(engine or "chromium").strip().lower()
    if name.startswith("chrom"):
        args = list(launch_options.get("args") or [])
        if NO_PROXY_ARG not in args:
            args.append(NO_PROXY_ARG)
        launch_options["args"] = args
    elif name.startswith("fire"):
        prefs = dict(launch_options.get("firefox_user_prefs") or {})
        # 0 = 不使用代理（Firefox 默认 5 = 跟随系统设置）。
        prefs.setdefault("network.proxy.type", 0)
        launch_options["firefox_user_prefs"] = prefs
    return launch_options
