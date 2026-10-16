# UPI 提链本地控制台

这是从 `zkky` 项目拆出的 UPI Python 核心和一个最简单的 HTML 操作页。后端只监听 `127.0.0.1`，不会自动连接服务器；只有用户在页面提交任务后，核心才会按原流程访问其配置的上游服务。

## 启动

需要 Python 3.10+。在此目录执行：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m playwright install chromium
python app.py
```

然后打开控制台输出的 `http://127.0.0.1:8765`。Windows 也可双击 `run_local.cmd`（仍需先安装依赖）。

## 使用

1. 填入一个账号 Access Token。
2. 每行填一条自定义代理，支持代理 URL 或 `host:port:user:pass`。
3. 默认勾选“仅交付 0 元结果”；关闭后由核心按原价流程处理。
4. 开始后可查看状态、日志和捕获到的 Stripe UPI Instructions 链接。

控制台每次只运行一个任务。Token 和代理不写入浏览器存储或持久化任务记录；代理临时文件在任务结束后删除，运行状态与指纹库放在 `data/`。日志会对 Token 和常见代理认证信息做二次脱敏，但仍应按敏感文件保护 `data/`。

默认会保留指纹库中的浏览器、平台、UA、语言、时区、设备参数和 TLS 组合。只有设置 `UPI_FORCE_CHROME_PROFILE=1` 时，才启用旧版的固定 Chrome/Windows/hi-IN 兼容模式。

新账号默认启用桌面指纹多样化：Chrome、Edge、Firefox 与 Windows、macOS 会按现有指纹池规则抽取；移动端默认关闭，可通过 `UPI_MOBILE_FINGERPRINTS=1` 开启。

## 目录

- `app.py`：仅标准库的本地 HTTP 服务、任务生命周期和日志脱敏。
- `web/index.html`：轻量 HTML/CSS/JS 页面。
- `standalone_core/alt_extractors/upi/`：UPI 核心、出口评分。
- `standalone_core/`：核心运行所需的传输、指纹、会话与 Sentinel 支持模块。
- `data/`：本地运行状态、日志、指纹状态与临时数据；`fingerprint_profiles.json` 为随项目提供的指纹库。

## 校验

```powershell
python -m unittest discover -s tests -v
python -m compileall -q app.py standalone_core
```

此目录没有复制原项目的 Token、代理池、代理状态、账单分配或指纹库数据。
