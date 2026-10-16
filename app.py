from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "web"
DATA_ROOT = ROOT / "data"
MAX_BODY_BYTES = 1_000_000
MAX_TOKEN_LENGTH = 64_000
MAX_PROXY_COUNT = 5_000
MAX_LOG_LINES = 1_500
LINK_RE = re.compile(r"https://payments\.stripe\.com/upi/instructions/[^\s\"'<>]+", re.I)
AUTH_PROXY_RE = re.compile(r"(?i)\b(https?|socks5h?)://([^:/\s@]+):([^@/\s]+)@")


class RequestError(ValueError):
    pass


def validate_run_payload(payload: Any) -> tuple[str, list[str], bool]:
    if not isinstance(payload, dict):
        raise RequestError("请求内容必须是 JSON 对象")

    token = str(payload.get("token") or "").strip()
    if not token:
        raise RequestError("请填写账号 access token")
    if len(token) > MAX_TOKEN_LENGTH or "\n" in token or "\r" in token:
        raise RequestError("Token 长度或格式不正确")

    raw_proxies = payload.get("proxies")
    if not isinstance(raw_proxies, str):
        raise RequestError("代理池必须是文本，每行一条代理")
    proxies = [line.strip() for line in raw_proxies.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not proxies:
        raise RequestError("请至少填写一条代理")
    if len(proxies) > MAX_PROXY_COUNT:
        raise RequestError(f"代理条数不能超过 {MAX_PROXY_COUNT}")
    if any(len(line) > 2_048 or "\x00" in line for line in proxies):
        raise RequestError("代理行长度或格式不正确")

    require_zero = bool(payload.get("require_zero", True))
    return token, proxies, require_zero


def redact_line(line: str, secrets_to_mask: list[str]) -> str:
    text = str(line or "").rstrip("\r\n")
    for value in sorted((item for item in secrets_to_mask if item), key=len, reverse=True):
        text = text.replace(value, "[已脱敏]")
    return AUTH_PROXY_RE.sub(r"\1://***:***@", text)


def collect_secrets(token: str, proxies: list[str]) -> list[str]:
    values = [token, *proxies]
    for proxy in proxies:
        candidate = proxy if "://" in proxy else "http://" + proxy
        try:
            parsed = urlsplit(candidate)
            if parsed.username:
                values.append(unquote(parsed.username))
            if parsed.password:
                values.append(unquote(parsed.password))
        except ValueError:
            pass
        if "://" not in proxy:
            parts = proxy.split(":")
            if len(parts) >= 4:
                values.extend(parts[-2:])
    return list(dict.fromkeys(value for value in values if value and (value == token or value in proxies or len(value) >= 4)))


def extract_instruction_links(lines: list[str]) -> list[str]:
    links: list[str] = []
    for line in lines:
        for match in LINK_RE.findall(line):
            link = match.rstrip(".,);]")
            if link not in links:
                links.append(link)
    return links


class TaskManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._task: dict[str, Any] | None = None
        self._process: subprocess.Popen[str] | None = None
        self._stop_requested = False

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            if self._task is None:
                return {"status": "idle", "logs": [], "links": []}
            task = dict(self._task)
            task["logs"] = list(self._task["logs"])
            task["links"] = list(self._task["links"])
            return task

    def start(self, token: str, proxies: list[str], require_zero: bool) -> str:
        with self._lock:
            if self._task and self._task["status"] in {"starting", "running", "stopping"}:
                raise RequestError("已有提链任务正在运行")
            task_id = uuid.uuid4().hex[:12]
            self._stop_requested = False
            self._task = {
                "id": task_id,
                "status": "starting",
                "started_at": int(time.time()),
                "finished_at": None,
                "exit_code": None,
                "logs": [],
                "links": [],
                "error": "",
            }
            thread = threading.Thread(
                target=self._run,
                args=(task_id, token, proxies, require_zero),
                name=f"upi-task-{task_id}",
                daemon=True,
            )
            thread.start()
            return task_id

    def stop(self) -> bool:
        with self._lock:
            process = self._process
            if not process or process.poll() is not None:
                if self._task and self._task["status"] == "starting":
                    self._stop_requested = True
                    self._task["status"] = "stopping"
                    return True
                return False
            self._stop_requested = True
            if self._task:
                self._task["status"] = "stopping"
            pid = process.pid

        try:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    capture_output=True,
                    check=False,
                    timeout=8,
                )
            else:
                process.terminate()
        except (OSError, subprocess.SubprocessError):
            try:
                process.kill()
            except OSError:
                pass
        return True

    def _append_log(self, task_id: str, line: str, secrets_to_mask: list[str]) -> None:
        safe_line = redact_line(line, secrets_to_mask)
        with self._lock:
            if not self._task or self._task["id"] != task_id:
                return
            self._task["logs"].append(safe_line)
            if len(self._task["logs"]) > MAX_LOG_LINES:
                del self._task["logs"][:-MAX_LOG_LINES]
            self._task["links"] = extract_instruction_links(self._task["logs"])

    @staticmethod
    def _child_environment(token: str, proxy_file: Path, require_zero: bool) -> dict[str, str]:
        allowed = {
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "LOCALAPPDATA",
            "APPDATA",
            "USERPROFILE",
            "PROGRAMFILES",
            "PROGRAMFILES(X86)",
            "PLAYWRIGHT_BROWSERS_PATH",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
        }
        env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
        env.update(
            {
                "PYTHONPATH": str(ROOT),
                "PYTHONUTF8": "1",
                "UPI_TOKEN": token,
                "UPI_PROXY_SEED_FILE": str(proxy_file),
                "UPI_PROXY_STATE_FILE": str(DATA_ROOT / "proxy_state.json"),
                "UPI_BILLING_POOL_FILE": str(DATA_ROOT / "billing_assignments.json"),
                "UPI_FINGERPRINT_STORE": str(DATA_ROOT / "fingerprint_profiles.json"),
                "UPI_RUNTIME_DIR": str(DATA_ROOT),
                "UPI_DIVERSE_FINGERPRINTS": "1",
                "UPI_MOBILE_FINGERPRINTS": "0",
                "UPI_FORCE_CHROME_PROFILE": "1" if os.environ.get("UPI_FORCE_CHROME_PROFILE", "").strip() == "1" else "0",
                "UPI_REQUIRE_ZERO": "1" if require_zero else "0",
                "UPI_WORKERS": "1",
                "UPI_WORKERS_MAX": "1",
            }
        )
        return env

    def _run(self, task_id: str, token: str, proxies: list[str], require_zero: bool) -> None:
        DATA_ROOT.mkdir(parents=True, exist_ok=True)
        proxy_path: Path | None = None
        process: subprocess.Popen[str] | None = None
        secrets_to_mask = collect_secrets(token, proxies)
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="\n",
                prefix="upi-proxies-",
                suffix=".txt",
                dir=DATA_ROOT,
                delete=False,
            ) as proxy_file:
                proxy_file.write("\n".join(proxies) + "\n")
                proxy_path = Path(proxy_file.name)

            command = [
                sys.executable,
                "-u",
                "-m",
                "standalone_core.alt_extractors.upi.upi_extract",
            ]
            popen_options: dict[str, Any] = {
                "cwd": str(ROOT),
                "env": self._child_environment(token, proxy_path, require_zero),
                "stdout": subprocess.PIPE,
                "stderr": subprocess.STDOUT,
                "text": True,
                "encoding": "utf-8",
                "errors": "replace",
                "bufsize": 1,
            }
            if os.name == "nt":
                popen_options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            else:
                popen_options["start_new_session"] = True

            process = subprocess.Popen(command, **popen_options)
            with self._lock:
                if self._task and self._task["id"] == task_id:
                    self._process = process
                    if self._stop_requested:
                        self._task["status"] = "stopping"
                    else:
                        self._task["status"] = "running"
                stop_immediately = self._stop_requested
            if stop_immediately:
                self.stop()

            assert process.stdout is not None
            for line in process.stdout:
                self._append_log(task_id, line, secrets_to_mask)
            exit_code = process.wait()

            with self._lock:
                if self._task and self._task["id"] == task_id:
                    self._task["exit_code"] = exit_code
                    self._task["finished_at"] = int(time.time())
                    self._task["status"] = (
                        "stopped"
                        if self._stop_requested
                        else "succeeded"
                        if exit_code == 0
                        else "failed"
                    )
                    self._process = None
        except Exception as exc:  # keep task state readable if process startup fails
            self._append_log(task_id, f"启动失败：{type(exc).__name__}: {exc}", secrets_to_mask)
            with self._lock:
                if self._task and self._task["id"] == task_id:
                    self._task["status"] = "failed"
                    self._task["finished_at"] = int(time.time())
                    self._task["error"] = type(exc).__name__
                    self._task["exit_code"] = process.poll() if process else None
                    self._process = None
        finally:
            if process and process.poll() is None:
                try:
                    process.kill()
                    process.wait(timeout=5)
                except (OSError, subprocess.SubprocessError):
                    pass
            if proxy_path:
                try:
                    proxy_path.unlink(missing_ok=True)
                except OSError:
                    pass


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], csrf_token: str) -> None:
        super().__init__(address, RequestHandler)
        self.csrf_token = csrf_token
        self.task_manager = TaskManager()


class RequestHandler(BaseHTTPRequestHandler):
    server: LocalServer

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; connect-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _local_request(self, *, check_origin: bool = False) -> bool:
        try:
            parsed_host = urlsplit("//" + self.headers.get("Host", ""))
            host = parsed_host.hostname
            host_port = parsed_host.port or 80
        except ValueError:
            return False
        if host not in {"127.0.0.1", "localhost"} or host_port != self.server.server_address[1]:
            return False
        if check_origin:
            origin = self.headers.get("Origin", "")
            if not origin:
                return False
            parsed = urlsplit(origin)
            expected_port = self.server.server_address[1]
            try:
                origin_port = parsed.port or (80 if parsed.scheme == "http" else 443)
            except ValueError:
                return False
            if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
                return False
            if origin_port != expected_port:
                return False
            if self.headers.get("Sec-Fetch-Site", "").lower() == "cross-site":
                return False
        return True

    def do_GET(self) -> None:  # noqa: N802
        if not self._local_request():
            self._json(403, {"error": "仅允许本机访问"})
            return
        if self.path == "/":
            html = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
            html = html.replace("__CSRF_TOKEN__", self.server.csrf_token)
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
            return
        if self.path == "/api/status":
            self._json(200, self.server.task_manager.snapshot())
            return
        self._json(404, {"error": "Not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._local_request(check_origin=True):
            self._json(403, {"error": "本机来源校验失败"})
            return
        received_csrf = self.headers.get("X-CSRF-Token", "")
        if not hmac.compare_digest(received_csrf, self.server.csrf_token):
            self._json(403, {"error": "CSRF 校验失败，请刷新页面"})
            return
        if self.headers.get_content_type() != "application/json":
            self._json(415, {"error": "Content-Type 必须是 application/json"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(400, {"error": "请求长度无效"})
            return
        if length <= 0 or length > MAX_BODY_BYTES:
            self._json(413, {"error": "请求内容为空或超过大小限制"})
            return
        try:
            payload = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._json(400, {"error": "JSON 格式无效"})
            return

        if self.path == "/api/start":
            try:
                token, proxies, require_zero = validate_run_payload(payload)
                task_id = self.server.task_manager.start(token, proxies, require_zero)
            except RequestError as exc:
                self._json(400, {"error": str(exc)})
                return
            self._json(202, {"task_id": task_id, "status": "starting"})
            return
        if self.path == "/api/stop":
            stopped = self.server.task_manager.stop()
            self._json(200, {"stopped": stopped})
            return
        self._json(404, {"error": "Not found"})

    def log_message(self, fmt: str, *args: Any) -> None:
        # Request paths only; request bodies are never logged.
        super().log_message(fmt, *args)


def create_server(host: str = "127.0.0.1", port: int = 8765) -> LocalServer:
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("服务只允许绑定到 127.0.0.1 或 localhost")
    return LocalServer((host, port), secrets.token_urlsafe(32))


def main() -> None:
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    server = create_server(
        os.environ.get("UPI_EXTRAY_HOST", "127.0.0.1"),
        int(os.environ.get("UPI_EXTRAY_PORT", "8765")),
    )
    host, port = server.server_address
    print(f"UPI 本地控制台已启动：http://{host}:{port}")
    print("按 Ctrl+C 停止。Token 与代理只在任务运行期间保存在内存/临时文件中。")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n正在停止本地控制台…")
    finally:
        server.task_manager.stop()
        server.server_close()


if __name__ == "__main__":
    main()
