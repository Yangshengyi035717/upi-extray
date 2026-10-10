from __future__ import annotations

import unittest
import json
import io
import re
import threading
import time
from http.client import HTTPConnection
from unittest.mock import patch

import app


class ValidatePayloadTests(unittest.TestCase):
    def test_accepts_token_and_proxy_lines(self) -> None:
        token, proxies, require_zero = app.validate_run_payload(
            {
                "token": "sample-access-token",
                "proxies": "# comment\nhttp://user:password@proxy.example:8080\n",
            }
        )
        self.assertEqual(token, "sample-access-token")
        self.assertEqual(proxies, ["http://user:password@proxy.example:8080"])
        self.assertTrue(require_zero)

    def test_requires_at_least_one_proxy(self) -> None:
        with self.assertRaisesRegex(app.RequestError, "至少填写一条代理"):
            app.validate_run_payload({"token": "sample-token", "proxies": "# none\n"})

    def test_rejects_newline_in_token(self) -> None:
        with self.assertRaisesRegex(app.RequestError, "Token"):
            app.validate_run_payload({"token": "first\nsecond", "proxies": "proxy:8080"})

    def test_accepts_original_price_mode(self) -> None:
        _token, _proxies, require_zero = app.validate_run_payload(
            {"token": "sample-token", "proxies": "proxy:8080", "require_zero": False}
        )
        self.assertFalse(require_zero)


class RedactionTests(unittest.TestCase):
    def test_masks_exact_token_proxy_and_url_credentials(self) -> None:
        secrets_to_mask = app.collect_secrets(
            "access-token-value",
            ["http://proxy-user:proxy-password@host.example:1234"],
        )
        line = "token=access-token-value proxy=http://proxy-user:proxy-password@host.example:1234"
        result = app.redact_line(line, secrets_to_mask)
        self.assertNotIn("access-token-value", result)
        self.assertNotIn("proxy-user", result)
        self.assertNotIn("proxy-password", result)
        self.assertIn("[已脱敏]", result)

    def test_extracts_only_instruction_links(self) -> None:
        lines = [
            "done https://payments.stripe.com/upi/instructions/abc123.",
            "repeat https://payments.stripe.com/upi/instructions/abc123",
            "internal https://api.stripe.com/v1/checkout/sessions",
        ]
        self.assertEqual(
            app.extract_instruction_links(lines),
            ["https://payments.stripe.com/upi/instructions/abc123"],
        )


class LocalServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = app.create_server("127.0.0.1", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method: str, path: str, body: bytes | None = None, headers: dict[str, str] | None = None):
        connection = HTTPConnection(self.host, self.port, timeout=3)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        result = response.status, response.read()
        connection.close()
        return result

    def test_home_injects_csrf_token_and_status_is_idle(self) -> None:
        status, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        match = re.search(rb'const csrfToken = "([^"]+)"', body)
        self.assertIsNotNone(match)
        self.assertTrue(match.group(1).decode("ascii"))

        status, body = self.request("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "idle")

    def test_post_rejects_missing_csrf(self) -> None:
        status, body = self.request(
            "POST",
            "/api/start",
            body=b"{}",
            headers={
                "Content-Type": "application/json",
                "Origin": f"http://127.0.0.1:{self.port}",
            },
        )
        self.assertEqual(status, 403)
        self.assertIn("CSRF", json.loads(body)["error"])


class TaskManagerTests(unittest.TestCase):
    def test_mocked_child_finishes_redacts_secrets_and_extracts_link(self) -> None:
        token = "access-token-sensitive"
        proxy = "http://proxy-user:proxy-password@host.example:1234"

        class FakeProcess:
            pid = 100
            stdout = io.StringIO(
                f"token={token} proxy={proxy}\n"
                "结果 https://payments.stripe.com/upi/instructions/test-id\n"
            )

            @staticmethod
            def poll() -> int:
                return 0

            @staticmethod
            def wait(timeout: float | None = None) -> int:
                return 0

        manager = app.TaskManager()
        with patch.object(app.subprocess, "Popen", return_value=FakeProcess()):
            manager.start(token, [proxy], True)
            deadline = time.monotonic() + 3
            state = manager.snapshot()
            while state["status"] in {"starting", "running"} and time.monotonic() < deadline:
                time.sleep(0.01)
                state = manager.snapshot()

        self.assertEqual(state["status"], "succeeded")
        logs = "\n".join(state["logs"])
        self.assertNotIn(token, logs)
        self.assertNotIn("proxy-user", logs)
        self.assertNotIn("proxy-password", logs)
        self.assertEqual(state["links"], ["https://payments.stripe.com/upi/instructions/test-id"])


if __name__ == "__main__":
    unittest.main()
