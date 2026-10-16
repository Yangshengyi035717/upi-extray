from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


class FingerprintRuntimeTests(unittest.TestCase):
    def test_store_contains_bundled_profiles(self) -> None:
        path = Path(__file__).resolve().parents[1] / "data" / "fingerprint_profiles.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload.get("version"), 3)
        self.assertGreater(len(payload.get("accounts") or {}), 0)

    def test_upi_preserves_generated_profile_by_default(self) -> None:
        from standalone_core.alt_extractors.upi import upi_extract

        profile = {
            "browser": "firefox",
            "platform": "macOS",
            "platform_os": "macOS",
            "major": "147",
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 13.6; rv:147.0) Gecko/20100101 Firefox/147.0",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 13.6; rv:147.0) Gecko/20100101 Firefox/147.0",
            "sec_ch_ua_platform": "",
            "language": "en-US",
            "timezone_id": "America/Los_Angeles",
            "tls_impersonate": "firefox147",
        }
        from standalone_core import fingerprint_store
        from standalone_core.alt_extractors.upi import upi_extract

        mocked_get_profile = MagicMock(return_value=(object(), "device-id"))
        mocked_extract_profile = MagicMock(return_value=profile)
        with (
            patch.dict(os.environ, {"UPI_FORCE_CHROME_PROFILE": "0"}, clear=False),
            patch.object(
                fingerprint_store,
                "get_account_fingerprint",
                mocked_get_profile,
            ),
            patch.object(
                fingerprint_store,
                "extractor_profile",
                mocked_extract_profile,
            ),
        ):
            result = upi_extract.resolve_upi_fingerprint("token", account_id="acct")
        self.assertEqual(result["browser"], "firefox")
        self.assertEqual(result["platform_os"], "macOS")
        self.assertEqual(result["user_agent"], profile["user_agent"])
        self.assertEqual(
            mocked_get_profile.call_args.kwargs,
            {
                "region": "IN",
                "diversify": True,
                "include_mobile": False,
            },
        )

    def test_legacy_chrome_override_remains_opt_in(self) -> None:
        from standalone_core.alt_extractors.upi import upi_extract

        profile = {
            "browser": "firefox",
            "platform_os": "macOS",
            "ua": "firefox",
            "user_agent": "firefox",
        }
        with patch.dict(os.environ, {"UPI_FORCE_CHROME_PROFILE": "1"}, clear=False):
            result = upi_extract._upi_default_chrome_profile(profile)
        self.assertEqual(result["platform"], "Windows")
        self.assertIn("Chrome/152.0.0.0", result["user_agent"])


if __name__ == "__main__":
    unittest.main()
