import os
import time
import unittest

from nebulauth_sdk.client import NebulAuthClient

DEFAULT_BASE_URL = "https://api.nebulauth.com/api/v1"


class NebulAuthLiveIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.enabled = os.getenv("NEBULAUTH_LIVE_TEST") == "1"
        cls.base_url = os.getenv("NEBULAUTH_BASE_URL") or DEFAULT_BASE_URL
        cls.bearer_token = os.getenv("NEBULAUTH_BEARER_TOKEN")
        cls.signing_secret = os.getenv("NEBULAUTH_SIGNING_SECRET")
        cls.test_key = os.getenv("NEBULAUTH_TEST_KEY")
        cls.test_hwid = os.getenv("NEBULAUTH_TEST_HWID")

        cls.missing = [
            name
            for name, value in {
                "NEBULAUTH_BEARER_TOKEN": cls.bearer_token,
                "NEBULAUTH_SIGNING_SECRET": cls.signing_secret,
                "NEBULAUTH_TEST_KEY": cls.test_key,
            }.items()
            if not value
        ]

        if not cls.enabled:
            raise unittest.SkipTest("Live tests disabled (set NEBULAUTH_LIVE_TEST=1)")
        if cls.missing:
            raise unittest.SkipTest(
                f"Missing required live env vars: {', '.join(cls.missing)}"
            )

        cls.client = NebulAuthClient(
            base_url=cls.base_url,
            bearer_token=cls.bearer_token,
            signing_secret=cls.signing_secret,
            replay_protection="strict",
        )

    def test_live_verify_key(self) -> None:
        response = self.client.verify_key(
            key=self.test_key,
            request_id=f"live-py-{int(time.time() * 1000)}",
            hwid=self.test_hwid,
        )

        self.assertIsInstance(response.status_code, int)
        self.assertIsInstance(response.data, dict)
        self.assertIn("valid", response.data)

    def test_live_auth_verify_bootstrap(self) -> None:
        response = self.client.auth_verify(
            key=self.test_key,
            hwid=self.test_hwid,
            request_id=f"live-py-bootstrap-{int(time.time() * 1000)}",
        )

        self.assertIsInstance(response.status_code, int)
        self.assertIsInstance(response.data, dict)
        self.assertIn("valid", response.data)


if __name__ == "__main__":
    unittest.main()
