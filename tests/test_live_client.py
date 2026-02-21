import os
import time
import unittest

from nebulauth_sdk.client import NebulAuthClient
from nebulauth_sdk.dashboard import NebulAuthDashboardClient

DEFAULT_BASE_URL = "https://api.nebulauth.com/api/v1"
DEFAULT_DASHBOARD_BASE_URL = "https://api.nebulauth.com/dashboard"


class NebulAuthLiveIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.enabled = os.getenv("NEBULAUTH_LIVE_TEST") == "1"
        cls.base_url = os.getenv("NEBULAUTH_BASE_URL") or DEFAULT_BASE_URL
        cls.bearer_token = os.getenv("NEBULAUTH_BEARER_TOKEN")
        cls.dashboard_bearer_token = os.getenv("NEBULAUTH_DASHBOARD_BEARER_TOKEN")
        cls.dashboard_base_url = (
            os.getenv("NEBULAUTH_DASHBOARD_BASE_URL") or DEFAULT_DASHBOARD_BASE_URL
        )
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

        if cls.dashboard_bearer_token:
            cls.dashboard_client = NebulAuthDashboardClient(
                base_url=cls.dashboard_base_url,
                auth={"mode": "bearer", "bearer_token": cls.dashboard_bearer_token},
            )
        else:
            cls.dashboard_client = None

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

    def test_live_dashboard_me(self) -> None:
        if self.dashboard_client is None:
            self.skipTest(
                "Missing NEBULAUTH_DASHBOARD_BEARER_TOKEN for dashboard live test"
            )

        response = self.dashboard_client.me()

        self.assertIsInstance(response.status_code, int)
        self.assertIsInstance(response.data, dict)


if __name__ == "__main__":
    unittest.main()
