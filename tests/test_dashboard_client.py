import unittest
from unittest.mock import patch

from nebulauth_sdk.dashboard import NebulAuthDashboardClient
from nebulauth_sdk.exceptions import NebulAuthConfigError


class NebulAuthDashboardClientTests(unittest.TestCase):
    @patch("nebulauth_sdk.dashboard.NebulAuthDashboardClient._send")
    def test_me_uses_bearer_auth_header(self, mock_send) -> None:
        mock_send.return_value = (200, {}, '{"ok":true}')
        client = NebulAuthDashboardClient(
            base_url="https://api.nebulauth.com/dashboard",
            auth={"mode": "bearer", "bearer_token": "mk_at_test"},
        )

        response = client.me()

        self.assertEqual(response.status_code, 200)
        args, _ = mock_send.call_args
        self.assertEqual(args[0], "GET")
        self.assertEqual(args[1], "https://api.nebulauth.com/dashboard/me")
        self.assertEqual(args[3]["Authorization"], "Bearer mk_at_test")

    @patch("nebulauth_sdk.dashboard.NebulAuthDashboardClient._send")
    def test_list_users_uses_session_cookie(self, mock_send) -> None:
        mock_send.return_value = (200, {}, "[]")
        client = NebulAuthDashboardClient(
            auth={"mode": "session", "session_cookie": "sess-123"}
        )

        client.list_users()

        args, _ = mock_send.call_args
        self.assertEqual(args[3]["Cookie"], "mc_session=sess-123")

    @patch("nebulauth_sdk.dashboard.NebulAuthDashboardClient._send")
    def test_bulk_create_keys_adds_format_query(self, mock_send) -> None:
        mock_send.return_value = (200, {"content-type": "text/plain"}, "key-1")
        client = NebulAuthDashboardClient(
            auth={"mode": "bearer", "bearer_token": "mk_at_test"}
        )

        client.bulk_create_keys(
            {"count": 1, "labelPrefix": "Promo"},
            format="txt",
        )

        args, _ = mock_send.call_args
        self.assertEqual(
            args[1],
            "https://api.nebulauth.com/dashboard/keys/batch?format=txt",
        )

    @patch("nebulauth_sdk.dashboard.NebulAuthDashboardClient._send")
    def test_analytics_summary_adds_days_query(self, mock_send) -> None:
        mock_send.return_value = (200, {}, '{"totals":{}}')
        client = NebulAuthDashboardClient(
            auth={"mode": "bearer", "bearer_token": "mk_at_test"}
        )

        client.analytics_summary(30)

        args, _ = mock_send.call_args
        self.assertEqual(
            args[1],
            "https://api.nebulauth.com/dashboard/analytics/summary?days=30",
        )

    def test_missing_session_cookie_raises(self) -> None:
        client = NebulAuthDashboardClient(auth={"mode": "session"})

        with self.assertRaises(NebulAuthConfigError):
            client.me()


if __name__ == "__main__":
    unittest.main()
