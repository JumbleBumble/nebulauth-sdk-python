import hashlib
import hmac
import unittest
from unittest.mock import patch

from nebulauth_sdk.client import NebulAuthClient
from nebulauth_sdk.exceptions import NebulAuthConfigError


class NebulAuthClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = NebulAuthClient(
            base_url="https://api.nebulauth.com/api/v1",
            bearer_token="mk_at_test",
            signing_secret="mk_sig_test",
            service_slug="svc",
            replay_protection="strict",
        )

    def test_canonical_path_strips_base_prefix(self) -> None:
        path = self.client._canonical_path(
            "https://api.nebulauth.com/api/v1/keys/verify"
        )
        self.assertEqual(path, "/keys/verify")

    def test_defaults_base_url_when_omitted(self) -> None:
        client = NebulAuthClient(
            bearer_token="mk_at_test",
            signing_secret="mk_sig_test",
        )

        self.assertEqual(client.base_url, "https://api.nebulauth.com/api/v1")

    @patch("nebulauth_sdk.client.time.time", return_value=1_700_000_000.123)
    @patch("nebulauth_sdk.client.secrets.token_urlsafe", return_value="nonce-token")
    def test_build_signing_headers_uses_expected_canonical_format(
        self, _mock_nonce, _mock_time
    ) -> None:
        body = '{"key":"mk_live_abc"}'
        headers = self.client._build_signing_headers(
            method="POST",
            url="https://api.nebulauth.com/api/v1/keys/verify",
            body_bytes=body.encode("utf-8"),
            secret="mk_sig_test",
        )

        expected_ts = "1700000000123"
        expected_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        expected_canonical = (
            f"POST\n/keys/verify\n{expected_ts}\nnonce-token\n{expected_hash}"
        )
        expected_signature = hmac.new(
            b"mk_sig_test", expected_canonical.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        self.assertEqual(headers["X-Timestamp"], expected_ts)
        self.assertEqual(headers["X-Nonce"], "nonce-token")
        self.assertEqual(headers["X-Body-Sha256"], expected_hash)
        self.assertEqual(headers["X-Signature"], expected_signature)

    def test_nonce_mode_omits_body_hash_header(self) -> None:
        client = NebulAuthClient(
            base_url="https://api.nebulauth.com/api/v1",
            bearer_token="mk_at_test",
            signing_secret="mk_sig_test",
            replay_protection="nonce",
        )

        headers = client._build_auth_headers(
            method="POST",
            url="https://api.nebulauth.com/api/v1/keys/verify",
            body_bytes=b'{"key":"mk_live_abc"}',
            use_pop=False,
            access_token=None,
            pop_key=None,
        )

        self.assertIn("Authorization", headers)
        self.assertNotIn("X-Body-Sha256", headers)
        self.assertIn("X-Signature", headers)

    def test_redeem_requires_service_slug(self) -> None:
        client = NebulAuthClient(
            base_url="https://api.nebulauth.com/api/v1",
            bearer_token="mk_at_test",
            signing_secret="mk_sig_test",
        )

        with self.assertRaises(NebulAuthConfigError):
            client.redeem_key(key="mk_live_abc", discord_id="123")

    def test_reset_hwid_requires_key_or_discord(self) -> None:
        with self.assertRaises(NebulAuthConfigError):
            self.client.reset_hwid()

    @patch("nebulauth_sdk.client.NebulAuthClient._send_post")
    def test_verify_key_sends_expected_endpoint_body_and_hwid_header(
        self, mock_post
    ) -> None:
        mock_post.return_value = (
            200,
            {"content-type": "application/json"},
            '{"valid":true}',
        )

        result = self.client.verify_key(
            key="mk_live_abc",
            request_id="req-1",
            hwid="HWID-1",
        )

        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.data, {"valid": True})

        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://api.nebulauth.com/api/v1/keys/verify")
        self.assertEqual(
            args[1],
            b'{"key":"mk_live_abc","requestId":"req-1"}',
        )
        self.assertEqual(args[2]["Authorization"], "Bearer mk_at_test")
        self.assertEqual(args[2]["X-HWID"], "HWID-1")
        self.assertIn("X-Signature", args[2])

    @patch("nebulauth_sdk.client.NebulAuthClient._send_post")
    def test_redeem_uses_default_service_slug(self, mock_post) -> None:
        mock_post.return_value = (
            200,
            {"content-type": "application/json"},
            '{"redeemed":true}',
        )

        self.client.redeem_key(
            key="mk_live_abc",
            discord_id="123",
            request_id="req-2",
        )

        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://api.nebulauth.com/api/v1/keys/redeem")
        self.assertEqual(
            args[1],
            b'{"key":"mk_live_abc","discordId":"123","serviceSlug":"svc","requestId":"req-2"}',
        )

    @patch("nebulauth_sdk.client.NebulAuthClient._send_post")
    def test_pop_mode_works_without_bearer_token(self, mock_post) -> None:
        client = NebulAuthClient(
            base_url="https://api.nebulauth.com/api/v1",
            replay_protection="strict",
        )
        mock_post.return_value = (
            200,
            {"content-type": "application/json"},
            '{"valid":true}',
        )

        client.verify_key(
            key="mk_live_abc",
            use_pop=True,
            access_token="v4.public.token",
            pop_key="pop-key-secret",
        )

        args, kwargs = mock_post.call_args
        self.assertEqual(
            args[2]["Authorization"],
            "Bearer v4.public.token",
        )
        self.assertIn("X-Signature", args[2])


if __name__ == "__main__":
    unittest.main()
