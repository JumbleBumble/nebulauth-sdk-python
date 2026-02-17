from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urljoin, urlparse

from .exceptions import NebulAuthConfigError, NebulAuthRequestError

ReplayProtectionMode = Literal["none", "nonce", "strict"]
DEFAULT_BASE_URL = "https://api.nebulauth.com/api/v1"


@dataclass(slots=True)
class NebulAuthResponse:
    """Normalized HTTP response wrapper returned by SDK methods."""

    status_code: int
    ok: bool
    data: Any
    headers: dict[str, str]


class NebulAuthClient:
    """
    Python SDK client for NebulAuth runtime API.
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        bearer_token: str | None = None,
        signing_secret: str | None = None,
        service_slug: str | None = None,
        replay_protection: ReplayProtectionMode = "strict",
        timeout_seconds: float = 15.0,
    ) -> None:
        """
        Initialize a NebulAuth API client.

        Args:
            base_url: Runtime API base URL. Defaults to production API.
            bearer_token: API bearer token (mk_at_...).
            signing_secret: HMAC signing secret (mk_sig_...) for nonce/strict modes.
            service_slug: Default service slug used by redeem operations.
            replay_protection: Request signing mode: none, nonce, or strict.
            timeout_seconds: HTTP timeout in seconds for each request.

        Raises:
            NebulAuthConfigError: If configuration values are invalid.
        """
        resolved_base_url = (base_url or "").strip() or DEFAULT_BASE_URL
        normalized_base = resolved_base_url.rstrip("/")
        self.base_url = normalized_base
        self._base_path = urlparse(normalized_base).path.rstrip("/")

        self.bearer_token = bearer_token
        self.signing_secret = signing_secret
        self.service_slug = service_slug
        self.replay_protection = replay_protection
        self.timeout_seconds = timeout_seconds

        if replay_protection not in ("none", "nonce", "strict"):
            raise NebulAuthConfigError(
                "replay_protection must be one of: none, nonce, strict"
            )

    def verify_key(
        self,
        *,
        key: str,
        request_id: str | None = None,
        hwid: str | None = None,
        use_pop: bool = False,
        access_token: str | None = None,
        pop_key: str | None = None,
    ) -> NebulAuthResponse:
        """
        Verify an end-user key using /keys/verify.

        Args:
            key: End-user key value.
            request_id: Optional request correlation ID.
            hwid: Optional HWID header value.
            use_pop: Use PoP auth instead of bearer mode.
            access_token: PoP access token when use_pop=True.
            pop_key: PoP key used to sign the request when use_pop=True.

        Returns:
            NebulAuthResponse containing parsed JSON or raw text fallback.
        """
        payload: dict[str, Any] = {"key": key}
        if request_id:
            payload["requestId"] = request_id

        extra_headers: dict[str, str] = {}
        if hwid:
            extra_headers["X-HWID"] = hwid

        return self._post(
            "/keys/verify",
            payload,
            extra_headers=extra_headers,
            use_pop=use_pop,
            access_token=access_token,
            pop_key=pop_key,
        )

    def auth_verify(
        self,
        *,
        key: str,
        hwid: str | None = None,
        request_id: str | None = None,
    ) -> NebulAuthResponse:
        """
        Verify a key and bootstrap PoP credentials using /auth/verify.

        Args:
            key: End-user key value.
            hwid: Optional HWID sent in request body.
            request_id: Optional request correlation ID.

        Returns:
            NebulAuthResponse with PoP bootstrap payload on success.
        """
        payload: dict[str, Any] = {"key": key}
        if hwid:
            payload["hwid"] = hwid
        if request_id:
            payload["requestId"] = request_id

        return self._post("/auth/verify", payload)

    def redeem_key(
        self,
        *,
        key: str,
        discord_id: str,
        service_slug: str | None = None,
        request_id: str | None = None,
        use_pop: bool = False,
        access_token: str | None = None,
        pop_key: str | None = None,
    ) -> NebulAuthResponse:
        """
        Redeem a key against a Discord user ID using /keys/redeem.

        Args:
            key: End-user key value.
            discord_id: Discord user identifier.
            service_slug: Optional per-call service slug override.
            request_id: Optional request correlation ID.
            use_pop: Use PoP auth instead of bearer mode.
            access_token: PoP access token when use_pop=True.
            pop_key: PoP key used to sign the request when use_pop=True.

        Returns:
            NebulAuthResponse with redemption result payload.

        Raises:
            NebulAuthConfigError: If no service slug is provided.
        """
        slug = service_slug or self.service_slug
        if not slug:
            raise NebulAuthConfigError(
                "service_slug is required either on client initialization or redeem_key()"
            )

        payload: dict[str, Any] = {
            "key": key,
            "discordId": discord_id,
            "serviceSlug": slug,
        }
        if request_id:
            payload["requestId"] = request_id

        return self._post(
            "/keys/redeem",
            payload,
            use_pop=use_pop,
            access_token=access_token,
            pop_key=pop_key,
        )

    def reset_hwid(
        self,
        *,
        discord_id: str | None = None,
        key: str | None = None,
        request_id: str | None = None,
        use_pop: bool = False,
        access_token: str | None = None,
        pop_key: str | None = None,
    ) -> NebulAuthResponse:
        """
        Reset stored HWID via /keys/reset-hwid.

        At least one of discord_id or key must be provided.

        Args:
            discord_id: Discord user identifier.
            key: End-user key value.
            request_id: Optional request correlation ID.
            use_pop: Use PoP auth instead of bearer mode.
            access_token: PoP access token when use_pop=True.
            pop_key: PoP key used to sign the request when use_pop=True.

        Returns:
            NebulAuthResponse with reset result payload.

        Raises:
            NebulAuthConfigError: If neither discord_id nor key is provided.
        """
        if not discord_id and not key:
            raise NebulAuthConfigError("reset_hwid requires either discord_id or key")

        payload: dict[str, Any] = {}
        if discord_id:
            payload["discordId"] = discord_id
        if key:
            payload["key"] = key
        if request_id:
            payload["requestId"] = request_id

        return self._post(
            "/keys/reset-hwid",
            payload,
            use_pop=use_pop,
            access_token=access_token,
            pop_key=pop_key,
        )

    def post(
        self,
        endpoint: str,
        payload: dict[str, Any],
        *,
        use_pop: bool = False,
        access_token: str | None = None,
        pop_key: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> NebulAuthResponse:
        """
        Send a signed POST request to a NebulAuth runtime endpoint.

        This helper is useful for calling future endpoints before dedicated
        wrapper methods are added.
        """
        return self._post(
            endpoint,
            payload,
            use_pop=use_pop,
            access_token=access_token,
            pop_key=pop_key,
            extra_headers=extra_headers,
        )

    def _post(
        self,
        endpoint: str,
        payload: dict[str, Any],
        *,
        use_pop: bool = False,
        access_token: str | None = None,
        pop_key: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> NebulAuthResponse:
        """Internal POST request pipeline with auth, signing, and parsing."""
        url = self._endpoint_url(endpoint)
        body_bytes = self._json_body_bytes(payload)

        headers = {
            "Content-Type": "application/json",
        }
        headers.update(
            self._build_auth_headers(
                method="POST",
                url=url,
                body_bytes=body_bytes,
                use_pop=use_pop,
                access_token=access_token,
                pop_key=pop_key,
            )
        )
        if extra_headers:
            headers.update(extra_headers)

        status_code, response_headers, response_text = self._send_post(
            url,
            body_bytes,
            headers,
        )

        data = self._parse_response_data(response_text)
        return NebulAuthResponse(
            status_code=status_code,
            ok=200 <= status_code < 300,
            data=data,
            headers=response_headers,
        )

    def _send_post(
        self,
        url: str,
        body_bytes: bytes,
        headers: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        """Send POST using stdlib HTTP transport and return status, headers, body text."""
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.hostname:
            raise NebulAuthRequestError(f"Invalid URL: {url}")

        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        port = parsed.port
        conn: http.client.HTTPConnection
        if parsed.scheme == "https":
            conn = http.client.HTTPSConnection(
                parsed.hostname,
                port or 443,
                timeout=self.timeout_seconds,
            )
        elif parsed.scheme == "http":
            conn = http.client.HTTPConnection(
                parsed.hostname,
                port or 80,
                timeout=self.timeout_seconds,
            )
        else:
            raise NebulAuthRequestError(f"Unsupported URL scheme: {parsed.scheme}")

        try:
            conn.request("POST", path, body=body_bytes, headers=headers)
            response = conn.getresponse()
            response_text = response.read().decode("utf-8", errors="replace")
            response_headers = {k: v for k, v in response.getheaders()}
            return response.status, response_headers, response_text
        except Exception as exc:
            raise NebulAuthRequestError(str(exc)) from exc
        finally:
            conn.close()

    def _build_auth_headers(
        self,
        *,
        method: str,
        url: str,
        body_bytes: bytes,
        use_pop: bool,
        access_token: str | None,
        pop_key: str | None,
    ) -> dict[str, str]:
        """Build authorization and signing headers for bearer or PoP mode."""
        if use_pop:
            if not access_token:
                raise NebulAuthConfigError("access_token is required when use_pop=True")
            if not pop_key:
                raise NebulAuthConfigError("pop_key is required when use_pop=True")

            headers = {"Authorization": f"Bearer {access_token}"}
            headers.update(
                self._build_signing_headers(
                    method,
                    url,
                    body_bytes,
                    secret=pop_key,
                )
            )
            return headers

        if not self.bearer_token:
            raise NebulAuthConfigError("bearer_token is required for bearer mode")

        headers = {"Authorization": f"Bearer {self.bearer_token}"}
        if self.replay_protection != "none":
            if not self.signing_secret:
                raise NebulAuthConfigError(
                    "signing_secret is required when replay_protection is nonce/strict"
                )
            signing_headers = self._build_signing_headers(
                method,
                url,
                body_bytes,
                secret=self.signing_secret,
            )

            if self.replay_protection == "nonce":
                signing_headers.pop("X-Body-Sha256", None)

            headers.update(signing_headers)

        return headers

    def _build_signing_headers(
        self,
        method: str,
        url: str,
        body_bytes: bytes,
        *,
        secret: str,
    ) -> dict[str, str]:
        """Build canonical HMAC request signing headers for NebulAuth."""
        path = self._canonical_path(url)
        timestamp = str(int(time.time() * 1000))
        nonce = secrets.token_urlsafe(16)
        body_hash = hashlib.sha256(body_bytes).hexdigest()

        canonical = f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{body_hash}"
        signature = hmac.new(
            secret.encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return {
            "X-Timestamp": timestamp,
            "X-Nonce": nonce,
            "X-Signature": signature,
            "X-Body-Sha256": body_hash,
        }

    def _canonical_path(self, url: str) -> str:
        """Return canonical path used in signature generation."""
        target = urlparse(url)
        path = target.path or "/"

        if self._base_path and path.startswith(self._base_path):
            path = path[len(self._base_path) :] or "/"

        if not path.startswith("/"):
            path = f"/{path}"

        return path

    def _endpoint_url(self, endpoint: str) -> str:
        """Resolve a relative endpoint path against the configured base URL."""
        base = f"{self.base_url}/"
        return urljoin(base, endpoint.lstrip("/"))

    @staticmethod
    def _json_body_bytes(payload: dict[str, Any]) -> bytes:
        """Serialize payload to compact UTF-8 JSON bytes for deterministic signing."""
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _parse_response_data(text: str) -> Any:
        """Parse JSON response body; fall back to raw text wrapped as error."""
        if not text:
            return {}
        try:
            return json.loads(text)
        except ValueError:
            return {"error": text}
