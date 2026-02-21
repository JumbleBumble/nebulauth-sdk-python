from __future__ import annotations

import http.client
import json
from dataclasses import dataclass
from typing import Any, Literal, TypedDict
from urllib.parse import urlencode, urlparse

from .exceptions import NebulAuthConfigError, NebulAuthRequestError

DashboardHttpMethod = Literal["GET", "POST", "PATCH", "DELETE"]
DashboardAuthMode = Literal["session", "bearer"]


@dataclass(slots=True)
class DashboardResponse:
    """Normalized HTTP response wrapper returned by dashboard SDK methods."""

    status_code: int
    ok: bool
    data: Any
    headers: dict[str, str]


class DashboardAuthOptions(TypedDict, total=False):
    """Per-request or default dashboard auth configuration."""

    mode: DashboardAuthMode
    session_cookie: str
    bearer_token: str


class DashboardRequestOptions(TypedDict, total=False):
    """Optional request overrides for auth, query string, and headers."""

    auth: DashboardAuthOptions
    query: dict[str, str | int | float | bool | None]
    headers: dict[str, str]


class LoginRequest(TypedDict):
    email: str
    password: str


class CustomerUpdateRequest(TypedDict, total=False):
    requireDiscordRedeem: bool
    requireHwid: bool
    paused: bool


class TeamMemberCreateRequest(TypedDict):
    email: str
    password: str
    role: Literal["READONLY", "MEMBER", "ADMIN"]


class TeamMemberUpdateRequest(TypedDict, total=False):
    role: Literal["READONLY", "MEMBER", "ADMIN"]
    password: str


class KeyCreateRequest(TypedDict, total=False):
    label: str
    durationHours: int
    metadata: dict[str, Any]


class KeyBatchCreateRequest(TypedDict, total=False):
    labelPrefix: str
    count: int
    durationHours: int
    keyOnly: bool
    metadata: dict[str, Any]


class KeyUpdateRequest(TypedDict, total=False):
    label: str
    durationHours: int
    metadata: dict[str, Any]


class KeyRevokeRequest(TypedDict, total=False):
    reason: str


class RevokeSessionRequest(TypedDict, total=False):
    reason: str
    revokeKey: bool
    resetHwid: bool
    blacklistDiscord: bool
    terminateAllForKey: bool
    terminateAllForToken: bool


class RevokeAllSessionsRequest(TypedDict, total=False):
    reason: str
    keyId: str
    tokenId: str


class CheckpointStepInput(TypedDict):
    adUrl: str


class CheckpointCreateRequest(TypedDict):
    name: str
    durationHours: int
    isActive: bool
    steps: list[CheckpointStepInput]
    referrerDomainOnly: bool


class CheckpointUpdateRequest(TypedDict, total=False):
    name: str
    durationHours: int
    isActive: bool
    referrerDomainOnly: bool
    steps: list[CheckpointStepInput]


class BlacklistCreateRequest(TypedDict, total=False):
    type: Literal["DISCORD", "IP"]
    value: str
    reason: str


class ApiTokenCreateRequest(TypedDict, total=False):
    scopes: list[str]
    replayProtection: Literal["none", "nonce", "strict"]
    authMode: Literal["bearer", "pop_optional", "pop_required"]
    expiresAt: str | None


class ApiTokenUpdateRequest(TypedDict, total=False):
    scopes: list[str]
    replayProtection: Literal["none", "nonce", "strict"]
    authMode: Literal["bearer", "pop_optional", "pop_required"]
    expiresAt: str | None


class NebulAuthDashboardClient:
    """Python SDK client for NebulAuth dashboard API."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        auth: DashboardAuthOptions | None = None,
        timeout_seconds: float = 15.0,
    ) -> None:
        """Initialize a dashboard API client.

        Args:
            base_url: Dashboard API base URL. Defaults to production dashboard API.
            auth: Optional default auth context used when per-call auth is omitted.
            timeout_seconds: HTTP timeout in seconds for each request.
        """
        resolved_base = (base_url or "https://api.nebulauth.com/dashboard").strip()
        self.base_url = resolved_base.rstrip("/")
        self.default_auth = auth
        self.timeout_seconds = timeout_seconds

    def login(self, payload: LoginRequest, options: DashboardRequestOptions | None = None) -> DashboardResponse:
        """Authenticate a dashboard user via POST /auth/login."""
        return self.request("POST", "/auth/login", payload, options)

    def logout(self, options: DashboardRequestOptions | None = None) -> DashboardResponse:
        """Terminate dashboard session via POST /auth/logout."""
        return self.request("POST", "/auth/logout", {}, options)

    def me(self, options: DashboardRequestOptions | None = None) -> DashboardResponse:
        """Get current dashboard principal via GET /me."""
        return self.request("GET", "/me", None, options)

    def get_customer(self, options: DashboardRequestOptions | None = None) -> DashboardResponse:
        """Get customer settings via GET /customer."""
        return self.request("GET", "/customer", None, options)

    def update_customer(
        self, payload: CustomerUpdateRequest, options: DashboardRequestOptions | None = None
    ) -> DashboardResponse:
        """Update customer settings via PATCH /customer."""
        return self.request("PATCH", "/customer", payload, options)

    def create_user(
        self, payload: TeamMemberCreateRequest, options: DashboardRequestOptions | None = None
    ) -> DashboardResponse:
        """Create a dashboard team member via POST /users."""
        return self.request("POST", "/users", payload, options)

    def list_users(self, options: DashboardRequestOptions | None = None) -> DashboardResponse:
        """List dashboard team members via GET /users."""
        return self.request("GET", "/users", None, options)

    def update_user(
        self,
        user_id: str,
        payload: TeamMemberUpdateRequest,
        options: DashboardRequestOptions | None = None,
    ) -> DashboardResponse:
        """Update a dashboard team member via PATCH /users/:id."""
        return self.request("PATCH", f"/users/{user_id}", payload, options)

    def delete_user(self, user_id: str, options: DashboardRequestOptions | None = None) -> DashboardResponse:
        """Delete a dashboard team member via DELETE /users/:id."""
        return self.request("DELETE", f"/users/{user_id}", None, options)

    def create_key(self, payload: KeyCreateRequest, options: DashboardRequestOptions | None = None) -> DashboardResponse:
        """Create a license key via POST /keys."""
        return self.request("POST", "/keys", payload, options)

    def bulk_create_keys(
        self,
        payload: KeyBatchCreateRequest,
        *,
        format: Literal["json", "csv", "txt"] = "json",
        options: DashboardRequestOptions | None = None,
    ) -> DashboardResponse:
        """Create keys in batch via POST /keys/batch with format query option."""
        merged = dict(options or {})
        merged_query = dict(merged.get("query", {}))
        merged_query["format"] = format
        merged["query"] = merged_query
        return self.request("POST", "/keys/batch", payload, merged)

    def extend_key_durations(self, hours: int, options: DashboardRequestOptions | None = None) -> DashboardResponse:
        """Extend key durations globally via POST /keys/extend-duration."""
        return self.request("POST", "/keys/extend-duration", {"hours": hours}, options)

    def get_key(self, key_id: str, options: DashboardRequestOptions | None = None) -> DashboardResponse:
        """Get a key by ID via GET /keys/:id."""
        return self.request("GET", f"/keys/{key_id}", None, options)

    def list_keys(self, options: DashboardRequestOptions | None = None) -> DashboardResponse:
        """List keys via GET /keys."""
        return self.request("GET", "/keys", None, options)

    def update_key(
        self, key_id: str, payload: KeyUpdateRequest, options: DashboardRequestOptions | None = None
    ) -> DashboardResponse:
        """Update key fields via PATCH /keys/:id."""
        return self.request("PATCH", f"/keys/{key_id}", payload, options)

    def reset_key_hwid(self, key_id: str, options: DashboardRequestOptions | None = None) -> DashboardResponse:
        """Reset key HWID via POST /keys/:id/reset-hwid."""
        return self.request("POST", f"/keys/{key_id}/reset-hwid", {}, options)

    def delete_key(
        self,
        key_id: str,
        payload: KeyRevokeRequest | None = None,
        options: DashboardRequestOptions | None = None,
    ) -> DashboardResponse:
        """Delete/revoke a key via DELETE /keys/:id."""
        return self.request("DELETE", f"/keys/{key_id}", payload or {}, options)

    def list_key_sessions(self, options: DashboardRequestOptions | None = None) -> DashboardResponse:
        """List key sessions via GET /key-sessions."""
        return self.request("GET", "/key-sessions", None, options)

    def revoke_key_session(
        self,
        session_id: str,
        payload: RevokeSessionRequest,
        options: DashboardRequestOptions | None = None,
    ) -> DashboardResponse:
        """Revoke a key session via DELETE /key-sessions/:id."""
        return self.request("DELETE", f"/key-sessions/{session_id}", payload, options)

    def revoke_all_key_sessions(
        self, payload: RevokeAllSessionsRequest, options: DashboardRequestOptions | None = None
    ) -> DashboardResponse:
        """Revoke multiple sessions via POST /key-sessions/revoke-all."""
        return self.request("POST", "/key-sessions/revoke-all", payload, options)

    def list_checkpoints(self, options: DashboardRequestOptions | None = None) -> DashboardResponse:
        """List checkpoints via GET /checkpoints."""
        return self.request("GET", "/checkpoints", None, options)

    def get_checkpoint(self, checkpoint_id: str, options: DashboardRequestOptions | None = None) -> DashboardResponse:
        """Get a checkpoint by ID via GET /checkpoints/:id."""
        return self.request("GET", f"/checkpoints/{checkpoint_id}", None, options)

    def create_checkpoint(
        self, payload: CheckpointCreateRequest, options: DashboardRequestOptions | None = None
    ) -> DashboardResponse:
        """Create a checkpoint via POST /checkpoints."""
        return self.request("POST", "/checkpoints", payload, options)

    def update_checkpoint(
        self,
        checkpoint_id: str,
        payload: CheckpointUpdateRequest,
        options: DashboardRequestOptions | None = None,
    ) -> DashboardResponse:
        """Update a checkpoint via PATCH /checkpoints/:id."""
        return self.request("PATCH", f"/checkpoints/{checkpoint_id}", payload, options)

    def delete_checkpoint(
        self, checkpoint_id: str, options: DashboardRequestOptions | None = None
    ) -> DashboardResponse:
        """Delete a checkpoint via DELETE /checkpoints/:id."""
        return self.request("DELETE", f"/checkpoints/{checkpoint_id}", None, options)

    def list_blacklist(self, options: DashboardRequestOptions | None = None) -> DashboardResponse:
        """List blacklist entries via GET /blacklist."""
        return self.request("GET", "/blacklist", None, options)

    def create_blacklist_entry(
        self, payload: BlacklistCreateRequest, options: DashboardRequestOptions | None = None
    ) -> DashboardResponse:
        """Create blacklist entry via POST /blacklist."""
        return self.request("POST", "/blacklist", payload, options)

    def delete_blacklist_entry(
        self, blacklist_id: str, options: DashboardRequestOptions | None = None
    ) -> DashboardResponse:
        """Delete blacklist entry via DELETE /blacklist/:id."""
        return self.request("DELETE", f"/blacklist/{blacklist_id}", None, options)

    def create_api_token(
        self, payload: ApiTokenCreateRequest, options: DashboardRequestOptions | None = None
    ) -> DashboardResponse:
        """Create API token via POST /api-tokens."""
        return self.request("POST", "/api-tokens", payload, options)

    def update_api_token(
        self,
        token_id: str,
        payload: ApiTokenUpdateRequest,
        options: DashboardRequestOptions | None = None,
    ) -> DashboardResponse:
        """Update API token via PATCH /api-tokens/:id."""
        return self.request("PATCH", f"/api-tokens/{token_id}", payload, options)

    def list_api_tokens(self, options: DashboardRequestOptions | None = None) -> DashboardResponse:
        """List API tokens via GET /api-tokens."""
        return self.request("GET", "/api-tokens", None, options)

    def delete_api_token(self, token_id: str, options: DashboardRequestOptions | None = None) -> DashboardResponse:
        """Delete API token via DELETE /api-tokens/:id."""
        return self.request("DELETE", f"/api-tokens/{token_id}", None, options)

    def analytics_summary(self, days: int | None = None, options: DashboardRequestOptions | None = None) -> DashboardResponse:
        """Fetch analytics summary via GET /analytics/summary."""
        merged = dict(options or {})
        if days is not None:
            merged_query = dict(merged.get("query", {}))
            merged_query["days"] = days
            merged["query"] = merged_query
        return self.request("GET", "/analytics/summary", None, merged)

    def analytics_geo(self, days: int | None = None, options: DashboardRequestOptions | None = None) -> DashboardResponse:
        """Fetch analytics geo breakdown via GET /analytics/geo."""
        merged = dict(options or {})
        if days is not None:
            merged_query = dict(merged.get("query", {}))
            merged_query["days"] = days
            merged["query"] = merged_query
        return self.request("GET", "/analytics/geo", None, merged)

    def analytics_activity(self, options: DashboardRequestOptions | None = None) -> DashboardResponse:
        """Fetch recent activity via GET /analytics/activity."""
        return self.request("GET", "/analytics/activity", None, options)

    def request(
        self,
        method: DashboardHttpMethod,
        path: str,
        body: dict[str, Any] | list[Any] | None,
        options: DashboardRequestOptions | None = None,
    ) -> DashboardResponse:
        """Send a dashboard API request with optional auth/query/header overrides."""
        opts = options or {}
        auth = opts.get("auth") or self.default_auth
        headers = dict(opts.get("headers", {}))

        if auth:
            mode = auth.get("mode")
            if mode == "session":
                session_cookie = auth.get("session_cookie")
                if not session_cookie:
                    raise NebulAuthConfigError(
                        "session_cookie is required for session auth mode"
                    )
                headers["Cookie"] = f"mc_session={session_cookie}"
            elif mode == "bearer":
                bearer_token = auth.get("bearer_token")
                if not bearer_token:
                    raise NebulAuthConfigError(
                        "bearer_token is required for bearer auth mode"
                    )
                headers["Authorization"] = f"Bearer {bearer_token}"

        payload = None
        if method != "GET" and body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        url = self._build_url(path, opts.get("query"))
        status_code, response_headers, response_text = self._send(method, url, payload, headers)
        data = self._parse_response_data(response_text)

        return DashboardResponse(
            status_code=status_code,
            ok=200 <= status_code < 300,
            data=data,
            headers=response_headers,
        )

    def _send(
        self,
        method: DashboardHttpMethod,
        url: str,
        body: bytes | None,
        headers: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        """Execute the HTTP request and return status, headers, and text body."""
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.hostname:
            raise NebulAuthRequestError(f"Invalid URL: {url}")

        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        if parsed.scheme == "https":
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                parsed.hostname,
                parsed.port or 443,
                timeout=self.timeout_seconds,
            )
        elif parsed.scheme == "http":
            conn = http.client.HTTPConnection(
                parsed.hostname,
                parsed.port or 80,
                timeout=self.timeout_seconds,
            )
        else:
            raise NebulAuthRequestError(f"Unsupported URL scheme: {parsed.scheme}")

        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            response_text = response.read().decode("utf-8", errors="replace")
            response_headers = {k: v for k, v in response.getheaders()}
            return response.status, response_headers, response_text
        except Exception as exc:
            raise NebulAuthRequestError(str(exc)) from exc
        finally:
            conn.close()

    def _build_url(
        self,
        path: str,
        query: dict[str, str | int | float | bool | None] | None,
    ) -> str:
        """Compose absolute URL and optional query string for dashboard request."""
        endpoint = path if path.startswith("/") else f"/{path}"
        url = f"{self.base_url}{endpoint}"

        if not query:
            return url

        pairs: list[tuple[str, str]] = []
        for key, value in query.items():
            if value is None:
                continue
            pairs.append((key, str(value)))

        if not pairs:
            return url
        return f"{url}?{urlencode(pairs)}"

    @staticmethod
    def _parse_response_data(response_text: str) -> Any:
        """Parse JSON response text; fall back to plain text when not JSON."""
        if not response_text.strip():
            return {}
        try:
            return json.loads(response_text)
        except Exception:
            return response_text
