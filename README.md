# NebulAuth Python SDK Repo

This repository contains the Python package source and test suite for NebulAuth.

## Structure

- `nebulauth_sdk/` — package source
- `tests/` — unit tests + env-gated live tests
- `pyproject.toml` — package/build metadata

## Install (local)

```bash
cd "NebulAuth SDKs/Python"
pip install -e .
```

## Quick start

```python
from nebulauth_sdk import NebulAuthClient

client = NebulAuthClient(
    bearer_token="mk_at_...",
    signing_secret="mk_sig_...",
    service_slug="your-service",
    replay_protection="strict",  # "none" | "nonce" | "strict"
)

# Verify key
verify = client.verify_key(
    key="mk_live_...",
    request_id="req-123",
    hwid="WIN-DEVICE-12345",
)
print(verify.status_code, verify.data)

# Redeem
redeem = client.redeem_key(
    key="mk_live_...",
    discord_id="123456789012345678",
)
print(redeem.status_code, redeem.data)

# Reset HWID
reset = client.reset_hwid(
    discord_id="123456789012345678",
    key="mk_live_...",
)
print(reset.status_code, reset.data)
```

## PoP flow support

When you mint PoP credentials from `/auth/verify`, you can call endpoints with those values:

```python
pop_bootstrap = client.auth_verify(key="mk_live_...", hwid="WIN-DEVICE-12345")
if pop_bootstrap.data.get("valid"):
    access_token = pop_bootstrap.data["accessToken"]
    pop_key = pop_bootstrap.data["popKey"]

    verify_with_pop = client.verify_key(
        key="mk_live_...",
        use_pop=True,
        access_token=access_token,
        pop_key=pop_key,
    )
```

## Notes

- Canonical signing string matches your bot implementation:
  - `METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY_SHA256`
- Canonical path strips the base URL path prefix (e.g. `/api/v1`) before signing.
- NebulAuth may return HTTP 200 with logical denials (e.g. `{"valid": false, "reason": "NOT_FOUND"}`).
- SDK returns `NebulAuthResponse` with:
  - `status_code`
  - `ok`
  - `data`
  - `headers`

## Tests

- Unit/contract tests (mocked HTTP):

```bash
python -m unittest discover -s tests -v
```

- Live integration tests (real API calls, optional):

```bash
NEBULAUTH_LIVE_TEST=1 \
NEBULAUTH_BEARER_TOKEN=mk_at_... \
NEBULAUTH_SIGNING_SECRET=mk_sig_... \
NEBULAUTH_TEST_KEY=mk_live_... \
python -m unittest tests.test_live_client -v
```

Optional: `NEBULAUTH_BASE_URL=...`, `NEBULAUTH_TEST_HWID=...`
