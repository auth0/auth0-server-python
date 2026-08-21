# Mutual TLS (mTLS) Client Authentication

Authenticate to Auth0 with a TLS client certificate instead of a client secret (RFC 8705). The certificate is presented during the TLS handshake; no credential travels in the request body.

## Prerequisites

- Auth0 **Enterprise** tenant with the **Highly Regulated Identity** add-on
- A `self_managed_certs` **custom domain** configured on the tenant
- **Allow mTLS Endpoint Aliases** enabled on the tenant (Dashboard → Settings → Advanced)
- Client application's authentication method set to **mTLS** in Dashboard → Applications → Settings → Credentials

## Generating a client certificate (development)

```bash
# Self-signed CA + client cert (development only — use your PKI in production)
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 365 -nodes \
  -subj "/CN=dev-ca"
openssl req -newkey rsa:2048 -keyout client.key -out client.csr -nodes \
  -subj "/CN=my-app-client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 365
```

## Wiring into `ServerClient`

```python
import ssl
from auth0_server_python.auth_server.server_client import ServerClient

ssl_context = ssl.create_default_context()          # trusts system/public CAs for the server side
ssl_context.load_cert_chain("client.crt", "client.key")  # attaches the client identity

auth0 = ServerClient(
    domain="login.example.com",       # self_managed_certs custom domain
    client_id="<AUTH0_CLIENT_ID>",
    use_mtls=True,
    ssl_context=ssl_context,
    secret="<AUTH0_SECRET>",
    authorization_params={
        "audience": "<API_IDENTIFIER>",
        "scope": "openid profile email offline_access",
    },
)
```

The SDK passes `ssl_context` as `verify=ssl_context` to every `httpx.AsyncClient` it constructs, including the authlib client used for the authorization-code exchange. You never call `load_cert_chain` inside the SDK — the caller owns the TLS material.

## Mutual exclusion

`use_mtls=True` cannot be combined with:

| Parameter | Reason |
|-----------|--------|
| `client_secret` | One client-auth method only — Auth0 rejects requests carrying both. |
| `client_assertion_signing_key` | Same — one method only. |
| `dpop_key` (per-call on `signin_with_passkey` / `mfa.verify`) | DPoP binds to its own key (`cnf.jkt`) and suppresses `cnf.x5t#S256`; combining them silently defeats mTLS token binding. |

All three raise `ConfigurationError` immediately (constructor for the first two, at the call site for DPoP).

## Token sender-constraining

When the target API has **Token Sender-Constraining (mTLS)** enabled, issued access tokens carry a `cnf.x5t#S256` claim binding the token to the certificate thumbprint. The SDK warns if it receives a token that lacks this claim:

> `UserWarning: mTLS is enabled but the access token is not certificate-bound (no cnf.x5t#S256). Sender-constraining is not active — configure Token Sender-Constraining (mTLS) on the API resource server.`

To verify the thumbprint yourself:

```bash
openssl x509 -in client.crt -outform DER | openssl dgst -sha256 -binary | openssl enc -base64 | tr '+/' '-_' | tr -d '='
# Compare the output to the cnf.x5t#S256 claim in the decoded access token.
```

## MFA under mTLS

The client certificate is presented on all MFA API calls. Only the token-endpoint call inside `mfa.verify` is routed through the mTLS alias; challenge and enrollment calls stay on the standard host (the standard host does not request a client certificate, so the loaded context is inert on those calls).

When calling `client.mfa.verify` directly (rather than through the SDK's built-in flow), pass the resolved mTLS token endpoint:

```python
metadata = await auth0._get_oidc_metadata_cached(domain)
mtls_token_endpoint = auth0._resolve_token_endpoint(metadata)

await auth0.mfa.verify(
    {"mfa_token": encrypted_token, "otp": "123456"},
    token_endpoint_override=mtls_token_endpoint,
)
```
