# DPoP — Sender-Constrained Tokens

DPoP (Demonstrating Proof of Possession, [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) binds an access token to a cryptographic key the client holds. A normal **Bearer** token is usable by anyone who holds it; a **DPoP-bound** token is useless without a matching proof signed by the private key — so a stolen token alone cannot be replayed.

This SDK supports DPoP for **passkey sign-in** (`ServerClient.signin_with_passkey`) and for every **My Account API** call (`MyAccountClient`).

> [!NOTE]
> DPoP is a confidential-client (Regular Web App) capability here: your server holds the key. The SDK does not store the key for you — you generate it and pass it in, so it lives in whatever secret store you choose (KMS/HSM/etc.).

## Table of Contents

- [`dpop_key` vs `dpop_proof`](#dpop_key-vs-dpop_proof)
- [1. Generate a key](#1-generate-a-key)
- [2. DPoP-bound passkey sign-in](#2-dpop-bound-passkey-sign-in)
- [3. DPoP on My Account API calls](#3-dpop-on-my-account-api-calls)
- [4. Generating a proof manually](#4-generating-a-proof-manually)
- [Key lifecycle and security](#key-lifecycle-and-security)
- [Error Handling](#error-handling)
- [Additional Resources](#additional-resources)

## `dpop_key` vs `dpop_proof`

These are **different things**, and the distinction is the whole mental model. You only ever handle the **key**; the SDK derives a fresh **proof** from it on every request.

| | `dpop_key` | `dpop_proof` |
|---|------------|--------------|
| What it is | A long-lived **EC P-256 key pair** | A signed **JWT**, created fresh for one request |
| Lifetime | Reused across sign-in and every API call | Single-use — one per HTTP request |
| Who holds it | You (the private key never leaves your server) | Sent on the wire in the `DPoP:` header |
| Sensitivity | **Tier 0** — it is a secret | Not a stored secret — a short-lived derived artifact |
| In the SDK | The `dpop_key` parameter you pass in | Built internally — you never construct one |

Think of `dpop_key` as a **signet ring** you keep, and `dpop_proof` as the **wax seal** you stamp on each letter: verifiably yours, but the seal from one letter is worthless on another. Each request the SDK mints a new proof (binding the HTTP method, the URL, a unique id, a timestamp, and — at the resource server — a hash of the access token), so a captured proof cannot be reused elsewhere.

## 1. Generate a key

The SDK uses `jwcrypto` (already a dependency). Generate one EC P-256 key and reuse the **same instance** for sign-in and for all subsequent API calls — the token is bound to that key.

```python
from jwcrypto import jwk

dpop_key = jwk.JWK.generate(kty="EC", crv="P-256")
```

> [!NOTE]
> The key **must** be EC P-256 (Auth0 advertises `ES256` only). Passing an RSA or P-384 key raises `ValueError` before any network call — it fails closed.

## 2. DPoP-bound passkey sign-in

Pass `dpop_key` to `signin_with_passkey`. The SDK attaches a token-endpoint DPoP proof so Auth0 issues a DPoP-bound token, and **rejects a Bearer downgrade**: if a key was supplied but the server returns `token_type: Bearer`, it raises instead of silently accepting an unbound token.

```python
result = await server_client.signin_with_passkey(
    auth_session=challenge.auth_session,
    authn_response=authn_response,
    dpop_key=dpop_key,
    store_options={"request": request, "response": response},
)
```

See [examples/Passkeys.md](Passkeys.md) for the full passkey flow.

## 3. DPoP on My Account API calls

Every `MyAccountClient` method takes an optional `dpop_key`. Supply it and the call sends `Authorization: DPoP <token>` plus a fresh `DPoP:` proof header; omit it and the call uses a plain `Authorization: Bearer <token>` — no behaviour change for callers that don't need DPoP.

```python
from auth0_server_python.auth_server.my_account_client import MyAccountClient

my_account = MyAccountClient(domain="YOUR_CUSTOM_DOMAIN")

methods = await my_account.list_authentication_methods(
    access_token=access_token,    # a DPoP-bound token from sign-in / MRRT
    dpop_key=dpop_key,            # the SAME key the token was bound to
)
```

> [!NOTE]
> If a `/me/v1/...` call is answered with `401 + DPoP-Nonce` (the server demanding a nonce), the SDK transparently retries the request **once** with the nonce embedded in the proof (RFC 9449 §9.1). The token endpoint nonce challenge (`400 + DPoP-Nonce`, §8.1) is handled the same way during sign-in. There is never more than one retry — it will not loop.

## 4. Generating a proof manually

For the token endpoint specifically (no access token exists yet, so the proof omits the `ath` claim), the SDK exposes a helper. You rarely need this — `signin_with_passkey` and the `MyAccountClient` methods build proofs for you — but it is available for custom token requests:

```python
from auth0_server_python.auth_schemes.dpop_auth import make_dpop_proof_for_token_endpoint

proof = make_dpop_proof_for_token_endpoint(
    dpop_key,
    "POST",
    "https://YOUR_CUSTOM_DOMAIN/oauth/token",
    # nonce="..."  # supply when the server returned a DPoP-Nonce
)
# send as the "DPoP" request header
```

For resource-server requests, the `DPoPAuth` httpx handler (also exported from `auth_schemes`) builds the proof — including the `ath` token-hash claim — automatically. The `MyAccountClient` methods select it internally when you pass `dpop_key`.

## Key lifecycle and security

- **You own the key.** Generate it, store it in your secret store, and reuse the same instance for the bound token's lifetime. Discard it when the session ends.
- **One key, one bound token.** The token is bound to the key; using a different key on a later API call will be rejected by the resource server (`401 invalid_dpop_proof`).
- **The proof is request-specific.** Method, URL, a unique `jti`, and a timestamp are baked into every proof, so it cannot be replayed against a different endpoint or reused.
- **Never log the private key or a proof.** Treat the key as Tier 0 and proofs as transient secrets. The SDK's auth handlers redact the key and token in their `repr()`.

## Error Handling

DPoP failures surface through the error type of the operation that used the key:

```python
from auth0_server_python.error import PasskeyError, MyAccountApiError, Auth0Error

# Wrong key type — fails closed before any request
try:
    await server_client.signin_with_passkey(
        auth_session=auth_session, authn_response=authn_response,
        dpop_key=rsa_key,   # not EC P-256
    )
except ValueError as e:
    print(e)   # "DPoP key must be an EC P-256 key"

# Bearer downgrade when DPoP was requested
except PasskeyError as e:
    print(e.code, e.message)   # passkey_token_error — "DPoP token binding failed..."
```

On the My Account surface, a key mismatch or a DPoP-required endpoint reached without binding surfaces as `MyAccountApiError` (typically `status=401`). Catch `Auth0Error` for uniform handling.

## Additional Resources

- [Passkey Authentication](Passkeys.md)
- [My Account — Authentication Methods](MyAccountAuthenticationMethods.md)
- [RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449)
