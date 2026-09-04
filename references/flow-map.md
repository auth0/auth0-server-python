# Flow Map — where each flow lives

Before working on a flow, read its entry points and supporting modules. Every flow lives in a
`# ==== SECTION ====` banner in `server_client.py`; grep the banner name to find it.

| Flow | Entry points (`ServerClient`) | Also read | Guide |
|------|-------------------------------|-----------|-------|
| Interactive login | `start_interactive_login`, `complete_interactive_login` | `utils/helpers.py` (`PKCE`, `State`), `store/abstract.py` (`TransactionStore`) | `examples/InteractiveLogin.md` |
| Session + user | `get_user`, `get_session`, `logout`, `handle_backchannel_logout` | `store/abstract.py` (`StateStore`, `delete_by_logout_token`), `encryption/encrypt.py` | `examples/RetrievingData.md` |
| Access tokens | `get_access_token`, `get_token_by_refresh_token` | `auth_schemes/bearer_auth.py`, `auth_schemes/dpop_auth.py` | `examples/RetrievingData.md` |
| CIBA | `login_backchannel`, `backchannel_authentication`, `initiate_backchannel_authentication`, `backchannel_authentication_grant` | `auth_types/` (`BackchannelAuthenticationOptions`, poll/grant models) | `examples/ClientInitiatedBackChannelLogin.md` |
| User linking | `start_link_user`, `complete_link_user`, `start_unlink_user`, `complete_unlink_user` | the interactive-login flow — linking reuses its transaction round-trip | `examples/UserLinking.md` |
| Federated connection tokens | `get_access_token_for_connection`, `get_token_for_connection` | `error/` (`AccessTokenForConnectionErrorCode`) | `examples/ConnectedAccounts.md` |
| Connected accounts | `start_connect_account`, `complete_connect_account`, `list_connected_accounts`, `delete_connected_account`, `list_connected_account_connections` | `auth_server/my_account_client.py` — these proxy the My Account API | `examples/ConnectedAccounts.md` |
| Custom token exchange | `custom_token_exchange`, `login_with_custom_token_exchange` | `error/` (`CustomTokenExchangeErrorCode`) — RFC 8693 subject/actor token types | `examples/CustomTokenExchange.md` |
| MFA | `ServerClient.mfa` → `MfaClient` (`list_authenticators`, `enroll_authenticator`, `challenge_authenticator`, `verify`, `decrypt_mfa_token`) | `auth_server/mfa_client.py`, `encryption/encrypt.py` (the MFA token is encrypted at rest) | `examples/MFA.md` |
| Passkeys | `passkey_signup_challenge`, `passkey_login_challenge`, `signin_with_passkey` | `auth_schemes/dpop_auth.py` — passkey sign-in is the DPoP-bound path | `examples/Passkeys.md` |
| My Account | `MyAccountClient` (factors, authentication methods, enroll/verify) | `auth_schemes/dpop_auth.py`; stateless — every call takes a user token | `examples/MyAccountAuthenticationMethods.md` |
| MCD | any flow — `domain` may be an async resolver | `_resolve_current_domain`, pitfall 5 in `references/pitfalls.md` | `examples/MultipleCustomDomains.md` |
| Enterprise Connect | `start_enterprise_login`, `complete_interactive_login` (EC branch), `is_federated_domain` (standalone), `logout` (`federated`) | `auth_types/` (`StartEnterpriseLoginOptions`, `LogoutOptions.federated`), `error/` (`EnterpriseConnectError`); the SDK owns no session in this mode | `examples/EnterpriseConnect.md` |

Two rules cut across every flow above, so check them on any change here: resolve the domain through
`await self._resolve_current_domain(store_options)` rather than reading `self._domain`, and accept
`store_options` on every public method so cookie-backed stores keep working. Both are in
`references/pitfalls.md`.
