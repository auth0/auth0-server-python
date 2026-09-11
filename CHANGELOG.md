# Change Log

## [1.0.0b16](https://github.com/auth0/auth0-server-python/tree/1.0.0b16) (2026-09-10)
[Full Changelog](https://github.com/auth0/auth0-server-python/compare/1.0.0b15...1.0.0b16)

**Added**
- feat: add mTLS (RFC 8705) client authentication - new `use_mtls` and `ssl_context` params let `ServerClient` present a TLS client certificate at the token endpoint instead of sending a client secret [\#159](https://github.com/auth0/auth0-server-python/pull/159) ([cschetan77](https://github.com/cschetan77))

## [1.0.0b15](https://github.com/auth0/auth0-server-python/tree/1.0.0b15) (2026-09-07)
[Full Changelog](https://github.com/auth0/auth0-server-python/compare/1.0.0b14...1.0.0b15)

⚠️ **Breaking Changes**
- feat!: add Private Key JWT (`private_key_jwt`) client authentication - clients with neither a `client_secret` nor a `client_assertion_signing_key` now raise `ConfigurationError` instead of proceeding as a public client. PAR requests now set `response_type=code` [\#154](https://github.com/auth0/auth0-server-python/pull/154) ([kishore7snehil](https://github.com/kishore7snehil))

**Added**
- feat: passwordless support - adds `ServerClient.passwordless` for Email OTP, SMS OTP, and Email Magic Link embedded flows [\#153](https://github.com/auth0/auth0-server-python/pull/153) ([rmad17](https://github.com/rmad17))
- feat: Private JWT CA support for passwordless - extends passwordless start and verify to use `_apply_client_authentication` so `private_key_jwt` is supported [\#158](https://github.com/auth0/auth0-server-python/pull/158) ([rmad17](https://github.com/rmad17))

**Fixed**
- fix: reject blank organization before actor resolution in session transfer token request [\#150](https://github.com/auth0/auth0-server-python/pull/150) ([kishore7snehil](https://github.com/kishore7snehil))

**Changed**
- docs: add Step-up authentication example [\#161](https://github.com/auth0/auth0-server-python/pull/161) ([kailash-b](https://github.com/kailash-b))
- docs: fix documentation drift in README and examples [\#144](https://github.com/auth0/auth0-server-python/pull/144) ([rmad17](https://github.com/rmad17))

## [1.0.0b14](https://github.com/auth0/auth0-server-python/tree/1.0.0b14) (2026-07-29)
[Full Changelog](https://github.com/auth0/auth0-server-python/compare/1.0.0b13...1.0.0b14)

**Added**
- feat: add Session Transfer Token support for CTE impersonation via session transfer [\#139](https://github.com/auth0/auth0-server-python/pull/139) ([kishore7snehil](https://github.com/kishore7snehil))

## [1.0.0b13](https://github.com/auth0/auth0-server-python/tree/1.0.0b13) (2026-07-21)
[Full Changelog](https://github.com/auth0/auth0-server-python/compare/1.0.0b12...1.0.0b13)

**Added**
- feat: passkey support in signup, signin along with MFA [\#135](https://github.com/auth0/auth0-server-python/pull/135) ([rmad17](https://github.com/rmad17))
- feat: support for MyAccount API - Authentication Methods, Factors and Enrollment [\#136](https://github.com/auth0/auth0-server-python/pull/136) ([rmad17](https://github.com/rmad17))
- feat: dpop sender-constrained tokens support for MyAccount API and passkey [\#137](https://github.com/auth0/auth0-server-python/pull/137) ([rmad17](https://github.com/rmad17))

## [1.0.0b12](https://github.com/auth0/auth0-server-python/tree/1.0.0b12) (2026-07-01)
[Full Changelog](https://github.com/auth0/auth0-server-python/compare/1.0.0b11...1.0.0b12)

**Added**
- feat: enforce upstream IdP session_expiry ceiling (IPSIE SL1) [\#120](https://github.com/auth0/auth0-server-python/pull/120) ([kishore7snehil](https://github.com/kishore7snehil))

## [1.0.0b11](https://github.com/auth0/auth0-server-python/tree/1.0.0b11) (2026-06-25)
[Full Changelog](https://github.com/auth0/auth0-server-python/compare/1.0.0b10...1.0.0b11)

**Added**
- feat: Organisations support [\#114](https://github.com/auth0/auth0-server-python/pull/114) ([rmad17](https://github.com/rmad17))
- feat: validate CTE actor token pairing and surface act claim for delegation/impersonation [\#122](https://github.com/auth0/auth0-server-python/pull/122) ([kishore7snehil](https://github.com/kishore7snehil))

## [1.0.0b10](https://github.com/auth0/auth0-server-python/tree/1.0.0b10) (2026-04-24)
[Full Changelog](https://github.com/auth0/auth0-server-python/compare/1.0.0b9...1.0.0b10)

**Added**
- feat: Add MFA (Multi-Factor Authentication) API support [\#79](https://github.com/auth0/auth0-server-python/pull/79) ([subhankarmaiti](https://github.com/subhankarmaiti))
- feat: add Auth0-Client telemetry header [\#103](https://github.com/auth0/auth0-server-python/pull/103) ([kishore7snehil](https://github.com/kishore7snehil))

**Fixed**
- fix: Make MfaRequiredError extend AccessTokenError and privatize encrypt_mfa_token [\#104](https://github.com/auth0/auth0-server-python/pull/104) ([kishore7snehil](https://github.com/kishore7snehil))

## [1.0.0b9](https://github.com/auth0/auth0-server-python/tree/1.0.0b9) (2026-04-08)
[Full Changelog](https://github.com/auth0/auth0-server-python/compare/1.0.0b8...1.0.0b9)

**Added**
- feat: add Multiple Custom Domains (MCD) support and fix JWT verification [\#71](https://github.com/auth0/auth0-server-python/pull/71) ([kishore7snehil](https://github.com/kishore7snehil))

**Changed**
- chore: bump dependencies and add SCA scan workflow [\#93](https://github.com/auth0/auth0-server-python/pull/93) ([kishore7snehil](https://github.com/kishore7snehil))

## [1.0.0b8](https://github.com/auth0/auth0-server-python/tree/1.0.0b8) (2026-02-06)
[Full Changelog](https://github.com/auth0/auth0-server-python/compare/1.0.0b7...1.0.0b8)

**Added**
- feat: Add Custom Token Exchange support [\#70](https://github.com/auth0/auth0-server-python/pull/70) ([subhankarmaiti](https://github.com/subhankarmaiti))

- feat: FGI-1575 Add ability to manage a users connected accounts [\#60](https://github.com/auth0/auth0-server-python/pull/60) ([sam-muncke](https://github.com/sam-muncke))

## [1.0.0.b7](https://github.com/auth0/auth0-server-python/tree/1.0.0b7) (2026-01-06)
[Full Changelog](https://github.com/auth0/auth0-server-python/compare/1.0.0b6...1.0.0b7)

**Added**
- docs: Add user unlinking example [\#62](https://github.com/auth0/auth0-server-python/pull/62)

## [1.0.0b6](https://github.com/auth0/auth0-server-python/tree/1.0.0b6) (2025-11-18)
[Full Changelog](https://github.com/auth0/auth0-server-python/compare/1.0.0b5...1.0.0b6)

**Added**
- feat: FGI-1573 add MRRT support  [\#58](https://github.com/auth0/auth0-server-python/pull/58) ([sam-muncke](https://github.com/sam-muncke))

- feat: FGI-1573 add connected account support  [\#57](https://github.com/auth0/auth0-server-python/pull/57) ([sam-muncke](https://github.com/sam-muncke))

## [1.0.0b5](https://github.com/auth0/auth0-server-python/tree/1.0.0b5) (2025-09-15)
[Full Changelog](https://github.com/auth0/auth0-server-python/compare/auth0_server_python-v1.0.0b4...1.0.0b5)

**Added**
- feat: Updates for CIBA with Email [\#28](https://github.com/auth0/auth0-server-python/pull/28) ([adamjmcgrath](https://github.com/adamjmcgrath))