# Docs Update Rules

Treat docs as part of the change. This is a **library**, so the public surface is the exported API — chiefly `ServerClient` and the `AbstractDataStore` contract. There is no generated API-doc site; `README.md` and the `examples/*.md` guides are the reference.

## Tracked docs

| Doc | Covers | Maintained |
|-----|--------|-----------|
| `README.md` | Install + getting started (client construction, basic login) | Hand-written |
| `examples/*.md` | One guide per use case (see mapping below) | Hand-written |
| `CHANGELOG.md` | User-facing changes per release | Hand-written |

> No `EXAMPLES.md` at the repo root — usage guides live as individual files under `examples/`.

## When you change code, update these docs

| Code change | Update |
|-------------|--------|
| `ServerClient` construction / config options | `README.md` "Create the Auth0 SDK client" + `examples/ConfigureStore.md` |
| Interactive login (`start_/complete_interactive_login`) | `examples/InteractiveLogin.md` |
| Backchannel login/logout | `examples/ClientInitiatedBackChannelLogin.md` |
| MFA (`mfa_client`) | `examples/MFA.md` |
| Connected accounts (`*_connect_account`, `list/delete_connected_account`) | `examples/ConnectedAccounts.md` |
| User linking (`start_/complete_link_user`, unlink) | `examples/UserLinking.md` |
| Token retrieval / connection tokens | `examples/RetrievingData.md`, `examples/CustomTokenExchange.md` |
| Custom-domain handling | `examples/MultipleCustomDomains.md` |
| Any user-facing behavior change | `CHANGELOG.md` |

> When you touch a public symbol that maps to a doc above, update that doc **in the same PR** — do not defer.
