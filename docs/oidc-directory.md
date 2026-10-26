# OIDC and dynamic directory integration

`NewOIDCClient` builds a confidential authorization-code client with PKCE.
`OIDCClientConfig.Validate` performs local configuration validation; construction
then checks discovery's exact issuer and HTTPS endpoints (HTTP loopback is
allowed for tests/development). Application-specific discovery/JWKS is supported.
Explicit authorization, token and JWKS endpoints must be supplied together.

The client supports discovery-advertised `client_secret_basic` and
`client_secret_post`. Credential-bearing redirects are not followed. Provider
error bodies are not exposed. ID tokens use `go-oidc` with asymmetric algorithms;
issuer, audience, expiry, subject, nonce, authorized party, nbf/future iat and
optional access-token hash are checked separately from internal JWT verification.

For managed deployments, set `Config.OIDCFactory` and `OIDCRedirectURL` on
`NewService`. The factory runs on first login, after the identity service and
ingress can start. Concurrent initialization is shared; waiting requests can
cancel. Failed initialization returns `ErrOIDCUnavailable` with a short retry
backoff. It does not fall back to a second identity authority. A factory cannot
coexist with a separately configured verifier/exchanger.

## Browser binding

`HTTPHandler` creates a per-attempt HttpOnly, SameSite=Lax cookie. HTTPS callback
configuration selects Secure and the `__Host-` prefix, independently of forwarded
protocol hints. Only the binding digest is stored with state/nonce/PKCE verifier.

The browser callback requires exactly one matching cookie and, when advertised,
the RFC 9207 response issuer. Memory/GORM stores compare the binding **before**
consuming the state. A wrong browser cannot burn another browser's login. State
consumption is atomic and replay fails. Return targets must be local paths.
Session and CSRF cookies retain the existing Warden names for Portal compatibility.

`CompleteBoundOIDCCallback` is the browser service entry. The legacy
`CompleteOIDCCallback` remains for trusted Go clients using unbound state; it is
not used by the HTTP callback. Custom Store implementations need
`TakeBoundOIDCLoginState(ctx,state,bindingDigest)` before they can serve browser
login. Missing support fails closed. The GORM migration adds `browser_binding`;
old in-flight browser logins must restart. Avoid mixing old unbound callback
instances with the new handler during rollout.

`GET /auth/oidc/start?return_to=/workbench/` redirects to the IdP, matching Portal
navigation. Existing API callers using `redirect_url` receive JSON and explicitly
navigate to `authorization_url`. Both forms create the browser cookie.

## Directory authority

`NewCasdoorDirectorySource` reads Casdoor's authenticated
`/api/get-user?owner=...&userId=...` API. It uses the verified subject UUID and
checks both the returned UUID and organization. Credentials use HTTP Basic in
headers; responses are bounded and redirects are rejected. No email/name merge
or external `isAdmin` flag grants Warden privileges.

Each `CasdoorTenantMapping` explicitly assigns an organization and optional
required groups to a Warden tenant ID. Role mappings use fully qualified external
role IDs and known Warden roles. All required groups must be present. Only
enabled, explicitly mapped roles are projected. Credentials must be authorized
to read every configured organization; any directory failure fails closed.

`DirectoryRefreshOnSession` refreshes membership/roles at session validation.
Disabled/deleted users and removed membership revoke sessions. Transient directory
failures deny the request without destroying an otherwise valid session. Manual
Warden disabled states are retained; an existing tenant cannot silently change
its Casdoor organization. Disabled/missing tenants cannot create/use sessions.

The source binds to one Service. Background reconcile enumerates all persisted
subjects for its tenants, including after restart, instead of using the bounded
admin list endpoint. It does not auto-provision every IdP user. A custom store
also needs `ListDirectorySubjects(ctx,tenantID)` for this source.

## SakerWeb permissions

The internal audience is `sakerweb`. Its scopes are `sakerweb:read`,
`sakerweb:write`, `sakerweb:run` and `sakerweb:terminal`.

| Role | Granted scopes |
|---|---|
| `app.sakerweb.viewer` | read |
| `app.sakerweb.user` | read, write, run |
| `app.sakerweb.operator` | read, write, run, terminal |

These are identity-policy primitives. The application must still check each RPC,
WS frame and resource; a read-only WebSocket handshake does not grant writes.
Custom policy configurations must explicitly add the desired role scopes.

`POST /internal/session/validate` returns the current tenant, normalized role
keys, effective `permissions`, policy version and session expiry alongside the
existing session and principal fields. Permissions come from the live Warden
policy on every validation. An empty policy produces `"permissions": []`;
clients must preserve that explicit denial instead of restoring default role
grants. Older servers may omit the field, which is a distinct compatibility
case. The endpoint continues to require the internal caller credential.

## Verification

`go test -race -tags integration ./...` covers a local signed OIDC discovery,
PKCE token exchange and bound HTTP callback, replay/issuer/token negatives,
directory removal/outage/role changes, restart reconciliation, more than 500
projected users and concurrent SQL state consumption. These fixtures do not
prove real Casdoor/GitHub/Google, real PostgreSQL or production deployment.

Protocol references: [Casdoor OIDC](https://casdoor.ai/docs/how-to-connect/oidc-client/),
[Casdoor API authentication](https://casdoor.ai/docs/basic/public-api/),
[Casdoor user identifiers](https://casdoor.ai/docs/basic/core-concepts/).
