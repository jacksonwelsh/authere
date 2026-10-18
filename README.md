# Authere

Authentication and authorization software for web services.

Authere is a small Rust auth service intended to replace [Authentik](https://goauthentik.io) in a homelab. It's a single binary with an embedded UI on top of SQLite, with no external services to run. Current capabilities:

- **Forward auth** for Caddy, with redirect-to-login and per-app role requirements
- **OIDC provider** with discovery, JWKS, authorization code + PKCE, and end-session
- **LDAP** with enough surface area to authenticate Jellyfin against
- **TOTP** as a second factor
- **Passkeys** for passwordless, phishing-resistant sign-in that satisfies MFA
- **Audit log** with an admin UI

The server is Axum + SQLx + SQLite. The UI is Svelte, compiled into the release binary.

## Building

Requires Rust (stable), Node 20+, and OpenSSL development libraries
(`pkg-config libssl-dev` on Debian/Ubuntu, `openssl@3` via Homebrew on macOS).

```sh
cd ui && npm install && npm run build
cd ../server && cargo build --release
```

In release builds, `build.rs` runs `npm run build` automatically. The manual UI build above is only needed once when working on the server in debug mode. Output is `server/target/release/authere_server`.

## Running locally

The server needs a SQLite file and a key-encryption secret. The defaults are fine for development:

```sh
export AUTHERE_KEY_SECRET=$(openssl rand -hex 32)
export DATABASE_URL=sqlite:./data.db

./authere_server init-admin --username admin --password <password>
./authere_server serve
```

`init-admin` refuses to run if an admin already exists. After that, everything is managed through the web UI at <http://localhost:3000>. In debug builds, Swagger lives at `/docs`.

### Configuration

LDAP, session expiry, and invitations are all configured at runtime through the admin UI. The handful of things that need to be set as env vars:

- `AUTHERE_KEY_SECRET`: 32 hex bytes, used to encrypt the JWT signing key at rest
- `DATABASE_URL`: SQLite connection string (default `sqlite:./data.db`)
- `AUTHERE_BIND_ADDR`: listen address (default `0.0.0.0:3000`)
- `AUTHERE_ORIGIN`: public URL, used for forward-auth redirects, the OIDC issuer, and passkey origin/RP validation
- `AUTHERE_ALLOWED_ORIGINS`: comma-separated CORS allowlist for browser API clients
- `AUTHERE_TRUSTED_PROXIES`: comma-separated IP addresses of the reverse proxies allowed to supply client IPs for rate limiting and audit logs
- `AUTHERE_SWAGGER_ENABLED`: set to anything to expose `/docs` in release builds

`AUTHERE_ALLOWED_ORIGINS` grants access to the authenticated Authere API. Only list
browser front ends you trust with account administration; a protected application's
origin does not need to be added for normal forward auth or server-side OIDC.

### Sessions

Session expiry is an absolute deadline measured from password/MFA or passkey sign-in. Refreshing
credentials, visiting another protected app, and issuing OIDC tokens do not extend it.
Access tokens expire after at most 15 minutes and never outlive the session. Changing
the setting affects new logins; existing sessions keep their original deadline.
Role changes and account deactivation are checked on each authenticated request.
Logout and password changes revoke Authere, forward-auth, and provider-side OIDC sessions.
An OIDC application may also keep its own local session; configure its logout and
session lifetime separately.

### Passkeys

Open **Credentials → Add passkey** while signed in, name the passkey, and follow
your browser's prompt. Authere supports device passkeys, synced password managers,
and security keys that support discoverable credentials and user verification.
The login page recommends **Sign in with a passkey**; no username or password is needed.
Fingerprint, face, or PIN verification is required by the server, so passkey sign-in
already satisfies MFA and never asks for TOTP. Password sign-in still requires TOTP
or a recovery code when enabled.

Set `AUTHERE_ORIGIN` to the exact public HTTPS origin, such as
`https://auth.example.com`. Passkeys are bound to that hostname; changing it requires
enrolling new passkeys. HTTP is supported only at `http://localhost` for development;
use a domain rather than an IP address. The UI and passkey API must share this origin.
Use HTTPS when testing on other devices.

The browser integration uses standard WebAuthn with portable binary serialization
for Chrome/Edge, Firefox, and Safari, including mobile browsers. It does not require
conditional autofill, Level 3 JSON helpers, or a built-in authenticator. The browser
can offer another device or a security key. Unsupported browsers retain password
sign-in. Available passkey providers depend on the browser and operating system.

Each account can register up to 20 named passkeys. Removing a passkey signs out all
sessions, including sessions created with that credential. Keep another passkey or
your password and MFA recovery codes available. Authentication challenges expire
after five minutes and are consumed once; verification state stays in SQLite and
is bound to a host-only HttpOnly browser cookie. Stored credentials contain public
keys, not private keys. Creation, removal, and passkey sign-ins appear in the audit log.

Passkey checks: `cargo test --test passkey_flow` in `server/`, and
`npm run test:e2e -- passkeys.spec.ts` in `ui/` after
`npx playwright install chromium firefox webkit`. Chromium exercises a real virtual
CTAP2 authenticator end to end. Firefox and WebKit exercise browser integration,
portable serialization, cancellation, and fallback with simulated OS responses;
physical biometrics, security keys, and phone handoff require manual device testing.

### Forward-auth security and upgrades

Register every protected HTTPS host in Applications. Unknown hosts, disabled apps,
and ambiguous policies are denied. Plain hostname patterns match literally; regex
patterns match the whole hostname. The longest matching path prefix takes precedence,
with a literal hostname preferred over a regex at the same path length. Equally
specific overlapping policies are denied, and disabling a specific policy does not
expose that path through a broader one. Encoded ambiguous paths are rejected.

Keep the Authere origin dedicated to Authere. Protected sites receive a separate
credential bound to their origin and application; it cannot authenticate to the
Authere API or another application. Sign-in handoffs expire after 60 seconds, can be
redeemed once, and require the browser state set on the protected origin.
Use separate HTTPS origins for applications with different trust levels: browser
same-origin rules do not isolate applications hosted under different paths.

When upgrading from the older global-cookie flow, sign in again and regenerate the
Caddy configuration from the Applications UI. Proxy all `/.authere/*` routes to
Authere, including `/.authere/start`, and set this header on that proxy:

```caddyfile
header_up X-Authere-Target-Host {http.request.host}
```

Use a direct internal Authere upstream for forward-auth checks. Replace the generated
`AUTHERE_INTERNAL_HOST:3000` placeholder with that listener's internal address. Proxy hops must
preserve the original `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Forwarded-Uri`;
missing or invalid metadata is denied. Keep Authere's listener and protected backends
reachable only through the intended reverse proxy. LDAP currently uses plaintext
simple bind and belongs on a private network or inside a TLS tunnel.

OIDC supports authorization code flow with S256 PKCE. `prompt=none` returns
`login_required` when no session exists. `max_age`, `prompt=login`, and `prompt=consent`
are rejected until their reauthentication/consent flows are implemented.

### Dependency checks

Run `npm audit` in `ui/` and `cargo audit` in `server/` when updating dependencies.
Swagger UI uses a fixed vendored archive rather than downloading code during builds.
The lockfile still includes RSA through SQLx's disabled MySQL dependency, and the
Swagger build dependency uses a ZIP version with extraction advisories. RSA is not
compiled, and ZIP extraction processes the fixed vendored archive, not request data.
These are residual dependency warnings, not claims that the lockfile is advisory-free.

## Deploying

The expected production target is a Debian 13 LXC behind Caddy, with new binaries shipped by a webhook that fires on GitHub releases. Everything to set that up lives in `deploy/`:

```sh
# On a fresh LXC, as root:
scp deploy/* root@<lxc>:/opt/authere/
ssh root@<lxc> bash /opt/authere/bootstrap.sh
```

`bootstrap.sh` is idempotent. It installs runtime dependencies, generates the secrets, creates the `authere` user, installs the systemd units, and prints the remaining steps: first binary copy, `init-admin`, GitHub webhook config, and a Caddy snippet.

To skip the auto-deploy bit, drop a binary at `/opt/authere/authere_server` and start `authere.service`. The webhook service is optional.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Short version: please don't, this is a personal project.

## License

Public domain. See [LICENSE](./LICENSE).
