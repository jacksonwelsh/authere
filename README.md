# Authere

Authentication and authorization software for web services.

Authere is a small Rust auth service intended to replace [Authentik](https://goauthentik.io) in a homelab. It's a single binary with an embedded UI on top of SQLite, with no external services to run. Current capabilities:

- **Forward auth** for Caddy, with redirect-to-login and per-app role requirements
- **OIDC provider** with discovery, JWKS, authorization code + PKCE, and end-session
- **LDAP** with enough surface area to authenticate Jellyfin against
- **TOTP** as a second factor
- **Audit log** with an admin UI

The server is Axum + SQLx + SQLite. The UI is Svelte, compiled into the release binary.

## Building

Requires Rust (stable) and Node 20+.

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
- `AUTHERE_ORIGIN`: public URL, used for forward-auth redirects and as the OIDC issuer
- `AUTHERE_ALLOWED_ORIGINS`: comma-separated CORS allowlist for browser API clients
- `AUTHERE_SWAGGER_ENABLED`: set to anything to expose `/docs` in release builds

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
