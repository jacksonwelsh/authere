# Authere Implementation Plan

A lightweight authentication/authorization service for homelab use, written in Rust.

## Current State

**Implemented:**
- Axum server with SQLite database
- User CRUD with input validation
- Password authentication (Argon2)
- Ed25519 JWT signing keys (generated, stored)
- OpenAPI/Swagger documentation
- CI pipeline

**Partially Implemented:**
- JWT tokens (infrastructure exists, not wired to login)
- TOTP (schema exists, logic not implemented)

---

## Phase 1: Token System & Session Management

**Goal:** Complete the authentication flow so users receive tokens on login.

### 1.1 Access & Refresh Tokens
- Wire `token::generate_token()` into login endpoint
- Define token claims: `sub` (user ID), `roles`, `exp`, `iat`, `jti`
- Access token: short-lived (15 min)
- Refresh token: longer-lived (7 days), stored in DB for revocation

### 1.2 Token Verification Middleware
- Create Axum extractor for authenticated requests
- Verify JWT signature using stored public key
- Extract user info and roles into request extensions

### 1.3 Refresh & Logout
- `POST /auth/refresh` - exchange refresh token for new access token
- `POST /auth/logout` - revoke refresh token

### Database Changes
```sql
CREATE TABLE refresh_tokens (
    id BLOB PRIMARY KEY,
    user_id BLOB NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL,  -- SHA256 of refresh token
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);
```

---

## Phase 2: RBAC (Role-Based Access Control)

**Goal:** Simple role system where users have one or more roles.

### 2.1 Role Schema
- Predefined roles stored in DB
- User-role many-to-many relationship
- Default roles: `admin`, `user`

### 2.2 Role Management APIs
- `GET /roles` - list all roles
- `POST /roles` - create role (admin only)
- `DELETE /roles/{id}` - delete role (admin only)
- `POST /users/{id}/roles` - assign role to user
- `DELETE /users/{id}/roles/{role_id}` - remove role from user

### 2.3 Role Checking
- Include roles in JWT claims
- Create `RequireRole` extractor for protected endpoints
- Helper: `user.has_role("admin")`

### Database Changes
```sql
CREATE TABLE roles (
    id BLOB PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE user_roles (
    user_id BLOB NOT NULL REFERENCES users(id),
    role_id BLOB NOT NULL REFERENCES roles(id),
    PRIMARY KEY (user_id, role_id)
);
```

---

## Phase 3: Caddy Forward Auth

**Goal:** Protect applications via Caddy's `forward_auth` directive.

### 3.1 Application Registry
- Register protected applications with required roles
- Match by host header or path prefix

### 3.2 Forward Auth Endpoint
- `GET /auth/verify` - Caddy calls this for each request
- Check `Authorization` header or cookie
- Return 200 + headers if authorized, 401 if not
- Response headers: `X-Auth-User`, `X-Auth-Roles`, `X-Auth-Email`

### 3.3 Login Redirect
- If unauthorized, redirect to login page with `redirect_uri`
- After login, redirect back to original destination

### Database Changes
```sql
CREATE TABLE applications (
    id BLOB PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,  -- for URLs
    host_pattern TEXT,          -- regex or exact match
    path_prefix TEXT,
    required_roles TEXT,        -- JSON array of role names
    enabled INTEGER NOT NULL DEFAULT 1
);
```

### Caddy Configuration Example
```caddyfile
app.example.com {
    forward_auth localhost:3000 {
        uri /auth/verify
        copy_headers X-Auth-User X-Auth-Roles X-Auth-Email
    }
    reverse_proxy app:8080
}
```

---

## Phase 4: Web Portal (Leptos)

**Goal:** Admin UI for user management, embedded in single binary.

### 4.1 Project Setup
- Add Leptos as dependency with SSR + hydration
- Configure for WASM embedding in release build
- Serve static assets from embedded files

### 4.2 Authentication UI
- Login page (username/password)
- Logout functionality
- Session management (store token in httpOnly cookie)

### 4.3 User Management
- List users with search/filter
- Create user form
- Edit user (name, email)
- Reset password
- Assign/remove roles
- Delete user

### 4.4 Application Management
- List protected applications
- Create/edit application
- Configure required roles per app

### 4.5 Self-Service
- User profile page
- Change password
- Manage MFA (Phase 7)
- Manage passkeys (Phase 8)

### Build Configuration
- Use `cargo-leptos` for build
- Embed WASM + JS in binary via `include_bytes!` or `rust-embed`
- Single binary output with `--release`

---

## Phase 5: OIDC Provider

**Goal:** Allow applications to authenticate users via OpenID Connect.

### 5.1 Client Registration
- Register OIDC clients with client_id, client_secret, redirect_uris
- Support public clients (PKCE) and confidential clients

### 5.2 Authorization Endpoint
- `GET /oauth/authorize`
- Support `code` response type
- PKCE support (code_challenge, code_verifier)
- Consent screen (optional, can auto-approve for trusted apps)

### 5.3 Token Endpoint
- `POST /oauth/token`
- Support `authorization_code` grant
- Support `refresh_token` grant
- Return access_token, id_token, refresh_token

### 5.4 Discovery & Keys
- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json` - public keys for token verification

### 5.5 UserInfo Endpoint
- `GET /oauth/userinfo`
- Return user claims based on requested scopes

### Database Changes
```sql
CREATE TABLE oidc_clients (
    id BLOB PRIMARY KEY,
    client_id TEXT NOT NULL UNIQUE,
    client_secret_hash TEXT,  -- NULL for public clients
    name TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,  -- JSON array
    allowed_scopes TEXT NOT NULL, -- JSON array
    is_public INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE authorization_codes (
    code_hash TEXT PRIMARY KEY,
    client_id BLOB NOT NULL REFERENCES oidc_clients(id),
    user_id BLOB NOT NULL REFERENCES users(id),
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL,
    code_challenge TEXT,
    code_challenge_method TEXT,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
```

---

## Phase 6: LDAP (Jellyfin Sync)

**Goal:** Minimal LDAP server for Jellyfin user authentication.

### 6.1 LDAP Server
- Implement minimal LDAP protocol (RFC 4511 subset)
- Listen on configurable port (default 3389)
- Support operations: BIND, SEARCH, UNBIND

### 6.2 BIND Operation
- Simple bind with username/password
- Map DN to authere username
- Verify password against stored hash

### 6.3 SEARCH Operation
- Support user lookups by username
- Return basic attributes: uid, cn, mail
- Base DN: `dc=authere,dc=local` (configurable)

### 6.4 App Passwords for Passwordless Users
- Generate random "app password" for users without primary password
- Store separately, scoped to LDAP use only
- Users can regenerate via web portal

### Database Changes
```sql
CREATE TABLE app_passwords (
    id BLOB PRIMARY KEY,
    user_id BLOB NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,  -- e.g., "Jellyfin"
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
);
```

### Jellyfin Configuration
```
LDAP Server: authere.local
Port: 3389
Base DN: dc=authere,dc=local
User Filter: (uid={0})
```

---

## Phase 7: MFA (TOTP)

**Goal:** Add TOTP-based two-factor authentication.

### 7.1 TOTP Enrollment
- Generate secret, display QR code
- User confirms with initial code
- Store secret in `authenticators` table (type='totp')

### 7.2 Login Flow Update
- After password verification, check if user has TOTP enabled
- If yes, return partial auth state, require TOTP code
- `POST /auth/totp/verify` - complete login with TOTP code

### 7.3 Recovery
- Backup codes generated during enrollment (store hashed)
- Each code single-use

### 7.4 Management UI
- Enable/disable TOTP
- View backup codes (once, at enrollment)
- Regenerate backup codes

### Database Changes
```sql
-- Uses existing authenticators table with type='totp'
-- Add backup codes table
CREATE TABLE backup_codes (
    id BLOB PRIMARY KEY,
    user_id BLOB NOT NULL REFERENCES users(id),
    code_hash TEXT NOT NULL,
    used_at INTEGER
);
```

---

## Phase 8: Passkeys (WebAuthn)

**Goal:** Support hardware security keys and platform authenticators as second factor.

### 8.1 WebAuthn Registration
- `POST /auth/webauthn/register/start` - get challenge
- `POST /auth/webauthn/register/finish` - store credential

### 8.2 WebAuthn Authentication
- After password, offer passkey as MFA option
- `POST /auth/webauthn/authenticate/start` - get challenge
- `POST /auth/webauthn/authenticate/finish` - verify assertion

### 8.3 Management UI
- List registered passkeys
- Rename passkey
- Delete passkey

### Future: Passwordless
- Design allows promoting passkey to primary authenticator
- Would skip password step entirely
- Requires resident key support

### Database Changes
```sql
CREATE TABLE webauthn_credentials (
    id BLOB PRIMARY KEY,
    user_id BLOB NOT NULL REFERENCES users(id),
    credential_id BLOB NOT NULL UNIQUE,
    public_key BLOB NOT NULL,
    counter INTEGER NOT NULL,
    name TEXT,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
);
```

### Dependencies
- `webauthn-rs` crate for WebAuthn protocol handling

---

## Dependency Additions

```toml
# Phase 4: Web UI
leptos = { version = "0.7", features = ["ssr", "hydrate"] }
leptos_axum = "0.7"
rust-embed = "8"

# Phase 5: OIDC
# (mostly custom implementation using existing JWT infrastructure)

# Phase 6: LDAP
ldap3_proto = "0.5"  # or implement minimal protocol manually

# Phase 7: TOTP
totp-rs = "5"
qrcode = "0.14"
base32 = "0.5"

# Phase 8: WebAuthn
webauthn-rs = "0.5"
```

---

## Configuration

All configuration via environment variables (12-factor app style):

```bash
# Database
DATABASE_URL=sqlite:./data.db

# Server
BIND_ADDRESS=0.0.0.0:3000
PUBLIC_URL=https://auth.example.com

# LDAP (Phase 6)
LDAP_ENABLED=true
LDAP_BIND_ADDRESS=0.0.0.0:3389
LDAP_BASE_DN=dc=authere,dc=local

# Security
ACCESS_TOKEN_LIFETIME=900      # 15 minutes
REFRESH_TOKEN_LIFETIME=604800  # 7 days
```

---

## Implementation Order

Based on dependencies between features:

1. **Phase 1** (Tokens) - Foundation for everything
2. **Phase 2** (RBAC) - Needed for forward auth
3. **Phase 3** (Forward Auth) - Core functionality
4. **Phase 4** (Web Portal) - Management UI, can be started in parallel with 3
5. **Phase 7** (TOTP) - Simpler than WebAuthn, completes MFA story
6. **Phase 5** (OIDC) - Complex but well-defined spec
7. **Phase 8** (Passkeys) - Builds on MFA infrastructure
8. **Phase 6** (LDAP) - Can be done anytime, relatively isolated

---

## Architectural Decisions

1. **Session storage:** SQLite for simplicity. Add Redis later if multi-instance needed.

2. **Admin bootstrap:** CLI command `authere init-admin --username admin --password <pw>`
   - Add as part of Phase 1
   - Fails if admin already exists

3. **Rate limiting:** In-memory rate limiter (per-IP, resets on restart)
   - Add in Phase 1
   - Login endpoint: 5 attempts per minute per IP
   - Configurable via env vars

4. **Audit logging:** Yes, from the start
   - Add `audit_log` table in Phase 1
   - Log: logins (success/fail), role changes, password resets, MFA changes

### Audit Log Schema
```sql
CREATE TABLE audit_log (
    id BLOB PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    event_type TEXT NOT NULL,  -- 'login_success', 'login_failed', 'role_assigned', etc.
    user_id BLOB REFERENCES users(id),  -- NULL for failed logins with unknown user
    actor_id BLOB REFERENCES users(id), -- Who performed the action (NULL for self-service)
    ip_address TEXT,
    user_agent TEXT,
    details TEXT  -- JSON with event-specific data
);
```
