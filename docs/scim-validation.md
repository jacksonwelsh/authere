# SCIM 2.0 compliance validation

Authere's SCIM 2.0 surface is covered by in-tree Rust integration tests (`server/tests/scim_*.rs`) that mirror the test catalog of [python-scim/scim2-tester](https://github.com/python-scim/scim2-tester). For belt-and-suspenders coverage, you can run the canonical Python tester against a live Authere instance before shipping SCIM changes.

This is **manual** and not part of CI. Run it once per significant SCIM change and paste the output into the PR description.

## Prerequisites

- A running Authere instance (local or staging) reachable over HTTP/HTTPS
- An admin account
- Python 3.10+

## Steps

1. **Start Authere** and confirm the usual health check:
   ```sh
   curl -sS http://localhost:3000/api/auth/verify -H "authorization: Bearer $ADMIN_JWT"
   ```

2. **Mint a SCIM token** as the admin. Replace `$ADMIN_JWT` with a valid admin access token:
   ```sh
   curl -sS -X POST http://localhost:3000/api/scim/tokens \
     -H "authorization: Bearer $ADMIN_JWT" \
     -H "content-type: application/json" \
     -d '{"name": "scim2-tester validation run"}'
   ```
   Save the `token` field from the response — it's shown exactly once.

3. **Install scim2-tester** in a disposable virtualenv:
   ```sh
   python3 -m venv /tmp/scim-venv
   /tmp/scim-venv/bin/pip install scim2-tester
   ```

4. **Run the tester**:
   ```sh
   /tmp/scim-venv/bin/scim2-tester \
     --url http://localhost:3000/scim/v2 \
     --token "$SCIM_TOKEN"
   ```

## Expected outcome

Last recorded result: **29 / 36 checks pass**. The remaining 7 are all consequences of Authere storing `users.name` as one string and one email — not bugs, not fixable without a schema change. When you run the tester against your own instance, expect the same shape of failures.

### What passes

- **Discovery**: ServiceProviderConfig, ResourceTypes (+ individual access), Schemas (+ individual access), invalid-resource-type 404s, invalid-schema 404s, random-URL 404 with `application/scim+json` body.
- **User CRUD**: create (with or without a display name; we fall back to `userName`), query by id, query-in-list, replace, delete, POST `/.search` (root) and POST `/Users/.search`.
- **Attribute projection**: both `?attributes=` and `?excludedAttributes=` on GET and on search.
- **PATCH**: add/remove/replace on `externalId`, `userName`, `displayName`, `active`. Remove of `active` resets to default (true), consistent with the schema advertising `active` as optional.

### Known deltas vs. scim2-tester expectations

| Check | Gap | Why |
|---|---|---|
| `check_add_attribute` / `check_replace_attribute` on `name` | Complex-name round-trip: the tester sends `{givenName, familyName, middleName, honorifics}` and compares it to the response | Authere stores a single `users.name` column. We accept every subfield on input, derive one display string, and emit it as `name.formatted` only. |
| `check_add_attribute` / `check_replace_attribute` on `emails` | Multi-valued email round-trip: custom `type`, `display`, multiple entries | We store one email in `users.email`. Array input is flattened; custom sub-fields are normalized to `{primary: true, type: "work"}`. |
| `check_remove_attribute` on `name` / `displayName` | Tester expects the attribute absent from the response after remove | `users.name` is NOT NULL; a removed display falls back to `userName` for persistence, so the response always has a non-empty `name`/`displayName`. |
| `check_remove_attribute` on `active` | Tester expects `active` absent after remove | `users.active` is a boolean column, always present in the projection. We reset it to the SCIM default (true) on remove. |

If any of these matter for your IdP integration, the fix is a schema change (split `name` into subfields, move `emails` to its own table). None of them block Okta or Azure AD provisioning, which only use the single-valued shape.

### What will fail if you don't bump rate limits

The default SCIM rate limit is 60 req/min per client IP. scim2-tester hammers the server — set `AUTHERE_SCIM_MAX_REQUESTS=10000` before starting Authere for the validation run, or you'll see spurious `rate limit exceeded` errors attributed to CRUD checks.

## Cleanup

Revoke the token after the run so stale SCIM credentials don't linger:

```sh
curl -sS -X DELETE http://localhost:3000/api/scim/tokens/$TOKEN_ID \
  -H "authorization: Bearer $ADMIN_JWT"
```

(`$TOKEN_ID` was in the create response.)

## What Authere's tests already cover

The Python tester is a backstop; most of its catalog is already covered in-tree. If you're changing:

- Filter parsing → `server/src/scim/filter.rs` unit tests + `server/tests/scim_filter.rs`
- PATCH semantics → `server/src/scim/patch.rs` unit tests + `server/tests/scim_user_patch.rs`
- Discovery payloads → `server/tests/scim_discovery.rs`
- Auth → `server/tests/scim_auth.rs`
- Error shapes → `server/tests/scim_errors.rs`
- CRUD → `server/tests/scim_user_crud.rs`

Changes to any of those files should leave all Rust tests green before running the Python tester.
