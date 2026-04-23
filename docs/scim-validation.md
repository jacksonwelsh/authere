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

All checks in the `discovery`, `users.crud`, and `users.patch` categories should pass. Known non-supported areas that may surface as failures — treat these as expected:

- **`/Groups`** — not implemented. scim2-tester's Groups discovery will find no resource type and skip; if it flags missing Groups CRUD, that's expected.
- **Complex `emails[type eq "work"]` sub-filters on GET** — rejected with `invalidFilter`. The PATCH form is accepted and routed to our single email slot.
- **Phone numbers, addresses, photos, enterprise extension attributes** — rejected with `invalidPath` on write. Not in the User schema we advertise.
- **Multi-valued emails** — we store one. If the tester sends two emails and expects both to round-trip, the second will be dropped.

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
