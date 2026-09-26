# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the evidence.

## 2026-09-26 · Phase 0 — orientation

Expected `npm run db:reset` and `node scripts/load-db.js` to work cleanly on Windows out of the box.
Observed: `load-db.js` failed with `ENOENT: no such file or directory, open 'C:\C:\...\db\schema.sql'` due to `new URL(...).pathname` returning `/C:/...` on Windows, which Node's path normalization prepended with the drive root again. Furthermore, `npm run db:reset` failed with `'rm' is not recognized`.
Changed: Fixed `here(p)` in `scripts/load-db.js` and `DIST` in `server/index.js` to use `fileURLToPath(new URL(p, import.meta.url))`. Simplified `package.json` `db:reset` script to `npm run db:load` because `load-db.js` already performs cross-platform `rmSync` on database files.
Ran `node scripts/check-jwt.js` against the untouched skeleton: as expected, 0/43 passed because `verifyAccessToken` in `server/auth.js` is a stub throwing `NOT_IMPLEMENTED`.

## 2026-09-26 · Phase 1 — token verification

Expected expiration check (`exp`) to be `< now` like standard libraries.
Observed: `AUTH-DATA-MODEL.md §10` and `check-jwt.js` explicitly enforce half-open interval `exp <= now` (a token expiring at the exact current timestamp is considered expired).
Implemented `verifyAccessToken` in `server/auth.js` validating:
1. 3 dot-separated segments.
2. Safe JSON parsing of base64url header and payload.
3. Strict header algorithm pinning (`alg === 'HS256'` and `typ === 'JWT'`) to block `alg: none` and algorithm substitution attacks.
4. Constant-time signature comparison (`timingSafeEqual`) against `createHmac('sha256', secret)`.
5. Expiration (`exp <= now`), issuer (`remoteops`), audience (`remoteops-api`), and non-empty `jti`.
Ran `node scripts/check-jwt.js`: 43/43 passed.

## 2026-09-26 · Phase 2 — caller context and the resolution engine

Expected a scope-hierarchy model where a device-scoped `allow` grant could override an org-level baseline or deny.
Observed: `PERMISSIONS.md §4` and `check-permissions.js` ("device-scoped ALLOW does NOT carve out org-wide DENY") dictate that `DENY` wins unconditionally regardless of scope. Furthermore, `npm run personalisation` proved that hardcoding the 5-role/19-permission matrix fails because the database carries an overlay (role `reviewer`, permission `device:reboot`).
Implemented:
- `server/context.js`: verifies bearer tokens, enforces structural org isolation (cross-org parameter mismatch returns 404 `notFound()`, never 403), checks membership status (`removed` -> 401, `org_deleted_at` -> 404), and checks freshness against `perm_version` for non-suspended members.
- `server/permissions.js`: dynamic table-driven resolution engine (`loadCatalogue`, `loadBaseline`, `collectGrants`). Evaluates all `deny` grants first into a `denied` map before processing role baselines or `allow` grants. Implemented batched resolution (`resolveDevices`) with single-query grant loading to avoid N+1 per row.
Ran `node scripts/check-permissions.js`: 35/35 passed.
Ran `npm run personalisation`: 18/18 passed.

## Phase 3 — orgs, members, invites

## Phase 4 — devices and grants

## Phase 5 — sessions

## Phase 6 — audit

## Phase 7 — the console

## Phase 8 — hardening

## Open threads



