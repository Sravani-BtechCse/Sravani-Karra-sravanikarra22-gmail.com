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

## Phase 2 — caller context and the resolution engine

## Phase 3 — orgs, members, invites

## Phase 4 — devices and grants

## Phase 5 — sessions

## Phase 6 — audit

## Phase 7 — the console

## Phase 8 — hardening

## Open threads


