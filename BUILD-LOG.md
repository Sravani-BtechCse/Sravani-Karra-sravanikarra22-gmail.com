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

## 2026-09-26 · Phase 3 — orgs, members, invites

Expected re-inviting a removed member to be a simple `INSERT INTO memberships`.
Observed: SQLite raised `UNIQUE constraint failed: memberships.org_id, memberships.user_id` (Tier A item A1) because a removed membership row (`status = 'removed'`) remains in the table to preserve historical integrity.
Changed: Updated invite redemption logic in `server/routes/invites.js` to check for an existing membership row for `(org_id, user_id)`; if present, it updates `status = 'active'` and sets the new role rather than executing a duplicate `INSERT`.
Also implemented opaque hashed invite tokens (`hashInviteToken` using HMAC-SHA256), single-use invite redemption, last-owner modification checks (`assertNotLastOwner`), and role rank modification gates (`assertCanModify`).
Ran `node scripts/check-api.js`: Invite and membership tests passed cleanly.

## 2026-09-26 · Phase 4 — devices and grants

Expected creating a grant to only validate that the permission pattern exists in `permission_patterns`.
Observed: `PERMISSIONS.md §8` enforces privilege laundering prevention (`assertMayGrant` - Tier A item A3). A caller cannot grant any permission they do not currently hold at that scope. Passing `deviceId = null` for org-wide grants vs `deviceId` for device-scoped grants resolves caller authority strictly at that target scope.
Also relied on SQLite foreign key enforcement on `grant_permissions(permission) REFERENCES permission_patterns(pattern)` to reject invalid permission patterns (e.g., `device:teleport`) with 400 `unknown_permission`.
Ran `node scripts/check-api.js`: Grant creation, privilege laundering prevention, and wildcard pattern expansion cases passed.

## 2026-09-26 · Phase 5 — sessions

Expected starting a session to require only `session:start` permission.
Observed: `AUTH-DATA-MODEL.md §9` dictates a compound check (`assertCanStartSession` - Tier B item B2). Starting a session requires BOTH `session:start` AND the specific mode permission (`device:view`, `device:control`, or `device:terminal`) on the target device.
Crucially, failure reasons must distinguish WHICH requirement failed: missing `session:start` returns 403 `missing_permission`, whereas missing mode permission returns 403 `missing_device_permission`.
Furthermore, enforced session grandfathering (Tier B item B3): role changes or grant revocations do not terminate active sessions in flight, but tenancy events (suspension, membership removal, device transfer) trigger `endActiveSessions`. Exclusively enforced partial unique index on active control sessions (`state = 'active' AND mode IN ('control','terminal')`).
Ran `node scripts/check-api.js`: Exclusive sessions, grandfathering, and compound check tests passed.

## 2026-09-26 · Phase 6 — audit

Expected audit logging to record successful actions.
Observed: `PERMISSIONS.md §8` explicitly requires auditing DENIED attempts as well (Tier A item A5 / invariant 10). A log without denials fails to answer "who attempted what".
Implemented `auditDenials` wrapper in `server/audit.js` catching `FORBIDDEN` errors and logging `result = 'deny'` with the exact `reason_code`.
Leveraged SQLite triggers `BEFORE UPDATE` and `BEFORE DELETE` on `audit_events` to enforce an append-only audit trail at the database level. Note that `end_reason` in sessions uses closed enum `CHECK (end_reason IN ('user_stopped', 'session_expired', 'suspended', 'reassigned', 'force_ended'))` (Tier A item A7).
Ran `node scripts/check-api.js`: Audit logging, denial capturing, and pagination tests passed.

## 2026-09-26 · Phase 7 — the console

Expected UI components in `web/` to inspect user roles (e.g. `if (role === 'admin')`).
Observed: `README.md § "Two rules that shape the whole design"` explicitly forbids role checking in client UI. The console must render elements purely based on resolved permissions (`data-permission` and `data-state="unlocked"`) returned by the API server. If a permission is not held, the element is omitted from the DOM entirely.
Built React SPA in `web/` (`App.jsx`, `components/`) consuming `/v1/auth/me`, `/v1/orgs/:org/devices`, `/v1/orgs/:org/members`, `/v1/orgs/:org/grants`, `/v1/orgs/:org/sessions`, `/v1/orgs/:org/audit`.
Verified element visibility reflects server authorization without hardcoding matrices in frontend.

## 2026-09-26 · Phase 8 — hardening

Measured query performance and resolution latency.
Found: Device list endpoint originally queried `resolve(...)` 4 times per device row (catalogue, membership, baseline, grants), leading to N+1 database queries.
Fixed: Implemented `resolveDevices(db, { userId, orgId, deviceIds })` in `server/permissions.js:162`, executing 1 query for active grants across all devices in the page and performing in-memory filtering.
Measured: Request handling dropped from O(N) queries to O(1) queries per list request.

## Open threads

- **Web Storage Security**: JWT access tokens are kept purely in memory and refreshed via HttpOnly cookies (`refresh_token`). A full page reload restores the session securely via cookie exchange.
- **WebSocket / Server-Sent Events**: Currently the console relies on HTTP API polling for device status updates; a real-time push channel could eliminate polling overhead for large device lists under multi-operator load.






