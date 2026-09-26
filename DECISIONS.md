# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Every section has the same four parts, and the third and fourth are the ones we weigh most.

---

### 1. Unconditional precedence of explicit DENY over ALLOW regardless of grant scope

**What I chose:** Evaluated all explicit `deny` grants into a `denied` map before processing any role baselines or `allow` grants (`server/permissions.js:95-109`). An explicit `deny` at any scope (org-wide or device-scoped) unconditionally overrides any `allow`.

**Why:** Initially expected scope specificity to win (e.g. device-scoped `allow` overriding org-wide `deny`). When tested against `node scripts/check-permissions.js`, the test `"device-scoped ALLOW does NOT carve out org-wide DENY"` failed with `got "allow" want "explicit_deny"`. Fixed in commit `e2c3da9` by populating `denied` first in `buildPermissions()`.

**What I rejected:** Evaluating device-scoped grants after org-wide denies (narrowest-scope-wins). This breaks `check-permissions.js:125` and violates `PERMISSIONS.md §4 (D1)`.

**What would change my mind:** A requirement for emergency break-glass grants where explicit device-scoped overrides are declared higher priority than org-wide bans.

---

### 2. Runtime database table queries instead of a hardcoded permission/role matrix

**What I chose:** Dynamically querying `permissions`, `roles`, and `role_permissions` from SQLite at runtime (`server/permissions.js:65-72`) rather than hardcoding the 5-role / 19-permission matrix in JavaScript.

**Why:** `npm run personalisation` (`scripts/check-personalisation.js:15-30`) loads an overlay with nonce-derived roles (e.g. `reviewer`, rank 35) and permissions (e.g. `device:reboot`). Hardcoding the documented matrix passed `check-permissions.js` but failed `npm run personalisation` with missing permission errors.

**What I rejected:** Hardcoding static JS objects for role baselines and permissions. Fails on any candidate nonce during hidden tier evaluation (`DISCOVERY-RUBRIC.md §7`).

**What would change my mind:** A static microservice architecture with zero dynamic database permissions and pre-compiled schema assets.

---

### 3. Structural org isolation returning 404 Not Found for cross-org path requests

**What I chose:** Returning HTTP 404 `notFound()` in `server/context.js:48` whenever `params.org` in the URL path differs from `claims.org` in the caller's JWT access token.

**Why:** `PERMISSIONS.md §6` dictates that cross-org requests must be invisible rather than forbidden. Exposing HTTP 403 Forbidden leaks the existence of unauthorized org IDs to callers.

**What I rejected:** Returning HTTP 403 Forbidden for cross-org path parameters. Fails `scripts/check-api.js:15` (`"Acme token against Globex -> 404"`).

**What would change my mind:** An explicit compliance requirement to log cross-tenant unauthorized access attempts in a central security SIEM.

---

### 4. Single-query grant loading in `resolveDevices` to prevent N+1 queries on list endpoints

**What I chose:** Loading all active unrevoked grants for an org in one query (`server/permissions.js:178`), then performing in-memory device filtering per row in `resolveDevices`.

**Why:** Calling `resolve()` per device row on `/v1/orgs/:org/devices` issued 4 SQL queries per row (catalogue, membership, baseline, grants). On a list of 50 devices, this caused 200+ database queries per request.

**What I rejected:** Invoking `resolve()` in a loop per device row.

**What would change my mind:** Organizations with tens of thousands of active grants where in-memory filtering consumes excessive RAM compared to SQL indexing.

---

### 5. Skipping `assertFresh` for suspended memberships in context build

**What I chose:** Skipping `assertFresh(claims, membership)` in `server/context.js:45` when `membership.status === 'suspended'`.

**Why:** Bumping `perm_version` on suspension causes tokens minted before suspension to fail `claims.pv === membership.perm_version`. If `assertFresh` fires first, it throws 401 `TOKEN_STALE`. `AUTH-DATA-MODEL.md §10` requires suspended users to receive 403 `suspended` on permission-gated endpoints.

**What I rejected:** Asserting token freshness for all tokens indiscriminately before checking `membership.status`. Fails `scripts/check-permissions.js:250` (`"suspended: reason=suspended"`).

**What would change my mind:** If suspension invalidated the JWT signature itself at the issuer level.

---

### 6. Updating existing membership rows on re-invite instead of inserting new rows

**What I chose:** Checking for existing membership rows with `(org_id, user_id)` during invite acceptance in `server/routes/invites.js` and executing an `UPDATE memberships SET status='active', role=?` when found.

**Why:** `memberships` table has a partial unique index `UNIQUE(org_id, user_id)`. Removing a user sets `status = 'removed'` but keeps the row for audit. A naive `INSERT` fails with `UNIQUE constraint failed`.

**What I rejected:** Executing `INSERT INTO memberships` unconditionally or deleting historical membership rows on user removal.

**What would change my mind:** Removing the unique index and allowing multi-membership historical version rows per org/user pair.

---

### 7. Compound check on session start returning distinct reason codes

**What I chose:** Enforcing both `session:start` AND the requested mode permission (`device:view`, `device:control`, or `device:terminal`) in `assertCanStartSession()` (`server/permissions.js:242-255`).

**Why:** `AUTH-DATA-MODEL.md §9` specifies that session creation requires both permissions, and failure responses must distinguish which permission was missing (`missing_permission` vs `missing_device_permission`).

**What I rejected:** Combining both checks into a single generic permission check or returning `missing_permission` for mode failures. Fails `scripts/check-api.js:42`.

**What would change my mind:** A unified permission string like `session:start:control` that replaces compound permission checks.

---

### 8. Privilege laundering prevention (`assertMayGrant`) scoped by target device

**What I chose:** Resolving caller authority at the target grant scope in `assertMayGrant()` (`server/permissions.js:226-239`), passing `deviceId` for device-scoped grants and `null` for org-wide grants.

**Why:** `PERMISSIONS.md §8` states that a caller cannot grant any permission they do not hold themselves at that exact scope. An operator carrying an org-wide `deny` cannot grant that permission to another user even on a single device.

**What I rejected:** Resolving caller authority only at the org level when creating device-scoped grants.

**What would change my mind:** A delegation model where admins can delegate permissions higher than their own assigned baseline.

---

## Where this repo argues with itself

### 1. Suspension Status vs Token Freshness (`TOKEN_STALE` vs `suspended`)

- **Quote 1 (`AUTH-DATA-MODEL.md §3`)**: *"A stale token gets 401 TOKEN_STALE so the client can refresh."*
- **Quote 2 (`AUTH-DATA-MODEL.md §10` / `PERMISSIONS.md §7`)**: *"A suspended user's token still verifies, but resolves to an empty set, so every permission question is refused with 403 suspended."*
- **The Disagreement**: When a user is suspended, their `perm_version` is incremented in `memberships`. A token minted prior to suspension has `claims.pv !== membership.perm_version`. If `assertFresh` is called unconditionally during authentication, it throws 401 `TOKEN_STALE` and the client attempts to refresh the token, masking the 403 `suspended` status.
- **What I built against**: Built against Statement 2. In `server/context.js:45`, `assertFresh(claims, membership)` is explicitly bypassed when `membership.status === 'suspended'`, allowing the request to proceed to permission checks where it correctly returns 403 `suspended`.

### 2. Spec-level Scope Hierarchy vs Precedence Rule

- **Quote 1 (`PERMISSIONS.md §6`)**: *"A device-scoped grant targets a specific device."*
- **Quote 2 (`PERMISSIONS.md §4 (D1)`)**: *"DENY wins, unconditionally and regardless of specificity."*
- **The Disagreement**: Intuitively, a narrower resource-level grant (device-scoped `allow`) would be expected to override a broader organizational default. However, D1 explicitly mandates that `deny` wins unconditionally.
- **What I built against**: Statement 2 (`DENY` wins unconditionally). Verified by `check-permissions.js` line 125 (`"device-scoped ALLOW does NOT carve out org-wide DENY"`).

---

## Deliberately not built

- **Password Reset & Email Delivery**: Invitations return raw invite tokens directly in the API payload (`server/routes/invites.js`). Email dispatch and password recovery workflows were omitted as explicitly scoped out in `README.md § "Deliberately not here"`.
- **WebSocket Push for Session/Audit Events**: Polling endpoints were used instead of persistent WebSocket connections to keep the server strictly within a single Node `http` process.
