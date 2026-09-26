// Shared domain lifecycle helpers: role ranks, last-owner protection, session termination.
import { newId, nowIso } from './db.js';
import { badRequest, forbidden, lastOwner } from './http.js';

export function roleRanks(database) {
  const roleRows = database.prepare('SELECT key, rank FROM roles').all();
  const rankMapping = {};
  for (const row of roleRows) {
    rankMapping[row.key] = row.rank;
  }
  return rankMapping;
}

export function assertRoleExists(database, targetRoleKey) {
  const existingRole = database
    .prepare('SELECT key FROM roles WHERE key = ?')
    .get(targetRoleKey);

  if (!existingRole) {
    throw badRequest(`unknown role: ${targetRoleKey}`, 'unknown_role');
  }
}

export function assertCanModify(database, actorRoleKey, targetRoleKey) {
  if (actorRoleKey === 'owner') return;

  const ranksMap = roleRanks(database);
  const actorRank = ranksMap[actorRoleKey] ?? 0;
  const targetRank = ranksMap[targetRoleKey] ?? 0;

  if (actorRank > targetRank) return;

  throw forbidden(
    'you cannot modify a user at or above your own role',
    'insufficient_rank'
  );
}

export function assertNotLastOwner(database, orgId, userId) {
  const userMembership = database
    .prepare('SELECT role FROM memberships WHERE org_id = ? AND user_id = ?')
    .get(orgId, userId);

  if (userMembership?.role !== 'owner') return;

  const activeOwnerCount = database
    .prepare(
      `SELECT COUNT(*) AS total
         FROM memberships
        WHERE org_id = ? AND role = 'owner' AND status = 'active'`
    )
    .get(orgId).total;

  if (activeOwnerCount <= 1) {
    throw lastOwner();
  }
}

export function endActiveSessions(
  database,
  { orgId, userId = null, deviceId = null, reason, exceptSessionId = null }
) {
  const timestampIso = nowIso();
  const filterConditions = ['org_id = ?', "state = 'active'"];
  const queryArgs = [orgId];

  if (userId) {
    filterConditions.push('user_id = ?');
    queryArgs.push(userId);
  }
  if (deviceId) {
    filterConditions.push('device_id = ?');
    queryArgs.push(deviceId);
  }
  if (exceptSessionId) {
    filterConditions.push('id != ?');
    queryArgs.push(exceptSessionId);
  }

  const whereClause = filterConditions.join(' AND ');
  const activeSessionIds = database
    .prepare(`SELECT id FROM sessions WHERE ${whereClause}`)
    .all(...queryArgs)
    .map((row) => row.id);

  if (activeSessionIds.length === 0) return [];

  const updateStmt = database.prepare(
    `UPDATE sessions SET state = 'ended', ended_at = ?, end_reason = ? WHERE id = ?`
  );
  for (const sessionId of activeSessionIds) {
    updateStmt.run(timestampIso, reason, sessionId);
  }

  return activeSessionIds;
}

export function snapshotAuthority(database, { userId, orgId, deviceId }) {
  const userRole =
    database
      .prepare('SELECT role FROM memberships WHERE org_id = ? AND user_id = ?')
      .get(orgId, userId)?.role ?? null;

  const timestampIso = nowIso();
  const validGrants = database
    .prepare(
      `SELECT g.id FROM grants g
        WHERE g.user_id = ?
          AND g.org_id  = ?
          AND g.revoked_at IS NULL
          AND (g.starts_at  IS NULL OR g.starts_at  <= ?)
          AND (g.expires_at IS NULL OR g.expires_at >  ?)
          AND (g.device_id  IS NULL OR g.device_id  = ?)`
    )
    .all(userId, orgId, timestampIso, timestampIso, deviceId)
    .map((row) => row.id);

  return JSON.stringify({
    role: userRole,
    grantIds: validGrants,
    snapshotAt: timestampIso,
  });
}

export function sessionExpiry(database, orgId) {
  const maxMinutes =
    database
      .prepare('SELECT max_session_minutes AS m FROM organizations WHERE id = ?')
      .get(orgId)?.m ?? 60;

  return new Date(Date.now() + maxMinutes * 60_000).toISOString();
}

export { newId, nowIso };
