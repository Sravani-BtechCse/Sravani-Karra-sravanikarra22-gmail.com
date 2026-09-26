// Permission resolution engine. Single source of truth for authorization decisions.
// Reads roles, permissions, and baselines dynamically from the database to handle personalized overlays.

import { forbidden } from './http.js';

export const MODE_PERMISSION = {
  view: 'device:view',
  control: 'device:control',
  terminal: 'device:terminal',
};

function expandPattern(pattern, catalogueKeys) {
  if (pattern === '*') return catalogueKeys;
  if (pattern.endsWith(':*')) {
    const prefix = pattern.slice(0, -1);
    return catalogueKeys.filter((key) => key.startsWith(prefix));
  }
  return catalogueKeys.includes(pattern) ? [pattern] : [];
}

function fetchActiveGrants(db, { userId, orgId, deviceId, timestampIso }) {
  const queryBase = `
    SELECT g.id AS grant_id, g.device_id, g.effect, gp.permission
      FROM grants g
      JOIN grant_permissions gp ON gp.grant_id = g.id
     WHERE g.user_id = ?
       AND g.org_id  = ?
       AND g.revoked_at IS NULL
       AND (g.starts_at  IS NULL OR g.starts_at  <= ?)
       AND (g.expires_at IS NULL OR g.expires_at >  ?)`;

  if (deviceId === null) {
    return db.prepare(queryBase).all(userId, orgId, timestampIso, timestampIso);
  }

  return db
    .prepare(`${queryBase} AND (g.device_id IS NULL OR g.device_id = ?)`)
    .all(userId, orgId, timestampIso, timestampIso, deviceId);
}

function buildEmptyDenialSet(catalogueKeys, roleName, reasonCode) {
  const permissions = {};
  for (const key of catalogueKeys) {
    permissions[key] = { effect: 'deny', source: null, reason: reasonCode };
  }
  return { role: roleName, permissions };
}

const getPermissionCatalogue = (db) =>
  db.prepare('SELECT key FROM permissions').all().map((row) => row.key);

const getRoleBaselinePermissions = (db, roleName) =>
  new Set(
    db
      .prepare('SELECT permission FROM role_permissions WHERE role = ?')
      .all(roleName)
      .map((row) => row.permission)
  );

const getMembershipRecord = (db, orgId, userId) =>
  db.prepare('SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?').get(orgId, userId);

function evaluateGateStatus(status) {
  if (status === 'suspended') return 'suspended';
  if (status !== 'active') return 'inactive_membership';
  return null;
}

function computePermissionResolution({ catalogueKeys, roleName, baselineSet, grantRows }) {
  const explicitDenies = new Map();
  const explicitAllows = new Map();

  // Rule D1: Evaluates explicit DENY grants first so nothing can override them
  for (const grant of grantRows) {
    if (grant.effect !== 'deny') continue;
    const matchedKeys = expandPattern(grant.permission, catalogueKeys);
    for (const key of matchedKeys) {
      if (!explicitDenies.has(key)) {
        explicitDenies.set(key, grant.grant_id);
      }
    }
  }

  // Evaluates role baseline first, then ALLOW grants for remaining gaps
  for (const key of baselineSet) {
    explicitAllows.set(key, `role:${roleName}`);
  }

  for (const grant of grantRows) {
    if (grant.effect !== 'allow') continue;
    const matchedKeys = expandPattern(grant.permission, catalogueKeys);
    for (const key of matchedKeys) {
      if (!explicitAllows.has(key)) {
        explicitAllows.set(key, `grant:${grant.grant_id}`);
      }
    }
  }

  const permissions = {};
  for (const key of catalogueKeys) {
    if (explicitDenies.has(key)) {
      permissions[key] = {
        effect: 'deny',
        source: `grant:${explicitDenies.get(key)}`,
        reason: 'explicit_deny',
      };
    } else if (explicitAllows.has(key)) {
      permissions[key] = {
        effect: 'allow',
        source: explicitAllows.get(key),
        reason: null,
      };
    } else {
      permissions[key] = {
        effect: 'deny',
        source: null,
        reason: 'implicit',
      };
    }
  }

  return permissions;
}

export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const timestampIso = now.toISOString();
  const catalogueKeys = getPermissionCatalogue(db);

  const membership = getMembershipRecord(db, orgId, userId);
  if (!membership) {
    return buildEmptyDenialSet(catalogueKeys, null, 'not_a_member');
  }

  const gateReason = evaluateGateStatus(membership.status);
  if (gateReason) {
    return buildEmptyDenialSet(catalogueKeys, membership.role, gateReason);
  }

  const baselineSet = getRoleBaselinePermissions(db, membership.role);
  const grantRows = fetchActiveGrants(db, { userId, orgId, deviceId, timestampIso });

  return {
    role: membership.role,
    permissions: computePermissionResolution({
      catalogueKeys,
      roleName: membership.role,
      baselineSet,
      grantRows,
    }),
  };
}

export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const timestampIso = now.toISOString();
  const catalogueKeys = getPermissionCatalogue(db);
  const membership = getMembershipRecord(db, orgId, userId);

  const roleName = membership?.role ?? null;
  const gateReason = membership ? evaluateGateStatus(membership.status) : 'not_a_member';

  if (gateReason) {
    const { permissions } = buildEmptyDenialSet(catalogueKeys, roleName, gateReason);
    const byDevice = {};
    for (const devId of deviceIds) {
      byDevice[devId] = permissions;
    }
    return { role: roleName, byDevice };
  }

  const baselineSet = getRoleBaselinePermissions(db, roleName);
  const allOrgGrants = fetchActiveGrants(db, { userId, orgId, deviceId: null, timestampIso });

  const byDevice = {};
  for (const devId of deviceIds) {
    const deviceSpecificGrants = allOrgGrants.filter(
      (row) => row.device_id === null || row.device_id === devId
    );
    byDevice[devId] = computePermissionResolution({
      catalogueKeys,
      roleName,
      baselineSet,
      grantRows: deviceSpecificGrants,
    });
  }

  return { role: roleName, byDevice };
}

export function can(db, ctx, permissionKey, deviceId) {
  const { permissions } = resolve(db, { ...ctx, deviceId });
  return permissions[permissionKey]?.effect === 'allow';
}

export function assertCan(db, ctx, permissionKey, deviceId) {
  const { permissions } = resolve(db, { ...ctx, deviceId });
  const targetEntry = permissions[permissionKey];

  if (targetEntry?.effect === 'allow') return;

  const reasonCodeMap = {
    explicit_deny: 'explicit_deny',
    suspended: 'suspended',
    not_a_member: 'not_a_member',
    inactive_membership: 'not_a_member',
    implicit: 'missing_permission',
  };

  const finalReason = reasonCodeMap[targetEntry?.reason] ?? 'missing_permission';
  throw forbidden(`missing permission: ${permissionKey}`, finalReason);
}

export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  const { permissions } = resolve(db, { ...ctx, deviceId });
  const catalogueKeys = Object.keys(permissions);

  for (const pattern of patterns) {
    const expandedKeys = expandPattern(pattern, catalogueKeys);
    for (const key of expandedKeys) {
      if (permissions[key]?.effect === 'allow') continue;

      const reasonCode =
        permissions[key]?.reason === 'explicit_deny'
          ? 'explicit_deny'
          : 'missing_permission';

      throw forbidden(
        `you cannot grant a permission you do not hold at this scope: ${key}`,
        reasonCode
      );
    }
  }
}

export function assertCanStartSession(db, ctx, modeKey, deviceId) {
  const requiredModePermission = MODE_PERMISSION[modeKey];
  if (!requiredModePermission) {
    throw forbidden('unknown session mode', 'validation');
  }

  assertCan(db, ctx, 'session:start', deviceId);

  const { permissions } = resolve(db, { ...ctx, deviceId });
  if (permissions[requiredModePermission]?.effect !== 'allow') {
    throw forbidden(
      `${modeKey} sessions also require ${requiredModePermission}`,
      'missing_device_permission'
    );
  }
}
