// Custom devices and grants routes implementation.
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { send, badRequest, notFound, conflict, forbidden } from '../http.js';
import { normalizeTs } from '../http.js';
import { assertCan, assertMayGrant, resolve, resolveDevices } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import { endActiveSessions, snapshotAuthority } from '../lifecycle.js';

const SUPPORTED_DEVICE_KINDS = ['macos', 'windows', 'linux', 'android', 'ios'];

function findOrgDeviceOrThrow(db, orgId, deviceId) {
  const deviceRecord = db
    .prepare('SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL')
    .get(deviceId, orgId);

  if (!deviceRecord) throw notFound();
  return deviceRecord;
}

export function register(router, { db }) {
  // GET /v1/orgs/:org/devices
  router.get('/v1/orgs/:org/devices', (ctx, params, res) => {
    assertCan(db, ctx, 'device:list');

    const orgDeviceRows = db
      .prepare(
        `SELECT id, name, kind, online, created_at
           FROM devices
          WHERE org_id = ? AND deleted_at IS NULL
          ORDER BY name`
      )
      .all(params.org);

    const { byDevice: devicePermissionMap } = resolveDevices(db, {
      userId: ctx.userId,
      orgId: params.org,
      deviceIds: orgDeviceRows.map((d) => d.id),
    });

    const visibleDevices = [];
    for (const dev of orgDeviceRows) {
      const resolvedPerms = devicePermissionMap[dev.id];
      if (resolvedPerms['device:view'].effect !== 'allow') continue;
      visibleDevices.push({ ...dev, online: dev.online === 1, permissions: resolvedPerms });
    }

    send(res, 200, { devices: visibleDevices });
  });

  // GET /v1/orgs/:org/devices/:id
  router.get('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const deviceRecord = findOrgDeviceOrThrow(db, params.org, params.id);
    const { permissions: resolvedPerms } = resolve(db, {
      userId: ctx.userId,
      orgId: params.org,
      deviceId: deviceRecord.id,
    });

    if (resolvedPerms['device:view'].effect !== 'allow') throw notFound();

    send(res, 200, { ...deviceRecord, online: deviceRecord.online === 1, permissions: resolvedPerms });
  });

  // POST /v1/orgs/:org/devices
  router.post('/v1/orgs/:org/devices', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'device.create', targetType: 'device' }, () => {
      assertCan(db, ctx, 'device:provision');
    });

    const deviceName = String(ctx.body.name ?? '').trim();
    const deviceKind = String(ctx.body.kind ?? '');

    if (deviceName.length < 1 || deviceName.length > 200) {
      throw badRequest('name must be 1-200 characters');
    }
    if (!SUPPORTED_DEVICE_KINDS.includes(deviceKind)) {
      throw badRequest(`kind must be one of: ${SUPPORTED_DEVICE_KINDS.join(', ')}`);
    }

    const newDeviceId = newId('dev');
    db.prepare('INSERT INTO devices (id, org_id, name, kind, online) VALUES (?, ?, ?, ?, ?)').run(
      newDeviceId,
      params.org,
      deviceName,
      deviceKind,
      ctx.body.online ? 1 : 0
    );

    audit(db, {
      orgId: ctx.orgId,
      actorId: ctx.userId,
      action: 'device.create',
      targetType: 'device',
      targetId: newDeviceId,
      result: 'allow',
      requestId: ctx.requestId,
    });

    send(res, 201, { id: newDeviceId, name: deviceName, kind: deviceKind });
  });

  // PATCH /v1/orgs/:org/devices/:id
  router.patch('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const deviceRecord = findOrgDeviceOrThrow(db, params.org, params.id);

    auditDenials(db, ctx, { action: 'device.update', targetType: 'device', targetId: deviceRecord.id }, () => {
      assertCan(db, ctx, 'device:update', deviceRecord.id);
    });

    const updatedName =
      ctx.body.name === undefined ? deviceRecord.name : String(ctx.body.name).trim();

    if (updatedName.length < 1 || updatedName.length > 200) {
      throw badRequest('name must be 1-200 characters');
    }

    const updatedOnline =
      ctx.body.online === undefined
        ? deviceRecord.online
        : ctx.body.online
        ? 1
        : 0;

    db.prepare('UPDATE devices SET name = ?, online = ? WHERE id = ?').run(
      updatedName,
      updatedOnline,
      deviceRecord.id
    );

    audit(db, {
      orgId: ctx.orgId,
      actorId: ctx.userId,
      action: 'device.update',
      targetType: 'device',
      targetId: deviceRecord.id,
      result: 'allow',
      requestId: ctx.requestId,
    });

    send(res, 200, { id: deviceRecord.id, name: updatedName, online: updatedOnline === 1 });
  });

  // DELETE /v1/orgs/:org/devices/:id
  router.delete('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const deviceRecord = findOrgDeviceOrThrow(db, params.org, params.id);

    auditDenials(db, ctx, { action: 'device.decommission', targetType: 'device', targetId: deviceRecord.id }, () => {
      assertCan(db, ctx, 'device:provision', deviceRecord.id);
    });

    const deleteTx = db.transaction(() => {
      db.prepare('UPDATE devices SET deleted_at = ? WHERE id = ?').run(nowIso(), deviceRecord.id);
      endActiveSessions(db, {
        orgId: params.org,
        deviceId: deviceRecord.id,
        reason: 'device_transferred',
      });
      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        action: 'device.decommission',
        targetType: 'device',
        targetId: deviceRecord.id,
        result: 'allow',
        requestId: ctx.requestId,
      });
    });
    deleteTx();

    send(res, 204, undefined);
  });

  // POST /v1/orgs/:org/devices/:id/transfer
  router.post('/v1/orgs/:org/devices/:id/transfer', (ctx, params, res) => {
    const deviceRecord = findOrgDeviceOrThrow(db, params.org, params.id);
    const targetOrgId = String(ctx.body.targetOrgId ?? '');

    auditDenials(db, ctx, { action: 'device.transfer', targetType: 'device', targetId: deviceRecord.id }, () => {
      assertCan(db, ctx, 'device:provision', deviceRecord.id);
    });

    const targetOrg = db
      .prepare('SELECT id FROM organizations WHERE id = ? AND deleted_at IS NULL')
      .get(targetOrgId);

    if (!targetOrg) throw notFound();

    const targetPermissions = resolve(db, { userId: ctx.userId, orgId: targetOrgId });
    if (targetPermissions.permissions['device:provision'].effect !== 'allow') {
      throw forbidden('you need device:provision in the target organization', 'missing_permission');
    }

    const transferTx = db.transaction(() => {
      db.prepare('UPDATE devices SET org_id = ? WHERE id = ?').run(targetOrgId, deviceRecord.id);
      db.prepare(
        'DELETE FROM grant_permissions WHERE grant_id IN (SELECT id FROM grants WHERE device_id = ?)'
      ).run(deviceRecord.id);
      db.prepare('DELETE FROM grants WHERE device_id = ?').run(deviceRecord.id);

      endActiveSessions(db, {
        orgId: params.org,
        deviceId: deviceRecord.id,
        reason: 'device_transferred',
      });
      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        action: 'device.transfer',
        targetType: 'device',
        targetId: deviceRecord.id,
        result: 'allow',
        requestId: ctx.requestId,
      });
    });
    transferTx();

    send(res, 200, { id: deviceRecord.id, orgId: targetOrgId });
  });

  // GET /v1/orgs/:org/grants
  router.get('/v1/orgs/:org/grants', (ctx, params, res) => {
    assertCan(db, ctx, 'user:read');
    const filterUserId = ctx.query.get('userId');

    const grantRows = db
      .prepare(
        `SELECT g.id, g.user_id, g.device_id, g.effect, g.starts_at, g.expires_at, g.created_at,
                group_concat(gp.permission) AS permissions
           FROM grants g
           JOIN grant_permissions gp ON gp.grant_id = g.id
          WHERE g.org_id = ? AND g.revoked_at IS NULL ${filterUserId ? 'AND g.user_id = ?' : ''}
          GROUP BY g.id
          ORDER BY g.created_at DESC`
      )
      .all(...(filterUserId ? [params.org, filterUserId] : [params.org]));

    send(res, 200, {
      grants: grantRows.map((row) => ({ ...row, permissions: row.permissions.split(',') })),
    });
  });

  // POST /v1/orgs/:org/grants
  router.post('/v1/orgs/:org/grants', (ctx, params, res) => {
    const { userId, deviceId = null, effect, permissions, startsAt = null, expiresAt = null } = ctx.body;

    auditDenials(db, ctx, { action: 'grant.create', targetType: 'user', targetId: userId }, () => {
      assertCan(db, ctx, 'grant:create');
    });

    if (userId === ctx.userId) {
      throw forbidden('you cannot create a grant for yourself', 'self_grant');
    }

    if (typeof userId !== 'string' || userId.length === 0) throw badRequest('userId is required');
    if (deviceId !== null && typeof deviceId !== 'string') throw badRequest('deviceId must be a string or null');
    if (!Array.isArray(permissions) || permissions.length === 0) {
      throw badRequest('permissions must be a non-empty array');
    }
    if (!permissions.every((p) => typeof p === 'string' && p.length > 0)) {
      throw badRequest('permissions must be non-empty strings');
    }
    if (effect !== 'allow' && effect !== 'deny') throw badRequest("effect must be 'allow' or 'deny'");

    const uniquePermissions = [...new Set(permissions)];

    const targetMember = db
      .prepare("SELECT 1 FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'")
      .get(params.org, userId);

    if (!targetMember) throw notFound();

    if (deviceId !== null) {
      const targetDevice = db
        .prepare('SELECT id FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL')
        .get(deviceId, params.org);
      if (!targetDevice) throw notFound();
    }

    const timestampIso = nowIso();
    const startsAtNormalized = normalizeTs(startsAt, 'startsAt');
    const expiresAtNormalized = normalizeTs(expiresAt, 'expiresAt');

    if (expiresAtNormalized !== null && expiresAtNormalized <= timestampIso) {
      throw badRequest('expiresAt is in the past', 'expired_grant');
    }
    if (
      startsAtNormalized !== null &&
      expiresAtNormalized !== null &&
      expiresAtNormalized <= startsAtNormalized
    ) {
      throw badRequest('expiresAt must be after startsAt');
    }

    assertMayGrant(db, ctx, uniquePermissions, deviceId);

    const newGrantId = newId('grt');
    const createGrantTx = db.transaction(() => {
      db.prepare(
        `INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        newGrantId,
        params.org,
        userId,
        deviceId,
        effect,
        startsAtNormalized,
        expiresAtNormalized,
        ctx.userId
      );

      const insertPermStmt = db.prepare(
        'INSERT INTO grant_permissions (grant_id, permission) VALUES (?, ?)'
      );
      for (const permKey of uniquePermissions) {
        try {
          insertPermStmt.run(newGrantId, permKey);
        } catch (err) {
          if (String(err.code).includes('FOREIGNKEY')) {
            throw badRequest(`unknown permission: ${permKey}`, 'unknown_permission');
          }
          throw err;
        }
      }

      bumpPermVersion(db, { orgId: params.org, userId });
      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        action: 'grant.create',
        targetType: 'user',
        targetId: userId,
        result: 'allow',
        requestId: ctx.requestId,
      });
    });
    createGrantTx();

    send(res, 201, {
      id: newGrantId,
      userId,
      deviceId,
      effect,
      permissions: uniquePermissions,
    });
  });

  // DELETE /v1/orgs/:org/grants/:id
  router.delete('/v1/orgs/:org/grants/:id', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'grant.revoke', targetType: 'grant', targetId: params.id }, () => {
      assertCan(db, ctx, 'grant:revoke');
    });

    const grantRecord = db
      .prepare('SELECT * FROM grants WHERE id = ? AND org_id = ? AND revoked_at IS NULL')
      .get(params.id, params.org);

    if (!grantRecord) throw notFound();

    const revokeTx = db.transaction(() => {
      db.prepare('UPDATE grants SET revoked_at = ? WHERE id = ?').run(nowIso(), params.id);
      bumpPermVersion(db, { orgId: params.org, userId: grantRecord.user_id });
      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        action: 'grant.revoke',
        targetType: 'grant',
        targetId: params.id,
        result: 'allow',
        requestId: ctx.requestId,
      });
    });
    revokeTx();

    send(res, 204, undefined);
  });
}
