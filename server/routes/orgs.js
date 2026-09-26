// Custom orgs, members, and audit routes implementation.
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { send, badRequest, notFound, conflict, forbidden, selfRoleChange } from '../http.js';
import { assertCan, resolve } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import {
  assertCanModify, assertNotLastOwner, endActiveSessions, roleRanks, assertRoleExists,
} from '../lifecycle.js';

const MAXIMUM_PAGINATION_LIMIT = 200;

function parsePaginationParams(queryMap) {
  const paramLimit = queryMap.get('limit');
  const paramOffset = queryMap.get('offset');

  const limitVal = paramLimit === null ? 50 : Number(paramLimit);
  const offsetVal = paramOffset === null ? 0 : Number(paramOffset);

  if (!Number.isInteger(limitVal) || limitVal < 1 || limitVal > MAXIMUM_PAGINATION_LIMIT) {
    throw badRequest(`limit must be an integer between 1 and ${MAXIMUM_PAGINATION_LIMIT}`);
  }
  if (!Number.isInteger(offsetVal) || offsetVal < 0) {
    throw badRequest('offset must be a non-negative integer');
  }
  return { limit: limitVal, offset: offsetVal };
}

const AVAILABLE_PALETTES = ['cobalt', 'amber', 'moss', 'plum', 'rust', 'teal'];

export function register(router, { db }) {
  // GET /v1/orgs
  router.get('/v1/orgs', (ctx, _p, res) => {
    const userOrgs = db
      .prepare(
        `SELECT o.id, o.name, o.theme, m.role, m.status
           FROM memberships m
           JOIN organizations o ON o.id = m.org_id
          WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
          ORDER BY o.name`
      )
      .all(ctx.userId);

    send(res, 200, { orgs: userOrgs });
  });

  // POST /v1/orgs
  router.post('/v1/orgs', (ctx, _p, res) => {
    const orgNameInput = String(ctx.body.name ?? '').trim();
    if (orgNameInput.length < 1 || orgNameInput.length > 200) {
      throw badRequest('name must be 1-200 characters');
    }

    const newOrgId = newId('org');
    const selectedTheme = AVAILABLE_PALETTES.includes(ctx.body.theme)
      ? ctx.body.theme
      : AVAILABLE_PALETTES[
          db.prepare('SELECT COUNT(*) AS total FROM organizations').get().total % AVAILABLE_PALETTES.length
        ];

    const createTransaction = db.transaction(() => {
      db.prepare('INSERT INTO organizations (id, name, theme) VALUES (?, ?, ?)').run(
        newOrgId,
        orgNameInput,
        selectedTheme
      );
      db.prepare(
        `INSERT INTO memberships (id, org_id, user_id, role, status, joined_at)
         VALUES (?, ?, ?, 'owner', 'active', ?)`
      ).run(newId('mem'), newOrgId, ctx.userId, nowIso());

      audit(db, {
        orgId: newOrgId,
        actorId: ctx.userId,
        action: 'org.create',
        targetType: 'org',
        targetId: newOrgId,
        result: 'allow',
        requestId: ctx.requestId,
      });
    });
    createTransaction();

    send(res, 201, { id: newOrgId, name: orgNameInput, theme: selectedTheme, role: 'owner' });
  });

  // PATCH /v1/orgs/:org
  router.patch('/v1/orgs/:org', (ctx, params, res) => {
    assertCan(db, ctx, 'org:update');
    const updatedName = String(ctx.body.name ?? '').trim();
    if (updatedName.length < 1 || updatedName.length > 200) {
      throw badRequest('name must be 1-200 characters');
    }

    db.prepare('UPDATE organizations SET name = ? WHERE id = ?').run(updatedName, params.org);

    audit(db, {
      orgId: ctx.orgId,
      actorId: ctx.userId,
      action: 'org.update',
      targetType: 'org',
      targetId: params.org,
      result: 'allow',
      requestId: ctx.requestId,
    });

    send(res, 200, { id: params.org, name: updatedName });
  });

  // DELETE /v1/orgs/:org
  router.delete('/v1/orgs/:org', (ctx, params, res) => {
    assertCan(db, ctx, 'org:delete');
    db.prepare('UPDATE organizations SET deleted_at = ? WHERE id = ?').run(nowIso(), params.org);

    audit(db, {
      orgId: ctx.orgId,
      actorId: ctx.userId,
      action: 'org.delete',
      targetType: 'org',
      targetId: params.org,
      result: 'allow',
      requestId: ctx.requestId,
    });

    send(res, 204, undefined);
  });

  // GET /v1/orgs/:org/members
  router.get('/v1/orgs/:org/members', (ctx, params, res) => {
    assertCan(db, ctx, 'user:read');
    const memberList = db
      .prepare(
        `SELECT u.id, u.email, u.name, m.role, m.status, m.perm_version, m.joined_at
           FROM memberships m
           JOIN users u ON u.id = m.user_id
          WHERE m.org_id = ? AND m.status != 'removed'
          ORDER BY u.name`
      )
      .all(params.org);

    send(res, 200, { members: memberList });
  });

  // DELETE /v1/orgs/:org/members/me
  router.delete('/v1/orgs/:org/members/me', (ctx, params, res) => {
    assertNotLastOwner(db, params.org, ctx.userId);
    executeMemberRemoval(db, ctx, params.org, ctx.userId, 'member.leave');
    send(res, 204, undefined);
  });

  // PATCH /v1/orgs/:org/members/:userId
  router.patch('/v1/orgs/:org/members/:userId', (ctx, params, res) => {
    const { userId } = params;
    const requestedRole = ctx.body.role;

    if (userId === ctx.userId) throw selfRoleChange();
    if (typeof requestedRole !== 'string') throw badRequest('role is required');
    assertRoleExists(db, requestedRole);

    auditDenials(db, ctx, { action: 'user.role.update', targetType: 'user', targetId: userId }, () => {
      assertCan(db, ctx, 'user:role:update');
    });

    const targetMembership = db
      .prepare('SELECT * FROM memberships WHERE org_id = ? AND user_id = ?')
      .get(params.org, userId);

    if (!targetMembership || targetMembership.status === 'removed') throw notFound();

    assertCanModify(db, ctx.role, targetMembership.role);
    if (requestedRole === 'owner' && ctx.role !== 'owner') {
      throw forbidden('only an owner may assign the owner role', 'cannot_confer_owner');
    }
    if (targetMembership.role === 'owner' && requestedRole !== 'owner') {
      assertNotLastOwner(db, params.org, userId);
    }

    const updateRoleTx = db.transaction(() => {
      db.prepare('UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?').run(
        requestedRole,
        params.org,
        userId
      );
      bumpPermVersion(db, { orgId: params.org, userId });
      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        action: 'user.role.update',
        targetType: 'user',
        targetId: userId,
        result: 'allow',
        requestId: ctx.requestId,
      });
    });
    updateRoleTx();

    send(res, 200, { id: userId, role: requestedRole });
  });

  // POST /v1/orgs/:org/members/:userId/suspend
  router.post('/v1/orgs/:org/members/:userId/suspend', (ctx, params, res) => {
    updateMemberStatus(db, ctx, params.org, params.userId, 'suspended', 'member.suspend');
    send(res, 200, { id: params.userId, status: 'suspended' });
  });

  // DELETE /v1/orgs/:org/members/:userId/suspend
  router.delete('/v1/orgs/:org/members/:userId/suspend', (ctx, params, res) => {
    updateMemberStatus(db, ctx, params.org, params.userId, 'active', 'member.reinstate');
    send(res, 200, { id: params.userId, status: 'active' });
  });

  // DELETE /v1/orgs/:org/members/:userId
  router.delete('/v1/orgs/:org/members/:userId', (ctx, params, res) => {
    executeMemberRemoval(db, ctx, params.org, params.userId, 'member.remove');
    send(res, 204, undefined);
  });

  // GET /v1/orgs/:org/users/:userId/effective
  router.get('/v1/orgs/:org/users/:userId/effective', (ctx, params, res) => {
    const isSelfQuery = params.userId === ctx.userId;
    if (!isSelfQuery) assertCan(db, ctx, 'user:read');

    const targetMembership = db
      .prepare('SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?')
      .get(params.org, params.userId);

    if (!targetMembership) throw notFound();

    const queryDeviceId = ctx.query.get('deviceId');
    const resolvedSet = resolve(db, {
      userId: params.userId,
      orgId: params.org,
      deviceId: queryDeviceId ?? null,
    });

    send(res, 200, {
      userId: params.userId,
      orgId: params.org,
      deviceId: queryDeviceId ?? null,
      ...resolvedSet,
    });
  });

  // GET /v1/orgs/:org/audit
  router.get('/v1/orgs/:org/audit', (ctx, params, res) => {
    assertCan(db, ctx, 'audit:read');
    const { limit, offset } = parsePaginationParams(ctx.query);
    const filterSince = ctx.query.get('since');

    const auditRows = filterSince
      ? db
          .prepare(
            'SELECT * FROM audit_events WHERE org_id = ? AND at >= ? ORDER BY at DESC LIMIT ? OFFSET ?'
          )
          .all(params.org, filterSince, limit, offset)
      : db
          .prepare(
            'SELECT * FROM audit_events WHERE org_id = ? ORDER BY at DESC LIMIT ? OFFSET ?'
          )
          .all(params.org, limit, offset);

    send(res, 200, { events: auditRows, limit, offset });
  });
}

function updateMemberStatus(db, ctx, orgId, userId, newStatus, actionName) {
  auditDenials(db, ctx, { action: actionName, targetType: 'user', targetId: userId }, () => {
    assertCan(db, ctx, 'user:remove');
  });

  const targetMembership = db
    .prepare('SELECT * FROM memberships WHERE org_id = ? AND user_id = ?')
    .get(orgId, userId);

  if (!targetMembership || targetMembership.status === 'removed') throw notFound();
  if (targetMembership.role === 'owner' && newStatus !== 'active') {
    assertNotLastOwner(db, orgId, userId);
  }
  assertCanModify(db, ctx.role, targetMembership.role);

  const statusTx = db.transaction(() => {
    db.prepare('UPDATE memberships SET status = ? WHERE org_id = ? AND user_id = ?').run(
      newStatus,
      orgId,
      userId
    );
    bumpPermVersion(db, { orgId, userId });

    if (newStatus !== 'active') {
      endActiveSessions(db, { orgId, userId, reason: 'user_suspended' });
    }

    audit(db, {
      orgId,
      actorId: ctx.userId,
      action: actionName,
      targetType: 'user',
      targetId: userId,
      result: 'allow',
      requestId: ctx.requestId,
    });
  });
  statusTx();
}

function executeMemberRemoval(db, ctx, orgId, userId, actionName) {
  if (actionName === 'member.remove') {
    auditDenials(db, ctx, { action: actionName, targetType: 'user', targetId: userId }, () => {
      assertCan(db, ctx, 'user:remove');
    });
  }

  const targetMembership = db
    .prepare('SELECT * FROM memberships WHERE org_id = ? AND user_id = ?')
    .get(orgId, userId);

  if (!targetMembership || targetMembership.status === 'removed') throw notFound();
  if (targetMembership.role === 'owner') assertNotLastOwner(db, orgId, userId);
  if (userId !== ctx.userId) assertCanModify(db, ctx.role, targetMembership.role);

  const removalTx = db.transaction(() => {
    db.prepare("UPDATE memberships SET status = 'removed' WHERE org_id = ? AND user_id = ?").run(
      orgId,
      userId
    );
    bumpPermVersion(db, { orgId, userId });
    endActiveSessions(db, { orgId, userId, reason: 'membership_removed' });

    audit(db, {
      orgId,
      actorId: ctx.userId,
      action: actionName,
      targetType: 'user',
      targetId: userId,
      result: 'allow',
      requestId: ctx.requestId,
    });
  });
  removalTx();
}
