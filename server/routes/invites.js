// Custom invite lifecycle routes implementation.
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { send, badRequest, notFound, conflict, forbidden, gone } from '../http.js';
import { assertCan } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import { assertRoleExists, assertCanModify } from '../lifecycle.js';
import { hashPassword, hashInviteToken, newInviteToken } from '../auth.js';

const INVITATION_EXPIRY_DAYS = 7;
const EMAIL_REGEX_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function findInviteByRawToken(db, rawTokenValue) {
  if (!rawTokenValue || rawTokenValue.length < 16) throw notFound();

  const inviteRecord = db
    .prepare(
      `SELECT i.*, o.name AS org_name, o.deleted_at AS org_deleted
         FROM invites i
         JOIN organizations o ON o.id = i.org_id
        WHERE i.token_hash = ?`
    )
    .get(hashInviteToken(rawTokenValue));

  if (!inviteRecord) throw notFound();
  if (inviteRecord.org_deleted) throw notFound();
  if (inviteRecord.revoked_at) throw gone('this invite was revoked');
  if (inviteRecord.accepted_at) throw conflict('this invite has already been used');
  if (inviteRecord.expires_at <= nowIso()) throw gone('this invite has expired');

  return inviteRecord;
}

export function register(router, { db }) {
  // POST /v1/orgs/:org/invites
  router.post('/v1/orgs/:org/invites', (ctx, params, res) => {
    const targetEmail = String(ctx.body.email ?? '').trim().toLowerCase();
    const assignedRole = String(ctx.body.role ?? '');

    if (!EMAIL_REGEX_PATTERN.test(targetEmail) || targetEmail.length > 320) {
      throw badRequest('a valid email is required');
    }
    assertRoleExists(db, assignedRole);

    auditDenials(
      db,
      ctx,
      { action: 'user.invite', targetType: 'email', targetId: targetEmail },
      () => {
        assertCan(db, ctx, 'user:invite');
      }
    );

    if (assignedRole === 'owner' && ctx.role !== 'owner') {
      throw forbidden('only an owner may invite an owner', 'cannot_confer_owner');
    }
    assertCanModify(db, ctx.role, assignedRole);

    const existingActiveMember = db
      .prepare(
        `SELECT 1 FROM memberships m
           JOIN users u ON u.id = m.user_id
          WHERE m.org_id = ? AND u.email = ? AND m.status != 'removed'`
      )
      .get(params.org, targetEmail);

    if (existingActiveMember) throw conflict('that email already has a membership in this org');

    const pendingInvite = db
      .prepare(
        'SELECT 1 FROM invites WHERE org_id = ? AND email = ? AND accepted_at IS NULL AND revoked_at IS NULL'
      )
      .get(params.org, targetEmail);

    if (pendingInvite) throw conflict('a pending invite already exists for that email');

    const rawInviteToken = newInviteToken();
    const newInviteId = newId('inv');
    const expiryTimestamp = new Date(Date.now() + INVITATION_EXPIRY_DAYS * 864e5).toISOString();

    const createInviteTx = db.transaction(() => {
      db.prepare(
        `INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).run(
        newInviteId,
        params.org,
        targetEmail,
        assignedRole,
        hashInviteToken(rawInviteToken),
        ctx.userId,
        expiryTimestamp
      );

      const existingUser = db
        .prepare('SELECT id FROM users WHERE email = ?')
        .get(targetEmail);

      if (existingUser) {
        db.prepare(
          `INSERT INTO memberships (id, org_id, user_id, role, status, invited_by)
           VALUES (?, ?, ?, ?, 'invited', ?)`
        ).run(newId('mem'), params.org, existingUser.id, assignedRole, ctx.userId);
      }

      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        action: 'user.invite',
        targetType: 'email',
        targetId: targetEmail,
        result: 'allow',
        requestId: ctx.requestId,
      });
    });
    createInviteTx();

    send(res, 201, {
      id: newInviteId,
      email: targetEmail,
      role: assignedRole,
      expiresAt: expiryTimestamp,
      inviteToken: rawInviteToken,
    });
  });

  // GET /v1/orgs/:org/invites
  router.get('/v1/orgs/:org/invites', (ctx, params, res) => {
    assertCan(db, ctx, 'user:invite');
    const activeInvites = db
      .prepare(
        `SELECT id, email, role, expires_at, accepted_at, revoked_at, created_at
           FROM invites WHERE org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL
          ORDER BY created_at DESC`
      )
      .all(params.org);

    send(res, 200, { invites: activeInvites });
  });

  // DELETE /v1/orgs/:org/invites/:id
  router.delete('/v1/orgs/:org/invites/:id', (ctx, params, res) => {
    assertCan(db, ctx, 'user:invite');

    const targetInvite = db
      .prepare('SELECT * FROM invites WHERE id = ? AND org_id = ?')
      .get(params.id, params.org);

    if (!targetInvite) throw notFound();
    if (targetInvite.accepted_at) throw conflict('invite was already accepted; remove the member instead');

    db.prepare('UPDATE invites SET revoked_at = ? WHERE id = ?').run(nowIso(), params.id);
    db.prepare(
      "DELETE FROM memberships WHERE org_id = ? AND user_id = (SELECT id FROM users WHERE email = ?) AND status = 'invited'"
    ).run(params.org, targetInvite.email);

    audit(db, {
      orgId: ctx.orgId,
      actorId: ctx.userId,
      action: 'user.invite.revoke',
      targetType: 'invite',
      targetId: params.id,
      result: 'allow',
      requestId: ctx.requestId,
    });

    send(res, 204, undefined);
  });

  // GET /v1/invites/:token
  router.get('/v1/invites/:token', (ctx, params, res) => {
    const inviteRecord = findInviteByRawToken(db, params.token);
    send(res, 200, {
      email: inviteRecord.email,
      role: inviteRecord.role,
      orgName: inviteRecord.org_name,
      expiresAt: inviteRecord.expires_at,
    });
  });

  // POST /v1/invites/:token/accept
  router.post('/v1/invites/:token/accept', (ctx, params, res) => {
    const inviteRecord = findInviteByRawToken(db, params.token);
    const userNameInput = String(ctx.body.name ?? '').trim();
    const userPasswordInput = String(ctx.body.password ?? '');

    if (userNameInput.length < 1 || userNameInput.length > 200) {
      throw badRequest('name must be 1-200 characters');
    }
    if (userPasswordInput.length < 8) {
      throw badRequest('password must be at least 8 characters');
    }

    const acceptTx = db.transaction(() => {
      const claimResult = db
        .prepare(
          `UPDATE invites SET accepted_at = ?, accepted_by = ?
            WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL`
        )
        .run(nowIso(), null, inviteRecord.id);

      if (claimResult.changes !== 1) throw conflict('invite has already been used');

      let targetUser = db
        .prepare('SELECT * FROM users WHERE email = ?')
        .get(inviteRecord.email);

      if (!targetUser) {
        const newUserId = newId('usr');
        db.prepare('INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)').run(
          newUserId,
          inviteRecord.email,
          userNameInput,
          hashPassword(userPasswordInput)
        );
        targetUser = db.prepare('SELECT * FROM users WHERE id = ?').get(newUserId);
      }

      const existingMembership = db
        .prepare('SELECT * FROM memberships WHERE org_id = ? AND user_id = ?')
        .get(inviteRecord.org_id, targetUser.id);

      if (existingMembership) {
        if (existingMembership.status === 'active') {
          throw conflict('you are already a member of this org');
        }
        db.prepare(
          "UPDATE memberships SET status = 'active', role = ?, joined_at = ? WHERE id = ?"
        ).run(inviteRecord.role, nowIso(), existingMembership.id);
        bumpPermVersion(db, { orgId: inviteRecord.org_id, userId: targetUser.id });
      } else {
        db.prepare(
          `INSERT INTO memberships (id, org_id, user_id, role, status, invited_by, joined_at)
           VALUES (?, ?, ?, ?, 'active', ?, ?)`
        ).run(
          newId('mem'),
          inviteRecord.org_id,
          targetUser.id,
          inviteRecord.role,
          inviteRecord.invited_by,
          nowIso()
        );
      }

      db.prepare('UPDATE invites SET accepted_by = ? WHERE id = ?').run(targetUser.id, inviteRecord.id);
      audit(db, {
        orgId: inviteRecord.org_id,
        actorId: targetUser.id,
        action: 'user.invite.accept',
        targetType: 'invite',
        targetId: inviteRecord.id,
        result: 'allow',
        requestId: ctx.requestId,
      });

      return { userId: targetUser.id, orgId: inviteRecord.org_id, role: inviteRecord.role };
    });

    const result = acceptTx();
    send(res, 200, { userId: result.userId, orgId: result.orgId, role: result.role });
  });
}
