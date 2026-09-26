// Custom sessions route implementation.
import { newId, nowIso } from '../db.js';
import { send, badRequest, notFound, conflict, forbidden, deviceBusy } from '../http.js';
import { assertCan, assertCanStartSession } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import { snapshotAuthority, sessionExpiry, endActiveSessions } from '../lifecycle.js';

const VALID_SESSION_MODES = ['view', 'control', 'terminal'];

function cleanExpiredSessions(db, orgId) {
  const timestampIso = nowIso();
  const expiredSessionIds = db
    .prepare("SELECT id FROM sessions WHERE org_id = ? AND state = 'active' AND expires_at <= ?")
    .all(orgId, timestampIso)
    .map((row) => row.id);

  const expireStmt = db.prepare(
    "UPDATE sessions SET state = 'ended', ended_at = ?, end_reason = 'session_expired' WHERE id = ?"
  );
  for (const sessionId of expiredSessionIds) {
    expireStmt.run(timestampIso, sessionId);
  }
  return expiredSessionIds;
}

export function register(router, { db }) {
  // POST /v1/orgs/:org/sessions
  router.post('/v1/orgs/:org/sessions', (ctx, params, res) => {
    const targetDeviceId = String(ctx.body.deviceId ?? '');
    const requestedMode = String(ctx.body.mode ?? '');

    if (!VALID_SESSION_MODES.includes(requestedMode)) {
      throw badRequest(`mode must be one of: ${VALID_SESSION_MODES.join(', ')}`);
    }

    const deviceRecord = db
      .prepare('SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL')
      .get(targetDeviceId, params.org);

    if (!deviceRecord) throw notFound();

    auditDenials(
      db,
      ctx,
      { action: 'session.start', targetType: 'device', targetId: targetDeviceId },
      () => {
        assertCanStartSession(db, ctx, requestedMode, targetDeviceId);
      }
    );

    cleanExpiredSessions(db, params.org);

    const newSessionId = newId('ses');
    try {
      db.prepare(
        `INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, expires_at)
         VALUES (?, ?, ?, ?, ?, 'active', ?, ?)`
      ).run(
        newSessionId,
        params.org,
        ctx.userId,
        targetDeviceId,
        requestedMode,
        snapshotAuthority(db, { userId: ctx.userId, orgId: params.org, deviceId: targetDeviceId }),
        sessionExpiry(db, params.org)
      );
    } catch (err) {
      if (String(err.code).startsWith('SQLITE_CONSTRAINT')) {
        const activeHolder = db
          .prepare(
            "SELECT id, user_id FROM sessions WHERE device_id = ? AND state = 'active' AND mode IN ('control', 'terminal')"
          )
          .get(targetDeviceId);
        throw deviceBusy(`device is already held by session ${activeHolder?.id ?? 'unknown'}`);
      }
      throw err;
    }

    audit(db, {
      orgId: ctx.orgId,
      actorId: ctx.userId,
      action: 'session.start',
      targetType: 'device',
      targetId: targetDeviceId,
      result: 'allow',
      requestId: ctx.requestId,
    });

    send(res, 201, { id: newSessionId, deviceId: targetDeviceId, mode: requestedMode, state: 'active' });
  });

  // GET /v1/orgs/:org/sessions
  router.get('/v1/orgs/:org/sessions', (ctx, params, res) => {
    assertCan(db, ctx, 'session:view');
    cleanExpiredSessions(db, params.org);

    const sessionList = db
      .prepare(
        `SELECT s.id, s.user_id, u.name AS user_name, s.device_id, d.name AS device_name,
                s.mode, s.state, s.end_reason, s.started_at, s.ended_at, s.expires_at
           FROM sessions s
           JOIN users u ON u.id = s.user_id
           JOIN devices d ON d.id = s.device_id
          WHERE s.org_id = ?
          ORDER BY s.started_at DESC LIMIT 200`
      )
      .all(params.org);

    send(res, 200, { sessions: sessionList });
  });

  // GET /v1/sessions/:id
  router.get('/v1/sessions/:id', (ctx, params, res) => {
    cleanExpiredSessions(db, ctx.orgId);
    const sessionRecord = db
      .prepare('SELECT * FROM sessions WHERE id = ? AND org_id = ?')
      .get(params.id, ctx.orgId);

    if (!sessionRecord) throw notFound();

    if (sessionRecord.user_id !== ctx.userId) {
      assertCan(db, ctx, 'session:view');
    }
    send(res, 200, sessionRecord);
  });

  // DELETE /v1/sessions/:id
  router.delete('/v1/sessions/:id', (ctx, params, res) => {
    cleanExpiredSessions(db, ctx.orgId);
    const sessionRecord = db
      .prepare('SELECT * FROM sessions WHERE id = ? AND org_id = ?')
      .get(params.id, ctx.orgId);

    if (!sessionRecord) throw notFound();

    const isSessionOwner = sessionRecord.user_id === ctx.userId;
    if (!isSessionOwner) {
      auditDenials(
        db,
        ctx,
        { action: 'session.terminate', targetType: 'session', targetId: params.id },
        () => {
          assertCan(db, ctx, 'session:terminate');
        }
      );
    }

    if (sessionRecord.state === 'ended') {
      throw conflict('session already ended');
    }

    db.prepare("UPDATE sessions SET state = 'ended', ended_at = ?, end_reason = ? WHERE id = ?").run(
      nowIso(),
      isSessionOwner ? 'user_stopped' : 'admin_terminated',
      params.id
    );

    audit(db, {
      orgId: ctx.orgId,
      actorId: ctx.userId,
      action: isSessionOwner ? 'session.stop' : 'session.terminate',
      targetType: 'session',
      targetId: params.id,
      result: 'allow',
      requestId: ctx.requestId,
    });

    send(res, 204, undefined);
  });
}
