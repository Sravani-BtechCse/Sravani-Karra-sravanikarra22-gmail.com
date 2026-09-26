// Append-only audit logging helper.
import { newId, nowIso } from './db.js';

export function audit(database, {
  orgId,
  actorId = null,
  action,
  targetType = null,
  targetId = null,
  result,
  reasonCode = null,
  requestId = null,
}) {
  database
    .prepare(
      `INSERT INTO audit_events
         (id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id, at)
       VALUES (?,?,?,?,?,?,?,?,?,?)`
    )
    .run(
      newId('aud'),
      orgId,
      actorId,
      action,
      targetType,
      targetId,
      result,
      reasonCode,
      requestId,
      nowIso()
    );
}

export function auditDenials(database, context, targetMetadata, executeAction) {
  try {
    return executeAction();
  } catch (error) {
    if (error?.code === 'FORBIDDEN') {
      audit(database, {
        orgId: context.orgId,
        actorId: context.userId,
        result: 'deny',
        reasonCode: error.reason ?? 'missing_permission',
        requestId: context.requestId,
        ...targetMetadata,
      });
    }
    throw error;
  }
}
