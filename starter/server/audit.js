// Audit helper.
//
// Two things candidates routinely get wrong, both enforced by the spec:
//   - DENIED attempts are audited too, not just successes (invariant 10)
//   - the audit table is append-only; there is no update or delete path
//
// The DB trigger will reject any attempt to mutate a row, so this file only inserts.

import { newId, nowIso } from './db.js';

export function audit(db, {
  orgId,
  actorId = null,
  action,
  targetType = null,
  targetId = null,
  result,
  reasonCode = null,
  requestId = null,
}) {
  db.prepare(
    `INSERT INTO audit_events
       (id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id, at)
     VALUES (?,?,?,?,?,?,?,?,?,?)`
  ).run(
    newId('aud'), orgId, actorId, action, targetType, targetId,
    result, reasonCode, requestId, nowIso()
  );
}

// Wrap a permission-gated action so that a denial is recorded before it propagates.
// Usage: auditDenials(db, ctx, {action, targetType, targetId}, () => { ...work... })
//
// Denials ONLY. The caller's success row is written by the route itself, inside the same
// transaction as the change it describes; writing an `allow` here as well would log every
// successful action twice (once without a target id, once with one).
export function auditDenials(db, ctx, meta, fn) {
  try {
    return fn();
  } catch (err) {
    if (err?.code === 'FORBIDDEN') {
      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        result: 'deny',
        reasonCode: err.reason ?? 'missing_permission',
        requestId: ctx.requestId,
        ...meta,
      });
    }
    throw err;
  }
}
