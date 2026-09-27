import { newId, nowIso, bumpPermVersion } from '../db.js';
import { send, badRequest, notFound, conflict, forbidden, selfRoleChange } from '../http.js';
import { assertCan, resolve } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import {
  assertCanModify, assertNotLastOwner, endActiveSessions, roleRanks, assertRoleExists,
} from '../lifecycle.js';

// Pagination is part of the contract, so the boundaries are defined rather than left
// to whatever the query string happens to contain. Anything outside the range is a
// 400, not a silent clamp.
const MAX_LIMIT = 200;
function pagination(query) {
  const rawLimit = query.get('limit');
  const rawOffset = query.get('offset');

  const limit = rawLimit === null ? 50 : Number(rawLimit);
  const offset = rawOffset === null ? 0 : Number(rawOffset);

  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_LIMIT) {
    throw badRequest(`limit must be an integer between 1 and ${MAX_LIMIT}`);
  }
  if (!Number.isInteger(offset) || offset < 0) {
    throw badRequest('offset must be a non-negative integer');
  }
  return { limit, offset };
}

const THEMES = ['cobalt', 'amber', 'moss', 'plum', 'rust', 'teal'];

export function register(router, { db }) {
  // --- orgs -----------------------------------------------------------------

  // GET /v1/orgs — every org the caller belongs to. This is the one place cross-org
  // data legitimately appears, and only orgs they are actually a member of.
  router.get('/v1/orgs', (ctx, _p, res) => {
    const orgs = db.prepare(
      `SELECT o.id, o.name, o.theme, m.role, m.status
         FROM memberships m JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
        ORDER BY o.name`
    ).all(ctx.userId);
    send(res, 200, { orgs });
  });

  // POST /v1/orgs — create an org. The creator becomes its owner.
  router.post('/v1/orgs', (ctx, _p, res) => {
    const name = String(ctx.body.name ?? '').trim();
    if (name.length < 1 || name.length > 200) throw badRequest('name must be 1-200 characters');

    const orgId = newId('org');
    const theme = THEMES.includes(ctx.body.theme)
      ? ctx.body.theme
      : THEMES[db.prepare('SELECT count(*) AS n FROM organizations').get().n % THEMES.length];

    const tx = db.transaction(() => {
      db.prepare('INSERT INTO organizations (id,name,theme) VALUES (?,?,?)').run(orgId, name, theme);
      db.prepare(
        `INSERT INTO memberships (id,org_id,user_id,role,status,joined_at)
         VALUES (?,?,?,'owner','active',?)`
      ).run(newId('mem'), orgId, ctx.userId, nowIso());
      audit(db, { orgId, actorId: ctx.userId, action: 'org.create', targetType: 'org', targetId: orgId, result: 'allow', requestId: ctx.requestId });
    });
    tx();

    send(res, 201, { id: orgId, name, theme, role: 'owner' });
  });

  router.patch('/v1/orgs/:org', (ctx, params, res) => {
    assertCan(db, ctx, 'org:update');
    const name = String(ctx.body.name ?? '').trim();
    if (name.length < 1 || name.length > 200) throw badRequest('name must be 1-200 characters');

    db.prepare('UPDATE organizations SET name = ? WHERE id = ?').run(name, params.org);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'org.update', targetType: 'org', targetId: params.org, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { id: params.org, name });
  });

  router.delete('/v1/orgs/:org', (ctx, params, res) => {
    assertCan(db, ctx, 'org:delete');
    db.prepare('UPDATE organizations SET deleted_at = ? WHERE id = ?').run(nowIso(), params.org);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'org.delete', targetType: 'org', targetId: params.org, result: 'allow', requestId: ctx.requestId });
    send(res, 204, undefined);
  });

  // --- members --------------------------------------------------------------
  // NOTE the order: '/members/me' is registered BEFORE '/members/:userId'.
  // First match wins, so 'me' would otherwise be swallowed as a user id.

  router.get('/v1/orgs/:org/members', (ctx, params, res) => {
    assertCan(db, ctx, 'user:read');
    const members = db.prepare(
      `SELECT u.id, u.email, u.name, m.role, m.status, m.perm_version, m.joined_at
         FROM memberships m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND m.status != 'removed'
        ORDER BY u.name`
    ).all(params.org);
    send(res, 200, { members });
  });

  // Leave an org. Self-service, so no user:remove needed — but still cannot
  // orphan the org.
  router.delete('/v1/orgs/:org/members/me', (ctx, params, res) => {
    assertNotLastOwner(db, params.org, ctx.userId);
    removeMembership(db, ctx, params.org, ctx.userId, 'member.leave');
    send(res, 204, undefined);
  });

  router.patch('/v1/orgs/:org/members/:userId', (ctx, params, res) => {
    const { userId } = params;
    const role = ctx.body.role;

    if (userId === ctx.userId) throw selfRoleChange();   // no self role change, even for an owner
    if (typeof role !== 'string') throw badRequest('role is required');
    assertRoleExists(db, role);

    auditDenials(db, ctx, { action: 'user.role.update', targetType: 'user', targetId: userId }, () => {
      assertCan(db, ctx, 'user:role:update');
    });

    const target = db.prepare('SELECT * FROM memberships WHERE org_id=? AND user_id=?').get(params.org, userId);
    if (!target || target.status === 'removed') throw notFound();

    assertCanModify(db, ctx.role, target.role);
    if (role === 'owner' && ctx.role !== 'owner') {
      throw forbidden('only an owner may assign the owner role', 'cannot_confer_owner');
    }
    if (target.role === 'owner' && role !== 'owner') assertNotLastOwner(db, params.org, userId);

    const tx = db.transaction(() => {
      db.prepare('UPDATE memberships SET role = ? WHERE org_id=? AND user_id=?').run(role, params.org, userId);
      bumpPermVersion(db, { orgId: params.org, userId });
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'user.role.update', targetType: 'user', targetId: userId, result: 'allow', requestId: ctx.requestId });
    });
    tx();

    // Note: sessions are NOT terminated here. A role change is grandfathered
    // (PERMISSIONS.md §7.1). Only the next session is affected.
    send(res, 200, { id: userId, role });
  });

  // Suspend / reinstate. Suspension is the reversible form of removal and requires
  // user:remove — it is a weaker removal, so the permission is the same.
  router.post('/v1/orgs/:org/members/:userId/suspend', (ctx, params, res) => {
    setMembershipStatus(db, ctx, params.org, params.userId, 'suspended', 'member.suspend');
    send(res, 200, { id: params.userId, status: 'suspended' });
  });

  router.delete('/v1/orgs/:org/members/:userId/suspend', (ctx, params, res) => {
    setMembershipStatus(db, ctx, params.org, params.userId, 'active', 'member.reinstate');
    send(res, 200, { id: params.userId, status: 'active' });
  });

  router.delete('/v1/orgs/:org/members/:userId', (ctx, params, res) => {
    removeMembership(db, ctx, params.org, params.userId, 'member.remove');
    send(res, 204, undefined);
  });

  // --- effective permissions ------------------------------------------------

  // A user may always read their own; reading someone else's needs user:read.
  router.get('/v1/orgs/:org/users/:userId/effective', (ctx, params, res) => {
    const isSelf = params.userId === ctx.userId;
    if (!isSelf) assertCan(db, ctx, 'user:read');

    const membership = db.prepare('SELECT role,status FROM memberships WHERE org_id=? AND user_id=?')
      .get(params.org, params.userId);
    if (!membership) throw notFound();

    const deviceId = ctx.query.get('deviceId');
    const resolved = resolve(db, { userId: params.userId, orgId: params.org, deviceId: deviceId ?? null });
    send(res, 200, { userId: params.userId, orgId: params.org, deviceId: deviceId ?? null, ...resolved });
  });

  // --- audit ----------------------------------------------------------------

  router.get('/v1/orgs/:org/audit', (ctx, params, res) => {
    assertCan(db, ctx, 'audit:read');
    const { limit, offset } = pagination(ctx.query);
    const since = ctx.query.get('since');

    const rows = since
      ? db.prepare('SELECT * FROM audit_events WHERE org_id=? AND at >= ? ORDER BY at DESC LIMIT ? OFFSET ?')
          .all(params.org, since, limit, offset)
      : db.prepare('SELECT * FROM audit_events WHERE org_id=? ORDER BY at DESC LIMIT ? OFFSET ?')
          .all(params.org, limit, offset);

    send(res, 200, { events: rows, limit, offset });
  });
}

// ---------------------------------------------------------------------------

function setMembershipStatus(db, ctx, orgId, userId, status, action) {
  auditDenials(db, ctx, { action, targetType: 'user', targetId: userId }, () => {
    assertCan(db, ctx, 'user:remove');
  });

  const target = db.prepare('SELECT * FROM memberships WHERE org_id=? AND user_id=?').get(orgId, userId);
  if (!target || target.status === 'removed') throw notFound();
  if (target.role === 'owner' && status !== 'active') assertNotLastOwner(db, orgId, userId);
  assertCanModify(db, ctx.role, target.role);

  const tx = db.transaction(() => {
    db.prepare('UPDATE memberships SET status = ? WHERE org_id=? AND user_id=?').run(status, orgId, userId);
    bumpPermVersion(db, { orgId, userId });
    // Suspension DOES cascade: account integrity, not a permission tweak (§7.2).
    if (status !== 'active') endActiveSessions(db, { orgId, userId, reason: 'user_suspended' });
    audit(db, { orgId, actorId: ctx.userId, action, targetType: 'user', targetId: userId, result: 'allow', requestId: ctx.requestId });
  });
  tx();
}

function removeMembership(db, ctx, orgId, userId, action) {
  if (action === 'member.remove') {
    auditDenials(db, ctx, { action, targetType: 'user', targetId: userId }, () => {
      assertCan(db, ctx, 'user:remove');
    });
  }

  const target = db.prepare('SELECT * FROM memberships WHERE org_id=? AND user_id=?').get(orgId, userId);
  if (!target || target.status === 'removed') throw notFound();
  if (target.role === 'owner') assertNotLastOwner(db, orgId, userId);
  if (userId !== ctx.userId) assertCanModify(db, ctx.role, target.role);

  const tx = db.transaction(() => {
    // The membership is removed. The USER ROW IS NEVER DELETED (D15) — they may belong
    // to other orgs, and their audit history must survive.
    db.prepare("UPDATE memberships SET status='removed' WHERE org_id=? AND user_id=?").run(orgId, userId);
    bumpPermVersion(db, { orgId, userId });
    endActiveSessions(db, { orgId, userId, reason: 'membership_removed' });
    audit(db, { orgId, actorId: ctx.userId, action, targetType: 'user', targetId: userId, result: 'allow', requestId: ctx.requestId });
  });
  tx();
}
