import { newId, nowIso, bumpPermVersion } from '../db.js';
import { send, badRequest, notFound, conflict, forbidden } from '../http.js';
import { normalizeTs } from '../http.js';
import { assertCan, assertMayGrant, resolve, resolveDevices } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import { endActiveSessions, snapshotAuthority } from '../lifecycle.js';

const KINDS = ['macos', 'windows', 'linux', 'android', 'ios'];

export function register(router, { db }) {
  // --- devices --------------------------------------------------------------

  // GET /v1/orgs/:org/devices
  //
  // Two things worth noting, both from the spec:
  //   - device:list gates the ENDPOINT; device:view gates ROW INCLUSION. A device the
  //     caller cannot view is absent from the list entirely, not shown with redacted
  //     fields (PERMISSIONS.md §2).
  //   - each row carries the caller's RESOLVED permission set for that device. The UI
  //     reads data-state straight off this, so there is no reason for the frontend to
  //     reimplement the rules (§8.2). This is what makes the client-matrix test pass
  //     by construction rather than by discipline.
  router.get('/v1/orgs/:org/devices', (ctx, params, res) => {
    assertCan(db, ctx, 'device:list');

    const rows = db.prepare(
      `SELECT id, name, kind, online, created_at FROM devices
        WHERE org_id = ? AND deleted_at IS NULL ORDER BY name`
    ).all(params.org);

    // One batched resolution for the whole page, not one per row (see resolveDevices).
    const { byDevice } = resolveDevices(db, {
      userId: ctx.userId, orgId: params.org, deviceIds: rows.map((d) => d.id),
    });

    const devices = [];
    for (const device of rows) {
      const permissions = byDevice[device.id];
      if (permissions['device:view'].effect !== 'allow') continue; // row exclusion, not redaction
      devices.push({ ...device, online: device.online === 1, permissions });
    }

    send(res, 200, { devices });
  });

  router.get('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const device = requireDevice(db, params.org, params.id);
    const { permissions } = resolve(db, { userId: ctx.userId, orgId: params.org, deviceId: device.id });
    if (permissions['device:view'].effect !== 'allow') throw notFound(); // invisible, not forbidden
    send(res, 200, { ...device, online: device.online === 1, permissions });
  });

  router.post('/v1/orgs/:org/devices', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'device.create', targetType: 'device' }, () => {
      assertCan(db, ctx, 'device:provision');
    });

    const name = String(ctx.body.name ?? '').trim();
    const kind = String(ctx.body.kind ?? '');
    if (name.length < 1 || name.length > 200) throw badRequest('name must be 1-200 characters');
    if (!KINDS.includes(kind)) throw badRequest(`kind must be one of: ${KINDS.join(', ')}`);

    const id = newId('dev');
    db.prepare('INSERT INTO devices (id,org_id,name,kind,online) VALUES (?,?,?,?,?)')
      .run(id, params.org, name, kind, ctx.body.online ? 1 : 0);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'device.create', targetType: 'device', targetId: id, result: 'allow', requestId: ctx.requestId });
    send(res, 201, { id, name, kind });
  });

  router.patch('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const device = requireDevice(db, params.org, params.id);
    auditDenials(db, ctx, { action: 'device.update', targetType: 'device', targetId: device.id }, () => {
      assertCan(db, ctx, 'device:update', device.id);
    });

    const name = ctx.body.name === undefined ? device.name : String(ctx.body.name).trim();
    if (name.length < 1 || name.length > 200) throw badRequest('name must be 1-200 characters');
    const online = ctx.body.online === undefined ? device.online : (ctx.body.online ? 1 : 0);

    db.prepare('UPDATE devices SET name=?, online=? WHERE id=?').run(name, online, device.id);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'device.update', targetType: 'device', targetId: device.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { id: device.id, name, online: online === 1 });
  });

  router.delete('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const device = requireDevice(db, params.org, params.id);
    auditDenials(db, ctx, { action: 'device.decommission', targetType: 'device', targetId: device.id }, () => {
      // Decommissioning is a per-row entry (UI-INVENTORY.md §3), so the check is device-scoped.
      assertCan(db, ctx, 'device:provision', device.id);
    });

    const tx = db.transaction(() => {
      db.prepare('UPDATE devices SET deleted_at=? WHERE id=?').run(nowIso(), device.id);
      // Decommissioning is a tenancy event, so it DOES cascade to sessions (§7.2).
      endActiveSessions(db, { orgId: params.org, deviceId: device.id, reason: 'device_transferred' });
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'device.decommission', targetType: 'device', targetId: device.id, result: 'allow', requestId: ctx.requestId });
    });
    tx();
    send(res, 204, undefined);
  });

  // Transfer a device to another org.
  //
  // Requires device:provision in the SOURCE org, and — because the caller's authority is
  // per-membership — device:provision in the TARGET org too. The token is scoped to the
  // source, so the target authority is resolved separately for the same user.
  router.post('/v1/orgs/:org/devices/:id/transfer', (ctx, params, res) => {
    const device = requireDevice(db, params.org, params.id);
    const targetOrgId = String(ctx.body.targetOrgId ?? '');

    auditDenials(db, ctx, { action: 'device.transfer', targetType: 'device', targetId: device.id }, () => {
      assertCan(db, ctx, 'device:provision', device.id);
    });

    const target = db.prepare('SELECT id FROM organizations WHERE id=? AND deleted_at IS NULL').get(targetOrgId);
    if (!target) throw notFound();

    const targetPerms = resolve(db, { userId: ctx.userId, orgId: targetOrgId });
    if (targetPerms.permissions['device:provision'].effect !== 'allow') {
      throw forbidden('you need device:provision in the target organization', 'missing_permission');
    }

    const tx = db.transaction(() => {
      db.prepare('UPDATE devices SET org_id=? WHERE id=?').run(targetOrgId, device.id);
      // Grants naming this device belonged to the old org's context. Drop them.
      db.prepare('DELETE FROM grant_permissions WHERE grant_id IN (SELECT id FROM grants WHERE device_id=?)').run(device.id);
      db.prepare('DELETE FROM grants WHERE device_id=?').run(device.id);

      // The device left the org, so any live session would straddle a tenant boundary.
      endActiveSessions(db, { orgId: params.org, deviceId: device.id, reason: 'device_transferred' });
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'device.transfer', targetType: 'device', targetId: device.id, result: 'allow', requestId: ctx.requestId });
    });
    tx();

    send(res, 200, { id: device.id, orgId: targetOrgId });
  });

  // --- grants ---------------------------------------------------------------

  router.get('/v1/orgs/:org/grants', (ctx, params, res) => {
    assertCan(db, ctx, 'user:read');
    const userId = ctx.query.get('userId');
    const rows = db.prepare(
      `SELECT g.id, g.user_id, g.device_id, g.effect, g.starts_at, g.expires_at, g.created_at,
              group_concat(gp.permission) AS permissions
         FROM grants g JOIN grant_permissions gp ON gp.grant_id = g.id
        WHERE g.org_id = ? AND g.revoked_at IS NULL ${userId ? 'AND g.user_id = ?' : ''}
        GROUP BY g.id ORDER BY g.created_at DESC`
    ).all(...(userId ? [params.org, userId] : [params.org]));

    send(res, 200, { grants: rows.map((r) => ({ ...r, permissions: r.permissions.split(',') })) });
  });

  // POST /v1/orgs/:org/grants
  //
  // Grants are a delta in EITHER direction (D3): an allow widens past the role baseline,
  // a deny narrows it. Validation here is the whole of PERMISSIONS.md §7.
  router.post('/v1/orgs/:org/grants', (ctx, params, res) => {
    const { userId, deviceId = null, effect, permissions, startsAt = null, expiresAt = null } = ctx.body;

    auditDenials(db, ctx, { action: 'grant.create', targetType: 'user', targetId: userId }, () => {
      assertCan(db, ctx, 'grant:create');
    });

    // D9: you cannot grant to yourself, and you cannot hand out authority you do not hold.
    if (userId === ctx.userId) throw forbidden('you cannot create a grant for yourself', 'self_grant');

    if (typeof userId !== 'string' || userId.length === 0) throw badRequest('userId is required');
    if (deviceId !== null && typeof deviceId !== 'string') throw badRequest('deviceId must be a string or null');
    if (!Array.isArray(permissions) || permissions.length === 0) {
      throw badRequest('permissions must be a non-empty array');
    }
    if (!permissions.every((p) => typeof p === 'string' && p.length > 0)) {
      throw badRequest('permissions must be non-empty strings');
    }
    if (effect !== 'allow' && effect !== 'deny') throw badRequest("effect must be 'allow' or 'deny'");

    // The primary key on grant_permissions dedupes conceptually, but a repeated literal
    // still raises a constraint error at INSERT time. Collapse duplicates up front so a
    // harmless duplicate is a 201 rather than a 500.
    const wanted = [...new Set(permissions)];

    const target = db.prepare("SELECT 1 FROM memberships WHERE org_id=? AND user_id=? AND status='active'")
      .get(params.org, userId);
    if (!target) throw notFound();

    if (deviceId !== null) {
      const device = db.prepare('SELECT id FROM devices WHERE id=? AND org_id=? AND deleted_at IS NULL')
        .get(deviceId, params.org);
      if (!device) throw notFound();   // cross-org device ids are invisible
    }

    const now = nowIso();
    const startsAtN = normalizeTs(startsAt, 'startsAt');
    const expiresAtN = normalizeTs(expiresAt, 'expiresAt');
    if (expiresAtN !== null && expiresAtN <= now) throw badRequest('expiresAt is in the past', 'expired_grant');
    if (startsAtN !== null && expiresAtN !== null && expiresAtN <= startsAtN) {
      throw badRequest('expiresAt must be after startsAt');
    }

    // D9 — you cannot launder authority you do not hold at this scope. Runs AFTER the
    // 404 checks above so a cross-org device or a non-member is still invisible rather
    // than reported as a permission problem, and BEFORE the insert so an unknown
    // permission pattern still reaches the foreign key and becomes a 400 (D19).
    assertMayGrant(db, ctx, wanted, deviceId);

    const id = newId('grt');
    const tx = db.transaction(() => {
      db.prepare(
        `INSERT INTO grants (id,org_id,user_id,device_id,effect,starts_at,expires_at,created_by)
         VALUES (?,?,?,?,?,?,?,?)`
      ).run(id, params.org, userId, deviceId, effect, startsAtN, expiresAtN, ctx.userId);

      // The FK to permission_patterns is what rejects 'device:teleport'. Map that to a
      // 400 VALIDATION rather than letting a raw SQLite error escape as a 500.
      // Throwing here rolls the transaction back, so no partial grant survives.
      const stmt = db.prepare('INSERT INTO grant_permissions (grant_id,permission) VALUES (?,?)');
      for (const p of wanted) {
        try {
          stmt.run(id, p);
        } catch (err) {
          if (String(err.code).includes('FOREIGNKEY')) {
            throw badRequest(`unknown permission: ${p}`, 'unknown_permission');
          }
          throw err;
        }
      }

      // Permission changes take effect on the NEXT request (D11/§7.4). Sessions in
      // flight are grandfathered, so nothing is terminated here.
      bumpPermVersion(db, { orgId: params.org, userId });
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'grant.create', targetType: 'user', targetId: userId, result: 'allow', requestId: ctx.requestId });
    });
    tx();

    send(res, 201, { id, userId, deviceId, effect, permissions: wanted });
  });

  router.delete('/v1/orgs/:org/grants/:id', (ctx, params, res) => {
    auditDenials(db, ctx, { action: 'grant.revoke', targetType: 'grant', targetId: params.id }, () => {
      assertCan(db, ctx, 'grant:revoke');
    });

    const grant = db.prepare('SELECT * FROM grants WHERE id=? AND org_id=? AND revoked_at IS NULL')
      .get(params.id, params.org);
    if (!grant) throw notFound();   // already revoked is indistinguishable from never existed

    const tx = db.transaction(() => {
      db.prepare('UPDATE grants SET revoked_at=? WHERE id=?').run(nowIso(), params.id);
      bumpPermVersion(db, { orgId: params.org, userId: grant.user_id });
      // Deliberately NOT ending sessions. Grandfathering, §7.1.
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'grant.revoke', targetType: 'grant', targetId: params.id, result: 'allow', requestId: ctx.requestId });
    });
    tx();

    send(res, 204, undefined);
  });
}

function requireDevice(db, orgId, deviceId) {
  const device = db.prepare('SELECT * FROM devices WHERE id=? AND org_id=? AND deleted_at IS NULL')
    .get(deviceId, orgId);
  if (!device) throw notFound();   // wrong org -> invisible
  return device;
}
