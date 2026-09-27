// The permission resolution engine. This is PERMISSIONS.md §4, and it is the only
// place in the codebase that decides allow vs deny.
//
// If you find yourself writing `if (role === 'admin')` anywhere else, stop: that is
// the client-matrix bug from PERMISSIONS.md §8 wearing a different hat.

import { forbidden } from './http.js';

// Starting a session needs TWO independent permissions, both on the same device
// (AUTH-DATA-MODEL.md §9, "The compound check on session start"). Both are reported
// distinctly so a failure is debuggable.
export const MODE_PERMISSION = {
  view: 'device:view',
  control: 'device:control',
  terminal: 'device:terminal',
};

// ---------------------------------------------------------------------------
// Wildcard expansion. Grants may name '*', 'device:*', or an exact permission.
// ---------------------------------------------------------------------------
function expand(pattern, catalogue) {
  if (pattern === '*') return catalogue;
  if (pattern.endsWith(':*')) {
    const prefix = pattern.slice(0, -1); // 'device:*' -> 'device:'
    return catalogue.filter((key) => key.startsWith(prefix));
  }
  return catalogue.includes(pattern) ? [pattern] : [];
}

// ---------------------------------------------------------------------------
// Which grants apply to this question?
//
// Note the two modes:
//   deviceId === null  -> org-level view. ALL grants count, including device-scoped
//                         ones, because the nav should light up if you can act on
//                         *some* device.
//   deviceId === 'x'   -> exact check. Org-wide grants plus grants for that device.
// ---------------------------------------------------------------------------
function collectGrants(db, { userId, orgId, deviceId, at }) {
  const common = `
    SELECT g.id AS grant_id, g.device_id, g.effect, gp.permission
      FROM grants g
      JOIN grant_permissions gp ON gp.grant_id = g.id
     WHERE g.user_id  = ?
       AND g.org_id   = ?
       AND g.revoked_at IS NULL
       AND (g.starts_at  IS NULL OR g.starts_at  <= ?)
       AND (g.expires_at IS NULL OR g.expires_at >  ?)`;

  if (deviceId === null) {
    return db.prepare(common).all(userId, orgId, at, at);
  }

  return db
    .prepare(`${common} AND (g.device_id IS NULL OR g.device_id = ?)`)
    .all(userId, orgId, at, at, deviceId);
}

function denyAll(catalogue, role, reason) {
  const permissions = {};
  for (const key of catalogue) permissions[key] = { effect: 'deny', source: null, reason };
  return { role, permissions };
}

const loadCatalogue = (db) => db.prepare('SELECT key FROM permissions').all().map((r) => r.key);

const loadBaseline = (db, role) => new Set(
  db.prepare('SELECT permission FROM role_permissions WHERE role = ?').all(role).map((r) => r.permission)
);

const membershipOf = (db, orgId, userId) =>
  db.prepare('SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?').get(orgId, userId);

// Identity gates (step 1). Returns the deny reason, or null when the membership is live.
function gateReason(status) {
  if (status === 'suspended') return 'suspended';
  if (status !== 'active') return 'inactive_membership';
  return null;
}

// ---------------------------------------------------------------------------
// The resolution core, as a pure function over already-loaded inputs. The single
// question path (resolve) and the batched path (resolveDevices) both end here, so
// there is still exactly one implementation of allow-versus-deny.
//
//   (2) DENY wins, unconditionally and regardless of specificity  (D1)
//   (3) otherwise ALLOW if the role baseline or an allow-grant covers it
//   (4) otherwise DENY, with reason "implicit"                    (D4)
// ---------------------------------------------------------------------------
function buildPermissions({ catalogue, role, baseline, grants }) {
  const denied = new Map();  // permission -> grant id that denied it
  const allowed = new Map(); // permission -> where the allow came from

  // Denies first, so nothing can override them.
  for (const row of grants) {
    if (row.effect !== 'deny') continue;
    for (const key of expand(row.permission, catalogue)) {
      if (!denied.has(key)) denied.set(key, row.grant_id);
    }
  }

  // Allows: the role baseline first (it keeps provenance), then allow-grants for gaps.
  for (const key of baseline) allowed.set(key, `role:${role}`);
  for (const row of grants) {
    if (row.effect !== 'allow') continue;
    for (const key of expand(row.permission, catalogue)) {
      if (!allowed.has(key)) allowed.set(key, `grant:${row.grant_id}`);
    }
  }

  const permissions = {};
  for (const key of catalogue) {
    if (denied.has(key)) {
      permissions[key] = { effect: 'deny', source: `grant:${denied.get(key)}`, reason: 'explicit_deny' };
    } else if (allowed.has(key)) {
      permissions[key] = { effect: 'allow', source: allowed.get(key), reason: null };
    } else {
      permissions[key] = { effect: 'deny', source: null, reason: 'implicit' };
    }
  }

  return permissions;
}

// ---------------------------------------------------------------------------
// resolve() — the whole algorithm, in order.
//
//   1. identity gates short-circuit to total deny
//   2. collect applicable grants (org, device scope, time window)
//   3-5. buildPermissions
// ---------------------------------------------------------------------------
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const at = now.toISOString();
  const catalogue = loadCatalogue(db);

  const membership = membershipOf(db, orgId, userId);
  if (!membership) return denyAll(catalogue, null, 'not_a_member');
  const gate = gateReason(membership.status);
  if (gate) return denyAll(catalogue, membership.role, gate);

  const baseline = loadBaseline(db, membership.role);
  const grants = collectGrants(db, { userId, orgId, deviceId, at });

  return {
    role: membership.role,
    permissions: buildPermissions({ catalogue, role: membership.role, baseline, grants }),
  };
}

// ---------------------------------------------------------------------------
// Batched form for list endpoints.
//
// The device list resolves one permission set PER ROW; routing that through resolve()
// would issue four queries per row (catalogue, membership, baseline, grants) — the
// N+1 the brief warns about. Here the catalogue, the membership and the baseline are
// loaded once and every grant for the whole page in a single query, so per-row work is
// pure in-memory filtering.
//
// There is NO cache and no TTL: this is one database read taken at the instant of the
// request, exactly like resolve(), so it can never serve authority that is out of date.
// ---------------------------------------------------------------------------
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const at = now.toISOString();
  const catalogue = loadCatalogue(db);
  const membership = membershipOf(db, orgId, userId);

  const role = membership?.role ?? null;
  const gate = membership ? gateReason(membership.status) : 'not_a_member';

  if (gate) {
    const { permissions } = denyAll(catalogue, role, gate);
    const byDevice = {};
    for (const id of deviceIds) byDevice[id] = permissions;
    return { role, byDevice };
  }

  const baseline = loadBaseline(db, role);
  const all = collectGrants(db, { userId, orgId, deviceId: null, at });

  const byDevice = {};
  for (const id of deviceIds) {
    const grants = all.filter((row) => row.device_id === null || row.device_id === id);
    byDevice[id] = buildPermissions({ catalogue, role, baseline, grants });
  }
  return { role, byDevice };
}

export function can(db, ctx, permission, deviceId) {
  const { permissions } = resolve(db, { ...ctx, deviceId });
  return permissions[permission]?.effect === 'allow';
}

// Throws unless allowed, preserving WHY so the error is debuggable
// (PERMISSIONS.md §10: the reason code must distinguish the causes).
export function assertCan(db, ctx, permission, deviceId) {
  const { permissions } = resolve(db, { ...ctx, deviceId });
  const entry = permissions[permission];
  if (entry?.effect === 'allow') return;

  const reasons = {
    explicit_deny: 'explicit_deny',
    suspended: 'suspended',
    not_a_member: 'not_a_member',
    inactive_membership: 'not_a_member',
    implicit: 'missing_permission',
  };

  throw forbidden(`missing permission: ${permission}`, reasons[entry?.reason] ?? 'missing_permission');
}

// D9 / invariant 11 — no privilege laundering.
//
// You may only hand out authority you hold YOURSELF, at the same scope the new grant
// names. Resolve the caller's own set once (org-level for an org-wide grant, that device
// for a device-scoped one), then expand every requested pattern against the catalogue.
//
// Two details matter:
//   - an unknown pattern expands to nothing, so it falls through to the foreign key that
//     rejects it as 400 (D19) instead of being mis-reported as laundering;
//   - the reason is taken from the caller's own resolved entry, so an explicit deny reads
//     as `explicit_deny` and "never had it" reads as `missing_permission`.
//
// Applied to the permission list regardless of effect: PERMISSIONS.md §8 says "the caller
// holds every permission being granted, at that scope", and the whole point is that an
// admin carrying an org-wide deny cannot hand that permission to anyone.
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  const { permissions } = resolve(db, { ...ctx, deviceId });
  const catalogue = Object.keys(permissions);

  for (const pattern of patterns) {
    for (const key of expand(pattern, catalogue)) {
      if (permissions[key]?.effect === 'allow') continue;
      throw forbidden(
        `you cannot grant a permission you do not hold at this scope: ${key}`,
        permissions[key]?.reason === 'explicit_deny' ? 'explicit_deny' : 'missing_permission'
      );
    }
  }
}

// The compound check: session:start AND the permission for the requested mode.
export function assertCanStartSession(db, ctx, mode, deviceId) {
  const modePermission = MODE_PERMISSION[mode];
  if (!modePermission) throw forbidden('unknown session mode', 'validation');

  assertCan(db, ctx, 'session:start', deviceId);

  const { permissions } = resolve(db, { ...ctx, deviceId });
  if (permissions[modePermission]?.effect !== 'allow') {
    throw forbidden(
      `${mode} sessions also require ${modePermission}`,
      'missing_device_permission'
    );
  }
}
