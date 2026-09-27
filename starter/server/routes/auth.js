import { newId, nowIso } from '../db.js';
import { send, badRequest, unauthenticated, forbidden, notFound } from '../http.js';
import {
  issueAccessToken, verifyPassword, newRefreshToken, hashRefreshToken,
  REFRESH_TTL_SECONDS, ACCESS_TTL_SECONDS,
} from '../auth.js';
import { resolve } from '../permissions.js';
import { audit } from '../audit.js';

const REFRESH_COOKIE = 'rt';

function setRefreshCookie(res, raw) {
  res.setHeader('set-cookie',
    `${REFRESH_COOKIE}=${raw}; HttpOnly; SameSite=Strict; Path=/v1/auth; Max-Age=${REFRESH_TTL_SECONDS}`);
}

function readRefreshCookie(req) {
  const header = req.headers.cookie ?? '';
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === REFRESH_COOKIE) return v.join('=');
  }
  return null;
}

function membershipsOf(db, userId) {
  return db.prepare(
    `SELECT m.org_id AS orgId, o.name AS orgName, o.theme, m.role, m.status, m.perm_version
       FROM memberships m JOIN organizations o ON o.id = m.org_id
      WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
      ORDER BY o.name`
  ).all(userId);
}

export function register(router, { db, secret }) {
  // POST /v1/auth/login  { email, password, orgId? }
  router.post('/v1/auth/login', (ctx, _params, res) => {
    const { email, password, orgId } = ctx.body;
    if (typeof email !== 'string' || typeof password !== 'string') {
      throw badRequest('email and password are required');
    }

    // Emails are stored lowercase (schema CHECK). Normalise before lookup.
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.trim().toLowerCase());

    if (!user || !verifyPassword(password, user.password_hash)) {
      // NOTE: identical response for "unknown email" and "wrong password" — no user
      // enumeration. And the audit row can only be written if we can attribute it to an
      // org, because audit_events.org_id is NOT NULL and audit is org-scoped. For an
      // unknown email there is no org to attribute to, so there is nothing to write.
      if (user) {
        const m = db.prepare("SELECT org_id FROM memberships WHERE user_id=? AND status='active' LIMIT 1").get(user.id);
        if (m) {
          audit(db, { orgId: m.org_id, actorId: user.id, action: 'auth.login', result: 'deny', reasonCode: 'bad_credentials', requestId: ctx.requestId });
        }
      }
      throw unauthenticated('invalid email or password');
    }

    const orgs = membershipsOf(db, user.id);
    if (orgs.length === 0) throw forbidden('you are not an active member of any organization');

    const active = orgId ? orgs.find((o) => o.orgId === orgId) : orgs[0];
    // Not a member of the requested org: invisible, same as anywhere else.
    if (!active) throw notFound();

    const token = issueAccessToken(
      { userId: user.id, orgId: active.orgId, role: active.role, permVersion: active.perm_version },
      secret
    );

    const raw = newRefreshToken();
    db.prepare(
      `INSERT INTO refresh_tokens (id,user_id,token_hash,family_id,expires_at)
       VALUES (?,?,?,?,?)`
    ).run(newId('rft'), user.id, hashRefreshToken(raw), newId('fam'),
          new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString());

    setRefreshCookie(res, raw);
    audit(db, { orgId: active.orgId, actorId: user.id, action: 'auth.login', result: 'allow', requestId: ctx.requestId });

    send(res, 200, {
      token,
      expiresIn: ACCESS_TTL_SECONDS,
      user: { id: user.id, email: user.email, name: user.name },
      orgId: active.orgId,
      role: active.role,
      orgs: orgs.map(({ orgId: id, orgName, theme, role }) => ({ id, name: orgName, theme, role })),
    });
  });

  // POST /v1/auth/token  { orgId }  — switch org. The token's org claim IS the scope (D18),
  // so switching orgs means minting a new token, not re-scoping an old one.
  router.post('/v1/auth/token', (ctx, _params, res) => {
    const { orgId } = ctx.body;
    if (typeof orgId !== 'string') throw badRequest('orgId is required');

    const orgs = membershipsOf(db, ctx.userId);
    const target = orgs.find((o) => o.orgId === orgId);
    if (!target) throw notFound(); // not a member -> invisible

    const token = issueAccessToken(
      { userId: ctx.userId, orgId: target.orgId, role: target.role, permVersion: target.perm_version },
      secret
    );

    send(res, 200, {
      token,
      expiresIn: ACCESS_TTL_SECONDS,
      orgId: target.orgId,
      role: target.role,
      orgs: orgs.map(({ orgId: id, orgName, theme, role }) => ({ id, name: orgName, theme, role })),
    });
  });

  // POST /v1/auth/refresh — opaque, rotating, revocable. Reuse of a rotated token
  // revokes the whole family (token-theft detection).
  router.post('/v1/auth/refresh', (ctx, _params, res) => {
    const raw = readRefreshCookie(ctx.req);
    if (!raw) throw unauthenticated('no refresh token');

    const row = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(hashRefreshToken(raw));
    if (!row) throw unauthenticated('unknown refresh token');

    if (row.revoked_at) {
      // Someone replayed an already-rotated token. Assume theft: kill the family.
      db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL')
        .run(nowIso(), row.family_id);
      throw unauthenticated('refresh token reuse detected; session family revoked');
    }
    if (row.expires_at <= nowIso()) throw unauthenticated('refresh token expired');

    const orgs = membershipsOf(db, row.user_id);
    if (orgs.length === 0) throw forbidden('you are not an active member of any organization');

    db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?').run(nowIso(), row.id);

    const next = newRefreshToken();
    db.prepare(
      `INSERT INTO refresh_tokens (id,user_id,token_hash,family_id,expires_at) VALUES (?,?,?,?,?)`
    ).run(newId('rft'), row.user_id, hashRefreshToken(next), row.family_id,
          new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString());

    setRefreshCookie(res, next);
    const active = orgs[0];
    send(res, 200, {
      token: issueAccessToken(
        { userId: row.user_id, orgId: active.orgId, role: active.role, permVersion: active.perm_version },
        secret
      ),
      expiresIn: ACCESS_TTL_SECONDS,
      orgId: active.orgId,
      role: active.role,
      orgs: orgs.map(({ orgId: id, orgName, theme, role }) => ({ id, name: orgName, theme, role })),
    });
  });

  // GET /v1/auth/me — who am I, in the org my token names.
  router.get('/v1/auth/me', (ctx, _params, res) => {
    const user = db.prepare('SELECT id,email,name FROM users WHERE id = ?').get(ctx.userId);
    const org = db.prepare('SELECT id,name,theme,max_session_minutes FROM organizations WHERE id = ?').get(ctx.orgId);
    send(res, 200, {
      user,
      org,
      role: ctx.role,
      orgs: membershipsOf(db, ctx.userId).map(({ orgId: id, orgName, theme, role }) => ({ id, name: orgName, theme, role })),
      // Org-level view: the union across all devices, for nav gating only.
      permissions: resolve(db, { userId: ctx.userId, orgId: ctx.orgId }).permissions,
    });
  });
}
