
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { send, badRequest, notFound, conflict, forbidden, gone } from '../http.js';
import { assertCan } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import { assertRoleExists, assertCanModify } from '../lifecycle.js';
import { hashPassword, hashInviteToken, newInviteToken } from '../auth.js';

const INVITE_TTL_DAYS = 7;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function register(router, { db }) {
  // --- invite lifecycle (authenticated) -------------------------------------

  router.post('/v1/orgs/:org/invites', (ctx, params, res) => {
    const email = String(ctx.body.email ?? '').trim().toLowerCase();
    const role = String(ctx.body.role ?? '');

    if (!EMAIL.test(email) || email.length > 320) throw badRequest('a valid email is required');
    assertRoleExists(db, role);

    auditDenials(db, ctx, { action: 'user.invite', targetType: 'email', targetId: email }, () => {
      assertCan(db, ctx, 'user:invite');
    });

    // Only an owner may confer ownership — the same rule as role changes (D8).
    if (role === 'owner' && ctx.role !== 'owner') {
      throw forbidden('only an owner may invite an owner', 'cannot_confer_owner');
    }
    // You cannot invite at a level you do not outrank.
    assertCanModify(db, ctx.role, role);

    const existing = db.prepare(
      `SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND u.email = ? AND m.status != 'removed'`
    ).get(params.org, email);
    if (existing) throw conflict('that email already has a membership in this org');

    const live = db.prepare(
      'SELECT 1 FROM invites WHERE org_id=? AND email=? AND accepted_at IS NULL AND revoked_at IS NULL'
    ).get(params.org, email);
    if (live) throw conflict('a pending invite already exists for that email');

    // The raw token is a bearer credential. It is returned ONCE and only its hash is
    // stored — the same treatment as a Twitch stream key. It is never logged.
    const raw = newInviteToken();
    const inviteId = newId('inv');

    const tx = db.transaction(() => {
      db.prepare(
        `INSERT INTO invites (id,org_id,email,role,token_hash,invited_by,expires_at)
         VALUES (?,?,?,?,?,?,?)`
      ).run(inviteId, params.org, email, role, hashInviteToken(raw), ctx.userId,
            new Date(Date.now() + INVITE_TTL_DAYS * 864e5).toISOString());

      // The membership exists from the moment of invitation, in 'invited' state, so the
      // people list can show pending invites without a second source of truth.
      const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
      if (user) {
        db.prepare(
          `INSERT INTO memberships (id,org_id,user_id,role,status,invited_by)
           VALUES (?,?,?,?,'invited',?)`
        ).run(newId('mem'), params.org, user.id, role, ctx.userId);
      }
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'user.invite', targetType: 'email', targetId: email, result: 'allow', requestId: ctx.requestId });
    });
    tx();

    send(res, 201, {
      id: inviteId,
      email,
      role,
      expiresAt: new Date(Date.now() + INVITE_TTL_DAYS * 864e5).toISOString(),
      // Shown once. There is no endpoint that returns this again.
      inviteToken: raw,
    });
  });

  router.get('/v1/orgs/:org/invites', (ctx, params, res) => {
    assertCan(db, ctx, 'user:invite');
    const invites = db.prepare(
      `SELECT id, email, role, expires_at, accepted_at, revoked_at, created_at
         FROM invites WHERE org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL
        ORDER BY created_at DESC`
    ).all(params.org);
    // Note: token_hash is deliberately not selected.
    send(res, 200, { invites });
  });

  router.delete('/v1/orgs/:org/invites/:id', (ctx, params, res) => {
    assertCan(db, ctx, 'user:invite');

    const invite = db.prepare('SELECT * FROM invites WHERE id=? AND org_id=?').get(params.id, params.org);
    if (!invite) throw notFound();
    if (invite.accepted_at) throw conflict('invite was already accepted; remove the member instead');

    db.prepare('UPDATE invites SET revoked_at=? WHERE id=?').run(nowIso(), params.id);
    db.prepare("DELETE FROM memberships WHERE org_id=? AND user_id=(SELECT id FROM users WHERE email=?) AND status='invited'")
      .run(params.org, invite.email);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'user.invite.revoke', targetType: 'invite', targetId: params.id, result: 'allow', requestId: ctx.requestId });
    send(res, 204, undefined);
  });

  // --- redemption (PUBLIC — the token is the credential) ---------------------

  // Deliberately returns nothing about the org except its name and the offered role.
  // The token holder is not a member yet.
  router.get('/v1/invites/:token', (ctx, params, res) => {
    const invite = lookup(db, params.token);
    send(res, 200, {
      email: invite.email,
      role: invite.role,
      orgName: invite.org_name,
      expiresAt: invite.expires_at,
    });
  });

  router.post('/v1/invites/:token/accept', (ctx, params, res) => {
    const invite = lookup(db, params.token);
    const name = String(ctx.body.name ?? '').trim();
    const password = String(ctx.body.password ?? '');
    if (name.length < 1 || name.length > 200) throw badRequest('name must be 1-200 characters');
    if (password.length < 8) throw badRequest('password must be at least 8 characters');

    const tx = db.transaction(() => {
      // Atomic single-use claim. Under two concurrent accepts, exactly one UPDATE
      // affects a row; the other sees changes === 0 and gets a 409. The partial
      // unique index backs this up at the storage layer.
      const claim = db.prepare(
        `UPDATE invites SET accepted_at = ?, accepted_by = ?
          WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL`
      ).run(nowIso(), null, invite.id);

      if (claim.changes !== 1) throw conflict('invite has already been used');

      // Existing platform user? Attach a membership to them. Do NOT create a duplicate.
      let user = db.prepare('SELECT * FROM users WHERE email = ?').get(invite.email);
      if (!user) {
        const id = newId('usr');
        db.prepare('INSERT INTO users (id,email,name,password_hash) VALUES (?,?,?,?)')
          .run(id, invite.email, name, hashPassword(password));
        user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
      }

      const membership = db.prepare('SELECT * FROM memberships WHERE org_id=? AND user_id=?')
        .get(invite.org_id, user.id);

      if (membership && membership.status !== 'removed') {
        if (membership.status === 'active') throw conflict('you are already a member of this org');
        db.prepare("UPDATE memberships SET status='active', role=?, joined_at=? WHERE id=?")
          .run(invite.role, nowIso(), membership.id);
        bumpPermVersion(db, { orgId: invite.org_id, userId: user.id });
      } else if (membership) {
        db.prepare("UPDATE memberships SET status='active', role=?, joined_at=? WHERE id=?")
          .run(invite.role, nowIso(), membership.id);
        bumpPermVersion(db, { orgId: invite.org_id, userId: user.id });
      } else {
        db.prepare(
          `INSERT INTO memberships (id,org_id,user_id,role,status,invited_by,joined_at)
           VALUES (?,?,?,?,'active',?,?)`
        ).run(newId('mem'), invite.org_id, user.id, invite.role, invite.invited_by, nowIso());
      }

      db.prepare('UPDATE invites SET accepted_by = ? WHERE id = ?').run(user.id, invite.id);
      audit(db, { orgId: invite.org_id, actorId: user.id, action: 'user.invite.accept', targetType: 'invite', targetId: invite.id, result: 'allow', requestId: ctx.requestId });

      return { userId: user.id, orgId: invite.org_id, role: invite.role };
    });

    const result = tx();
    send(res, 200, { userId: result.userId, orgId: result.orgId, role: result.role });
  });
}

// Resolve a raw invite token to its row, enforcing every invalid state.
function lookup(db, rawToken) {
  if (!rawToken || rawToken.length < 16) throw notFound();

  const invite = db.prepare(
    `SELECT i.*, o.name AS org_name, o.deleted_at AS org_deleted
       FROM invites i JOIN organizations o ON o.id = i.org_id
      WHERE i.token_hash = ?`
  ).get(hashInviteToken(rawToken));

  if (!invite) throw notFound();
  if (invite.org_deleted) throw notFound();
  if (invite.revoked_at) throw gone('this invite was revoked');
  if (invite.accepted_at) throw conflict('this invite has already been used');
  if (invite.expires_at <= nowIso()) throw gone('this invite has expired');

  return invite;
}
