// Per-request context: turn a bearer token into an authenticated caller.
//
// This is the ONLY place that decides "who is asking". Everything downstream works
// from ctx. Two rules matter here and both are load-bearing:
//
//   1. The token's `org` claim IS the org you are allowed to address. If a request
//      names a different org in the path, that org is INVISIBLE — 404, not 403
//      (PERMISSIONS.md §6). Cross-org access is structurally impossible rather than
//      filtered, because the token cannot name another org.
//
//   2. Freshness is checked against the membership's perm_version. A stale token gets
//      TOKEN_STALE so the client can refresh. This is what makes a role change take
//      effect on the NEXT request rather than at token expiry (D11, Option A).

import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, notFound } from './http.js';

export function authenticate(db, secret) {
  return function buildContext(req, params) {
    const header = req.headers.authorization ?? '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) throw unauthenticated('missing bearer token');

    const claims = verifyAccessToken(token, secret);

    // Join the org in: a soft-deleted org is an invisible resource, exactly like a
    // missing one (PERMISSIONS.md §6). Without this, a token minted before the delete
    // keeps addressing the org's rows.
    const membership = db
      .prepare(
        `SELECT m.*, o.deleted_at AS org_deleted_at
           FROM memberships m JOIN organizations o ON o.id = m.org_id
          WHERE m.org_id = ? AND m.user_id = ?`
      )
      .get(claims.org, claims.sub);

    if (!membership) throw unauthenticated('not a member of this org');
    if (membership.org_deleted_at) throw notFound();
    if (membership.status === 'removed') throw unauthenticated('membership removed');

    // A suspended membership's token still verifies, but resolves to an empty set, so
    // every permission question is refused with 403 `suspended` (AUTH-DATA-MODEL §10).
    // The version was bumped by the suspension, so freshness must NOT be asserted here:
    // reporting TOKEN_STALE would turn that 403 into a 401 and lose the reason.
    if (membership.status !== 'suspended') assertFresh(claims, membership);

    // Structural isolation. A token scoped to org A cannot address org B at all.
    if (params.org && params.org !== claims.org) throw notFound();

    return {
      userId: claims.sub,
      orgId: claims.org,
      role: membership.role,
      membership,
      claims,
    };
  };
}
