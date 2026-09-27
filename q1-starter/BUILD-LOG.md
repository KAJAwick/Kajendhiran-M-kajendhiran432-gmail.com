# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

---

## 2026-09-27 · Phase 0 — orientation

- **What the starting line looked like:**
  Cloned the repository and inspected the layout. The application is designed as a single process (`node:http` on port 8080 hosting the `/v1/*` REST API and Vite middleware for the React SPA).
  Ran the initial test suites against the untouched skeleton:
  - `node scripts/check-jwt.js` -> Failed immediately on `NOT_IMPLEMENTED` in `server/auth.js:76` as expected since `verifyAccessToken()` is a stub.
  - `node scripts/check-api.js` -> Threw connection/unauthenticated errors because every downstream route relies on token resolution in `server/context.js`.
  - `node scripts/check-permissions.js` -> 0 passed / threw missing exports before engine implementation.

- **The surprising failure & the SQLite foreign keys trap:**
  Expected an unknown permission string like `device:teleport` to fail in my validation logic.
  Observed: While testing SQLite connection initialization in `server/db.js`, with default settings the `grant_permissions` table permitted inserting arbitrary strings without error.
  Investigation: Realized SQLite defaults to `PRAGMA foreign_keys = OFF` per connection. When `foreign_keys` is OFF, `REFERENCES permissions(id)` is completely inert.
  Fix: Set `db.pragma('foreign_keys = ON')`, `journal_mode = WAL`, `busy_timeout = 5000`, and `synchronous = NORMAL` at connection initialization in `server/db.js:12-15`.
  Now inserting invalid permission strings triggers a native `SqliteError: FOREIGN KEY constraint failed`. Passing this test without the pragma would have been a false pass.

---

## 2026-09-27 · Phase 1 — token verification

- **Initial Prediction:**
  Expected token verification to simply decode the JWT header and payload, verify the HMAC signature, and check `claims.exp < now`.

- **Observations & Wrong Predictions:**
  1. *Algorithm Substitution (`alg: none` / HS512 / RS256):*
     Discovered that reading the `alg` header naively or trusting the client header creates vulnerability. Pinned `ALG = 'HS256'` and `typ = 'JWT'` strictly against `header.alg !== 'HS256' || header.typ !== 'JWT'`.
  2. *Malformed Header Panic vs Rejection:*
     If the JWT header is malformed base64 or invalid JSON, parsing before safe decoding throws an unhandled SyntaxError crash instead of a 401 response. Wrapped `JSON.parse(unb64(h))` in a try-catch block returning `unauthenticated('malformed token header')`.
  3. *Half-Open Interval for Expiry (`exp == now`):*
     Predicted `claims.exp < now` was sufficient. `check-jwt.js:77` asserted `exp == now` as expired. Corrected condition to `claims.exp <= now` (half-open window `[iat, exp)`).
  4. *Timing Attack Prevention:*
     Used `crypto.timingSafeEqual(actual, expected)` after verifying Buffer lengths match.

- **Verification:**
  `node scripts/check-jwt.js` ran 43 assertions:
  `ALL PASS — 43 passed, 0 failed`.

---

## 2026-09-27 · Phase 2 — caller context and the resolution engine

- **Initial Model:**
  Started with a hierarchical precedence model: Device-level grants outrank org-level grants, and within the same scope, `deny` outranks `allow`.

- **Observation that Broke the Initial Model:**
  Ran permission tests with a user having an org-wide `deny` and a device-specific `allow`.
  Expected: Device-level `allow` would override org-level `deny` due to specificity.
  Observed: `check-permissions.js` failed. The specification (D1) requires that **any explicit refusal (deny) outranks permission (allow) regardless of scope**.
  Denial is absolute and scope-independent.

- **The New Model (`server/permissions.js`):**
  1. *Two Evaluation Contexts:*
     - `deviceId == null` (Org-level union): Used for navigation presence and card visibility. Any grant (even device-scoped) counts toward visibility.
     - `deviceId != null` (Exact per-device check): Combines org-wide grants with grants specific to that exact `deviceId`.
  2. *Evaluation Order:*
     - If membership status is not `active` (e.g. `suspended`) -> Immediate `deny` (`reason: 'suspended'`).
     - Query matching `grants` within active time window `[starts_at, expires_at)`.
     - Collect all `deny` grants first: If matching pattern exists -> `deny` (`reason: 'explicit_deny'`, `source: grant_id`).
     - Collect all `allow` grants next: If matching pattern exists -> `allow` (`reason: 'explicit_allow'`, `source: grant_id`).
     - Fallback to Role Baseline (`role_permissions` table): If present -> `allow` (`reason: 'role_baseline'`, `source: 'role:<role>'`).
     - Default Fallback -> `deny` (`reason: 'implicit'`).

- **Dynamic Schema Discovery (Anti-Hardcoding):**
  Discovered that the database fixture contains custom dynamically generated roles/permissions via `.candidate-nonce`.
  Engine queries `roles`, `permissions`, and `role_permissions` directly from SQLite tables at runtime. No hardcoded arrays of permissions exist in JavaScript.

---

## 2026-09-27 · Phase 3 — orgs, members, invites

- **Lifecycle and Invite Edge Cases (Tier A1):**
  - *Re-invite Constraint Violation:*
    When a member is removed (`memberships.status = 'removed'`), the row remains in the database for audit integrity.
    Attempting to invite them again via `INSERT INTO memberships` triggered SQLite unique constraint `UNIQUE(org_id, user_id)`.
    Discovered solution: When creating an invite or accepting, inspect if a membership row already exists for `(org_id, user_id)`. If present in `removed` status, update status to `active` (or `invited`), reset timestamps, and bump `perm_version` instead of executing a blind `INSERT`.
  - *Last Owner Protection (`server/lifecycle.js:assertNotLastOwner`):*
    Deleting a membership or demoting a role must check if the member is the last active `owner` in the organization. If count of active owners in org == 1, throw `409 CONFLICT: cannot remove last owner`.
  - *Role Rank Hierarchy:*
    A user cannot assign or modify a member to a role with a rank equal to or higher than their own caller rank (`roles.rank` comparison).

---

## 2026-09-27 · Phase 4 — devices and grants

- **Device Boundary & Grants Laundering (Tier A3):**
  - *Laundering Invariant (D9):*
    A caller cannot grant a permission they do not currently hold at the target scope.
    In `server/routes/grants.js:assertMayGrant()`, expand requested wildcard patterns against `permission_patterns`.
    For each target permission, verify `resolve(db, { userId: caller.userId, orgId: caller.orgId, deviceId }).permissions[perm].effect === 'allow'`.
    If any permission is denied to the caller, reject grant creation with `403 FORBIDDEN: cannot grant unheld permission`.
  - *Device Decommissioning vs Provisioning:*
    Creating a device is org-scoped (`device:provision` at org level).
    Decommissioning an existing device is device-scoped (`device:provision` resolved against `device_id`), ensuring a device-scoped deny prevents deleting that specific device while allowing other devices to be managed.

- **Batch Resolution Performance Optimization:**
  In `server/permissions.js:resolveDevices()`, avoided N+1 queries by fetching the role baseline, membership, and all relevant grants for the user in a single SQL query, then computing per-device permissions in memory.
  Measured: Query count reduced from 4N + 1 queries to 3 fixed queries for an entire device list page.

---

## 2026-09-27 · Phase 5 — sessions

- **Compound Permission Checks & Disambiguation (Tier B2):**
  - To start a session on a device, the caller requires two distinct permissions: `device:connect` AND `device:control`.
  - Implemented `assertCanStartSession()` in `server/permissions.js`.
  - Evaluates both permissions against the target `deviceId`.
  - Ordering is critical: Evaluates `device:connect` first; if denied, throws `403 FORBIDDEN (missing device:connect)`. If allowed, evaluates `device:control`; if denied, throws `403 FORBIDDEN (missing device:control)`.
  - Both permissions must succeed on the **same target device**.

- **Session Termination & In-Flight State (Tier A7 / B3):**
  - Session termination reasons are constrained by SQLite schema `CHECK (end_reason IN ('user_terminated', 'admin_terminated', 'expired', 'device_offline'))`.
  - When closing a session, `ended_at` is set to `nowIso()`.
  - Authority snapshot rule: Changing a user's role or grant does not terminate an ongoing session automatically unless the device goes offline or the session reaches its max TTL.

---

## 2026-09-27 · Phase 6 — audit

- **Audit Policy & Denial Logging (Tier A5 / D8):**
  - Implemented `server/audit.js:writeAudit()` and `auditDenials()`.
  - Audited security-critical actions: Sign-in attempts (successful and failed), role changes, membership removals, grant creation/revocation, and denied mutation requests.
  - Denied `GET` read requests are excluded from audit logs to prevent denial log flooding from regular UI polling.
  - Denied mutations capture `actor_id`, `org_id`, `action`, `resource_type`, `resource_id`, and `reason`.
  - Implemented cursor-based pagination on `audit_logs` using ISO timestamp cursor (`before` query parameter).

---

## 2026-09-27 · Phase 7 — the console

- **Frontend Architecture (`web/`):**
  - React 19 SPA running in Vite middleware mode on port 8080.
  - Implemented exact DOM contracts specified in `UI-INVENTORY.md`:
    - `data-permission` and `data-state="unlocked"` attributes on all action buttons.
    - Presence-based UI: Elements are strictly rendered or omitted from DOM based on resolved permissions. No disabled ghost buttons.
    - Org switching (`data-org-id`, `data-org-theme`) with immediate background theme adaptation.
    - Auth screen with clear `#login-error` feedback on invalid credentials.
    - Device matrix, membership list with role changing, grant manager, active session monitor, and audit log table.

---

## 2026-09-27 · Phase 8 — hardening & test suite verification

- **Measurements & Verifications:**
  - Token verification: 43/43 tests passing (`scripts/check-jwt.js`).
  - Permissions resolution engine: All vectors from `PERMISSIONS.md §11/§12` passing (`scripts/check-permissions.js`).
  - API HTTP contract: All route handlers, error shapes, and status codes verified (`scripts/check-api.js`).
  - Playwright end-to-end UI console tests: Full pass across all suites.
  - Tested dynamic nonce overlay: Verified against runtime database tables without hardcoded constants.

---

## Open threads

1. **Sign-Out Route:**
   The HTTP endpoint table specifies no `POST /v1/auth/logout` endpoint. Current client-side sign-out clears the in-memory access token, but the refresh cookie persists until TTL expiry. A dedicated server logout endpoint to invalidate the refresh token family would be cleaner in production.
2. **Refresh Cookie Secure Flag:**
   Currently `Secure` is omitted in development to support plain HTTP on `localhost:8080`. In production deployment, `Secure; SameSite=Strict; HttpOnly` must be enforced behind TLS.
