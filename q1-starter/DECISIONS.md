# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Every section has
the same four parts, and the third and fourth are the ones we weigh most.

---

### 1. One permission engine with two distinct evaluation contexts (`deviceId == null` vs `deviceId == id`)

**What I chose:**
A single `resolve(db, { userId, orgId, deviceId })` engine in `server/permissions.js` that evaluates two contexts: an org-level union when `deviceId == null` (for navigation gating and card visibility), and an exact per-device check when `deviceId` is provided.

**Why:**
`server/permissions.js:14-48`. In the console UI, a user who holds a device-scoped `device:control` grant on only one device should still see the "Devices" navigation link and page, but can only execute control on that specific device. Separating into two different engines would risk divergence and duplicate logic.

**What I rejected:**
Evaluating device permissions only at the point of action and hiding navigation items unless the user holds org-wide permissions. That fails vector `PERMISSIONS.md §11.4`, where a viewer with a single device grant was incorrectly locked out of the entire Devices view.

**What would change my mind:**
If organizational policies required strict device blind spots (i.e. zero awareness of the existence of other devices), an org-level union might leak metadata about device presence.

---

### 2. Refusal (`deny`) outranks permission (`allow`) unconditionally across all scopes

**What I chose:**
An explicit `deny` from any active grant (org-scoped or device-scoped) immediately terminates evaluation with `deny`, regardless of whether a narrower device-specific `allow` grant exists.

**Why:**
Tested in `scripts/check-permissions.js:72-85` against vector D1. When a user has an org-wide `deny` on `device:control` and a specific `allow` on device `dev_1`, evaluating specificity first produced `allow`, which violated the fundamental security guarantee that explicit refusal is absolute.

**What I rejected:**
Hierarchical CSS-style specificity rules where narrower device grants override broader org grants. This fails because a security administrator placing an explicit block on a user must not be bypassed by an unrevoked device-level grant.

**What would change my mind:**
If the authorization specification explicitly introduced an exception mechanism (e.g., explicit override tokens or break-glass grants), which is not present in this architecture.

---

### 3. Batched in-memory resolution for device tables without persistent caching

**What I chose:**
`resolveDevices(db, { userId, orgId, devices })` loads the role baseline, membership status, and all active grants for the caller in a single database roundtrip (3 fixed queries), computing individual device permission sets in memory.

**Why:**
Resolving permissions individually for each device row in a table of $N$ devices causes an $N+1$ query bottleneck (4 SQL queries per device $\rightarrow 4N + 1$ queries). Batching reduced the query count from 41 queries for 10 devices down to 3 queries. No TTL cache is used, ensuring revocation in `memberships.perm_version` takes effect immediately on the next request (`PERMISSIONS.md §7.4`).

**What I rejected:**
An in-memory LRU cache with TTL. A cache keyed by `userId` alone would leak permissions across org boundaries, and any positive TTL would serve stale permissions after an admin revokes a grant or suspends a user.

**What would change my mind:**
If device table size grew to tens of thousands of rows per organization, requiring server-side pagination with database-level permission filtering.

---

### 4. Re-inviting removed members updates existing row instead of inserting

**What I chose:**
In `server/routes/invites.js` and `server/lifecycle.js`, re-inviting a user who was previously removed updates the existing `memberships` row (`status = 'invited'`, updated timestamp, bumped `perm_version`) instead of executing `INSERT INTO memberships`.

**Why:**
The SQLite database schema defines a strict unique constraint `UNIQUE(org_id, user_id)` on `memberships`. Attempting an `INSERT` for a re-hired/re-invited user threw a `SqliteError: UNIQUE constraint failed: memberships.org_id, memberships.user_id`. Updating the existing tombstone preserves audit linkage while satisfying the schema constraint.

**What I rejected:**
Hard-deleting membership rows on removal (`DELETE FROM memberships`). This would violate foreign key integrity with historical audit logs and past grant records.

**What would change my mind:**
If the database schema changed the uniqueness constraint to a partial index `UNIQUE(org_id, user_id) WHERE status != 'removed'`.

---

### 5. Grant creation enforces anti-laundering via recursive pattern expansion

**What I chose:**
`assertMayGrant(db, caller, target)` in `server/routes/grants.js` expands all requested wildcard patterns (e.g. `device:*`, `*`) against `permission_patterns` and verifies that the caller currently holds `effect === 'allow'` for every expanded permission at the target scope.

**Why:**
Invariant 11 and D9 mandate that an actor cannot delegate authority they do not possess. Without pattern expansion, an admin holding all permissions except `org:delete` could grant `*` or `org:*` to another user, effectively laundering `org:delete`.

**What I rejected:**
String prefix matching against raw grant input without database pattern resolution. This failed when custom permissions were added dynamically at runtime via `.candidate-nonce`.

**What would change my mind:**
If role delegation permitted "blind granting" where an administrator can assign pre-configured system roles above their own clearance level (contrary to principle of least privilege).

---

### 6. Structural multi-tenant isolation ("Invisible not Forbidden")

**What I chose:**
Access tokens strictly bind to a single `org_id`. In `server/context.js`, every resource lookup automatically scopes with `WHERE org_id = ?`. If a resource belongs to another organization, the API immediately throws `404 NOT_FOUND` rather than `403 FORBIDDEN`.

**Why:**
`PERMISSIONS.md §5` and `AUTH-DATA-MODEL.md §1`. Returning `403 FORBIDDEN` for an alien resource confirms that the ID exists in another tenant, leaking tenant data and topology. `404 NOT_FOUND` ensures complete resource invisibility.

**What I rejected:**
Global resource lookups followed by an ownership check `if (resource.org_id !== caller.org_id) throw forbidden()`.

**What would change my mind:**
If cross-organization collaboration or shared global resources were introduced into the product domain.

---

### 7. Security audit logging on mutations and authentication failures only

**What I chose:**
`server/audit.js:writeAudit()` logs successful mutations, denied state-changing mutations, and authentication failures (failed logins). Read-only `GET` requests (even if denied) are not written to the audit table.

**Why:**
Auditing every denied `GET` request flooded the `audit_logs` table with hundreds of noise entries during normal UI polling and tab navigation, obscuring critical security events like unauthorized role elevation attempts or brute-force logins.

**What I rejected:**
Logging every single HTTP transaction and read check.

**What would change my mind:**
If compliance standards (e.g. FedRAMP High / HIPAA) specifically mandated complete read-access auditing for data export events.

---

### 8. Strict evaluation ordering for compound session permissions

**What I chose:**
In `server/permissions.js:assertCanStartSession()`, verify `device:connect` first, and then verify `device:control`. Both must evaluate to `allow` on the **same target device**.

**Why:**
`PERMISSIONS.md §12.1`. The failure reasons must be clearly distinguishable: if a user lacks connection rights, they receive `403 (missing device:connect)`. If they can connect but lack control, they receive `403 (missing device:control)`.

**What I rejected:**
Evaluating a single combined boolean flag `canConnect && canControl`. This stripped the actionable failure provenance needed by the UI to explain why the session was refused.

**What would change my mind:**
If connecting and controlling were merged into a single atomic permission in the database reference schema.

---

## Where this repo argues with itself

### 1. Suspension token version bump vs 403 response
- **Statement A:** `AUTH-DATA-MODEL.md §1` specifies that suspending a member increments `memberships.perm_version`, which immediately invalidates active access tokens via the freshness check (`401 TOKEN_STALE`).
- **Statement B:** `AUTH-DATA-MODEL.md §10` states that a request with a suspended membership's token should return `403 FORBIDDEN` with `reason: "suspended"`.
- **My Resolution:** In `server/context.js`, if a membership is marked `status === 'suspended'`, we bypass the `assertFresh` token version mismatch check so the request reaches the permission engine and returns the explicit `403 FORBIDDEN (reason: suspended)` expected by the contract. When reinstated, `perm_version` increments again, properly enforcing token renewal.

### 2. `device:provision` scope ambiguity on decommission
- **Statement A:** The endpoint table lists `DELETE /v1/devices/{id}` requiring `device:provision` with no explicit scope specified.
- **Statement B:** `UI-INVENTORY.md §3` lists `decommission-device` as a device-scoped row action.
- **My Resolution:** Creation of devices (`POST /v1/devices`) evaluates `device:provision` at the org-level (`deviceId = null`), while decommissioning (`DELETE /v1/devices/{id}`) evaluates `device:provision` scoped to that specific device.

### 3. `session:*` permissions vs Device Scoping
- **Statement A:** D6 scopes `device:*` permissions to a device.
- **Statement B:** `GET /v1/sessions/{id}` and `DELETE /v1/sessions/{id}` manage session records.
- **My Resolution:** `session:view` and `session:terminate` are evaluated **org-wide**, not scoped to the device. Scoping them to a device would allow a device-scoped grant to improperly widen session management authority across the organization.

---

## Deliberately not built

1. **In-memory Permission Cache:** Bypassed in favor of batched queries to prevent cross-tenant leakage and ensure immediate zero-delay permission revocation.
2. **Real Remote Protocol Access / Shell Injection:** Remote terminal access and screen streaming are mocked as stateful database session records (`started_at`, `ended_at`, `max_session_minutes`), keeping the challenge focused on authorization, concurrency, and lifecycle guarantees.
3. **Password Reset / Email Delivery:** Out of scope per design guidelines. Authentication uses local scrypt password hashes and database invite tokens.
