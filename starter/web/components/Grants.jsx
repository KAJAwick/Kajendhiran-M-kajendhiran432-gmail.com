import React, { useCallback, useEffect, useState } from 'react';
import { api, fmtTime, whyLocked } from '../api.js';
import Action from './Action.jsx';

// Grants are the thing that makes permissions visible, so this view matters more than it
// looks. Two rules it is built to demonstrate:
//
//   - a grant is a delta in EITHER direction: `allow` widens past the role baseline,
//     `deny` narrows it, and DENY WINS regardless of scope (D1)
//   - the permission catalogue is read from the SERVER's resolved map, not hardcoded here.
//     If it were hardcoded, adding a permission would need two edits and they would drift.
export default function Grants({ session, reload }) {
  const { org } = session;
  const [grants, setGrants] = useState(null);
  const [members, setMembers] = useState([]);
  const [devices, setDevices] = useState([]);
  const [error, setError] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ userId: '', deviceId: '', effect: 'allow', permissions: [] });

  // The 19 permission keys come from the server's own resolved map.
  const catalogue = Object.keys(session.permissions).sort();

  const load = useCallback(async () => {
    try {
      const [g, m, d] = await Promise.all([
        api.get(`/orgs/${org.id}/grants`),
        api.get(`/orgs/${org.id}/members`).catch(() => ({ members: [] })),
        api.get(`/orgs/${org.id}/devices`).catch(() => ({ devices: [] })),
      ]);
      setGrants(g.grants);
      setMembers(m.members);
      setDevices(d.devices);
      setError(null);
    } catch (err) {
      setError(err.message);
    }
  }, [org.id]);

  useEffect(() => { load(); }, [load]);

  function togglePermission(key) {
    setForm((f) => ({
      ...f,
      permissions: f.permissions.includes(key)
        ? f.permissions.filter((p) => p !== key)
        : [...f.permissions, key],
    }));
  }

  async function createGrant(e) {
    e.preventDefault();
    setError(null);
    try {
      await api.post(`/orgs/${org.id}/grants`, {
        userId: form.userId,
        deviceId: form.deviceId || null,
        effect: form.effect,
        permissions: form.permissions,
      });
      setForm({ userId: '', deviceId: '', effect: 'allow', permissions: [] });
      setShowForm(false);
      await load();
      await reload();   // the org-level permission view may have changed
    } catch (err) {
      setError(`${err.code ?? err.status}${err.reason ? ` / ${err.reason}` : ''}: ${err.message}`);
    }
  }

  async function revoke(id) {
    setError(null);
    try {
      await api.del(`/orgs/${org.id}/grants/${id}`);
      await load();
      await reload();
    } catch (err) {
      setError(`${err.code ?? err.status}: ${err.message}`);
    }
  }

  if (!grants) return <div>Loading grants…</div>;

  const nameOf = (id) => members.find((m) => m.id === id)?.name ?? id;
  const deviceOf = (id) => (id ? devices.find((d) => d.id === id)?.name ?? id : 'whole organization');

  return (
    <>
      {error && <div className="banner" data-testid="grants-error">{error}</div>}

      <div className="actions" style={{ marginBottom: 12 }}>
        <Action permission="grant:create" entry={session.permissions['grant:create']}
                onClick={() => setShowForm((s) => !s)} testid="new-grant">
          New grant
        </Action>
      </div>

      {showForm && (
        <form className="card" style={{ maxWidth: 620, marginBottom: 16 }} onSubmit={createGrant}
              data-testid="grant-form">
          <h3>New grant</h3>

          <label>Person</label>
          <select data-testid="grant-user" required value={form.userId}
                  onChange={(e) => setForm({ ...form, userId: e.target.value })}>
            <option value="">choose…</option>
            {members.filter((m) => m.status === 'active').map((m) => (
              <option key={m.id} value={m.id}>{m.name} ({m.role})</option>
            ))}
          </select>

          <label>Device — leave blank for an org-wide grant</label>
          <select data-testid="grant-device" value={form.deviceId}
                  onChange={(e) => setForm({ ...form, deviceId: e.target.value })}>
            <option value="">whole organization</option>
            {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
          </select>

          <label>Effect</label>
          <select data-testid="grant-effect" value={form.effect}
                  onChange={(e) => setForm({ ...form, effect: e.target.value })}>
            <option value="allow">allow — widens past the role</option>
            <option value="deny">deny — narrows the role, and always wins</option>
          </select>

          <label>Permissions</label>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(190px,1fr))', gap: 4 }}>
            {catalogue.map((key) => (
              <label key={key} style={{ display: 'flex', gap: 6, alignItems: 'center', margin: 0, fontSize: 12.5 }}>
                <input type="checkbox" style={{ width: 'auto' }}
                       data-testid="grant-permission" data-permission-key={key}
                       checked={form.permissions.includes(key)}
                       onChange={() => togglePermission(key)} />
                <code>{key}</code>
              </label>
            ))}
          </div>

          <button className="primary" type="submit" data-testid="grant-submit">Create grant</button>
        </form>
      )}

      <table data-testid="grants-table">
        <thead>
          <tr><th>Person</th><th>Scope</th><th>Effect</th><th>Permissions</th><th>Created</th><th /></tr>
        </thead>
        <tbody>
          {grants.map((g) => (
            <tr key={g.id} data-testid="grant-row" data-grant-id={g.id} data-effect={g.effect}>
              <td>{nameOf(g.user_id)}</td>
              <td style={{ fontSize: 12.5, color: 'var(--muted)' }}>{deviceOf(g.device_id)}</td>
              <td><span className={`pill ${g.effect === 'allow' ? 'allow' : 'deny'}`}>{g.effect}</span></td>
              <td>
                {g.permissions.map((p) => (
                  <code key={p} style={{ fontSize: 11.5, marginRight: 5 }}>{p}</code>
                ))}
              </td>
              <td style={{ fontSize: 12, color: 'var(--muted)' }}>{fmtTime(g.created_at)}</td>
              <td>
                <Action permission="grant:revoke" entry={session.permissions['grant:revoke']}
                        onClick={() => revoke(g.id)} testid="revoke-grant">Revoke</Action>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {grants.length === 0 && <div className="banner">No grants in this organization.</div>}

      <div className="hint">
        <strong>Deny always wins, regardless of scope.</strong> An org-wide <code>deny device:terminal</code>{' '}
        cannot be carved out by a device-scoped <code>allow</code> on the same device. Try it: create an
        org-wide deny, then a device-scoped allow, and watch the device's Terminal button stay locked.
        <br /><br />
        Revoking a grant takes effect on your <em>next</em> request — it does not terminate a session
        already in flight. Current status of this view:{' '}
        <code>{whyLocked(session.permissions['grant:create'])}</code> for grant creation.
      </div>
    </>
  );
}
