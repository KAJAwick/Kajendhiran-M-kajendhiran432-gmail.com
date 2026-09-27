import React from 'react';
import { api } from '../api.js';
import Action from './Action.jsx';

// The Admin card. Visible for org:update OR org:delete — which is what separates an owner
// from an admin: the admin has this panel, but no delete entry.
export default function Admin({ session, reload }) {
  const { org } = session;

  async function rename() {
    const name = prompt(`Rename "${org.name}" to:`);
    if (!name) return;
    try {
      await api.patch(`/orgs/${org.id}`, { name });
      await reload();
    } catch (err) {
      alert(`${err.code ?? err.status}: ${err.message}`);
    }
  }

  async function remove() {
    if (!confirm(`Delete "${org.name}"? This cannot be undone.`)) return;
    try {
      await api.del(`/orgs/${org.id}`);
      api.logout();
      window.location.reload();   // the org is gone; sign out cleanly
    } catch (err) {
      alert(`${err.code ?? err.status}: ${err.message}`);
    }
  }

  return (
    <div className="card" data-testid="admin-card" style={{ maxWidth: 460 }}>
      <h3>Organization settings</h3>
      <div className="hint" style={{ marginTop: 0 }}>
        These operations apply to <strong>{org.name}</strong> and are visible only to the
        permission levels that hold them.
      </div>

      <div className="actions" style={{ marginTop: 14 }}>
        <Action permission="org:update" entry={session.permissions['org:update']}
                onClick={rename} testid="rename-org">Rename org</Action>
        <Action permission="org:delete" entry={session.permissions['org:delete']}
                onClick={remove} testid="delete-org">Delete org</Action>
      </div>

      <div className="hint">
        <strong>owner</strong> sees both entries. <strong>admin</strong> sees Rename but not
        Delete. Every level below admin does not see this card at all — the nav item is absent.
      </div>
    </div>
  );
}
