import React, { useEffect, useState } from 'react';
import { api } from '../api.js';

// Invite redemption. The token in the URL is the credential, so this view is reachable
// without a session and must not assume one.
//
// Note what the peek returns: the org name and the offered role, and nothing else. The
// token holder is not a member yet, so there is no device list, no member count, no org
// id to leak.
export default function AcceptInvite({ token, onAccepted }) {
  const [invite, setInvite] = useState(null);
  const [error, setError] = useState(null);
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        setInvite(await api.get(`/invites/${token}`));
      } catch (err) {
        setError(
          err.code === 'GONE' ? 'This invite has expired or was revoked.'
          : err.code === 'CONFLICT' ? 'This invite has already been used.'
          : 'This invite link is not valid.'
        );
      }
    })();
  }, [token]);

  async function accept(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post(`/invites/${token}/accept`, { name, password });
      await onAccepted();
    } catch (err) {
      setError(`${err.code ?? err.status}: ${err.message}`);
    } finally {
      setBusy(false);
    }
  }

  if (error && !invite) {
    return (
      <div className="center">
        <div className="card">
          <h3>Invite</h3>
          <div className="error" data-testid="invite-error">{error}</div>
        </div>
      </div>
    );
  }

  if (!invite) return <div className="center">Checking invite…</div>;

  return (
    <div className="center">
      <form className="card" onSubmit={accept} data-testid="invite-form">
        <h3>Join {invite.orgName}</h3>
        <div className="hint" style={{ marginTop: 0 }}>
          You have been invited as <strong data-testid="invite-role">{invite.role}</strong>.
          <br />
          Invite expires {new Date(invite.expiresAt).toLocaleString()}.
        </div>

        <label htmlFor="inv-email">Email</label>
        <input id="inv-email" value={invite.email} readOnly data-testid="invite-email" />

        <label htmlFor="inv-name">Your name</label>
        <input id="inv-name" data-testid="invite-name" value={name}
               onChange={(e) => setName(e.target.value)} required />

        <label htmlFor="inv-pw">Choose a password (8+ characters)</label>
        <input id="inv-pw" type="password" data-testid="invite-password" value={password}
               onChange={(e) => setPassword(e.target.value)} required minLength={8} />

        <button className="primary" type="submit" disabled={busy} data-testid="invite-submit">
          {busy ? 'Joining…' : 'Accept invite'}
        </button>

        {error && <div className="error" data-testid="invite-error">{error}</div>}
      </form>
    </div>
  );
}
