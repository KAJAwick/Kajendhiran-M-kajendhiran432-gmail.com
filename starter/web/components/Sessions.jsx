import React, { useCallback, useEffect, useState } from 'react';
import { api, fmtTime } from '../api.js';
import Action from './Action.jsx';

export default function Sessions({ session, reload }) {
  const { org } = session;
  const [sessions, setSessions] = useState(null);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    try {
      setSessions((await api.get(`/orgs/${org.id}/sessions`)).sessions);
      setError(null);
    } catch (err) {
      setError(err.message);
    }
  }, [org.id]);

  useEffect(() => { load(); }, [load]);

  async function stop(id) {
    setError(null);
    try {
      await api.del(`/sessions/${id}`);
      await load();
    } catch (err) {
      setError(`${err.code ?? err.status}: ${err.message}`);
    }
  }

  if (!sessions) return <div>Loading sessions…</div>;

  return (
    <>
      {error && <div className="banner" data-testid="sessions-error">{error}</div>}

      <div className="actions" style={{ marginBottom: 12 }}>
        {/* Always rendered, even with no sessions in the list — otherwise session:start has
            visible surface when nothing is running, and an empty org would leave it
            visible surface. */}
        <Action permission="session:start" entry={session.permissions['session:start']}
                onClick={() => alert('Pick a device on the Devices view')} busy={false} testid="new-session">
          Start a session
        </Action>
        <span className="hint" style={{ marginTop: 0 }}>— pick a device on the Devices view</span>
      </div>

      <table data-testid="sessions-table">
        <thead>
          <tr><th>Device</th><th>Who</th><th>Mode</th><th>State</th><th>Started</th><th>Ended because</th><th /></tr>
        </thead>
        <tbody>
          {sessions.map((s) => (
            <tr key={s.id} data-testid="session-row" data-session-id={s.id}
                data-state={s.state} data-mode={s.mode}>
              <td>{s.device_name}</td>
              <td>{s.user_name}</td>
              <td><span className="pill">{s.mode}</span></td>
              <td>
                <span className={`pill ${s.state === 'active' ? 'online' : ''}`}>{s.state}</span>
              </td>
              <td style={{ fontSize: 12.5, color: 'var(--muted)' }}>{fmtTime(s.started_at)}</td>
              <td style={{ fontSize: 12.5, color: 'var(--muted)' }}>{s.end_reason ?? '—'}</td>
              <td>
                <Action
                  permission={s.user_id === session.user.id ? 'session:start' : 'session:terminate'}
                  entry={s.user_id === session.user.id
                    ? { effect: 'allow', source: 'self' }
                    : session.permissions['session:terminate']}
                  onClick={() => stop(s.id)}
                  testid="stop-session"
                >
                  Stop
                </Action>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {sessions.length === 0 && <div className="banner">No sessions yet.</div>}

      <div className="hint">
        A session's authority is snapshotted when it starts and <strong>does not change</strong>.
        Revoking a grant or changing a role blocks the <em>next</em> session but never terminates
        one already in flight. Every session is bounded by a TTL, which is what makes that safe.
        <br /><br />
        So a row can legitimately read <code>active</code> here while the device's Control button
        is <code>locked</code>. They answer different questions.
      </div>
    </>
  );
}
