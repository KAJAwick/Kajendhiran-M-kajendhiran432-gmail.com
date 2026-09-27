import React, { useCallback, useEffect, useState } from 'react';
import { api, fmtTime } from '../api.js';

// The audit log is append-only. There is no edit or delete affordance here because there
// is no route for one — and the database rejects UPDATE/DELETE with a trigger.
//
// Note that DENIED attempts appear alongside successful ones. Candidates routinely log
// only successes, which makes the log useless for the thing it exists to answer.
export default function Audit({ session }) {
  const { org } = session;
  const [events, setEvents] = useState(null);
  const [error, setError] = useState(null);
  const [only, setOnly] = useState('all');

  const load = useCallback(async () => {
    try {
      setEvents((await api.get(`/orgs/${org.id}/audit?limit=100`)).events);
      setError(null);
    } catch (err) {
      setError(err.message);
    }
  }, [org.id]);

  useEffect(() => { load(); }, [load]);

  if (!events) return <div>Loading audit log…</div>;

  const shown = only === 'all' ? events : events.filter((e) => e.result === only);

  return (
    <>
      {error && <div className="banner" data-testid="audit-error">{error}</div>}

      <div className="actions" style={{ marginBottom: 12 }}>
        {['all', 'allow', 'deny'].map((k) => (
          <button key={k} className="act" onClick={() => setOnly(k)}
                  data-testid={`audit-filter-${k}`} data-state={only === k ? 'unlocked' : 'locked'}>
            {k} ({k === 'all' ? events.length : events.filter((e) => e.result === k).length})
          </button>
        ))}
      </div>

      <table data-testid="audit-table">
        <thead>
          <tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Result</th><th>Reason</th></tr>
        </thead>
        <tbody>
          {shown.map((e) => (
            <tr key={e.id} data-testid="audit-row" data-result={e.result} data-action={e.action}>
              <td style={{ fontSize: 12.5, color: 'var(--muted)' }}>{fmtTime(e.at)}</td>
              <td>{e.actor_id ?? '—'}</td>
              <td><code style={{ fontSize: 12.5 }}>{e.action}</code></td>
              <td style={{ fontSize: 12.5, color: 'var(--muted)' }}>{e.target_id ?? '—'}</td>
              <td><span className={`pill ${e.result}`}>{e.result}</span></td>
              <td style={{ fontSize: 12.5, color: 'var(--muted)' }}>{e.reason_code ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="hint">
        Append-only, and it records denials as well as successes. Denied rows carry the machine
        readable cause — <code>missing_permission</code>, <code>explicit_deny</code>,
        <code>suspended</code> — so "why was this blocked?" is answerable after the fact.
      </div>
    </>
  );
}
