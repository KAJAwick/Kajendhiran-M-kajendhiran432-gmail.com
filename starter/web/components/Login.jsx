import React from 'react';
import { api, describeError } from '../api.js';

// Sign-in is the first screen anyone sees, and the one most likely to be reached in a broken
// state: an unbuilt database, a server that died, a typo in the password, an account that
// isn't a member of anything. Every one of those has to say what happened, on the page, next
// to the form.
//
// `login-error` is the element the UI contract reads. It is present only when the last
// attempt failed, and it stays until the next attempt so the reason can actually be read.

const DEMO = [
  { email: 'dana@example.test', note: 'owner in Acme · viewer in Globex' },
  { email: 'sam@example.test', note: 'operator in Acme · auditor in Globex' },
  { email: 'admin@acme.test', note: 'admin in Acme' },
  { email: 'viewer@acme.test', note: 'viewer in Acme' },
];

export default function Login({ onSignedIn, initialError = null }) {
  const [email, setEmail] = React.useState('dana@example.test');
  const [password, setPassword] = React.useState('demo1234');
  const [error, setError] = React.useState(initialError);
  const [busy, setBusy] = React.useState(false);

  async function submit(e) {
    e.preventDefault();
    if (busy) return;

    // Catch the empty form here rather than making a request that can only fail. The
    // message is the same shape as a server failure so there is one way to read it.
    if (!email.trim() || !password) {
      setError({ code: 'VALIDATION', message: 'Enter both an email address and a password.' });
      return;
    }

    setBusy(true);
    setError(null);
    try {
      await api.login(email, password);
      await onSignedIn();
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="center">
      <form className="card" onSubmit={submit} data-testid="login-form" noValidate>
        <h3>Sign in to RemoteOps</h3>

        <label htmlFor="email">Email</label>
        <input id="email" data-testid="login-email" value={email}
               onChange={(e) => setEmail(e.target.value)} autoComplete="username" />

        <label htmlFor="password">Password</label>
        <input id="password" data-testid="login-password" type="password" value={password}
               onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />

        <button className="primary" type="submit" disabled={busy} data-testid="login-submit">
          {busy ? 'Signing in…' : 'Sign in'}
        </button>

        {/* Announced as well as painted: a silent failure is the bug this exists to prevent. */}
        {error && (
          <div className="alert" role="alert" aria-live="assertive"
               data-testid="login-error" data-error-code={error.code ?? 'UNKNOWN'}>
            <strong>Couldn’t sign you in.</strong> {error.message}
          </div>
        )}

        <div className="hint">
          Password for every seeded user is <code>demo1234</code>.
          <div style={{ marginTop: 8 }}>
            {DEMO.map((d) => (
              <div key={d.email}>
                <button type="button" className="act" onClick={() => setEmail(d.email)}>{d.email}</button>{' '}
                <span style={{ fontSize: 12 }}>{d.note}</span>
              </div>
            ))}
          </div>
        </div>
      </form>
    </div>
  );
}
