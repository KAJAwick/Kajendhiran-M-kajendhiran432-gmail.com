import React, { useCallback, useEffect, useState } from 'react';
import { api, isAllowed, describeError } from './api.js';
import Action from './components/Action.jsx';
import Login from './components/Login.jsx';
import Devices from './components/Devices.jsx';
import People from './components/People.jsx';
import Grants from './components/Grants.jsx';
import Sessions from './components/Sessions.jsx';
import Audit from './components/Audit.jsx';
import AcceptInvite from './components/AcceptInvite.jsx';
import Admin from './components/Admin.jsx';

// Nav gating is driven by the resolved permission set the API returns. Nothing here knows
// that 'operator' implies 'device:control' — that knowledge lives only in the server's
// role_permissions table.
//
// Nav items are PRESENT or ABSENT: an item the caller cannot use is not rendered as a
// disabled button, it is not rendered at all.
const NAV = [
  { key: 'devices', label: 'Devices', permission: 'device:list' },
  { key: 'people', label: 'People', permission: 'user:read' },
  { key: 'grants', label: 'Grants', permission: 'user:read' },
  { key: 'sessions', label: 'Sessions', permission: 'session:view' },
  { key: 'audit', label: 'Audit log', permission: 'audit:read' },
  // The Admin card is what separates an owner from an admin: the admin has the panel but
  // no delete entry. Operator and below do not see the card at all.
  { key: 'admin', label: 'Admin', anyOf: ['org:update', 'org:delete'] },
];

// Does the caller hold whatever this nav item requires?
function holds(permissions, item) {
  if (item.anyOf) return item.anyOf.some((p) => isAllowed(permissions, p));
  return isAllowed(permissions, item.permission);
}

// Invite links are reachable without a session, so they short-circuit the app entirely.
const INVITE_PATH = /^\/invite\/([^/]+)$/;

export default function App() {
  const inviteToken = INVITE_PATH.exec(window.location.pathname)?.[1] ?? null;

  const [session, setSession] = useState(null);
  const [booting, setBooting] = useState(true);
  const [bootError, setBootError] = useState(null);
  const [view, setView] = useState('devices');

  const reload = useCallback(async () => {
    try {
      setSession(await api.me());
      return true;
    } catch (err) {
      if (err.status === 401) {
        // Token went stale (a role or grant changed elsewhere) or expired. Try the
        // refresh cookie once, then give up and show the login screen.
        const restored = await api.refresh();
        if (restored) {
          setSession(await api.me());
          return true;
        }
        api.logout();
        setSession(null);
      }
      return false;
    }
  }, []);

  // Restore a session from the httpOnly refresh cookie. There is no token in storage to read.
  // If the server is up but not usable — an unbuilt database, for instance — that has to be
  // visible before anyone types a password, so the reason is kept and handed to the sign-in
  // screen rather than swallowed.
  useEffect(() => {
    if (inviteToken) { setBooting(false); return; }
    (async () => {
      try {
        if (await api.refresh()) await reload();
      } catch (err) {
        setBootError(describeError(err));
      } finally {
        setBooting(false);
      }
    })();
  }, [reload, inviteToken]);

  async function switchOrg(orgId) {
    if (orgId === session?.org?.id) return;
    await api.switchOrg(orgId);
    await reload();
    setView('devices');
  }

  // Creating an org makes you its owner. It needs no permission — any authenticated user
  // may start one — but it does need a fresh token, because a token is scoped to one org.
  async function createOrg() {
    const name = prompt('New organization name?');
    if (!name) return;
    try {
      const created = await api.post('/orgs', { name });
      await api.switchOrg(created.id);
      await reload();
      setView('devices');
    } catch (err) {
      alert(`${err.code ?? err.status}: ${err.message}`);
    }
  }

  // Org settings live on the Admin card, not the topbar.

  if (inviteToken) {
    return (
      <AcceptInvite
        token={inviteToken}
        onAccepted={async () => {
          window.history.replaceState({}, '', '/');
          window.location.reload();
        }}
      />
    );
  }

  if (booting) return <div className="center">Loading…</div>;
  if (!session) return <Login onSignedIn={reload} initialError={bootError} />;

  const { org, user, role, orgs, permissions } = session;

  // Only the cards this permission level holds are candidates for the nav at all.
  const visible = NAV.filter((item) => holds(permissions, item));
  const activeView = visible.find((n) => n.key === view) ?? visible[0];

  return (
    // data-org-id + data-org-theme are the contract: org identity on the shell, and the
    // theme drives the actual rendered colours.
    <div className="app-shell" data-testid="app-shell" data-org-id={org.id} data-org-theme={org.theme}>
      <header className="topbar">
        <h1>RemoteOps</h1>

        <div className="org-switcher" data-testid="org-switcher">
          {orgs.map((o) => (
            <button
              key={o.id}
              className="org-option"
              data-testid="org-option"
              data-org-id={o.id}
              data-org-theme={o.theme}
              aria-pressed={o.id === org.id}
              onClick={() => switchOrg(o.id)}
              title={`${o.name} — you are ${o.role} here`}
            >
              {o.name} · {o.role}
            </button>
          ))}
          <button className="org-option" data-testid="create-org" onClick={createOrg}
                  title="Create a new organization; you become its owner">
            + New org
          </button>
        </div>

        <span className="who">
          {user.name} · <strong data-testid="active-role">{role}</strong>
        </span>
        <button className="org-option" onClick={() => { api.logout(); setSession(null); }}>Sign out</button>
      </header>

      <div className="layout">
        <nav className="nav">
          {/* Present or absent — never disabled. */}
          {visible.map((item) => (
            <button
              key={item.key}
              data-testid={`nav-${item.key}`}
              data-permission={item.permission ?? item.anyOf?.join('|')}
              data-state="unlocked"
              aria-current={item.key === activeView.key}
              onClick={() => setView(item.key)}
            >
              {item.label}
            </button>
          ))}
        </nav>

        <main className="main">
          <h2>{activeView.label}</h2>
          <div className="sub">
            {org.name} — you are <strong>{role}</strong> in this organization
          </div>

          {activeView.key === 'devices' && <Devices session={session} reload={reload} />}
          {activeView.key === 'people' && <People session={session} reload={reload} />}
          {activeView.key === 'grants' && <Grants session={session} reload={reload} />}
          {activeView.key === 'sessions' && <Sessions session={session} reload={reload} />}
          {activeView.key === 'audit' && <Audit session={session} reload={reload} />}
          {activeView.key === 'admin' && <Admin session={session} reload={reload} />}
        </main>
      </div>
    </div>
  );
}
