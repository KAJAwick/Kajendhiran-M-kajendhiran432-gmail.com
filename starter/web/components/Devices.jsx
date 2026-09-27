import React, { useCallback, useEffect, useState } from 'react';
import { api, whyLocked } from '../api.js';
import Action from './Action.jsx';

// The device list is where device-scoped authorization becomes visible.
//
// Note that each row's permission set comes from the API response — the server already
// resolved it PER DEVICE. The client does no filtering and no rule evaluation; it just
// reads `device.permissions`. That is why a viewer with a grant on one device shows an
// unlocked Control on that row and a locked one on every other row.
export default function Devices({ session, reload }) {
  const { org } = session;
  const [devices, setDevices] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(null);

  const load = useCallback(async () => {
    try {
      const out = await api.get(`/orgs/${org.id}/devices`);
      setDevices(out.devices);
      setError(null);
    } catch (err) {
      setError(err.message);
    }
  }, [org.id]);

  useEffect(() => { load(); }, [load]);

  async function startSession(device, mode) {
    setBusy(`${device.id}:${mode}`);
    setError(null);
    try {
      const out = await api.post(`/orgs/${org.id}/sessions`, { deviceId: device.id, mode });
      alert(`Session ${out.id} started (${mode}) on ${device.name}`);
      await load();
    } catch (err) {
      // Surface the server's own reason code — the two failure causes are deliberately
      // distinguishable (missing_permission vs missing_device_permission).
      setError(`${err.code}${err.reason ? ` / ${err.reason}` : ''}: ${err.message}`);
    } finally {
      setBusy(null);
    }
  }

  async function renameDevice(device) {
    const name = prompt(`Rename "${device.name}" to:`);
    if (!name) return;
    setError(null);
    try {
      await api.patch(`/orgs/${org.id}/devices/${device.id}`, { name, online: device.online });
      await load();
    } catch (err) {
      setError(`${err.code ?? err.status}: ${err.message}`);
    }
  }

  async function decommission(device) {
    if (!confirm(`Decommission "${device.name}"? Its live sessions will end.`)) return;
    setError(null);
    try {
      await api.del(`/orgs/${org.id}/devices/${device.id}`);
      await load();
    } catch (err) {
      setError(`${err.code ?? err.status}: ${err.message}`);
    }
  }

  async function createDevice() {
    const name = prompt('Device name?');
    if (!name) return;
    try {
      await api.post(`/orgs/${org.id}/devices`, { name, kind: 'linux' });
      await load();
    } catch (err) {
      setError(err.message);
    }
  }

  if (!devices) return <div>Loading devices…</div>;

  return (
    <>
      {error && <div className="banner" data-testid="devices-error">{error}</div>}

      <div className="actions" style={{ marginBottom: 12 }}>
        <Action permission="device:provision" entry={session.permissions['device:provision']}
                onClick={createDevice} testid="add-device">
          Add device
        </Action>
      </div>

      <table data-testid="device-table">
        <thead>
          <tr>
            <th>Device</th><th>Kind</th><th>Status</th><th>Sessions</th><th>Maintenance</th>
          </tr>
        </thead>
        <tbody>
          {devices.map((device) => (
            <tr key={device.id} data-testid="device-row" data-device-id={device.id}>
              <td>
                <strong>{device.name}</strong>
                <div style={{ fontSize: 11.5, color: 'var(--muted)' }}>{device.id}</div>
              </td>
              <td>{device.kind}</td>
              <td>
                <span className={`pill ${device.online ? 'online' : 'offline'}`}>
                  {device.online ? 'online' : 'offline'}
                </span>
              </td>
              <td>
                <div className="actions">
                  {['view', 'control', 'terminal'].map((mode) => {
                    const permission = `device:${mode}`;
                    const entry = device.permissions[permission];
                    return (
                      <Action
                        key={mode}
                        permission={permission}
                        entry={entry}
                        busy={busy === `${device.id}:${mode}`}
                        onClick={() => startSession(device, mode)}
                        testid={`start-${mode}`}
                      >
                        {mode === 'view' ? 'View' : mode === 'control' ? 'Control' : 'Terminal'}
                      </Action>
                    );
                  })}
                </div>
              </td>
              <td>
                <div className="actions">
                  <Action permission="device:update" entry={device.permissions['device:update']}
                          onClick={() => renameDevice(device)} testid="rename-device">Rename</Action>
                  <Action permission="device:file_transfer" entry={device.permissions['device:file_transfer']}
                          onClick={() => startSession(device, 'view')} testid="transfer-files">
                    Transfer files
                  </Action>
                  <Action permission="device:provision" entry={device.permissions['device:provision']}
                          onClick={() => decommission(device)} testid="decommission-device">
                    Decommission
                  </Action>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {devices.length === 0 && (
        <div className="banner" data-testid="devices-empty">
          No devices are visible to you in this organization.
        </div>
      )}

      <div className="hint">
        Each row's permission set was resolved by the server <em>for that device</em>. Hover a
        locked button to see the reason — for example{' '}
        <code>{whyLocked(devices[0]?.permissions['device:control'])}</code>.
      </div>
    </>
  );
}
