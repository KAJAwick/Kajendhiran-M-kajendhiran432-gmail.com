// The API client.
//
// The access token lives IN MEMORY ONLY — never localStorage, never sessionStorage. On
// reload the session is restored from the httpOnly refresh cookie, which JavaScript cannot
// read. That is why there is a `refresh()` call at boot rather than a token read from
// storage.
//
// It also turns transport and server failures into sentences a person can act on. The
// server keeps `message` short and free of internals on purpose, so the useful wording has
// to live here.

let token = null;

export const getToken = () => token;
export const setToken = (value) => { token = value; };

export class ApiError extends Error {
  constructor(status, payload) {
    const err = payload?.error ?? {};
    super(err.message ?? `HTTP ${status}`);
    this.status = status;
    this.code = err.code ?? null;
    this.reason = err.reason ?? null;
  }
}

async function request(method, path, body) {
  const res = await fetch(`/v1${path}`, {
    method,
    headers: {
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const text = await res.text();
  let payload = null;
  try { payload = text ? JSON.parse(text) : null; } catch { /* non-JSON body */ }

  if (!res.ok) throw new ApiError(res.status, payload);
  return payload;
}

export const api = {
  get: (p) => request('GET', p),
  post: (p, b) => request('POST', p, b),
  patch: (p, b) => request('PATCH', p, b),
  del: (p) => request('DELETE', p),

  // --- auth ----------------------------------------------------------------
  async login(email, password) {
    const out = await request('POST', '/auth/login', { email, password });
    setToken(out.token);
    return out;
  },

  // Restore a session from the refresh cookie. Returns null when there is no session —
  // the server said 401. Anything else means the server is up but not usable, so it is
  // rethrown: the caller has to say so on screen instead of quietly showing a login form.
  async refresh() {
    try {
      const out = await request('POST', '/auth/refresh');
      setToken(out.token);
      return out;
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return null;
      throw err;
    }
  },

  async switchOrg(orgId) {
    const out = await request('POST', '/auth/token', { orgId });
    setToken(out.token);
    return out;
  },

  logout() { token = null; },

  me: () => request('GET', '/auth/me'),
};

// --- helpers ---------------------------------------------------------------

// Every `data-state` in the UI comes from here. There is deliberately NO role ->
// permission table anywhere in this directory: the server resolves, the UI renders.
export const isAllowed = (permissions, key) => permissions?.[key]?.effect === 'allow';

// A failure the user should be told about, as { code, message }.
//
// The 401 case passes the server's own wording through, because "invalid email or password"
// is already the right thing to say and the server deliberately says the same thing for an
// unknown account as for a wrong password. Everything else gets a sentence that names the
// likely cause, since the server's message is intentionally uninformative.
export function describeError(err) {
  if (err instanceof ApiError) {
    const code = err.code ?? `HTTP_${err.status}`;
    if (err.status === 401) {
      return { code, message: err.message || 'That email address and password do not match.' };
    }
    if (err.status === 403) {
      return { code, message: err.message || 'This account is not active in any organization.' };
    }
    if (err.status === 404) {
      return { code, message: err.message || 'That was not found.' };
    }
    if (err.status === 410) {
      return { code, message: err.message || 'That link is no longer valid.' };
    }
    if (err.status === 400) {
      return { code, message: err.message || 'That request was not valid.' };
    }
    if (err.status >= 500) {
      return {
        code,
        message:
          'The server could not complete that request. On a fresh checkout this usually means ' +
          'the database has not been built yet — run `npm run db:reset`, then try again.',
      };
    }
    return { code, message: err.message || 'That request failed.' };
  }

  return {
    code: 'NETWORK',
    message:
      'Could not reach the server. Check that it is still running on this port, then try again.',
  };
}

// A short human explanation, using the server's own provenance.
export function whyLocked(entry) {
  if (!entry) return 'unknown';
  switch (entry.reason) {
    case 'explicit_deny': return `denied by ${entry.source}`;
    case 'implicit': return 'not granted';
    case 'suspended': return 'membership is suspended';
    case 'not_a_member': return 'not a member of this organization';
    default: return entry.reason ?? 'not granted';
  }
}

export const fmtTime = (iso) => (iso ? new Date(iso).toLocaleString() : '—');
