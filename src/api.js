const API_ROOT = '/api';
const SESSION_KEY = 'cybershield-session';

export function readSession() {
  try { return JSON.parse(sessionStorage.getItem(SESSION_KEY) || localStorage.getItem(SESSION_KEY) || 'null'); }
  catch { return null; }
}

function saveSession(data, keepSignedIn = false) {
  sessionStorage.setItem('cybershield-token', data.token);
  const session = { token: data.token, user: data.user };
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
  if (keepSignedIn) localStorage.setItem(SESSION_KEY, JSON.stringify(session));
  else localStorage.removeItem(SESSION_KEY);
  return session;
}

export async function login(email, password, keepSignedIn = false) {
  const response = await fetch(`${API_ROOT}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || 'Sign-in failed.');
  return saveSession(data, keepSignedIn);
}

export async function demoLogin(role, keepSignedIn = false) {
  const response = await fetch(`${API_ROOT}/auth/demo`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ role }) });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || 'Demo sign-in failed.');
  return saveSession(data, keepSignedIn);
}

export function logout() {
  sessionStorage.removeItem('cybershield-token');
  sessionStorage.removeItem(SESSION_KEY);
  localStorage.removeItem(SESSION_KEY);
}

async function request(path, options = {}) {
  let token = sessionStorage.getItem('cybershield-token');
  if (!token) throw new Error('Please sign in to continue.');
  const response = await fetch(`${API_ROOT}${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...options.headers },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `API request failed (${response.status})`);
  return data;
}

export const api = {
  health: async () => { const response = await fetch(`${API_ROOT}/health`); if (!response.ok) throw new Error('API health check failed'); return response.json(); },
  incidents: () => request('/incidents'),
  createIncident: incident => request('/incidents', { method: 'POST', body: JSON.stringify(incident) }),
  updateIncident: (id, changes) => request(`/incidents/${id}`, { method: 'PATCH', body: JSON.stringify(changes) }),
  queueAgent: (agentPath, incidentId, target) => request(`/agents/${agentPath}`, { method: 'POST', body: JSON.stringify({ incidentId, target }) }),
};

export function toIncident(row) {
  const assignee = row.assignee_name ? String(row.assignee_name).trim().split(/\s+/).map(part => part[0]).join('').slice(0, 2).toUpperCase() : (row.assignee_code || '—');
  const date = row.created_at ? new Date(row.created_at) : new Date();
  const minutes = Math.max(0, Math.floor((Date.now() - date.getTime()) / 60000));
  const time = minutes < 1 ? 'Just now' : minutes < 60 ? `${minutes} min ago` : minutes < 1440 ? `${Math.floor(minutes / 60)} hr ago` : 'Yesterday';
  return { id: row.incident_key || String(row.id), recordId: row.id, title: row.title, type: row.category || 'Security incident', severity: row.severity, status: row.status, assignee, assigneeName: row.assignee_name || '', reporter: row.reporter_name || 'Security team', time, target: row.affected_asset || 'Unspecified', description: row.description || '', score: row.score ?? 50 };
}
