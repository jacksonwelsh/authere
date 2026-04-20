// Typed API client — all calls go to the same origin (cookies handle auth)

export interface User {
  id: string;
  username: string;
  name: string;
  email: string;
}

export interface Role {
  id: string;
  name: string;
  description: string | null;
}

export interface Application {
  id: string;
  name: string;
  slug: string;
  host_pattern: string;
  path_prefix: string | null;
  required_roles: string[];
}

export interface AuditEntry {
  id: string;
  timestamp: number;
  event_type: string;
  user_id: string | null;
  actor_id: string | null;
  ip_address: string | null;
  user_agent: string | null;
  details: Record<string, unknown> | null;
  username: string | null;
  actor_username: string | null;
}

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: string;
}

export interface Me {
  user_id: string;
  roles: string[];
}

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

let refreshing: Promise<boolean> | null = null;

async function tryRefresh(): Promise<boolean> {
  if (refreshing) return refreshing;
  refreshing = fetch('/auth/browser-refresh', {
    method: 'POST',
    credentials: 'same-origin',
  }).then(r => r.ok).catch(() => false).finally(() => { refreshing = null; });
  return refreshing;
}

async function request<T>(path: string, init?: RequestInit, retry = true): Promise<T> {
  const res = await fetch(path, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    ...init,
  });
  if (res.status === 401 && retry) {
    const refreshed = await tryRefresh();
    if (refreshed) return request<T>(path, init, false);
    window.location.href = `/login?redirect_uri=${encodeURIComponent(window.location.pathname)}`;
    return new Promise(() => {});
  }
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new ApiError(res.status, body || res.statusText);
  }
  const text = await res.text();
  return text ? JSON.parse(text) : undefined as T;
}

// Auth
export const login = (username: string, password: string) =>
  request<TokenPair>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });

export const logout = () =>
  request<void>('/auth/browser-logout', { method: 'POST' });

export const getMe = () => request<Me>('/me');

// Users
export const getUsers = () => request<User[]>('/user');
export const getUser = (id: string) => request<User>(`/user/${id}`);
export const updateUser = (id: string, data: { name?: string; email?: string | null; username?: string }) =>
  request<User>(`/user/${id}`, { method: 'PATCH', body: JSON.stringify(data) });
export const updateMe = (data: { name?: string; email?: string | null; username?: string }) =>
  request<User>('/me', { method: 'PATCH', body: JSON.stringify(data) });
export const changeMyPassword = (data: { current_password: string; new_password: string }) =>
  request<void>('/me/password', { method: 'PATCH', body: JSON.stringify(data) });
export const adminChangePassword = (userId: string, data: { new_password: string }) =>
  request<void>(`/user/${userId}/password`, { method: 'PUT', body: JSON.stringify(data) });
export const createUser = (data: { username: string; name: string; email: string; password: string }) =>
  request<User>('/user', { method: 'POST', body: JSON.stringify(data) });

interface UserRole { user_id: string; role_id: string; role_name: string; }

export const getUserRoles = (userId: string) =>
  request<UserRole[]>(`/users/${userId}/roles`).then(rows =>
    rows.map(r => ({ id: r.role_id, name: r.role_name, description: null }) as Role)
  );
export const assignRole = (userId: string, roleId: string) =>
  request<void>(`/users/${userId}/roles`, {
    method: 'POST',
    body: JSON.stringify({ role_id: roleId }),
  });
export const removeRole = (userId: string, roleId: string) =>
  request<void>(`/users/${userId}/roles/${roleId}`, { method: 'DELETE' });

// Roles
export const getRoles = () => request<Role[]>('/roles');
export const createRole = (data: { name: string; description?: string }) =>
  request<Role>('/roles', { method: 'POST', body: JSON.stringify(data) });
export const deleteRole = (id: string) =>
  request<void>(`/roles/${id}`, { method: 'DELETE' });

// Applications
export const getApplications = () => request<Application[]>('/applications');
export const getApplication = (id: string) => request<Application>(`/applications/${id}`);
export const createApplication = (data: Partial<Application>) =>
  request<Application>('/applications', { method: 'POST', body: JSON.stringify(data) });
export const updateApplication = (id: string, data: Partial<Application>) =>
  request<Application>(`/applications/${id}`, { method: 'PUT', body: JSON.stringify(data) });
export const deleteApplication = (id: string) =>
  request<void>(`/applications/${id}`, { method: 'DELETE' });

// Audit log
export const getAuditLog = (params?: { limit?: number; offset?: number }) => {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set('limit', String(params.limit));
  if (params?.offset) qs.set('offset', String(params.offset));
  return request<AuditEntry[]>(`/audit?${qs}`);
};

// Registration
export interface RegisterInput {
  username: string;
  name: string;
  email?: string;
  password: string;
  confirm_password: string;
  invite_code?: string;
}

export const registerUser = (data: RegisterInput) =>
  request<{ success: boolean; redirect_uri: string | null }>('/register', {
    method: 'POST',
    body: JSON.stringify(data),
  });

export const validateInvite = (code: string) =>
  request<{ valid: boolean }>(`/register/validate-invite?code=${encodeURIComponent(code)}`);

// Settings
export interface Settings {
  open_registration: boolean;
}

export const getSettings = () => request<Settings>('/admin/settings');
export const updateSettings = (data: Partial<Settings>) =>
  request<Settings>('/admin/settings', { method: 'PATCH', body: JSON.stringify(data) });

// Invitations
export interface Invitation {
  id: string;
  created_by: string;
  created_by_username: string | null;
  label: string | null;
  max_uses: number | null;
  uses: number;
  expires_at: number | null;
  created_at: number;
  status: 'active' | 'exhausted' | 'expired';
}

export const getInvitations = () => request<Invitation[]>('/admin/invitations');
export const createInvitation = (data: { label?: string; max_uses?: number; expires_at?: number }) =>
  request<Invitation>('/admin/invitations', { method: 'POST', body: JSON.stringify(data) });
export const deleteInvitation = (id: string) =>
  request<void>(`/admin/invitations/${id}`, { method: 'DELETE' });

export { ApiError };
