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
  username: string;
  name: string;
  email: string | null;
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
  refreshing = fetch('/api/auth/browser-refresh', {
    method: 'POST',
    credentials: 'same-origin',
  }).then(r => r.ok).catch(() => false).finally(() => { refreshing = null; });
  return refreshing;
}

// Auth-related endpoints must not go through the refresh/redirect dance on
// 401 — a 401 here *is* the meaningful answer (wrong password, expired
// refresh token, etc.), and auto-redirecting to /login would hide the UX.
function isAuthPath(path: string): boolean {
  return (
    path.startsWith('/api/auth/login') ||
    path.startsWith('/api/auth/browser-refresh') ||
    path.startsWith('/api/auth/browser-logout') ||
    path.startsWith('/api/login')
  );
}

async function request<T>(path: string, init?: RequestInit, retry = true): Promise<T> {
  const res = await fetch(path, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    ...init,
  });
  if (res.status === 401 && retry && !isAuthPath(path)) {
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
  request<TokenPair>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });

export const logout = () =>
  request<void>('/api/auth/browser-logout', { method: 'POST' });

export const getMe = () => request<Me>('/api/me');

// Users
export const getUsers = () => request<User[]>('/api/user');
export const getUser = (id: string) => request<User>(`/api/user/${id}`);
export const updateUser = (id: string, data: { name?: string; email?: string | null; username?: string }) =>
  request<User>(`/api/user/${id}`, { method: 'PATCH', body: JSON.stringify(data) });
export const updateMe = (data: { name?: string; email?: string | null; username?: string }) =>
  request<User>('/api/me', { method: 'PATCH', body: JSON.stringify(data) });
export const changeMyPassword = (data: { current_password: string; new_password: string }) =>
  request<void>('/api/me/password', { method: 'PATCH', body: JSON.stringify(data) });
export const adminChangePassword = (userId: string, data: { new_password: string }) =>
  request<void>(`/api/user/${userId}/password`, { method: 'PUT', body: JSON.stringify(data) });
export const createUser = (data: { username: string; name: string; email: string; password: string }) =>
  request<User>('/api/user', { method: 'POST', body: JSON.stringify(data) });

interface UserRole { user_id: string; role_id: string; role_name: string; }

export const getUserRoles = (userId: string) =>
  request<UserRole[]>(`/api/users/${userId}/roles`).then(rows =>
    rows.map(r => ({ id: r.role_id, name: r.role_name, description: null }) as Role)
  );
export const assignRole = (userId: string, roleId: string) =>
  request<void>(`/api/users/${userId}/roles`, {
    method: 'POST',
    body: JSON.stringify({ role_id: roleId }),
  });
export const removeRole = (userId: string, roleId: string) =>
  request<void>(`/api/users/${userId}/roles/${roleId}`, { method: 'DELETE' });

// Roles
export const getRoles = () => request<Role[]>('/api/roles');
export const createRole = (data: { name: string; description?: string }) =>
  request<Role>('/api/roles', { method: 'POST', body: JSON.stringify(data) });
export const deleteRole = (id: string) =>
  request<void>(`/api/roles/${id}`, { method: 'DELETE' });

// Applications
export const getApplications = () => request<Application[]>('/api/applications');
export const getApplication = (id: string) => request<Application>(`/api/applications/${id}`);
export const createApplication = (data: Partial<Application>) =>
  request<Application>('/api/applications', { method: 'POST', body: JSON.stringify(data) });
export const updateApplication = (id: string, data: Partial<Application>) =>
  request<Application>(`/api/applications/${id}`, { method: 'PUT', body: JSON.stringify(data) });
export const deleteApplication = (id: string) =>
  request<void>(`/api/applications/${id}`, { method: 'DELETE' });

// Audit log
export const getAuditLog = (params?: { limit?: number; offset?: number }) => {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set('limit', String(params.limit));
  if (params?.offset) qs.set('offset', String(params.offset));
  return request<AuditEntry[]>(`/api/audit?${qs}`);
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
  request<{ success: boolean; redirect_uri: string | null }>('/api/register', {
    method: 'POST',
    body: JSON.stringify(data),
  });

export const validateInvite = (code: string) =>
  request<{ valid: boolean }>(`/api/register/validate-invite?code=${encodeURIComponent(code)}`);

// Settings
export type LdapPasswordMode = 'primary_and_app' | 'app_only' | 'primary_only';

export interface LdapSettings {
  enabled: boolean;
  base_dn: string;
  bind_address: string;
  service_account_dn: string;
  service_password_set: boolean;
  password_mode: LdapPasswordMode;
}

export interface LdapSettingsInput {
  enabled?: boolean;
  base_dn?: string;
  bind_address?: string;
  password_mode?: LdapPasswordMode;
}

export interface Settings {
  open_registration: boolean;
  ldap: LdapSettings;
}

export interface SettingsInput {
  open_registration?: boolean;
  ldap?: LdapSettingsInput;
}

export const getSettings = () => request<Settings>('/api/settings');
export const updateSettings = (data: SettingsInput) =>
  request<Settings>('/api/settings', { method: 'PATCH', body: JSON.stringify(data) });
export const regenerateLdapBindPassword = () =>
  request<{ password: string }>('/api/settings/ldap/regenerate-bind-password', { method: 'POST' });

// App passwords
export interface AppPassword {
  id: string;
  user_id: string;
  name: string;
  created_at: number;
  last_used_at: number | null;
}

export interface CreateAppPasswordResponse {
  app_password: AppPassword;
  password: string;
}

export const listMyAppPasswords = () =>
  request<AppPassword[]>('/api/me/app-passwords');
export const createMyAppPassword = (name: string) =>
  request<CreateAppPasswordResponse>('/api/me/app-passwords', {
    method: 'POST',
    body: JSON.stringify({ name }),
  });
export const deleteMyAppPassword = (id: string) =>
  request<void>(`/api/me/app-passwords/${id}`, { method: 'DELETE' });

export const listUserAppPasswords = (userId: string) =>
  request<AppPassword[]>(`/api/users/${userId}/app-passwords`);
export const deleteUserAppPassword = (userId: string, id: string) =>
  request<void>(`/api/users/${userId}/app-passwords/${id}`, { method: 'DELETE' });

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

export const getInvitations = () => request<Invitation[]>('/api/invitations');
export const createInvitation = (data: { label?: string; max_uses?: number; expires_at?: number }) =>
  request<Invitation>('/api/invitations', { method: 'POST', body: JSON.stringify(data) });
export const deleteInvitation = (id: string) =>
  request<void>(`/api/invitations/${id}`, { method: 'DELETE' });

export { ApiError };
