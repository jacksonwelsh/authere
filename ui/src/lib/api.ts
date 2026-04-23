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
export const login = (username: string, password: string, totp_code?: string) =>
  request<TokenPair>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password, totp_code }),
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
export interface AuditLogQuery {
  limit?: number;
  offset?: number;
  user_id?: string;
  actor_id?: string;
  event_type?: string[];
  /** Unix seconds */
  since?: number;
  /** Unix seconds */
  until?: number;
}

export interface AuditLogResponse {
  entries: AuditEntry[];
  total: number;
}

/**
 * Serialize an `AuditLogQuery` to URLSearchParams. Shared between the list
 * endpoint and the export endpoint so filter behavior stays identical.
 */
export function buildAuditQueryString(params: AuditLogQuery): URLSearchParams {
  const qs = new URLSearchParams();
  if (params.limit !== undefined) qs.set('limit', String(params.limit));
  if (params.offset !== undefined) qs.set('offset', String(params.offset));
  if (params.user_id) qs.set('user_id', params.user_id);
  if (params.actor_id) qs.set('actor_id', params.actor_id);
  if (params.event_type && params.event_type.length > 0) {
    qs.set('event_type', params.event_type.join(','));
  }
  if (params.since !== undefined) qs.set('since', String(params.since));
  if (params.until !== undefined) qs.set('until', String(params.until));
  return qs;
}

export const getAuditLog = (params: AuditLogQuery = {}) => {
  const qs = buildAuditQueryString(params);
  return request<AuditLogResponse>(`/api/audit?${qs}`);
};

export const getAuditEventTypes = () =>
  request<string[]>('/api/audit/event-types');

/**
 * Trigger a browser download of the audit log export. Uses a hidden link
 * rather than `fetch(...)` + `Blob` so the browser streams the body straight
 * to disk — audit exports can be large (up to 50k rows on the server).
 */
export function downloadAuditExport(format: 'json' | 'csv', params: AuditLogQuery = {}) {
  const qs = buildAuditQueryString({ ...params, limit: undefined, offset: undefined });
  qs.set('format', format);
  const url = `/api/audit/export?${qs}`;
  const a = document.createElement('a');
  a.href = url;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
}

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

// TOTP
export interface TotpStatus {
  enabled: boolean;
  pending: boolean;
}

export interface TotpEnrollResponse {
  secret: string;
  otpauth_uri: string;
}

export interface TotpActivateResponse {
  recovery_codes: string[];
}

export const getMyTotpStatus = () => request<TotpStatus>('/api/me/totp');
export const enrollMyTotp = () =>
  request<TotpEnrollResponse>('/api/me/totp/enroll', { method: 'POST' });
export const activateMyTotp = (code: string) =>
  request<TotpActivateResponse>('/api/me/totp/activate', {
    method: 'POST',
    body: JSON.stringify({ code }),
  });
export const disableMyTotp = (currentPassword: string) =>
  request<void>('/api/me/totp', {
    method: 'DELETE',
    body: JSON.stringify({ current_password: currentPassword }),
  });
export const adminDisableUserTotp = (userId: string) =>
  request<void>(`/api/user/${userId}/totp`, { method: 'DELETE' });

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

// Admin actions
export const restartService = () =>
  request<void>('/api/admin/restart', { method: 'POST' });

// SCIM tokens (admin)
export interface ScimToken {
  id: string;
  name: string;
  created_at: number;
  created_by: string;
  last_used_at: number | null;
  revoked_at: number | null;
}

export interface CreateScimTokenResponse {
  id: string;
  name: string;
  created_at: number;
  token: string;
}

export const listScimTokens = () => request<ScimToken[]>('/api/scim/tokens');
export const createScimToken = (name: string) =>
  request<CreateScimTokenResponse>('/api/scim/tokens', {
    method: 'POST',
    body: JSON.stringify({ name }),
  });
export const revokeScimToken = (id: string) =>
  request<void>(`/api/scim/tokens/${id}`, { method: 'DELETE' });

// Outbound provisioning (admin)
export interface ProvisioningTarget {
  id: string;
  name: string;
  kind: string;
  base_url: string;
  enabled: boolean;
  created_at: number;
  created_by: string | null;
  updated_at: number;
  backfill_done_at: number | null;
  attribute_map: string | null;
  dead_letter_webhook_url: string | null;
  last_success_at: number | null;
  last_failure_at: number | null;
  consecutive_failures: number;
}

export interface CreateProvisioningTargetInput {
  name: string;
  kind: string;
  base_url: string;
  auth_token: string;
  enabled?: boolean;
  attribute_map?: string;
  dead_letter_webhook_url?: string;
}

export interface UpdateProvisioningTargetInput {
  name?: string;
  base_url?: string;
  enabled?: boolean;
  auth_token?: string;
  attribute_map?: string | null;
  dead_letter_webhook_url?: string | null;
}

export interface ProvisioningJob {
  id: string;
  target_id: string;
  user_id: string;
  event_type: string;
  status: string;
  attempts: number;
  next_attempt_at: number;
  last_error: string | null;
  last_response_status: number | null;
  external_resource_id: string | null;
  created_at: number;
  updated_at: number;
}

export const listProvisioningTargets = () =>
  request<ProvisioningTarget[]>('/api/provisioning/targets');
export const createProvisioningTarget = (input: CreateProvisioningTargetInput) =>
  request<ProvisioningTarget>('/api/provisioning/targets', {
    method: 'POST',
    body: JSON.stringify(input),
  });
export const updateProvisioningTarget = (
  id: string,
  input: UpdateProvisioningTargetInput,
) =>
  request<ProvisioningTarget>(`/api/provisioning/targets/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(input),
  });
export const deleteProvisioningTarget = (id: string) =>
  request<void>(`/api/provisioning/targets/${id}`, { method: 'DELETE' });

export const listProvisioningJobs = (params: {
  target_id?: string;
  status?: string;
  limit?: number;
} = {}) => {
  const qs = new URLSearchParams();
  if (params.target_id) qs.set('target_id', params.target_id);
  if (params.status) qs.set('status', params.status);
  if (params.limit != null) qs.set('limit', String(params.limit));
  const suffix = qs.toString() ? `?${qs.toString()}` : '';
  return request<ProvisioningJob[]>(`/api/provisioning/jobs${suffix}`);
};
export const retryProvisioningJob = (id: string) =>
  request<void>(`/api/provisioning/jobs/${id}/retry`, { method: 'POST' });

export { ApiError };
