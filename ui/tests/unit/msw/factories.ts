import type {
  Me,
  User,
  Role,
  Application,
  Invitation,
  Settings,
  AuditEntry,
  AppPassword,
} from '../../../src/lib/api';

let counter = 0;
const id = () => `00000000-0000-0000-0000-${String(++counter).padStart(12, '0')}`;

export function mkMe(overrides: Partial<Me> = {}): Me {
  return {
    user_id: id(),
    username: 'e2e_admin',
    name: 'E2E Admin',
    email: 'admin@example.com',
    roles: ['admin'],
    ...overrides,
  };
}

export function mkUser(overrides: Partial<User> = {}): User {
  return {
    id: id(),
    username: 'alice',
    name: 'Alice Example',
    email: 'alice@example.com',
    ...overrides,
  };
}

export function mkRole(overrides: Partial<Role> = {}): Role {
  return {
    id: id(),
    name: 'viewer',
    description: null,
    ...overrides,
  };
}

export function mkApplication(overrides: Partial<Application> = {}): Application {
  return {
    id: id(),
    name: 'Example App',
    slug: 'example-app',
    host_pattern: '^app\\.example\\.com$',
    path_prefix: null,
    required_roles: [],
    ...overrides,
  };
}

export function mkInvitation(overrides: Partial<Invitation> = {}): Invitation {
  return {
    id: id(),
    created_by: 'admin-id',
    created_by_username: 'e2e_admin',
    label: 'Test invite',
    max_uses: null,
    uses: 0,
    expires_at: null,
    created_at: 1700000000,
    status: 'active',
    ...overrides,
  };
}

export function mkAuditEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    id: id(),
    timestamp: 1700000000,
    event_type: 'login_success',
    user_id: 'user-id',
    actor_id: null,
    ip_address: '127.0.0.1',
    user_agent: 'vitest',
    details: null,
    username: 'alice',
    actor_username: null,
    ...overrides,
  };
}

export function mkAppPassword(overrides: Partial<AppPassword> = {}): AppPassword {
  return {
    id: id(),
    user_id: 'user-id',
    name: 'My app password',
    created_at: 1700000000,
    last_used_at: null,
    ...overrides,
  };
}

export function mkSettings(overrides: Partial<Settings> = {}): Settings {
  return {
    open_registration: false,
    session_expiry_seconds: 7 * 24 * 60 * 60,
    ldap: {
      enabled: false,
      base_dn: 'dc=example,dc=com',
      bind_address: '0.0.0.0:389',
      service_account_dn: 'cn=authere,dc=example,dc=com',
      service_password_set: false,
      password_mode: 'primary_and_app',
    },
    ...overrides,
  };
}
