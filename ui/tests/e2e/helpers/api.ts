import { request as playwrightRequest, type APIRequestContext, type BrowserContext, type Page } from '@playwright/test';
import { ADMIN_PASSWORD, ADMIN_USERNAME } from './server';

// Typed helpers for exercising the real HTTP API from tests. These are the same
// endpoints the UI hits, so we avoid backdoor test-only seed endpoints.
//
// Note on auth: the browser endpoint (/api/auth/login) sets Secure cookies,
// which Playwright's standalone APIRequestContext will not send back over
// plain http (even on 127.0.0.1). For seed helpers we therefore use the
// JSON API (/api/login) which returns a bearer token, and attach it as an
// Authorization header. The browser-cookie path is still what the UI
// itself exercises in E2E flows.

async function obtainAdminBearer(baseURL: string): Promise<string> {
  const tmp = await playwrightRequest.newContext();
  try {
    const r = await tmp.post(`${baseURL}/api/login`, {
      data: { username: ADMIN_USERNAME, password: ADMIN_PASSWORD },
      failOnStatusCode: true,
    });
    const body = (await r.json()) as { access_token: string };
    return body.access_token;
  } finally {
    await tmp.dispose();
  }
}

export async function newAdminRequestContext(baseURL: string): Promise<APIRequestContext> {
  const token = await obtainAdminBearer(baseURL);
  return playwrightRequest.newContext({
    baseURL,
    extraHTTPHeaders: {
      Authorization: `Bearer ${token}`,
    },
  });
}

export interface SeedUserInput {
  username: string;
  name: string;
  email: string;
  password: string;
  roles?: string[]; // role names to assign after creation
}

export interface CreatedUser {
  id: string;
  username: string;
  name: string;
  email: string;
}

async function getRoleIdByName(
  request: APIRequestContext,
  baseURL: string,
  name: string,
): Promise<string> {
  const roles = (await request.get(`${baseURL}/api/roles`).then((r) => r.json())) as Array<{
    id: string;
    name: string;
  }>;
  const match = roles.find((r) => r.name === name);
  if (!match) throw new Error(`role not found: ${name}`);
  return match.id;
}

export async function createUser(
  request: APIRequestContext,
  baseURL: string,
  input: SeedUserInput,
): Promise<CreatedUser> {
  const user = (await request
    .post(`${baseURL}/api/user`, { data: input, failOnStatusCode: true })
    .then((r) => r.json())) as CreatedUser;

  for (const roleName of input.roles ?? []) {
    const roleId = await getRoleIdByName(request, baseURL, roleName);
    await request.post(`${baseURL}/api/users/${user.id}/roles`, {
      data: { role_id: roleId },
      failOnStatusCode: true,
    });
  }
  return user;
}

export interface CreateInvitationInput {
  label?: string;
  max_uses?: number;
  expires_at?: number;
}

export interface CreatedInvitation {
  id: string;
  label: string | null;
  max_uses: number | null;
  expires_at: number | null;
}

export async function createInvitation(
  request: APIRequestContext,
  baseURL: string,
  input: CreateInvitationInput = {},
): Promise<CreatedInvitation> {
  return request
    .post(`${baseURL}/api/invitations`, { data: input, failOnStatusCode: true })
    .then((r) => r.json());
}

// Pull the auth cookies out of an API request context and inject them into a
// browser context — so Playwright tests can "log in" without clicking through
// the login form (which is rate-limited) every time.
export async function adoptAuthCookies(
  from: APIRequestContext,
  into: BrowserContext,
) {
  const state = await from.storageState();
  await into.addCookies(state.cookies);
}

export async function loginPageAsAdmin(page: Page, baseURL: string) {
  await page.request.post(`${baseURL}/api/auth/login`, {
    data: { username: ADMIN_USERNAME, password: ADMIN_PASSWORD },
    failOnStatusCode: true,
  });
  await adoptAuthCookies(page.request, page.context());
}
