import { test as base, type APIRequestContext, type Page } from '@playwright/test';
import { startWorkerServer, type WorkerServer } from './helpers/server';
import { loginPageAsAdmin, newAdminRequestContext } from './helpers/api';

type WorkerFixtures = {
  server: WorkerServer;
};

type TestFixtures = {
  adminRequest: APIRequestContext;
  appURL: string;
  adminPage: Page;
};

export const test = base.extend<TestFixtures, WorkerFixtures>({
  // One Rust server per Playwright worker; unique port + SQLite file.
  server: [
    async ({}, use, workerInfo) => {
      const server = await startWorkerServer(workerInfo.parallelIndex, workerInfo.project.name.startsWith('passkeys-') ? 'localhost' : '127.0.0.1');
      try {
        await use(server);
      } finally {
        await server.stop();
      }
    },
    { scope: 'worker' },
  ],

  // Per-test base URL — tests should prefer this over hard-coding.
  appURL: async ({ server }, use) => {
    await use(server.baseURL);
  },

  // A request context already authenticated as the admin. Uses /api/login
  // to obtain a bearer token rather than browser cookies (Secure cookies
  // aren't sent by standalone APIRequestContexts over http).
  //
  // Each test receives a fresh session: logging out in one browser correctly
  // revokes that user's earlier sessions. Test servers relax login rate limits.
  adminRequest: async ({ server }, use) => {
    const request = await newAdminRequestContext(server.baseURL);
    await use(request);
    await request.dispose();
  },

  // A browser page already logged in as the admin. Equivalent to clicking
  // through the login form, but skips the rate-limited endpoint so tests
  // don't eat into the 5/60s window.
  adminPage: async ({ page, server }, use) => {
    await loginPageAsAdmin(page, server.baseURL);
    await use(page);
  },
});

export { expect } from '@playwright/test';
