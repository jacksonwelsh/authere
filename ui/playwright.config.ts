import { defineConfig, devices } from '@playwright/test';

const CI = !!process.env.CI;

export default defineConfig({
  testDir: './tests/e2e',
  testMatch: /.*\.spec\.ts/,
  globalSetup: './tests/e2e/global-setup.ts',

  fullyParallel: true,
  workers: CI ? 2 : 4,
  // Flake policy: one retry in CI to soak up rare network/IO blips; zero locally
  // so developers notice regressions immediately. Increasing past 1 hides bugs.
  retries: CI ? 1 : 0,
  reporter: CI ? [['list'], ['html', { open: 'never' }]] : [['list']],

  expect: {
    timeout: 5_000,
  },

  use: {
    // baseURL is set per-test from the worker fixture; no default here so that
    // a missing fixture throws instead of silently hitting localhost:3000.
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      testIgnore: /mobile-.*\.spec\.ts/,
      use: { ...devices['Desktop Chrome'] },
    },
    {
      // Mobile viewport project — runs the mobile-tagged specs plus the smoke
      // test, which has no layout dependencies. Desktop-layout specs (admin
      // tables with inline action rows, sidebar nav clicks, etc.) stay on
      // chromium to avoid duplicating assertions for both viewports.
      name: 'mobile-chromium',
      testMatch: /mobile-.*\.spec\.ts|smoke\.spec\.ts/,
      use: { ...devices['Pixel 5'] },
    },
  ],
});
