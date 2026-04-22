import { test, expect } from './fixtures';
import { createUser } from './helpers/api';

test.describe('login form', () => {
  test('signs in and redirects to /admin for admin users', async ({ page, appURL }) => {
    await page.goto(`${appURL}/login`);
    await page.getByLabel('Username').fill('e2e_admin');
    await page.getByLabel('Password').fill('E2E-Admin-Password-1');
    await page.getByRole('button', { name: /sign in/i }).click();
    await expect(page).toHaveURL(/\/admin/);
    await expect(page.getByRole('heading', { name: /users/i })).toBeVisible();
  });

  test('shows an error message on wrong password', async ({ page, appURL }) => {
    await page.goto(`${appURL}/login`);
    await page.getByLabel('Username').fill('e2e_admin');
    await page.getByLabel('Password').fill('wrong-password-123');
    await page.getByRole('button', { name: /sign in/i }).click();
    await expect(page.getByRole('alert')).toContainText(/username or password is incorrect/i);
    // Still on /login
    await expect(page).toHaveURL(/\/login/);
  });

  test('respects redirect_uri after successful sign-in', async ({ page, appURL }) => {
    await page.goto(`${appURL}/login?redirect_uri=/admin/invitations`);
    await page.getByLabel('Username').fill('e2e_admin');
    await page.getByLabel('Password').fill('E2E-Admin-Password-1');
    await page.getByRole('button', { name: /sign in/i }).click();
    await expect(page).toHaveURL(/\/admin\/invitations/);
  });
});

test.describe('logout', () => {
  test('clears session and redirects to /login', async ({ adminPage, appURL }) => {
    await adminPage.goto(`${appURL}/admin`);
    await adminPage.getByRole('button', { name: /sign out/i }).click();
    await expect(adminPage).toHaveURL(/\/login/);

    // Navigate again; without cookies, admin pages should force a login redirect.
    await adminPage.goto(`${appURL}/admin`);
    await expect(adminPage).toHaveURL(/\/login/);
  });
});

// Rate-limit wire-up (5/60s in production config) is verified in the unit
// test suite (tests/unit/routes/Login.test.ts): the 429 branch exercises
// exactly the UI code path users see. Driving the real counter from E2E
// would force every other spec into an artificially-tight window without
// adding coverage.

test.describe('non-admin user redirects', () => {
  test('regular user is sent to /account on root', async ({ page, adminRequest, appURL }) => {
    const user = await createUser(adminRequest, appURL, {
      username: 'regular_bob',
      name: 'Regular Bob',
      email: 'bob@example.com',
      password: 'Bob-Password-1234',
    });
    expect(user.id).toBeTruthy();

    await page.goto(`${appURL}/login`);
    await page.getByLabel('Username').fill('regular_bob');
    await page.getByLabel('Password').fill('Bob-Password-1234');
    await page.getByRole('button', { name: /sign in/i }).click();

    // Non-admin lands on /account, not /admin.
    await expect(page).toHaveURL(/\/account/);
  });
});
