import { test, expect } from './fixtures';
import { createInvitation } from './helpers/api';

test.describe('registration', () => {
  test.beforeEach(async ({ adminRequest, appURL }) => {
    // Enable open registration so the flow is exercised without always needing
    // an invite code (we test invite-gated flows separately below).
    await adminRequest.patch(`${appURL}/api/settings`, {
      data: { open_registration: true },
      failOnStatusCode: true,
    });
  });

  test.afterEach(async ({ adminRequest, appURL }) => {
    await adminRequest.patch(`${appURL}/api/settings`, {
      data: { open_registration: false },
      failOnStatusCode: true,
    });
  });

  test('creates an account and redirects to the account page', async ({ page, appURL }) => {
    await page.goto(`${appURL}/register`);
    await page.getByLabel('Username').fill('newbie');
    await page.getByLabel('Full name').fill('New Person');
    await page.getByLabel('Email').fill('newbie@example.com');
    await page.getByLabel('Password', { exact: true }).fill('Newbie-Password-1234');
    await page.getByLabel('Confirm password').fill('Newbie-Password-1234');
    await page.getByRole('button', { name: /create account/i }).click();

    await expect(page).toHaveURL(/\/account/);
  });

  test('shows "username taken" when reusing an existing username', async ({ page, appURL }) => {
    await page.goto(`${appURL}/register`);
    await page.getByLabel('Username').fill('e2e_admin');
    await page.getByLabel('Full name').fill('Impostor');
    await page.getByLabel('Password', { exact: true }).fill('Anything-1234!!');
    await page.getByLabel('Confirm password').fill('Anything-1234!!');
    await page.getByRole('button', { name: /create account/i }).click();

    await expect(page.getByRole('alert')).toContainText(/already taken/i);
  });
});

test.describe('invite code validation', () => {
  test('marks a valid invite code green on blur', async ({ page, adminRequest, appURL }) => {
    const inv = await createInvitation(adminRequest, appURL, { label: 'blur-test' });

    await page.goto(`${appURL}/register`);
    await page.getByLabel('Invitation code').fill(inv.id);
    await page.getByLabel('Invitation code').blur();

    await expect(page.getByText(/valid invitation/i)).toBeVisible();
  });

  test('marks an invalid invite code red on blur', async ({ page, appURL }) => {
    await page.goto(`${appURL}/register`);
    await page.getByLabel('Invitation code').fill('not-a-real-code');
    await page.getByLabel('Invitation code').blur();

    await expect(page.getByText(/invalid or expired/i)).toBeVisible();
  });

  test('pre-validates from ?invite= query parameter', async ({ page, adminRequest, appURL }) => {
    const inv = await createInvitation(adminRequest, appURL, { label: 'qs-test' });

    await page.goto(`${appURL}/register?invite=${inv.id}`);
    await expect(page.getByLabel('Invitation code')).toHaveValue(inv.id);
    await expect(page.getByText(/valid invitation/i)).toBeVisible();
  });
});
