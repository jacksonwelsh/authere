import { test, expect } from './fixtures';
import { createUser } from './helpers/api';

test.describe('shell navigation', () => {
  test('admin navigation links are all present', async ({ adminPage, appURL }) => {
    await adminPage.goto(`${appURL}/admin`);
    const nav = adminPage.getByRole('navigation');
    await expect(nav.getByRole('link', { name: /users/i })).toBeVisible();
    await expect(nav.getByRole('link', { name: /roles/i })).toBeVisible();
    await expect(nav.getByRole('link', { name: /applications/i })).toBeVisible();
    await expect(nav.getByRole('link', { name: /invitations/i })).toBeVisible();
    await expect(nav.getByRole('link', { name: /audit/i })).toBeVisible();
    await expect(nav.getByRole('link', { name: /settings/i })).toBeVisible();
  });

  test('regular user sees account-only nav, no admin links', async ({
    page,
    adminRequest,
    appURL,
  }) => {
    await createUser(adminRequest, appURL, {
      username: 'nav_user',
      name: 'Nav User',
      email: 'navuser@example.com',
      password: 'Nav-Password-1234!',
    });

    await page.goto(`${appURL}/login`);
    await page.getByLabel('Username').fill('nav_user');
    await page.getByLabel('Password').fill('Nav-Password-1234!');
    await page.getByRole('button', { name: /sign in/i }).click();
    await expect(page).toHaveURL(/\/account/);

    const nav = page.getByRole('navigation');
    // No admin-only links.
    await expect(nav.getByRole('link', { name: /^users$/i })).toHaveCount(0);
    await expect(nav.getByRole('link', { name: /settings/i })).toHaveCount(0);
  });
});
