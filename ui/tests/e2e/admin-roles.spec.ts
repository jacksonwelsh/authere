import { test, expect } from './fixtures';

test.describe('admin roles', () => {
  test('creates a custom role and then deletes it', async ({ adminPage, appURL }) => {
    await adminPage.goto(`${appURL}/admin/roles`);

    await adminPage.getByRole('button', { name: /add role/i }).click();
    const createModal = adminPage.getByRole('dialog');
    await createModal.getByLabel('Name').fill('e2e-custom-role');
    await createModal.getByLabel('Description').fill('Made by E2E');
    await createModal.getByRole('button', { name: /create role/i }).click();

    const row = adminPage.locator('tr', { hasText: 'e2e-custom-role' });
    await expect(row).toBeVisible();

    await row.getByRole('button', { name: /delete/i }).click();
    await adminPage.getByRole('dialog').getByRole('button', { name: /delete role/i }).click();
    await expect(row).toHaveCount(0);
  });

  test('system roles (admin, user) cannot be deleted', async ({ adminPage, appURL }) => {
    await adminPage.goto(`${appURL}/admin/roles`);

    const adminRow = adminPage.locator('tr', { hasText: /^admin/ }).first();
    // The delete action for system roles is omitted entirely.
    await expect(adminRow.getByRole('button', { name: /delete/i })).toHaveCount(0);

    const userRow = adminPage.locator('tr', { hasText: /^user/ }).first();
    await expect(userRow.getByRole('button', { name: /delete/i })).toHaveCount(0);
  });
});
