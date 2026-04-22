import { test, expect } from './fixtures';
import { createUser } from './helpers/api';

test.describe('admin users', () => {
  test('creates a new user via the modal form', async ({ adminPage, appURL }) => {
    await adminPage.goto(`${appURL}/admin`);

    await adminPage.getByRole('button', { name: /add user/i }).click();
    const modal = adminPage.getByRole('dialog');
    await modal.getByLabel('Username').fill('made_via_ui');
    await modal.getByLabel('Full name').fill('Made Via UI');
    await modal.getByLabel('Email').fill('made@example.com');
    await modal.getByLabel('Password').fill('UiCreated-Password-1');
    await modal.getByRole('button', { name: /create user/i }).click();

    await expect(adminPage.locator('tr', { hasText: 'made_via_ui' })).toBeVisible();
  });

  test('edits an existing user', async ({ adminPage, adminRequest, appURL }) => {
    const user = await createUser(adminRequest, appURL, {
      username: 'edit_target',
      name: 'Edit Target',
      email: 'edit@example.com',
      password: 'Target-Password-1234',
    });

    await adminPage.goto(`${appURL}/admin`);
    const row = adminPage.getByTestId(`row-${user.id}`);
    await row.getByRole('button', { name: /edit/i }).click();

    const modal = adminPage.getByRole('dialog');
    await modal.getByLabel('Full name').fill('Edit Target (Updated)');
    await modal.getByRole('button', { name: /save changes/i }).click();

    await expect(row).toContainText('Edit Target (Updated)');
  });

  test('assigns the admin role and removes it again', async ({ adminPage, adminRequest, appURL }) => {
    const user = await createUser(adminRequest, appURL, {
      username: 'promote_me',
      name: 'Promote Me',
      email: 'promote@example.com',
      password: 'Promote-Password-1',
    });

    await adminPage.goto(`${appURL}/admin`);
    const row = adminPage.getByTestId(`row-${user.id}`);
    await row.getByRole('button', { name: /roles/i }).click();

    const modal = adminPage.getByRole('dialog');
    // Role-picker rows are <button> elements whose accessible name is the
    // role name + description ("admin Full administrative access"). Match the
    // admin row by text rather than an exact name.
    const adminRow = modal.locator('button.role-row', { hasText: /admin/ });
    await adminRow.click();
    await expect(adminPage.getByRole('status')).toContainText(/assigned admin\./i);

    await adminRow.click();
    await expect(adminPage.getByRole('status').last()).toContainText(/removed admin\./i);
  });
});
