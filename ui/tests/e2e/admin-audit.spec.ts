import { test, expect } from './fixtures';

test.describe('admin audit log', () => {
  test('shows entries from login events', async ({ adminPage, appURL }) => {
    // The admin has already logged in via the adminPage fixture — that should
    // have generated a login_success event.
    await adminPage.goto(`${appURL}/admin/audit`);

    await expect(
      adminPage.locator('tbody tr', { has: adminPage.getByText('login_success') }).first(),
    ).toBeVisible();
  });

  test('opens the detail modal for rows with an acting admin', async ({
    adminPage,
    adminRequest,
    appURL,
  }) => {
    // Admin-updating a user produces an admin_update_user event with actor_id set.
    const user = await adminRequest
      .post(`${appURL}/api/user`, {
        data: {
          username: 'audit_target',
          name: 'Audit Target',
          email: 'audit@example.com',
          password: 'Target-Password-1234',
        },
        failOnStatusCode: true,
      })
      .then((r) => r.json());

    await adminRequest.patch(`${appURL}/api/user/${user.id}`, {
      data: { name: 'Audit Target (changed)' },
      failOnStatusCode: true,
    });

    await adminPage.goto(`${appURL}/admin/audit`);

    // The server emits `admin_update_user` for an admin-initiated PATCH /api/user/:id.
    const row = adminPage
      .locator('tr.clickable')
      .filter({ hasText: 'admin_update_user' })
      .first();
    await row.click();

    const dialog = adminPage.getByRole('dialog');
    await expect(dialog.getByRole('heading', { name: /event details/i })).toBeVisible();
    await expect(dialog).toContainText('Acting admin');
  });
});
