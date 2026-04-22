import { test, expect } from './fixtures';
import { createUser } from './helpers/api';

test.describe('mobile admin users', () => {
  test('adds a user via the full-screen modal', async ({ adminPage, appURL }) => {
    await adminPage.goto(`${appURL}/admin`);

    // "Add user" is above the fold on the Users page header — unaffected by the drawer.
    await adminPage.getByRole('button', { name: /add user/i }).click();
    const modal = adminPage.getByRole('dialog');
    await modal.getByLabel('Username').fill('mobile_made');
    await modal.getByLabel('Full name').fill('Mobile Made');
    await modal.getByLabel('Email').fill('mobile-made@example.com');
    await modal.getByLabel('Password').fill('MobileUI-Password-1');
    await modal.getByRole('button', { name: /create user/i }).click();

    // After creation the new record appears as a card in the mobile variant.
    // Scope to cards only — the table markup is still in the DOM but hidden by CSS.
    await expect(
      adminPage.locator('[data-testid^="card-"]').filter({ hasText: 'mobile_made' }),
    ).toBeVisible();
  });

  test('edits an existing user via the overflow action menu', async ({
    adminPage,
    adminRequest,
    appURL,
  }) => {
    const user = await createUser(adminRequest, appURL, {
      username: 'mobile_edit',
      name: 'Mobile Edit',
      email: 'mobile-edit@example.com',
      password: 'MobileEdit-Password-1',
    });

    await adminPage.goto(`${appURL}/admin`);

    // The mobile variant exposes each row as a card with an overflow ⋯ menu.
    const card = adminPage.getByTestId(`card-${user.id}`);
    await expect(card).toBeVisible();
    await card.getByTestId('action-menu-trigger').click();

    // The menu is rendered in the DOM adjacent to the trigger.
    const menu = adminPage.getByTestId('action-menu');
    await menu.getByRole('button', { name: /^edit$/i }).click();

    const modal = adminPage.getByRole('dialog');
    await modal.getByLabel('Full name').fill('Mobile Edit (Updated)');
    await modal.getByRole('button', { name: /save changes/i }).click();

    await expect(adminPage.getByTestId(`card-${user.id}`)).toContainText('Mobile Edit (Updated)');
  });
});
