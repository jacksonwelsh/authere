import { test, expect } from './fixtures';
import { createInvitation } from './helpers/api';

test.describe('admin invitations', () => {
  test('creates and deletes an invitation via the UI', async ({ adminPage, appURL }) => {
    await adminPage.goto(`${appURL}/admin/invitations`);

    await adminPage.getByRole('button', { name: /new invitation/i }).click();
    const modal = adminPage.getByRole('dialog');
    await modal.getByLabel('Label').fill('e2e-created');
    await modal.getByRole('button', { name: 'Create' }).click();

    // Find the row by its text (label is unique) and pull the id from data-testid.
    const row = adminPage.locator('tr', { hasText: 'e2e-created' });
    await expect(row).toBeVisible();

    // Delete it.
    await row.getByRole('button', { name: /delete/i }).click();
    await adminPage.getByRole('dialog').getByRole('button', { name: /delete/i }).click();
    await expect(row).toHaveCount(0);
  });

  test('lists an invitation seeded through the API', async ({ adminPage, adminRequest, appURL }) => {
    const inv = await createInvitation(adminRequest, appURL, { label: 'seeded-via-api' });
    await adminPage.goto(`${appURL}/admin/invitations`);
    await expect(adminPage.getByTestId(`row-${inv.id}`)).toBeVisible();
    await expect(adminPage.getByTestId(`row-${inv.id}`)).toContainText('seeded-via-api');
  });

  test('copies invite link via icon button', async ({ adminPage, adminRequest, appURL, browserName }) => {
    test.skip(browserName !== 'chromium', 'Clipboard API permissions vary by browser');
    await adminPage.context().grantPermissions(['clipboard-read', 'clipboard-write']);

    const inv = await createInvitation(adminRequest, appURL, { label: 'copy-me' });
    await adminPage.goto(`${appURL}/admin/invitations`);

    const row = adminPage.getByTestId(`row-${inv.id}`);
    await row.getByRole('button', { name: /copy invite link/i }).click();

    const clipboard = await adminPage.evaluate(() => navigator.clipboard.readText());
    expect(clipboard).toContain(`/register?invite=${inv.id}`);
  });
});
