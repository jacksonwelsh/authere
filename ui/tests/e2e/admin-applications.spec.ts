import { test, expect } from './fixtures';

test.describe('admin applications', () => {
  test('creates and deletes an application', async ({ adminPage, appURL }) => {
    await adminPage.goto(`${appURL}/admin/applications`);

    await adminPage.getByRole('button', { name: /add application/i }).click();
    const modal = adminPage.getByRole('dialog');
    await modal.getByLabel('Name').fill('E2E App');
    await modal.getByLabel('Slug').fill('e2e-app');
    await modal.getByLabel('Host pattern (regex)').fill('^e2e\\.example\\.com$');
    await modal.getByRole('button', { name: /create application/i }).click();

    const row = adminPage.locator('tr', { hasText: 'E2E App' });
    await expect(row).toBeVisible();

    await row.getByRole('button', { name: /^delete$/i }).click();
    await adminPage.getByRole('dialog').getByRole('button', { name: /delete application/i }).click();
    await expect(row).toHaveCount(0);
  });

  test('shows Caddy config snippet', async ({ adminPage, appURL }) => {
    await adminPage.goto(`${appURL}/admin/applications`);

    // Create an app first.
    await adminPage.getByRole('button', { name: /add application/i }).click();
    const createModal = adminPage.getByRole('dialog');
    await createModal.getByLabel('Name').fill('Config App');
    await createModal.getByLabel('Slug').fill('config-app');
    await createModal.getByLabel('Host pattern (regex)').fill('^config\\.example\\.com$');
    await createModal.getByRole('button', { name: /create application/i }).click();

    const row = adminPage.locator('tr', { hasText: 'Config App' });
    await row.getByRole('button', { name: /config/i }).click();

    const snippet = adminPage.getByRole('dialog');
    await expect(snippet).toContainText('forward_auth');
    await expect(snippet).toContainText('/api/auth/verify');
    await expect(snippet).toContainText('config.example.com');
  });
});
