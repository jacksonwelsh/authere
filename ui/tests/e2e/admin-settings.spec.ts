import { test, expect } from './fixtures';

test.describe('admin settings', () => {
  test('toggles open registration', async ({ adminPage, appURL }) => {
    await adminPage.goto(`${appURL}/admin/settings`);

    // The toggle is a custom <button aria-pressed> rather than a native checkbox.
    const toggle = adminPage.getByRole('button', { name: /toggle open registration/i });
    const initial = (await toggle.getAttribute('aria-pressed')) === 'true';

    await toggle.click();
    await expect(toggle).toHaveAttribute('aria-pressed', String(!initial));

    // Flip back to keep subsequent tests stable (server state persists per worker).
    await toggle.click();
    await expect(toggle).toHaveAttribute('aria-pressed', String(initial));
  });
});
