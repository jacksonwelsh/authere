import { test, expect } from './fixtures';

test.describe('mobile navigation', () => {
  test('drawer opens, navigates, and closes', async ({ adminPage, appURL }) => {
    await adminPage.goto(`${appURL}/admin`);

    // Desktop rail is hidden on mobile viewports; only the hamburger is visible.
    const menuBtn = adminPage.getByTestId('mobile-menu-button');
    await expect(menuBtn).toBeVisible();

    await menuBtn.click();

    const drawer = adminPage.getByTestId('mobile-nav-drawer');
    await expect(drawer).toBeVisible();
    await expect(menuBtn).toHaveAttribute('aria-expanded', 'true');

    // Tapping a nav link inside the drawer navigates and, on route load,
    // dismounts the drawer as part of the full-page navigation.
    await drawer.getByRole('link', { name: /invitations/i }).click();
    await expect(adminPage).toHaveURL(/\/admin\/invitations/);
    await expect(adminPage.getByTestId('mobile-nav-drawer')).toHaveCount(0);
  });

  test('drawer closes on backdrop click', async ({ adminPage, appURL }) => {
    await adminPage.goto(`${appURL}/admin`);
    await adminPage.getByTestId('mobile-menu-button').click();
    await expect(adminPage.getByTestId('mobile-nav-drawer')).toBeVisible();

    await adminPage.getByTestId('drawer-backdrop').click();
    await expect(adminPage.getByTestId('mobile-nav-drawer')).toHaveCount(0);
  });
});
