import { test, expect } from './fixtures';

test('server boots and SPA is served', async ({ page, appURL }) => {
  await page.goto(`${appURL}/login`);
  await expect(page.getByRole('heading', { name: /sign in/i })).toBeVisible();
});

test('admin fixture logs in via cookie injection', async ({ adminPage, appURL }) => {
  // Navigate to root — App.svelte should redirect logged-in admins to /admin.
  await adminPage.goto(`${appURL}/`);
  await expect(adminPage).toHaveURL(/\/admin/);
});
