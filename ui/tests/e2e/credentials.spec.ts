import { test, expect } from './fixtures';
import { createUser } from './helpers/api';

test('credentials — app password create + reveal-once', async ({
  page,
  adminRequest,
  appURL,
}) => {
  await createUser(adminRequest, appURL, {
    username: 'app_pw_user',
    name: 'App PW User',
    email: 'apppw@example.com',
    password: 'Initial-Password-1!',
  });

  await page.goto(`${appURL}/login`);
  await page.getByLabel('Username').fill('app_pw_user');
  await page.getByLabel('Password').fill('Initial-Password-1!');
  await page.getByRole('button', { name: /sign in/i }).click();
  // Wait for the post-login redirect to complete before navigating again —
  // otherwise the /credentials visit can overtake the login response and
  // bounce back to /login (which looks like a real auth failure).
  await expect(page).toHaveURL(/\/account/);
  await page.goto(`${appURL}/credentials`);

  await page.getByRole('button', { name: /new app password/i }).click();
  const modal = page.getByRole('dialog');
  await modal.getByLabel('Name').fill('Jellyfin');
  await modal.getByRole('button', { name: /^create$/i }).click();

  // The reveal-once modal opens with the generated password.
  const reveal = page.getByRole('dialog');
  await expect(reveal).toContainText(/app password created/i);
  const codeLocator = reveal.locator('code');
  const code = await codeLocator.innerText();
  expect(code.length).toBeGreaterThan(10);

  // Dismissing the reveal drops the plaintext from the DOM.
  await reveal.getByRole('button', { name: /^done$/i }).click();
  await expect(page.locator('code', { hasText: code })).toHaveCount(0);
});
