import { test, expect } from './fixtures';
import { createUser } from './helpers/api';

test('account — updates profile and reflects the change', async ({
  page,
  adminRequest,
  appURL,
}) => {
  await createUser(adminRequest, appURL, {
    username: 'acct_user',
    name: 'Account User',
    email: 'acct@example.com',
    password: 'Acct-Password-1234!',
  });

  await page.goto(`${appURL}/login`);
  await page.getByLabel('Username').fill('acct_user');
  await page.getByLabel('Password').fill('Acct-Password-1234!');
  await page.getByRole('button', { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/account/);

  const nameField = page.getByLabel('Full name');
  await nameField.fill('Renamed Account User');
  await page.getByRole('button', { name: /save changes/i }).click();
  await expect(page.getByRole('status')).toContainText(/profile updated/i);

  await page.reload();
  await expect(page.getByLabel('Full name')).toHaveValue('Renamed Account User');
});
