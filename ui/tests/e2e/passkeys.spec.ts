import { createHmac } from 'node:crypto';
import { test, expect } from './fixtures';
import { createUser } from './helpers/api';

// CDP supplies an actual CTAP2 authenticator to Chromium. Firefox and WebKit
// cannot automate an OS authenticator; the portable UI cases below run in all three.
test('passkey enrollment, MFA-free login, safe redirect, and removal', async ({ page, appURL, adminRequest, browserName }) => {
  test.skip(browserName !== 'chromium', 'Virtual WebAuthn authenticators require Chromium CDP');
  const username = 'passkey_user';
  const password = 'Passkey-Test-Password-1';
  await createUser(adminRequest, appURL, { username, password, name: 'Passkey User', email: 'passkey@example.com' });
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
    hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
    automaticPresenceSimulation: true,
  } });
  await page.goto(`${appURL}/login`);
  await page.getByLabel('Username').fill(username);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page).toHaveURL(/\/account/);
  await page.goto(`${appURL}/credentials`);
  await page.getByRole('button', { name: 'Add passkey', exact: true }).click();
  await page.getByLabel('Passkey name').fill('Test device');
  await page.getByRole('button', { name: 'Create passkey', exact: true }).click();
  await expect(page.getByText('Test device', { exact: true })).toBeVisible();
  // Enable real TOTP through the API while the full authenticated session is active.
  const enrolled = await page.evaluate(async () => {
    const r = await fetch('/api/me/totp/enroll', { method: 'POST' });
    return r.json();
  });
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of enrolled.secret) bits += alphabet.indexOf(char).toString(2).padStart(5, '0');
  const secret = Buffer.from((bits.match(/.{8}/g) ?? []).map(byte => parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const digest = createHmac('sha1', secret).update(counter).digest();
  const offset = digest[digest.length - 1]! & 15;
  const code = ((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).toString().padStart(6, '0');
  const activated = await page.evaluate(async code => (await fetch('/api/me/totp/activate', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code }),
  })).status, code);
  expect(activated).toBe(200);
  await page.context().clearCookies();
  await page.goto(`${appURL}/login?redirect_uri=%2Fcredentials`);
  await page.getByRole('button', { name: 'Sign in with a passkey', exact: true }).click();
  await expect(page).toHaveURL(`${appURL}/credentials`);
  await expect(page.getByText('Test device', { exact: true })).toBeVisible();
  const passkeySection = page.getByRole('region', { name: /passkeys/i });
  await expect(passkeySection).toContainText('Last used');
  await passkeySection.getByRole('button', { name: 'Remove', exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Remove passkey', exact: true }).click();
  await expect(page).toHaveURL(`${appURL}/login`);
  await page.getByLabel('Username').fill(username);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByLabel('Authentication code')).toBeVisible();
});

test('cancelled passkey request permits retry and password fallback', async ({ page, appURL }) => {
  // Supply the WebAuthn surface as well as the OS prompt: Playwright's Linux
  // WebKit has no native PublicKeyCredential. Fetch, option conversion, Svelte
  // click handlers, and browser error handling still run in each engine.
  await page.addInitScript(() => {
    Object.defineProperty(window, 'PublicKeyCredential', { configurable: true, value: class {} });
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: async (options: CredentialRequestOptions) => {
      if (!(options.publicKey?.challenge instanceof ArrayBuffer)) throw new Error('Challenge was not decoded');
      if (options.publicKey.userVerification !== 'required') throw new Error('User verification missing');
      if (options.mediation === 'conditional') throw new Error('Explicit sign-in must not require autofill');
      const state = window as unknown as { passkeyPromptCount?: number };
      state.passkeyPromptCount = (state.passkeyPromptCount ?? 0) + 1;
      throw new DOMException('Cancelled', 'NotAllowedError');
    } } });
  });
  await page.goto(`${appURL}/login`);
  const passkey = page.getByRole('button', { name: 'Sign in with a passkey', exact: true });
  await expect(passkey).toBeVisible();
  await passkey.click();
  await expect(page.getByRole('alert')).toContainText('cancelled or timed out');
  await expect(passkey).toBeEnabled();
  expect(await page.evaluate(() => (window as unknown as Record<string, unknown>).passkeyPromptCount)).toBe(1);
  await passkey.click();
  await expect(page.getByRole('alert')).toContainText('cancelled or timed out');
  expect(await page.evaluate(() => (window as unknown as Record<string, unknown>).passkeyPromptCount)).toBe(2);
  await page.getByLabel('Username').fill('wrong-user');
  await page.getByLabel('Password', { exact: true }).fill('Wrong-Password-1');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Username or password is incorrect.');
});

test('browser without WebAuthn still offers password sign-in', async ({ page, appURL }) => {
  await page.addInitScript(() => Object.defineProperty(window, 'PublicKeyCredential', { value: undefined }));
  await page.goto(`${appURL}/login`);
  await expect(page.getByRole('button', { name: 'Sign in with a passkey', exact: true })).toHaveCount(0);
  await expect(page.getByLabel('Username')).toBeVisible();
  await expect(page.getByLabel('Password', { exact: true })).toBeVisible();
});

test('registration supports browsers without newer WebAuthn serialization helpers', async ({ page, appURL }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  // Exercise the library's portable ArrayBuffer/JSON conversion in each engine.
  // The simulated authenticator intentionally omits Level 3 response helpers.
  await page.addInitScript(() => {
    Object.defineProperty(window, 'PublicKeyCredential', { configurable: true, value: class {} });
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { create: async (options: CredentialCreationOptions) => {
      const key = options.publicKey!;
      if (!(key.challenge instanceof ArrayBuffer) || !(key.user.id instanceof ArrayBuffer)) throw new Error('Binary fields were not decoded');
      if (key.authenticatorSelection?.userVerification !== 'required' || key.authenticatorSelection?.residentKey !== 'required') throw new Error('Credential policy missing');
      if (key.authenticatorSelection.authenticatorAttachment) throw new Error('External authenticators excluded');
      return {
        id: 'AQID', rawId: new Uint8Array([1, 2, 3]).buffer, type: 'public-key',
        response: { clientDataJSON: new Uint8Array([4, 5]).buffer, attestationObject: new Uint8Array([6, 7]).buffer },
        getClientExtensionResults: () => ({ credProps: { rk: true } }),
      };
    } } });
  });
  await page.route('**/api/me', route => route.fulfill({ json: { user_id: 'test', username: 'test', name: 'Test User', email: null, roles: [] } }));
  await page.route('**/api/settings', route => route.fulfill({ json: { ldap: { password_mode: 'primary_only' } } }));
  await page.route('**/api/me/totp', route => route.fulfill({ json: { enabled: false, pending: false } }));
  await page.route('**/api/me/passkeys', route => route.fulfill({ json: [] }));
  await page.route('**/api/me/passkeys/register/start', async route => {
    expect(route.request().postDataJSON()).toEqual({ name: 'Portable passkey' });
    await route.fulfill({ json: {
      challenge: 'AQID', rp: { name: 'Authere', id: 'localhost' },
      user: { id: 'AQID', name: 'test', displayName: 'Test User' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
      attestation: 'none',
    } });
  });
  await page.route('**/api/me/passkeys/register/finish', async route => {
    expect(route.request().postDataJSON()).toMatchObject({
      id: 'AQID', rawId: 'AQID', type: 'public-key',
      response: { clientDataJSON: 'BAU', attestationObject: 'Bgc' },
      clientExtensionResults: { credProps: { rk: true } },
    });
    await route.fulfill({ status: 201, json: { id: 'test-key', name: 'Portable passkey', created_at: 1, last_used_at: null } });
  });
  await page.goto(`${appURL}/credentials`);
  await page.getByRole('button', { name: 'Add passkey', exact: true }).click();
  await page.getByLabel('Passkey name').fill('Portable passkey');
  await page.getByLabel('Passkey name').press('Enter');
  await expect(page.getByText('Portable passkey', { exact: true })).toBeVisible();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});
