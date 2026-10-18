import { execFileSync } from 'node:child_process';
import { createServer } from 'node:https';
import { request as httpRequest } from 'node:http';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request as standaloneRequest } from '@playwright/test';
import { test, expect } from './fixtures';
import { ADMIN_USERNAME, ADMIN_PASSWORD } from './helpers/server';

// This local TLS proxy implements Caddy's documented forward_auth contract. It
// exercises actual browser cookie rules and the release server's complete SSO
// flow, while keeping every connection inside the test machine.
test.use({ ignoreHTTPSErrors: true });

test('forward login isolates upstream credentials and preserves the requested query', async ({ page, appURL, adminRequest }) => {
  const certificateDir = mkdtempSync(join(tmpdir(), 'authere-forward-e2e-'));
  let upstreamCookie = '';
  let authority = '';
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-keyout', join(certificateDir, 'key.pem'),
    '-out', join(certificateDir, 'cert.pem')], { stdio: 'ignore' });
  const proxy = createServer({ key: readFileSync(join(certificateDir, 'key.pem')),
    cert: readFileSync(join(certificateDir, 'cert.pem')) }, (incoming, outgoing) => {
    const handoffEndpoint = incoming.url?.startsWith('/.authere/');
    const headers: Record<string, string> = {};
    if (incoming.headers.cookie) headers.cookie = incoming.headers.cookie;
    if (handoffEndpoint) {
      // Preserve the protected host without changing the upstream routing Host.
      headers['x-authere-target-host'] = authority;
    } else {
      headers['x-forwarded-host'] = authority;
      headers['x-forwarded-proto'] = 'https';
      headers['x-forwarded-uri'] = incoming.url ?? '/';
    }
    const check = httpRequest(`${appURL}${handoffEndpoint ? incoming.url : '/api/auth/verify'}`,
      { headers, method: 'GET' }, response => {
        if (!handoffEndpoint && response.statusCode === 200) {
          response.resume();
          upstreamCookie = incoming.headers.cookie ?? '';
          outgoing.writeHead(200, { 'Content-Type': 'application/json' });
          outgoing.end(JSON.stringify({ path: incoming.url, username: response.headers['x-auth-username'],
            cookieNames: upstreamCookie.split(';').map(value => value.trim().split('=')[0]) }));
        } else {
          outgoing.writeHead(response.statusCode ?? 500, response.headers);
          response.pipe(outgoing);
        }
      });
    check.on('error', () => { outgoing.writeHead(502); outgoing.end(); });
    check.end();
  });
  await new Promise<void>(resolve => proxy.listen(0, '127.0.0.1', resolve));
  const address = proxy.address();
  if (!address || typeof address === 'string') throw new Error('No proxy port');
  authority = `localhost:${address.port}`;
  const protectedOrigin = `https://${authority}`;
  const appSlug = `browser-forward-${address.port}`;
  let applicationId: string | undefined;
  try {
    const created = await adminRequest.post(`${appURL}/api/applications`, { data: {
      name: 'Browser Protected App', slug: appSlug, host_pattern: authority, required_roles: [],
    }, failOnStatusCode: true });
    applicationId = (await created.json()).id;
    await page.goto(`${protectedOrigin}/dashboard?view=recent`);
    await expect(page).toHaveURL(new RegExp(`${appURL.replaceAll('.', '\\.')}\\/login\\?`));
    await expect(page.getByText('Sign in to continue to Browser Protected App.')).toBeVisible();
    await page.getByLabel('Username').fill(ADMIN_USERNAME);
    await page.getByLabel('Password').fill(ADMIN_PASSWORD);
    await page.getByRole('button', { name: /^sign in$/i }).click();
    await expect(page).toHaveURL(`${protectedOrigin}/dashboard?view=recent`);
    const body = JSON.parse(await page.locator('body').innerText());
    expect(body.path).toBe('/dashboard?view=recent');
    expect(body.username).toBe(ADMIN_USERNAME);
    expect(body.cookieNames).toContain('__Host-authere_forward');
    expect(body.cookieNames).not.toContain('__Host-authere_token');
    expect(body.cookieNames).not.toContain('__Host-authere_refresh');
    expect(body.cookieNames).not.toContain('__Host-authere_forward_state');
    const cookies = await page.context().cookies(protectedOrigin);
    const scoped = cookies.find(cookie => cookie.name === '__Host-authere_forward');
    expect(scoped?.secure).toBe(true);
    expect(scoped?.httpOnly).toBe(true);
    expect(scoped?.sameSite).toBe('Lax');
    const attacker = await standaloneRequest.newContext({ ignoreHTTPSErrors: true });
    try {
      // A compromised protected upstream cannot replay its credential at Authere.
      const central = await attacker.get(`${appURL}/api/me`, { headers: {
        Cookie: `__Host-authere_token=${scoped!.value}`,
      } });
      expect(central.status()).toBe(401);
      // Inspect the full jar: Playwright's URL filter excludes Secure cookies
      // for HTTP loopback URLs even though Chromium sends them on trusted loopback.
      const centralCookies = await page.context().cookies();
      const centralAccess = centralCookies.find(cookie => cookie.name === '__Host-authere_token'
        && cookie.domain === new URL(appURL).hostname);
      expect(centralAccess).toBeDefined();
      const verify = await attacker.get(`${appURL}/api/auth/verify`, { maxRedirects: 0, headers: {
        Cookie: `__Host-authere_token=${centralAccess!.value}`, 'X-Forwarded-Host': authority,
        'X-Forwarded-Proto': 'https', 'X-Forwarded-Uri': '/dashboard',
      } });
      expect(verify.status()).toBe(303);
      const retainedCentralSession = await page.goto(`${appURL}/api/me`);
      expect(retainedCentralSession?.status()).toBe(200);
    } finally { await attacker.dispose(); }
  } finally {
    if (applicationId) await adminRequest.delete(`${appURL}/api/applications/${applicationId}`);
    await new Promise<void>(resolve => proxy.close(() => resolve()));
    rmSync(certificateDir, { recursive: true, force: true });
  }
});
