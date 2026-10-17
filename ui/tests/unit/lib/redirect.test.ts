import { describe, expect, it } from 'vitest';
import { sanitizeLoginRedirect } from '../../../src/lib/redirect';

describe('post-login redirect', () => {
  const origin = 'https://auth.example.com';

  it('preserves local OIDC and forward-auth continuation URLs', () => {
    for (const path of [
      '/account',
      '/authorize?client_id=example&state=opaque',
      '/api/auth/forward-redirect?redirect_uri=https%3A%2F%2Fapp.example.com%2F',
    ]) {
      expect(sanitizeLoginRedirect(path, origin)).toBe(path);
    }
  });

  it('rejects external destinations and browser URL normalization ambiguities', () => {
    for (const path of [
      'https://other.example.com/',
      '//other.example.com/',
      '/\\other.example.com/',
      '/\n/other.example.com/',
      'javascript:alert(1)',
      'https://auth.example.com/',
    ]) {
      expect(sanitizeLoginRedirect(path, origin)).toBe('/');
    }
  });
});
