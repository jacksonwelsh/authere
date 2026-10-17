/** Keep post-login navigation on Authere. External applications use the server's
 * validated forward-redirect endpoint, which is itself a local path. */
export function sanitizeLoginRedirect(raw: string, origin: string): string {
  if (!raw.startsWith('/') || raw.startsWith('//') || /[\\\u0000-\u0020\u007f]/.test(raw)) {
    return '/';
  }
  try {
    const url = new URL(raw, origin);
    return url.origin === origin ? `${url.pathname}${url.search}${url.hash}` : '/';
  } catch {
    return '/';
  }
}
