import { http, HttpResponse } from 'msw';
import { mkMe } from './factories';

// Default happy-path handlers for endpoints the UI calls on mount or frequently.
// Individual tests override specific endpoints via `server.use(...)`.
export const defaultHandlers = [
  http.get('/api/me', () => HttpResponse.json(mkMe())),
  http.post('/api/auth/browser-refresh', () => HttpResponse.json({})),
  http.post('/api/auth/browser-logout', () => HttpResponse.json({})),
];
