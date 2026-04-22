import '@testing-library/jest-dom/vitest';
import { afterAll, afterEach, beforeAll, vi } from 'vitest';
import { server } from './msw/server';
import { clearToasts } from './helpers/toasts';

// Unmocked requests should fail the test — prevents silent drift between UI and API.
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => {
  server.resetHandlers();
  clearToasts();
  vi.mocked(navigator.clipboard.writeText).mockClear();
});
afterAll(() => server.close());

// Stub clipboard so components that call navigator.clipboard.writeText don't
// bomb in happy-dom (which doesn't ship a clipboard implementation).
Object.defineProperty(navigator, 'clipboard', {
  configurable: true,
  value: {
    writeText: vi.fn(() => Promise.resolve()),
    readText: vi.fn(() => Promise.resolve('')),
  },
});

// crypto.randomUUID is used by toast.svelte.ts — happy-dom exposes it but
// older versions don't. Polyfill defensively (idempotent) so the setup stays
// robust across environment upgrades.
if (!('randomUUID' in globalThis.crypto)) {
  Object.defineProperty(globalThis.crypto, 'randomUUID', {
    configurable: true,
    value: () => 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = Math.floor(Math.random() * 16);
      const v = c === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    }),
  });
}
