import { toasts } from '../../../src/lib/toast.svelte';
import { waitFor } from '@testing-library/svelte';

// The Toast component is mounted by App.svelte in real usage, not by individual routes.
// Unit tests render a single route, so we observe toast state directly via the module
// instead of scraping DOM. This matches how tests should assert *behavior* (did the
// route notify the user?) rather than coupling to where the toast UI happens to live.

export async function waitForToast(pattern: RegExp) {
  await waitFor(() => {
    const match = toasts.items.find((t) => pattern.test(t.message));
    if (!match) throw new Error(`No toast matching ${pattern} found. Have: ${toasts.items.map(t => t.message).join(' | ')}`);
  });
}

export function clearToasts() {
  for (const t of [...toasts.items]) toasts.remove(t.id);
}
