import { describe, it, expect } from 'vitest';
import { render, screen, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '../../msw/server';
import AuditLog from '../../../../src/routes/admin/AuditLog.svelte';
import { mkAuditEntry } from '../../msw/factories';

function paged(entries: ReturnType<typeof mkAuditEntry>[]) {
  return http.get('/api/audit', ({ request }) => {
    const url = new URL(request.url);
    const offset = Number(url.searchParams.get('offset') ?? '0');
    const limit = Number(url.searchParams.get('limit') ?? '50');
    return HttpResponse.json(entries.slice(offset, offset + limit));
  });
}

describe('admin AuditLog', () => {
  it('renders one row per entry with correct event badge variants', async () => {
    server.use(
      paged([
        mkAuditEntry({ id: 'a', event_type: 'login_success' }),
        mkAuditEntry({ id: 'b', event_type: 'login_failed' }),
        mkAuditEntry({ id: 'c', event_type: 'admin_update_user', username: 'alice' }),
      ]),
    );
    render(AuditLog);

    expect(await screen.findByText('login_success')).toBeInTheDocument();
    expect(screen.getByText('login_failed')).toBeInTheDocument();
    expect(screen.getByText('admin_update_user')).toBeInTheDocument();
  });

  it('shows a Load more button only when the page is full', async () => {
    const full = Array.from({ length: 50 }, (_, i) =>
      mkAuditEntry({ id: `e${i}`, event_type: 'login_success' }),
    );
    server.use(paged([...full, mkAuditEntry({ id: 'e50' })]));
    render(AuditLog);

    expect(await screen.findByRole('button', { name: /load more/i })).toBeInTheDocument();
  });

  it('hides Load more when there are fewer than PAGE entries', async () => {
    server.use(paged([mkAuditEntry({ id: 'only' })]));
    render(AuditLog);

    await screen.findByText('login_success');
    expect(screen.queryByRole('button', { name: /load more/i })).not.toBeInTheDocument();
  });

  it('appends the next page when Load more is clicked', async () => {
    const page1 = Array.from({ length: 50 }, (_, i) =>
      mkAuditEntry({ id: `p1-${i}`, event_type: 'login_success' }),
    );
    const page2 = [mkAuditEntry({ id: 'p2-marker', event_type: 'login_failed' })];
    server.use(paged([...page1, ...page2]));
    render(AuditLog);

    await screen.findByRole('button', { name: /load more/i });
    await userEvent.click(screen.getByRole('button', { name: /load more/i }));

    expect(await screen.findByText('login_failed')).toBeInTheDocument();
  });

  it('opens the detail modal when a row with an actor is clicked', async () => {
    server.use(
      paged([
        mkAuditEntry({
          id: 'evt1',
          event_type: 'admin_update_user',
          actor_id: 'actor-id',
          actor_username: 'e2e_admin',
          username: 'alice',
        }),
      ]),
    );
    render(AuditLog);

    const row = await screen.findByText('admin_update_user');
    await userEvent.click(row);
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('Target user')).toBeInTheDocument();
    expect(within(dialog).getByText('Acting admin')).toBeInTheDocument();
  });

  it('does NOT open the detail modal for rows without an actor', async () => {
    server.use(
      paged([
        mkAuditEntry({
          id: 'evt2',
          event_type: 'login_success',
          actor_id: null,
          username: 'alice',
        }),
      ]),
    );
    render(AuditLog);

    const row = await screen.findByText('login_success');
    await userEvent.click(row);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
});
