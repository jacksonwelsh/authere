import { describe, it, expect } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '../../msw/server';
import AuditLog from '../../../../src/routes/admin/AuditLog.svelte';
import { mkAuditEntry } from '../../msw/factories';

/**
 * Simulate the paginated `/api/audit` endpoint. `entries` is the full dataset;
 * the handler slices based on the limit/offset query params and echoes the
 * filters the client sent via a spy so tests can assert against them.
 */
function paged(
  entries: ReturnType<typeof mkAuditEntry>[],
  spy?: { last?: Record<string, string> },
) {
  return http.get('/api/audit', ({ request }) => {
    const url = new URL(request.url);
    const offset = Number(url.searchParams.get('offset') ?? '0');
    const limit = Number(url.searchParams.get('limit') ?? '50');
    if (spy) {
      spy.last = Object.fromEntries(url.searchParams.entries());
    }
    return HttpResponse.json({
      entries: entries.slice(offset, offset + limit),
      total: entries.length,
    });
  });
}

function eventTypesHandler(types: string[] = ['login_success', 'login_failed', 'admin_update_user']) {
  return http.get('/api/audit/event-types', () => HttpResponse.json(types));
}

/**
 * Find the body of the data table. Scoping lookups to the table avoids false
 * hits on option text in the filter dropdown (which contains every event name).
 */
function tableBody(): HTMLElement {
  const table = screen.getByRole('table');
  // Grab the first `tbody`; the DOM only contains one in this component.
  const body = table.querySelector('tbody');
  if (!body) throw new Error('tbody not found');
  return body as HTMLElement;
}

describe('admin AuditLog', () => {
  it('renders one row per entry with correct event badge variants', async () => {
    server.use(
      eventTypesHandler(),
      paged([
        mkAuditEntry({ id: 'a', event_type: 'login_success' }),
        mkAuditEntry({ id: 'b', event_type: 'login_failed' }),
        mkAuditEntry({ id: 'c', event_type: 'admin_update_user', username: 'alice' }),
      ]),
    );
    render(AuditLog);

    await waitFor(() => {
      const body = tableBody();
      expect(within(body).getByText('login_success')).toBeInTheDocument();
      expect(within(body).getByText('login_failed')).toBeInTheDocument();
      expect(within(body).getByText('admin_update_user')).toBeInTheDocument();
    });
  });

  it('shows the total event count in the header', async () => {
    server.use(
      eventTypesHandler(),
      paged(Array.from({ length: 3 }, (_, i) => mkAuditEntry({ id: `e${i}` }))),
    );
    render(AuditLog);

    expect(await screen.findByText(/3 events/)).toBeInTheDocument();
  });

  it('shows pagination controls when results exceed the page size', async () => {
    const entries = Array.from({ length: 120 }, (_, i) =>
      mkAuditEntry({ id: `e${i}`, event_type: 'login_success' }),
    );
    server.use(eventTypesHandler(), paged(entries));
    render(AuditLog);

    await screen.findByText(/120 events/);
    expect(screen.getByRole('navigation', { name: /pagination/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /next/i })).toBeEnabled();
    expect(screen.getByRole('button', { name: /prev/i })).toBeDisabled();
  });

  it('hides pagination when a single page fits the result set', async () => {
    server.use(eventTypesHandler(), paged([mkAuditEntry({ id: 'only' })]));
    render(AuditLog);

    await waitFor(() => {
      expect(within(tableBody()).getByText('login_success')).toBeInTheDocument();
    });
    expect(screen.queryByRole('navigation', { name: /pagination/i })).not.toBeInTheDocument();
  });

  it('advances to the next page when Next is clicked', async () => {
    const entries = [
      ...Array.from({ length: 50 }, (_, i) =>
        mkAuditEntry({ id: `p1-${i}`, event_type: 'login_success' }),
      ),
      mkAuditEntry({ id: 'p2-marker', event_type: 'login_failed' }),
    ];
    server.use(eventTypesHandler(), paged(entries));
    render(AuditLog);

    await screen.findByRole('button', { name: /next/i });
    await userEvent.click(screen.getByRole('button', { name: /next/i }));

    // Second page has exactly one row — the login_failed marker — so scoping
    // to tbody finds it unambiguously.
    await waitFor(() => {
      expect(within(tableBody()).getByText('login_failed')).toBeInTheDocument();
    });
  });

  it('opens the detail modal when a row with an actor is clicked', async () => {
    server.use(
      eventTypesHandler(),
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

    await waitFor(() => {
      expect(within(tableBody()).getByText('admin_update_user')).toBeInTheDocument();
    });
    await userEvent.click(within(tableBody()).getByText('admin_update_user'));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('Target user')).toBeInTheDocument();
    expect(within(dialog).getByText('Acting admin')).toBeInTheDocument();
  });

  it('does NOT open the detail modal for rows without an actor', async () => {
    server.use(
      eventTypesHandler(),
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

    await waitFor(() => {
      expect(within(tableBody()).getByText('login_success')).toBeInTheDocument();
    });
    await userEvent.click(within(tableBody()).getByText('login_success'));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('applies an event type filter when Apply is clicked', async () => {
    const spy: { last?: Record<string, string> } = {};
    server.use(
      eventTypesHandler(['login_success', 'login_failed']),
      paged([mkAuditEntry({ id: 'a' })], spy),
    );
    render(AuditLog);

    // Wait for the dropdown to be populated before interacting.
    await waitFor(() => {
      const select = screen.getByLabelText(/Event type/i) as HTMLSelectElement;
      expect(select.options.length).toBeGreaterThan(1);
    });

    const select = screen.getByLabelText(/Event type/i) as HTMLSelectElement;
    await userEvent.selectOptions(select, 'login_failed');
    await userEvent.click(screen.getByRole('button', { name: /apply/i }));

    await waitFor(() => expect(spy.last?.event_type).toBe('login_failed'));
    // Pagination resets to page 0.
    expect(spy.last?.offset).toBe('0');
  });

  it('passes actor and user ID filters on Apply', async () => {
    const spy: { last?: Record<string, string> } = {};
    server.use(eventTypesHandler(), paged([], spy));
    render(AuditLog);

    await screen.findByText(/0 events/);
    await userEvent.type(screen.getByLabelText(/Actor ID/i), 'actor-uuid');
    await userEvent.type(screen.getByLabelText(/User ID/i), 'user-uuid');
    await userEvent.click(screen.getByRole('button', { name: /apply/i }));

    await waitFor(() => {
      expect(spy.last?.actor_id).toBe('actor-uuid');
      expect(spy.last?.user_id).toBe('user-uuid');
    });
  });

  it('clears all filters when Clear is clicked', async () => {
    const spy: { last?: Record<string, string> } = {};
    server.use(eventTypesHandler(), paged([mkAuditEntry({ id: 'a' })], spy));
    render(AuditLog);

    await screen.findByText(/1 event/);
    await userEvent.type(screen.getByLabelText(/Actor ID/i), 'actor-uuid');
    await userEvent.click(screen.getByRole('button', { name: /apply/i }));
    await waitFor(() => expect(spy.last?.actor_id).toBe('actor-uuid'));

    await userEvent.click(screen.getByRole('button', { name: /clear/i }));
    await waitFor(() => expect(spy.last?.actor_id).toBeUndefined());
  });
});
