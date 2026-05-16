import { describe, it, expect, vi } from 'vitest';
import { render, screen, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '../../msw/server';
import { waitForToast } from '../../helpers/toasts';
import Settings from '../../../../src/routes/admin/Settings.svelte';
import { mkSettings } from '../../msw/factories';

function mockSettingsEndpoints(settings = mkSettings()) {
  server.use(
    http.get('/api/settings', () => HttpResponse.json(settings)),
    http.get('/api/roles', () => HttpResponse.json([])),
  );
}

describe('Settings — Session expiry', () => {
  it('shows the current session expiry label', async () => {
    mockSettingsEndpoints(mkSettings({ session_expiry_seconds: 24 * 60 * 60 }));
    render(Settings);
    expect(await screen.findByText(/currently: 1 day/i)).toBeInTheDocument();
  });

  it('renders preset options including the current value', async () => {
    mockSettingsEndpoints(mkSettings({ session_expiry_seconds: 7 * 24 * 60 * 60 }));
    render(Settings);
    const select = (await screen.findByLabelText(/session expiry/i)) as HTMLSelectElement;
    expect(select.value).toBe(String(7 * 24 * 60 * 60));
    expect(within(select).getByRole('option', { name: '1 hour' })).toBeInTheDocument();
    expect(within(select).getByRole('option', { name: '90 days' })).toBeInTheDocument();
  });

  it('sends PATCH with the new session expiry and updates the display', async () => {
    mockSettingsEndpoints(mkSettings({ session_expiry_seconds: 7 * 24 * 60 * 60 }));
    let received: unknown = null;
    server.use(
      http.patch('/api/settings', async ({ request }) => {
        received = await request.json();
        return HttpResponse.json(
          mkSettings({ session_expiry_seconds: 60 * 60 }),
        );
      }),
    );
    render(Settings);

    const select = (await screen.findByLabelText(/session expiry/i)) as HTMLSelectElement;
    await userEvent.selectOptions(select, String(60 * 60));

    await waitForToast(/session lifetime updated/i);
    expect(received).toEqual({ session_expiry_seconds: 60 * 60 });
    expect(await screen.findByText(/currently: 1 hour/i)).toBeInTheDocument();
  });

  it('rolls back the UI when the server rejects the new value', async () => {
    mockSettingsEndpoints(mkSettings({ session_expiry_seconds: 7 * 24 * 60 * 60 }));
    server.use(
      http.patch('/api/settings', () =>
        HttpResponse.json({ error: 'too short' }, { status: 400 }),
      ),
    );
    render(Settings);

    const select = (await screen.findByLabelText(/session expiry/i)) as HTMLSelectElement;
    await userEvent.selectOptions(select, String(60 * 60));

    await waitForToast(/failed to save/i);
    // Label reflects rolled-back value.
    expect(await screen.findByText(/currently: 7 days/i)).toBeInTheDocument();
  });

  it('shows a Custom option when the stored value is not a preset', async () => {
    mockSettingsEndpoints(mkSettings({ session_expiry_seconds: 12345 }));
    render(Settings);
    const select = (await screen.findByLabelText(/session expiry/i)) as HTMLSelectElement;
    expect(within(select).getByRole('option', { name: /custom/i })).toBeInTheDocument();
    expect(select.value).toBe('12345');
  });
});

describe('Settings — Restart', () => {
  it('shows the restart button', async () => {
    mockSettingsEndpoints();
    render(Settings);

    expect(await screen.findByRole('button', { name: /restart/i })).toBeInTheDocument();
  });

  it('requires confirmation before restarting', async () => {
    mockSettingsEndpoints();
    render(Settings);

    await screen.findByText('Restart service');
    await userEvent.click(screen.getByRole('button', { name: /restart/i }));

    const dialog = await screen.findByRole('dialog');
    expect(dialog).toHaveTextContent(/shut down and restart/i);
    expect(within(dialog).getByRole('button', { name: /restart now/i })).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: /cancel/i })).toBeInTheDocument();
  });

  it('cancels without sending the request', async () => {
    mockSettingsEndpoints();
    let called = false;
    server.use(
      http.post('/api/admin/restart', () => {
        called = true;
        return new HttpResponse(null, { status: 202 });
      }),
    );
    render(Settings);

    await screen.findByText('Restart service');
    await userEvent.click(screen.getByRole('button', { name: /restart/i }));

    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: /cancel/i }));

    expect(called).toBe(false);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('sends restart request and shows success toast', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    mockSettingsEndpoints();
    let restarted = false;
    server.use(
      http.post('/api/admin/restart', () => {
        restarted = true;
        return new HttpResponse(null, { status: 202 });
      }),
    );
    render(Settings);

    await screen.findByText('Restart service');
    await userEvent.click(screen.getByRole('button', { name: /restart/i }));

    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: /restart now/i }));

    expect(restarted).toBe(true);
    await waitForToast(/restart initiated/i);
    vi.useRealTimers();
  });
});
