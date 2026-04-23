import { describe, it, expect, vi } from 'vitest';
import { render, screen, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '../../msw/server';
import { waitForToast } from '../../helpers/toasts';
import Settings from '../../../../src/routes/admin/Settings.svelte';
import { mkSettings, mkScimToken } from '../../msw/factories';

function mockSettingsEndpoints(
  settings = mkSettings(),
  scimTokens = [] as ReturnType<typeof mkScimToken>[],
) {
  server.use(
    http.get('/api/settings', () => HttpResponse.json(settings)),
    http.get('/api/roles', () => HttpResponse.json([])),
    http.get('/api/scim/tokens', () => HttpResponse.json(scimTokens)),
  );
}

describe('Settings — SCIM tokens', () => {
  it('shows empty state when no tokens exist', async () => {
    mockSettingsEndpoints();
    render(Settings);

    expect(await screen.findByText(/no scim tokens yet/i)).toBeInTheDocument();
  });

  it('renders existing SCIM tokens', async () => {
    mockSettingsEndpoints(mkSettings(), [
      mkScimToken({ id: 't-1', name: 'Okta' }),
      mkScimToken({ id: 't-2', name: 'Azure AD' }),
    ]);
    render(Settings);

    expect(await screen.findByText('Okta')).toBeInTheDocument();
    expect(screen.getByText('Azure AD')).toBeInTheDocument();
  });

  it('creates a new SCIM token and reveals it once', async () => {
    mockSettingsEndpoints();
    server.use(
      http.post('/api/scim/tokens', async ({ request }) => {
        const body = (await request.json()) as { name: string };
        return HttpResponse.json(
          {
            id: 'new-tok',
            name: body.name,
            created_at: 1700000000,
            token: 'authere_scim_abcdef1234567890',
          },
          { status: 201 },
        );
      }),
    );
    render(Settings);

    await screen.findByText(/no scim tokens yet/i);
    await userEvent.click(screen.getByRole('button', { name: /new token/i }));

    const dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText('Name'), 'Okta Production');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Create' }));

    const reveal = await screen.findByText('authere_scim_abcdef1234567890');
    expect(reveal).toBeInTheDocument();
  });

  it('revokes a SCIM token', async () => {
    mockSettingsEndpoints(mkSettings(), [
      mkScimToken({ id: 'doomed', name: 'Old IdP' }),
    ]);
    let revoked = false;
    server.use(
      http.delete('/api/scim/tokens/doomed', () => {
        revoked = true;
        return new HttpResponse(null, { status: 204 });
      }),
    );
    render(Settings);

    expect(await screen.findByText('Old IdP')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /revoke/i }));

    expect(revoked).toBe(true);
    await waitForToast(/token revoked\./i);
    expect(screen.queryByText('Old IdP')).not.toBeInTheDocument();
  });

  it('copies the token to clipboard from the reveal modal', async () => {
    mockSettingsEndpoints();
    server.use(
      http.post('/api/scim/tokens', () =>
        HttpResponse.json(
          { id: 'x', name: 'Test', created_at: 1700000000, token: 'authere_scim_secret123' },
          { status: 201 },
        ),
      ),
    );
    render(Settings);

    await screen.findByText(/no scim tokens yet/i);
    await userEvent.click(screen.getByRole('button', { name: /new token/i }));

    const dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText('Name'), 'Test');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Create' }));

    await screen.findByText('authere_scim_secret123');
    await userEvent.click(screen.getByRole('button', { name: /copy/i }));

    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('authere_scim_secret123');
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
