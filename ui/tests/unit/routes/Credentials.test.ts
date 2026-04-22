import { describe, it, expect } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '../msw/server';
import { waitForToast } from '../helpers/toasts';
import Credentials from '../../../src/routes/Credentials.svelte';
import { mkSettings, mkAppPassword } from '../msw/factories';

function mockSettings(partial: Partial<ReturnType<typeof mkSettings>> = {}) {
  server.use(
    http.get('/api/settings', () => HttpResponse.json(mkSettings(partial))),
  );
}

function mockAppPasswords(pws: ReturnType<typeof mkAppPassword>[] = []) {
  server.use(
    http.get('/api/me/app-passwords', () => HttpResponse.json(pws)),
  );
}

describe('Credentials — password change', () => {
  it('shows a length error when new password is under 12 chars', async () => {
    mockSettings();
    mockAppPasswords();
    render(Credentials);
    await userEvent.type(screen.getByLabelText('New password'), 'short');
    expect(await screen.findByText(/at least 12 characters/i)).toBeInTheDocument();
  });

  it('shows a mismatch error when confirmation differs', async () => {
    mockSettings();
    mockAppPasswords();
    render(Credentials);
    await userEvent.type(screen.getByLabelText('New password'), 'Passw0rd-abc!');
    await userEvent.type(screen.getByLabelText('Confirm new password'), 'Passw0rd-abc!x');
    expect(await screen.findByText(/passwords do not match/i)).toBeInTheDocument();
  });

  it('disables the change-password button until all three fields are valid', async () => {
    mockSettings();
    mockAppPasswords();
    render(Credentials);
    const btn = screen.getByRole('button', { name: /change password/i });
    expect(btn).toBeDisabled();
    await userEvent.type(screen.getByLabelText('Current password'), 'Current-1234');
    await userEvent.type(screen.getByLabelText('New password'), 'Passw0rd-abc!');
    await userEvent.type(screen.getByLabelText('Confirm new password'), 'Passw0rd-abc!');
    expect(btn).toBeEnabled();
  });

  it('shows a toast when current password is wrong (401)', async () => {
    mockSettings();
    mockAppPasswords();
    server.use(
      http.patch('/api/me/password', () => HttpResponse.text('', { status: 401 })),
    );
    render(Credentials);
    await userEvent.type(screen.getByLabelText('Current password'), 'Current-1234');
    await userEvent.type(screen.getByLabelText('New password'), 'Passw0rd-abc!');
    await userEvent.type(screen.getByLabelText('Confirm new password'), 'Passw0rd-abc!');
    await userEvent.click(screen.getByRole('button', { name: /change password/i }));
    await waitForToast(/current password is incorrect/i);
  });
});

describe('Credentials — app passwords', () => {
  it('hides the app-passwords section when ldap password_mode is primary_only', async () => {
    mockSettings({
      ldap: {
        enabled: false,
        base_dn: 'dc=example,dc=com',
        bind_address: '0.0.0.0:389',
        service_account_dn: 'cn=authere,dc=example,dc=com',
        service_password_set: false,
        password_mode: 'primary_only',
      },
    });
    render(Credentials);
    await waitFor(() => {
      expect(screen.queryByRole('heading', { name: /app passwords/i })).not.toBeInTheDocument();
    });
  });

  it('shows the app-passwords section and lists existing ones', async () => {
    mockSettings();
    mockAppPasswords([
      mkAppPassword({ name: 'Jellyfin' }),
      mkAppPassword({ name: 'Photo app' }),
    ]);
    render(Credentials);
    expect(await screen.findByRole('heading', { name: /app passwords/i })).toBeInTheDocument();
    expect(await screen.findByText('Jellyfin')).toBeInTheDocument();
    expect(await screen.findByText('Photo app')).toBeInTheDocument();
  });

  it('reveals the freshly-minted password in a one-time modal', async () => {
    mockSettings();
    mockAppPasswords();
    server.use(
      http.post('/api/me/app-passwords', async ({ request }) => {
        const body = (await request.json()) as { name: string };
        return HttpResponse.json({
          app_password: mkAppPassword({ name: body.name }),
          password: 'super-secret-abc123',
        });
      }),
    );
    render(Credentials);

    await userEvent.click(await screen.findByRole('button', { name: /new app password/i }));
    await userEvent.type(screen.getByLabelText('Name'), 'Jellyfin');
    await userEvent.click(screen.getByRole('button', { name: 'Create' }));

    expect(await screen.findByText('super-secret-abc123')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /app password created/i })).toBeInTheDocument();
  });
});
