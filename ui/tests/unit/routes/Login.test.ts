import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '../msw/server';
import Login from '../../../src/routes/Login.svelte';

async function fillCredentials() {
  await userEvent.type(screen.getByLabelText('Username'), 'alice');
  await userEvent.type(screen.getByLabelText('Password'), 'Passw0rd-abc!');
}

describe('Login', () => {
  // Each test starts on a clean URL — `Login.svelte` reads `window.location.search`
  // at module evaluation, so tests that exercise the redirect_uri behavior must
  // set the location BEFORE rendering.
  beforeEach(() => {
    window.history.replaceState({}, '', '/login');
  });

  it('disables the submit button until username and password are present', async () => {
    render(Login);
    const submit = screen.getByRole('button', { name: /sign in/i });
    expect(submit).toBeDisabled();

    await userEvent.type(screen.getByLabelText('Username'), 'alice');
    expect(submit).toBeDisabled();

    await userEvent.type(screen.getByLabelText('Password'), 'Passw0rd-abc!');
    expect(submit).toBeEnabled();
  });

  it('shows "incorrect" message on 401', async () => {
    server.use(
      http.post('/api/auth/login', () => HttpResponse.text('nope', { status: 401 })),
    );
    render(Login);
    await fillCredentials();
    await userEvent.click(screen.getByRole('button', { name: /sign in/i }));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/username or password is incorrect/i);
  });

  it('shows rate-limit message on 429', async () => {
    server.use(
      http.post('/api/auth/login', () => HttpResponse.text('slow down', { status: 429 })),
    );
    render(Login);
    await fillCredentials();
    await userEvent.click(screen.getByRole('button', { name: /sign in/i }));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/too many attempts/i);
  });

  it('shows a generic failure message with the status code on other errors', async () => {
    server.use(
      http.post('/api/auth/login', () => HttpResponse.text('boom', { status: 500 })),
    );
    render(Login);
    await fillCredentials();
    await userEvent.click(screen.getByRole('button', { name: /sign in/i }));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/sign-in failed \(500\)/i);
  });

  it('re-enables the button after a failed submit', async () => {
    server.use(
      http.post('/api/auth/login', () => HttpResponse.text('', { status: 401 })),
    );
    render(Login);
    await fillCredentials();
    const submit = screen.getByRole('button', { name: /sign in/i });
    await userEvent.click(submit);
    await waitFor(() => expect(submit).toBeEnabled());
  });

  it('prompts for a TOTP code when the server signals mfa_required', async () => {
    server.use(
      http.post('/api/auth/login', () =>
        HttpResponse.json({ error: 'mfa_required' }, { status: 401 }),
      ),
    );
    render(Login);
    await fillCredentials();
    await userEvent.click(screen.getByRole('button', { name: /sign in/i }));

    // The UI should switch to a code-entry step and a new Verify button.
    await screen.findByLabelText(/authentication code/i);
    expect(screen.getByRole('button', { name: /verify/i })).toBeInTheDocument();
    // No error alert — mfa_required is expected flow, not a failure.
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('submits the TOTP code on the second step and surfaces invalid_totp', async () => {
    let call = 0;
    server.use(
      http.post('/api/auth/login', async ({ request }) => {
        call += 1;
        const body = (await request.json()) as { totp_code?: string };
        if (call === 1) {
          return HttpResponse.json({ error: 'mfa_required' }, { status: 401 });
        }
        expect(body.totp_code).toBe('123456');
        return HttpResponse.json({ error: 'invalid_totp' }, { status: 401 });
      }),
    );
    render(Login);
    await fillCredentials();
    await userEvent.click(screen.getByRole('button', { name: /sign in/i }));

    const codeInput = await screen.findByLabelText(/authentication code/i);
    await userEvent.type(codeInput, '123456');
    await userEvent.click(screen.getByRole('button', { name: /verify/i }));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/code did not match/i);
  });

  describe('forward auth app name', () => {
    function setForwardLoginUrl(target: string) {
      const inner = encodeURIComponent(`/api/auth/forward-redirect?redirect_uri=${encodeURIComponent(target)}`);
      window.history.replaceState({}, '', `/login?redirect_uri=${inner}`);
    }

    it('shows the app name when forward auth lookup succeeds', async () => {
      let lookedUpFor: string | null = null;
      server.use(
        http.get('/api/auth/forward-app', ({ request }) => {
          lookedUpFor = new URL(request.url).searchParams.get('redirect_uri');
          return HttpResponse.json({ name: 'Flood Tracker' });
        }),
      );
      setForwardLoginUrl('https://flood.example.com/dashboard');
      render(Login);

      await waitFor(() => {
        expect(screen.getByText(/sign in to continue to flood tracker\./i)).toBeInTheDocument();
      });
      expect(lookedUpFor).toBe('https://flood.example.com/dashboard');
    });

    it('falls back to the generic prompt when the lookup returns 404', async () => {
      server.use(
        http.get('/api/auth/forward-app', () => HttpResponse.text('not found', { status: 404 })),
      );
      setForwardLoginUrl('https://unknown.example.com/');
      render(Login);

      // Generic prompt is rendered synchronously; wait a tick for the lookup to settle
      // and confirm we never swap to a "continue to ..." message.
      await waitFor(() => {
        expect(screen.getByText('Sign in to continue.')).toBeInTheDocument();
      });
      expect(screen.queryByText(/sign in to continue to /i)).toBeNull();
    });

    it('does not call the lookup endpoint for non-forward-auth redirect_uri values', async () => {
      let called = false;
      server.use(
        http.get('/api/auth/forward-app', () => {
          called = true;
          return HttpResponse.json({ name: 'Should Not Show' });
        }),
      );
      // A plain in-app path (e.g., admin link) should not trigger a lookup.
      window.history.replaceState({}, '', '/login?redirect_uri=%2Fadmin%2Fusers');
      render(Login);

      // Give the microtask queue a chance to fire any spurious request.
      await new Promise(r => setTimeout(r, 10));
      expect(called).toBe(false);
      expect(screen.getByText('Sign in to continue.')).toBeInTheDocument();
    });
  });
});
