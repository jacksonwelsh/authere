import { describe, it, expect } from 'vitest';
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
});
