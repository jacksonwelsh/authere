import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '../msw/server';
import Register from '../../../src/routes/Register.svelte';

describe('Register', () => {
  it('renders a password mismatch error when confirmation differs', async () => {
    render(Register);
    await userEvent.type(screen.getByLabelText('Password'), 'Passw0rd-abc!');
    await userEvent.type(screen.getByLabelText('Confirm password'), 'Different!');
    expect(await screen.findByText(/passwords do not match/i)).toBeInTheDocument();
  });

  it('clears the mismatch error once confirmation matches', async () => {
    render(Register);
    await userEvent.type(screen.getByLabelText('Password'), 'Passw0rd-abc!');
    await userEvent.type(screen.getByLabelText('Confirm password'), 'Different!');
    expect(screen.queryByText(/passwords do not match/i)).toBeInTheDocument();

    await userEvent.clear(screen.getByLabelText('Confirm password'));
    await userEvent.type(screen.getByLabelText('Confirm password'), 'Passw0rd-abc!');
    expect(screen.queryByText(/passwords do not match/i)).not.toBeInTheDocument();
  });

  it('marks the invite code valid on blur when the API returns valid=true', async () => {
    server.use(
      http.get('/api/register/validate-invite', () =>
        HttpResponse.json({ valid: true }),
      ),
    );
    render(Register);
    const invite = screen.getByLabelText('Invitation code');
    await userEvent.type(invite, 'good-code');
    invite.blur();
    expect(await screen.findByText(/valid invitation/i)).toBeInTheDocument();
  });

  it('marks the invite code invalid on blur when the API returns valid=false', async () => {
    server.use(
      http.get('/api/register/validate-invite', () =>
        HttpResponse.json({ valid: false }),
      ),
    );
    render(Register);
    const invite = screen.getByLabelText('Invitation code');
    await userEvent.type(invite, 'bad-code');
    invite.blur();
    expect(await screen.findByText(/invalid or expired/i)).toBeInTheDocument();
  });

  it('marks the invite code invalid on blur when the request errors out', async () => {
    server.use(
      http.get('/api/register/validate-invite', () =>
        HttpResponse.text('', { status: 500 }),
      ),
    );
    render(Register);
    const invite = screen.getByLabelText('Invitation code');
    await userEvent.type(invite, 'explode');
    invite.blur();
    expect(await screen.findByText(/invalid or expired/i)).toBeInTheDocument();
  });

  it('does not validate on blur when the code is empty', async () => {
    let called = false;
    server.use(
      http.get('/api/register/validate-invite', () => {
        called = true;
        return HttpResponse.json({ valid: true });
      }),
    );
    render(Register);
    const invite = screen.getByLabelText('Invitation code');
    invite.focus();
    invite.blur();
    expect(called).toBe(false);
  });

  it('shows "username taken" on 409 from register', async () => {
    server.use(
      http.post('/api/register', () => HttpResponse.text('', { status: 409 })),
    );
    render(Register);
    await userEvent.type(screen.getByLabelText('Username'), 'alice');
    await userEvent.type(screen.getByLabelText('Full name'), 'Alice');
    await userEvent.type(screen.getByLabelText('Password'), 'Passw0rd-abc!');
    await userEvent.type(screen.getByLabelText('Confirm password'), 'Passw0rd-abc!');
    await userEvent.click(screen.getByRole('button', { name: /create account/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/username is already taken/i);
  });

  it('disables submit when any required field is empty or passwords mismatch', async () => {
    render(Register);
    const submit = screen.getByRole('button', { name: /create account/i });
    expect(submit).toBeDisabled();

    await userEvent.type(screen.getByLabelText('Username'), 'alice');
    await userEvent.type(screen.getByLabelText('Full name'), 'Alice');
    await userEvent.type(screen.getByLabelText('Password'), 'Passw0rd-abc!');
    await userEvent.type(screen.getByLabelText('Confirm password'), 'nope');
    expect(submit).toBeDisabled();

    await userEvent.clear(screen.getByLabelText('Confirm password'));
    await userEvent.type(screen.getByLabelText('Confirm password'), 'Passw0rd-abc!');
    expect(submit).toBeEnabled();
  });
});
