import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '../msw/server';
import { waitForToast } from '../helpers/toasts';
import Account from '../../../src/routes/Account.svelte';
import { mkMe, mkUser } from '../msw/factories';

const me = mkMe({ username: 'alice', name: 'Alice Example', email: 'alice@example.com' });

describe('Account', () => {
  it('pre-fills fields from the me prop', () => {
    render(Account, { props: { me } });
    expect(screen.getByLabelText('Full name')).toHaveValue('Alice Example');
    expect(screen.getByLabelText('Username')).toHaveValue('alice');
    expect(screen.getByLabelText('Email')).toHaveValue('alice@example.com');
  });

  it('disables save when name or username is empty', async () => {
    render(Account, { props: { me } });
    const save = screen.getByRole('button', { name: /save changes/i });
    expect(save).toBeEnabled();
    await userEvent.clear(screen.getByLabelText('Full name'));
    expect(save).toBeDisabled();
  });

  it('sends PATCH with edited fields and shows a success toast', async () => {
    let received: any = null;
    server.use(
      http.patch('/api/me', async ({ request }) => {
        received = await request.json();
        return HttpResponse.json(mkUser({ ...received }));
      }),
    );

    render(Account, { props: { me } });
    const nameField = screen.getByLabelText('Full name');
    await userEvent.clear(nameField);
    await userEvent.type(nameField, 'Alice Example II');

    await userEvent.click(screen.getByRole('button', { name: /save changes/i }));

    await waitForToast(/profile updated\./i);
    expect(received).toEqual({
      name: 'Alice Example II',
      username: 'alice',
      email: 'alice@example.com',
    });
  });

  it('shows an error toast when the API fails', async () => {
    server.use(
      http.patch('/api/me', () => HttpResponse.text('boom', { status: 500 })),
    );
    render(Account, { props: { me } });
    await userEvent.click(screen.getByRole('button', { name: /save changes/i }));
    await waitForToast(/failed to update/i);
  });

  it('submits on Enter when the form area is focused', async () => {
    let called = false;
    server.use(
      http.patch('/api/me', async ({ request }) => {
        called = true;
        const body = (await request.json()) as any;
        return HttpResponse.json(mkUser(body));
      }),
    );
    render(Account, { props: { me } });
    const nameField = screen.getByLabelText('Full name');
    nameField.focus();
    await userEvent.keyboard('{Enter}');
    await waitForToast(/profile updated\./i);
    expect(called).toBe(true);
  });
});
