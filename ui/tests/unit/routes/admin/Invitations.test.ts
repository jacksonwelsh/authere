import { describe, it, expect } from 'vitest';
import { render, screen, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '../../msw/server';
import { waitForToast } from '../../helpers/toasts';
import Invitations from '../../../../src/routes/admin/Invitations.svelte';
import { mkInvitation } from '../../msw/factories';

function mockList(items: ReturnType<typeof mkInvitation>[]) {
  server.use(http.get('/api/invitations', () => HttpResponse.json(items)));
}

describe('admin Invitations', () => {
  it('renders each invitation row with its status badge', async () => {
    mockList([
      mkInvitation({ id: 'id-1', label: 'alpha', status: 'active' }),
      mkInvitation({ id: 'id-2', label: 'beta', status: 'exhausted' }),
      mkInvitation({ id: 'id-3', label: 'gamma', status: 'expired' }),
    ]);
    render(Invitations);

    expect(await screen.findByTestId('row-id-1')).toHaveTextContent('alpha');
    expect(screen.getByTestId('row-id-2')).toHaveTextContent('exhausted');
    expect(screen.getByTestId('row-id-3')).toHaveTextContent('expired');
  });

  it('creates a new invitation and prepends it to the list', async () => {
    mockList([]);
    server.use(
      http.post('/api/invitations', async ({ request }) => {
        const body = (await request.json()) as { label?: string };
        return HttpResponse.json(mkInvitation({ id: 'new-id', label: body.label ?? null }));
      }),
    );
    render(Invitations);

    await userEvent.click(await screen.findByRole('button', { name: /new invitation/i }));
    await userEvent.type(screen.getByLabelText('Label'), 'Team onboarding');
    await userEvent.click(screen.getByRole('button', { name: 'Create' }));

    const row = await screen.findByTestId('row-new-id');
    expect(row).toHaveTextContent('Team onboarding');
    await waitForToast(/invitation created\./i);
  });

  it('copies the invite link to the clipboard via the icon button', async () => {
    mockList([mkInvitation({ id: 'copy-me', label: 'copyable' })]);
    render(Invitations);

    const row = await screen.findByTestId('row-copy-me');
    const copyBtn = within(row).getByRole('button', { name: /copy invite link/i });
    await userEvent.click(copyBtn);

    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
      expect.stringContaining('/register?invite=copy-me'),
    );
    await waitForToast(/invite link copied\./i);
  });

  it('deletes via confirmation modal', async () => {
    mockList([mkInvitation({ id: 'doomed', label: 'goodbye' })]);
    let deleted = false;
    server.use(
      http.delete('/api/invitations/doomed', () => {
        deleted = true;
        return new HttpResponse(null, { status: 204 });
      }),
    );
    render(Invitations);

    const row = await screen.findByTestId('row-doomed');
    await userEvent.click(within(row).getByRole('button', { name: /delete/i }));
    // Confirm in modal — there are now multiple "Delete" buttons; target the one inside dialog.
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: /delete/i }));

    expect(deleted).toBe(true);
    await waitForToast(/invitation deleted\./i);
    expect(screen.queryByTestId('row-doomed')).not.toBeInTheDocument();
  });
});
