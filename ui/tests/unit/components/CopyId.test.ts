import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import CopyId from '../../../src/lib/components/CopyId.svelte';

describe('CopyId', () => {
  it('shows the last 12 characters of the ID', () => {
    render(CopyId, { props: { id: '0123456789abcdef0123456789abcdef' } });
    expect(screen.getByRole('button')).toHaveTextContent('…456789abcdef');
  });

  it('writes the full id to the clipboard when clicked', async () => {
    const full = 'full-id-value-12345';
    render(CopyId, { props: { id: full } });
    await userEvent.click(screen.getByRole('button'));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(full);
  });

  it('exposes an aria-label with the full id', () => {
    render(CopyId, { props: { id: 'abc' } });
    expect(screen.getByRole('button', { name: 'Copy ID abc' })).toBeInTheDocument();
  });
});
