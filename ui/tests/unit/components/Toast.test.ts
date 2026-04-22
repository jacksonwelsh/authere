import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import Toast from '../../../src/lib/components/Toast.svelte';
import type { ToastItem } from '../../../src/lib/components/Toast.svelte';

describe('Toast', () => {
  it('renders each item with role=status and correct message', () => {
    const items: ToastItem[] = [
      { id: '1', message: 'Saved', variant: 'success' },
      { id: '2', message: 'Oops', variant: 'danger' },
    ];
    render(Toast, { props: { items, onremove: () => {} } });
    const statuses = screen.getAllByRole('status');
    expect(statuses).toHaveLength(2);
    expect(statuses[0]).toHaveTextContent('Saved');
    expect(statuses[1]).toHaveTextContent('Oops');
  });

  it('exposes aria-live=polite on the stack', () => {
    const { container } = render(Toast, {
      props: { items: [], onremove: () => {} },
    });
    expect(container.querySelector('[aria-live="polite"]')).not.toBeNull();
  });

  it('calls onremove with the item id when dismiss is clicked', async () => {
    const items: ToastItem[] = [{ id: 'abc', message: 'Hi', variant: 'default' }];
    const onremove = vi.fn();
    render(Toast, { props: { items, onremove } });
    await userEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
    expect(onremove).toHaveBeenCalledWith('abc');
  });
});
