import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { createRawSnippet } from 'svelte';
import Modal from '../../../src/lib/components/Modal.svelte';

const body = createRawSnippet(() => ({
  render: () => '<p>Modal body content</p>',
}));

describe('Modal', () => {
  it('renders title and body', () => {
    render(Modal, { props: { title: 'Confirm', onclose: () => {}, children: body } });
    expect(screen.getByRole('heading', { name: 'Confirm' })).toBeInTheDocument();
    expect(screen.getByText('Modal body content')).toBeInTheDocument();
  });

  it('calls onclose when the close button is clicked', async () => {
    const onclose = vi.fn();
    render(Modal, { props: { title: 'X', onclose, children: body } });
    await userEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(onclose).toHaveBeenCalledOnce();
  });

  it('calls onclose when the backdrop is clicked', async () => {
    const onclose = vi.fn();
    const { container } = render(Modal, {
      props: { title: 'X', onclose, children: body },
    });
    const overlay = container.querySelector('.overlay')!;
    await userEvent.click(overlay);
    expect(onclose).toHaveBeenCalledOnce();
  });

  it('does NOT close when clicking inside the modal body', async () => {
    const onclose = vi.fn();
    render(Modal, { props: { title: 'X', onclose, children: body } });
    await userEvent.click(screen.getByText('Modal body content'));
    expect(onclose).not.toHaveBeenCalled();
  });

  it('calls onclose when Escape is pressed', async () => {
    const onclose = vi.fn();
    render(Modal, { props: { title: 'X', onclose, children: body } });
    await userEvent.keyboard('{Escape}');
    expect(onclose).toHaveBeenCalledOnce();
  });
});
