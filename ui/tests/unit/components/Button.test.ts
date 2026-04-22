import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import Button from '../../../src/lib/components/Button.svelte';
import { createRawSnippet } from 'svelte';

function text(label: string) {
  return createRawSnippet(() => ({ render: () => `<span>${label}</span>` }));
}

describe('Button', () => {
  it('renders label from snippet', () => {
    render(Button, { props: { children: text('Save') } });
    expect(screen.getByRole('button', { name: 'Save' })).toBeInTheDocument();
  });

  it('invokes onclick when clicked', async () => {
    const onclick = vi.fn();
    render(Button, { props: { children: text('Save'), onclick } });
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(onclick).toHaveBeenCalledOnce();
  });

  it('is disabled and skips onclick when disabled', async () => {
    const onclick = vi.fn();
    render(Button, { props: { children: text('Save'), onclick, disabled: true } });
    const btn = screen.getByRole('button', { name: 'Save' });
    expect(btn).toBeDisabled();
    await userEvent.click(btn);
    expect(onclick).not.toHaveBeenCalled();
  });

  it('shows loading spinner and exposes aria-busy=true when loading', () => {
    render(Button, { props: { children: text('Save'), loading: true } });
    const btn = screen.getByRole('button', { name: /save/i });
    expect(btn).toHaveAttribute('aria-busy', 'true');
    expect(btn.querySelector('.spin')).not.toBeNull();
  });

  it('applies variant and size classes', () => {
    render(Button, { props: { children: text('X'), variant: 'danger', size: 'lg' } });
    const btn = screen.getByRole('button', { name: 'X' });
    expect(btn).toHaveClass('btn-danger', 'btn-lg');
  });
});
