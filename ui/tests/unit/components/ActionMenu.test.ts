import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { createRawSnippet } from 'svelte';
import ActionMenu from '../../../src/lib/components/ActionMenu.svelte';

function itemsSnippet() {
  // Two buttons so we can verify menu-close-on-click behaviour.
  return createRawSnippet(() => ({
    render: () => `
      <button type="button" class="btn" data-testid="edit">Edit</button>
      <button type="button" class="btn" data-testid="delete">Delete</button>
    `,
  }));
}

describe('ActionMenu', () => {
  it('is closed by default; the trigger has aria-expanded=false', () => {
    render(ActionMenu, { props: { children: itemsSnippet() } });
    const trigger = screen.getByTestId('action-menu-trigger');
    expect(trigger).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByTestId('action-menu')).not.toBeInTheDocument();
  });

  it('opens the menu when the trigger is clicked', async () => {
    render(ActionMenu, { props: { children: itemsSnippet() } });
    const trigger = screen.getByTestId('action-menu-trigger');
    await userEvent.click(trigger);
    expect(trigger).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByTestId('action-menu')).toBeInTheDocument();
    expect(screen.getByTestId('edit')).toBeInTheDocument();
  });

  it('closes on Escape', async () => {
    render(ActionMenu, { props: { children: itemsSnippet() } });
    await userEvent.click(screen.getByTestId('action-menu-trigger'));
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByTestId('action-menu')).not.toBeInTheDocument();
  });

  it('closes when an item inside the menu is clicked', async () => {
    render(ActionMenu, { props: { children: itemsSnippet() } });
    await userEvent.click(screen.getByTestId('action-menu-trigger'));
    await userEvent.click(screen.getByTestId('edit'));
    expect(screen.queryByTestId('action-menu')).not.toBeInTheDocument();
  });

  it('closes when clicking outside the menu', async () => {
    render(ActionMenu, { props: { children: itemsSnippet() } });
    await userEvent.click(screen.getByTestId('action-menu-trigger'));
    expect(screen.getByTestId('action-menu')).toBeInTheDocument();
    // Click on the document body, outside any menu/trigger ancestor.
    await userEvent.click(document.body);
    expect(screen.queryByTestId('action-menu')).not.toBeInTheDocument();
  });
});
