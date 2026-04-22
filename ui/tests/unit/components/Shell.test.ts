import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { createRawSnippet } from 'svelte';
import Shell from '../../../src/lib/components/Shell.svelte';

const children = createRawSnippet(() => ({
  render: () => '<main data-testid="page-content">Hello</main>',
}));

function renderAdminShell() {
  return render(Shell, {
    props: {
      activePage: 'users',
      username: 'jackson',
      roles: ['admin'],
      children,
    },
  });
}

describe('Shell (mobile drawer)', () => {
  it('renders the mobile menu button with aria-expanded=false by default', () => {
    renderAdminShell();
    const btn = screen.getByTestId('mobile-menu-button');
    expect(btn).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByTestId('mobile-nav-drawer')).not.toBeInTheDocument();
  });

  it('opens the drawer when the menu button is clicked', async () => {
    renderAdminShell();
    await userEvent.click(screen.getByTestId('mobile-menu-button'));
    expect(screen.getByTestId('mobile-nav-drawer')).toBeInTheDocument();
    expect(screen.getByTestId('mobile-menu-button')).toHaveAttribute('aria-expanded', 'true');
    // Admin nav items appear inside the drawer.
    const drawer = screen.getByTestId('mobile-nav-drawer');
    expect(drawer.textContent).toContain('Users');
    expect(drawer.textContent).toContain('Invitations');
  });

  it('closes the drawer when Escape is pressed', async () => {
    renderAdminShell();
    await userEvent.click(screen.getByTestId('mobile-menu-button'));
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByTestId('mobile-nav-drawer')).not.toBeInTheDocument();
  });

  it('closes the drawer when the backdrop is clicked', async () => {
    renderAdminShell();
    await userEvent.click(screen.getByTestId('mobile-menu-button'));
    await userEvent.click(screen.getByTestId('drawer-backdrop'));
    expect(screen.queryByTestId('mobile-nav-drawer')).not.toBeInTheDocument();
  });

  it('closes the drawer when the explicit close button is pressed', async () => {
    renderAdminShell();
    await userEvent.click(screen.getByTestId('mobile-menu-button'));
    await userEvent.click(screen.getByTestId('drawer-close'));
    expect(screen.queryByTestId('mobile-nav-drawer')).not.toBeInTheDocument();
  });

  it('locks body scroll while the drawer is open', async () => {
    renderAdminShell();
    expect(document.body.style.overflow).not.toBe('hidden');
    await userEvent.click(screen.getByTestId('mobile-menu-button'));
    expect(document.body.style.overflow).toBe('hidden');
    await userEvent.keyboard('{Escape}');
    expect(document.body.style.overflow).not.toBe('hidden');
  });

  it('still renders page content in all cases', () => {
    renderAdminShell();
    expect(screen.getByTestId('page-content')).toBeInTheDocument();
  });
});
