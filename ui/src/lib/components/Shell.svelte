<script lang="ts">
  import { logout } from '../api';
  import { toasts } from '../toast.svelte';

  interface Props {
    activePage: string;
    username?: string;
    roles?: string[];
    children: import('svelte').Snippet;
  }
  let { activePage, username = '', roles = [], children }: Props = $props();

  const isAdmin = $derived(roles.includes('admin'));

  const adminNav = [
    { id: 'users',        label: 'Users',        icon: 'ph-users',                 href: '/admin' },
    { id: 'roles',        label: 'Roles',        icon: 'ph-shield-check',          href: '/admin/roles' },
    { id: 'applications', label: 'Applications', icon: 'ph-app-window',            href: '/admin/applications' },
    { id: 'invitations',  label: 'Invitations',  icon: 'ph-envelope-simple',       href: '/admin/invitations' },
    { id: 'audit',        label: 'Audit log',    icon: 'ph-list-magnifying-glass', href: '/admin/audit' },
    { id: 'settings',     label: 'Settings',     icon: 'ph-gear',                  href: '/admin/settings' },
  ];

  const userNav = [
    { id: 'account',     label: 'Account',     icon: 'ph-user',     href: '/account' },
    { id: 'credentials', label: 'Credentials', icon: 'ph-lock-key', href: '/credentials' },
  ];

  const nav = $derived(isAdmin ? adminNav : userNav);

  let drawerOpen = $state(false);

  async function handleLogout() {
    try {
      await logout();
      window.location.href = '/login';
    } catch {
      toasts.error('Logout failed.');
    }
  }

  function closeDrawer() { drawerOpen = false; }
  function openDrawer() { drawerOpen = true; }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape' && drawerOpen) closeDrawer();
  }

  // Close drawer whenever the active page changes (route navigation).
  $effect(() => {
    activePage;
    drawerOpen = false;
  });

  // Lock body scroll while the drawer is open.
  $effect(() => {
    if (typeof document === 'undefined') return;
    if (drawerOpen) {
      const prev = document.body.style.overflow;
      document.body.style.overflow = 'hidden';
      return () => { document.body.style.overflow = prev; };
    }
  });
</script>

<svelte:window onkeydown={onKeydown} />

<div class="shell">
  <!-- Mobile top bar (hidden on desktop) -->
  <header class="topbar">
    <button
      type="button"
      class="topbar-menu"
      aria-label="Open menu"
      aria-expanded={drawerOpen}
      aria-controls="mobile-nav-drawer"
      onclick={openDrawer}
      data-testid="mobile-menu-button"
    >
      <i class="ph ph-list"></i>
    </button>
    <a href={isAdmin ? '/admin' : '/account'} class="topbar-logo" aria-label="Authere home">
      <svg width="22" height="22" viewBox="0 0 22 22" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect width="22" height="22" rx="4" fill="#3B82F6" fill-opacity="0.15"/>
        <path d="M11 4L17 8v6l-6 4-6-4V8l6-4z" stroke="#3B82F6" stroke-width="1.5" stroke-linejoin="round" fill="none"/>
        <circle cx="11" cy="11" r="2" fill="#3B82F6"/>
      </svg>
      <span class="au-h4">authere</span>
    </a>
    {#if username}
      <a href="/account" class="topbar-user au-micro au-mono" aria-label="Account">{username}</a>
    {/if}
  </header>

  <!-- Left rail — desktop / tablet -->
  <nav class="rail" aria-label="Primary">
    <a href={isAdmin ? '/admin' : '/account'} class="rail-logo" aria-label="Authere home">
      <svg width="22" height="22" viewBox="0 0 22 22" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect width="22" height="22" rx="4" fill="#3B82F6" fill-opacity="0.15"/>
        <path d="M11 4L17 8v6l-6 4-6-4V8l6-4z" stroke="#3B82F6" stroke-width="1.5" stroke-linejoin="round" fill="none"/>
        <circle cx="11" cy="11" r="2" fill="#3B82F6"/>
      </svg>
      <span class="rail-wordmark au-h4">authere</span>
    </a>

    <ul class="rail-nav">
      {#each nav as item}
        <li>
          <a
            href={item.href}
            class="nav-item"
            class:active={activePage === item.id}
            aria-current={activePage === item.id ? 'page' : undefined}
          >
            <i class="ph {item.icon}"></i>
            <span>{item.label}</span>
          </a>
        </li>
      {/each}
    </ul>

    <div class="rail-footer">
      {#if username}
        <a href="/account" class="rail-user au-micro au-mono">{username}</a>
      {/if}
      <button class="nav-item logout-btn" onclick={handleLogout}>
        <i class="ph ph-sign-out"></i>
        <span>Sign out</span>
      </button>
    </div>
  </nav>

  <!-- Mobile drawer -->
  {#if drawerOpen}
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <button
      type="button"
      class="drawer-backdrop"
      aria-label="Close menu"
      onclick={closeDrawer}
      data-testid="drawer-backdrop"
    ></button>
    <div
      id="mobile-nav-drawer"
      class="drawer"
      role="dialog"
      aria-modal="true"
      aria-label="Primary navigation"
      tabindex="-1"
      data-testid="mobile-nav-drawer"
    >
      <div class="drawer-header">
        <a href={isAdmin ? '/admin' : '/account'} class="rail-logo" aria-label="Authere home">
          <svg width="22" height="22" viewBox="0 0 22 22" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect width="22" height="22" rx="4" fill="#3B82F6" fill-opacity="0.15"/>
            <path d="M11 4L17 8v6l-6 4-6-4V8l6-4z" stroke="#3B82F6" stroke-width="1.5" stroke-linejoin="round" fill="none"/>
            <circle cx="11" cy="11" r="2" fill="#3B82F6"/>
          </svg>
          <span class="rail-wordmark au-h4">authere</span>
        </a>
        <button
          type="button"
          class="drawer-close"
          aria-label="Close menu"
          onclick={closeDrawer}
          data-testid="drawer-close"
        >
          <i class="ph ph-x"></i>
        </button>
      </div>
      <ul class="rail-nav drawer-nav">
        {#each nav as item}
          <li>
            <a
              href={item.href}
              class="nav-item"
              class:active={activePage === item.id}
              aria-current={activePage === item.id ? 'page' : undefined}
              onclick={closeDrawer}
            >
              <i class="ph {item.icon}"></i>
              <span>{item.label}</span>
            </a>
          </li>
        {/each}
      </ul>
      <div class="rail-footer">
        {#if username}
          <a href="/account" class="rail-user au-micro au-mono" onclick={closeDrawer}>{username}</a>
        {/if}
        <button class="nav-item logout-btn" onclick={handleLogout}>
          <i class="ph ph-sign-out"></i>
          <span>Sign out</span>
        </button>
      </div>
    </div>
  {/if}

  <!-- Main content -->
  <main class="content">
    {@render children()}
  </main>
</div>

<style>
  .shell {
    display: flex;
    height: 100%;
  }

  .topbar {
    display: none;
  }

  .rail {
    width: 200px;
    flex-shrink: 0;
    background: var(--bg-1);
    border-right: 1px solid var(--border-0);
    display: flex;
    flex-direction: column;
    padding: var(--sp-3) 0;
  }

  .rail-logo {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    padding: var(--sp-1) var(--sp-3) var(--sp-3);
    text-decoration: none;
    color: var(--fg-1);
  }

  .rail-wordmark { color: var(--fg-1); }

  .rail-nav {
    list-style: none;
    flex: 1;
    padding: 0 var(--sp-2);
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .nav-item {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    padding: 0 var(--sp-2);
    height: 32px;
    border-radius: var(--radius);
    color: var(--fg-3);
    text-decoration: none;
    font-size: 13px;
    font-weight: 500;
    transition: background var(--duration-micro) var(--ease-out),
                color var(--duration-micro) var(--ease-out);
  }

  .nav-item i { font-size: 15px; }

  .nav-item:hover { background: var(--bg-3); color: var(--fg-2); }
  .nav-item.active { background: var(--bg-3); color: var(--fg-1); }

  .rail-footer {
    padding: var(--sp-3) var(--sp-2) 0;
    border-top: 1px solid var(--border-0);
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
  }

  .rail-user {
    display: block;
    padding: 0 var(--sp-2);
    color: var(--fg-4);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    text-decoration: none;
    border-radius: var(--radius);
    line-height: 28px;
    transition: color var(--duration-micro) var(--ease-out);
  }
  .rail-user:hover { color: var(--fg-2); }

  .logout-btn {
    width: 100%;
    background: none;
    border: none;
    cursor: pointer;
    text-align: left;
  }

  .content {
    flex: 1;
    overflow-y: auto;
    background: var(--bg-0);
  }

  /* ---------- Mobile / tablet ---------- */
  @media (max-width: 1023.98px) {
    .shell {
      flex-direction: column;
    }

    .topbar {
      display: flex;
      align-items: center;
      gap: var(--sp-3);
      height: 48px;
      padding: 0 var(--sp-3);
      background: var(--bg-1);
      border-bottom: 1px solid var(--border-0);
      flex-shrink: 0;
    }

    .topbar-menu {
      width: 40px;
      height: 40px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      background: none;
      border: none;
      color: var(--fg-2);
      cursor: pointer;
      border-radius: var(--radius);
      font-size: 20px;
    }
    .topbar-menu:hover { background: var(--bg-3); }

    .topbar-logo {
      display: flex;
      align-items: center;
      gap: var(--sp-2);
      color: var(--fg-1);
      text-decoration: none;
      flex: 1;
      min-width: 0;
    }

    .topbar-user {
      color: var(--fg-4);
      text-decoration: none;
      max-width: 40%;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .topbar-user:hover { color: var(--fg-2); }

    /* Hide the desktop rail; its content lives in the drawer. */
    .rail { display: none; }

    .drawer-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.6);
      z-index: 90;
      border: none;
      padding: 0;
      cursor: pointer;
      animation: drawerFade var(--duration-default) var(--ease-out);
    }

    .drawer {
      position: fixed;
      top: 0;
      left: 0;
      bottom: 0;
      width: min(280px, 80vw);
      background: var(--bg-1);
      border-right: 1px solid var(--border-1);
      z-index: 91;
      display: flex;
      flex-direction: column;
      padding: var(--sp-3) 0;
      animation: drawerSlide var(--duration-default) var(--ease-out);
    }

    .drawer-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 var(--sp-3);
    }

    .drawer-close {
      width: 36px;
      height: 36px;
      background: none;
      border: none;
      color: var(--fg-3);
      cursor: pointer;
      border-radius: var(--radius);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 18px;
    }
    .drawer-close:hover { background: var(--bg-3); color: var(--fg-1); }

    .drawer-nav { margin-top: var(--sp-3); }

    .drawer .nav-item {
      height: 44px;
      font-size: 15px;
      padding: 0 var(--sp-3);
    }
    .drawer .nav-item i { font-size: 18px; }

    .content {
      flex: 1;
      min-height: 0;
    }
  }

  @keyframes drawerFade { from { opacity: 0; } }
  @keyframes drawerSlide { from { transform: translateX(-100%); } }
</style>
