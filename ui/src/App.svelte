<script lang="ts">
  import { onMount } from 'svelte';
  import { getMe, type Me } from './lib/api';
  import Shell from './lib/components/Shell.svelte';
  import Toast from './lib/components/Toast.svelte';
  import { toasts } from './lib/toast.svelte';

  import Login from './routes/Login.svelte';
  import Register from './routes/Register.svelte';
  import Account from './routes/Account.svelte';
  import Credentials from './routes/Credentials.svelte';
  import Users from './routes/admin/Users.svelte';
  import Roles from './routes/admin/Roles.svelte';
  import Applications from './routes/admin/Applications.svelte';
  import AuditLog from './routes/admin/AuditLog.svelte';
  import Settings from './routes/admin/Settings.svelte';
  import Invitations from './routes/admin/Invitations.svelte';

  type Page = 'login' | 'register' | 'users' | 'roles' | 'applications' | 'audit' | 'settings' | 'invitations' | 'account' | 'credentials';

  let me = $state<Me | null>(null);
  let ready = $state(false);

  // Simple client-side routing from pathname
  function parsePage(): Page {
    const p = window.location.pathname;
    if (p.startsWith('/admin/roles'))        return 'roles';
    if (p.startsWith('/admin/applications')) return 'applications';
    if (p.startsWith('/admin/audit'))        return 'audit';
    if (p.startsWith('/admin/settings'))     return 'settings';
    if (p.startsWith('/admin/invitations'))  return 'invitations';
    if (p.startsWith('/admin'))              return 'users';
    if (p.startsWith('/register'))           return 'register';
    if (p.startsWith('/account'))            return 'account';
    if (p.startsWith('/credentials'))        return 'credentials';
    return 'login';
  }

  let page = $state<Page>(parsePage());

  onMount(async () => {
    // Root — redirect based on role
    if (window.location.pathname === '/') {
      try {
        const meData = await getMe();
        window.location.href = meData.roles.includes('admin') ? '/admin' : '/account';
      } catch {
        window.location.href = '/login';
      }
      return;
    }

    const publicPages: Page[] = ['login', 'register'];
    if (!publicPages.includes(page)) {
      try {
        me = await getMe();
      } catch {
        // Not authenticated — redirect to login
        const redirectUri = encodeURIComponent(window.location.pathname + window.location.search);
        window.location.href = `/login?redirect_uri=${redirectUri}`;
        return;
      }
    }
    ready = true;

    if (sessionStorage.getItem('authere:registrationSuccess') === '1') {
      sessionStorage.removeItem('authere:registrationSuccess');
      toasts.success('Account created successfully.');
    }
  });

  // Handle browser back/forward
  function onpopstate() { page = parsePage(); }
</script>

<svelte:window {onpopstate} />

{#if ready}
  {#if page === 'login'}
    <Login />
  {:else if page === 'register'}
    <Register />
  {:else}
    <Shell activePage={page} username={me?.user_id ?? ''} roles={me?.roles ?? []}>
      {#if page === 'users'}
        <Users />
      {:else if page === 'roles'}
        <Roles />
      {:else if page === 'applications'}
        <Applications />
      {:else if page === 'audit'}
        <AuditLog />
      {:else if page === 'settings'}
        <Settings />
      {:else if page === 'invitations'}
        <Invitations />
      {:else if page === 'account'}
        <Account me={me!} />
      {:else if page === 'credentials'}
        <Credentials />
      {/if}
    </Shell>
  {/if}
{/if}

<Toast items={toasts.items} onremove={(id) => toasts.remove(id)} />
