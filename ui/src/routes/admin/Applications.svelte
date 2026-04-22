<script lang="ts">
  import { onMount } from 'svelte';
  import {
    getApplications, getRoles, createApplication, updateApplication, deleteApplication,
    type Application, type Role
  } from '../../lib/api';
  import Button from '../../lib/components/Button.svelte';
  import Badge from '../../lib/components/Badge.svelte';
  import Input from '../../lib/components/Input.svelte';
  import Modal from '../../lib/components/Modal.svelte';
  import ResponsiveTable from '../../lib/components/ResponsiveTable.svelte';
  import { toasts } from '../../lib/toast.svelte';

  let apps = $state<Application[]>([]);
  let roles = $state<Role[]>([]);
  let loading = $state(true);
  let editApp = $state<Partial<Application> | null>(null);
  let isEditing = $state(false); // false = create, true = update
  let confirmDelete = $state<Application | null>(null);
  let configApp = $state<Application | null>(null);
  let saving = $state(false);
  let deleting = $state(false);

  let form = $state({ name: '', slug: '', host_pattern: '', path_prefix: '', required_roles: [] as string[] });

  // Best-effort extraction of a concrete hostname from a regex host_pattern.
  // Handles common cases like `^app\.example\.com$` → `app.example.com`.
  function guessHostname(pattern: string): string | null {
    let s = pattern.trim();
    if (s.startsWith('^')) s = s.slice(1);
    if (s.endsWith('$')) s = s.slice(0, -1);
    s = s.replace(/\\\./g, '.');
    if (/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i.test(s) && s.includes('.')) return s;
    return null;
  }

  function buildCaddySnippet(app: Application): string {
    const origin = window.location.origin;
    let upstreamHost = origin.replace(/^https?:\/\//, '');
    let tlsLines = '';
    try {
      const u = new URL(origin);
      upstreamHost = u.host;
      if (u.protocol === 'https:') {
        tlsLines = '\n        transport http {\n            tls\n        }';
      }
    } catch {}

    const host = guessHostname(app.host_pattern) ?? 'your-app.example.com';
    const patternComment = `# host_pattern: ${app.host_pattern}`;
    const pathComment = app.path_prefix ? `\n    # path_prefix: ${app.path_prefix}` : '';

    return `${patternComment}${pathComment}
${host} {
    forward_auth ${upstreamHost} {
        uri /api/auth/verify
        copy_headers X-Auth-User X-Auth-Username X-Auth-Roles X-Auth-Email${tlsLines}
    }
    reverse_proxy YOUR_UPSTREAM:8080
}`;
  }

  async function copyConfig() {
    if (!configApp) return;
    try {
      await navigator.clipboard.writeText(buildCaddySnippet(configApp));
      toasts.success('Caddy config copied.');
    } catch {
      toasts.error('Could not copy to clipboard.');
    }
  }

  onMount(async () => {
    try {
      [apps, roles] = await Promise.all([getApplications(), getRoles()]);
    } catch {
      toasts.error('Failed to load applications.');
    } finally {
      loading = false;
    }
  });

  function openCreate() {
    form = { name: '', slug: '', host_pattern: '', path_prefix: '', required_roles: [] };
    editApp = {};
    isEditing = false;
  }

  function openEdit(app: Application) {
    form = {
      name: app.name,
      slug: app.slug,
      host_pattern: app.host_pattern,
      path_prefix: app.path_prefix ?? '',
      required_roles: [...app.required_roles],
    };
    editApp = app;
    isEditing = true;
  }

  function toggleRole(roleId: string) {
    form.required_roles = form.required_roles.includes(roleId)
      ? form.required_roles.filter(r => r !== roleId)
      : [...form.required_roles, roleId];
  }

  async function handleSave() {
    if (saving) return;
    saving = true;
    try {
      const data = {
        name: form.name,
        slug: form.slug,
        host_pattern: form.host_pattern,
        path_prefix: form.path_prefix || null,
        required_roles: form.required_roles,
      };
      if (isEditing && editApp && 'id' in editApp) {
        const updated = await updateApplication(editApp.id!, data);
        apps = apps.map(a => a.id === updated.id ? updated : a);
        toasts.success('Application updated.');
      } else {
        const created = await createApplication(data);
        apps = [...apps, created];
        toasts.success('Application created.');
      }
      editApp = null;
    } catch (err: any) {
      toasts.error(`Failed to save: ${err.message}`);
    } finally {
      saving = false;
    }
  }

  async function handleDelete(app: Application) {
    if (deleting) return;
    deleting = true;
    try {
      await deleteApplication(app.id);
      apps = apps.filter(a => a.id !== app.id);
      confirmDelete = null;
      toasts.success('Application deleted.');
    } catch (err: any) {
      toasts.error(`Failed to delete: ${err.message}`);
    } finally {
      deleting = false;
    }
  }

  const roleMap = $derived(Object.fromEntries(roles.map(r => [r.id, r.name])));
</script>

<div class="page">
  <header class="page-header">
    <div>
      <h1 class="au-h3">Applications</h1>
      <p class="au-micro au-fg-3">{apps.length} registered</p>
    </div>
    <Button variant="primary" onclick={openCreate}>
      <i class="ph ph-plus"></i> Add application
    </Button>
  </header>

  {#if loading}
    <div class="page-loading au-fg-4 au-small">
      <i class="ph ph-circle-notch spin"></i> Loading…
    </div>
  {:else}
    <ResponsiveTable
      label="Applications"
      items={apps}
      getKey={(a) => a.id}
      columns={[
        { key: 'name',    label: 'Name',          tdClass: 'au-fg-1 font-medium' },
        { key: 'slug',    label: 'Slug',          tdClass: 'au-mono au-code-sm au-fg-3' },
        { key: 'host',    label: 'Host pattern',  tdClass: 'au-code-sm au-fg-3' },
        { key: 'roles',   label: 'Required roles' },
      ]}
    >
      {#snippet cell({ item, column })}
        {#if column.key === 'name'}{item.name}
        {:else if column.key === 'slug'}{item.slug}
        {:else if column.key === 'host'}{item.host_pattern}
        {:else if column.key === 'roles'}
          <div class="roles-cell">
            {#each item.required_roles as roleId}
              <Badge>{roleMap[roleId] ?? roleId}</Badge>
            {/each}
            {#if item.required_roles.length === 0}
              <span class="au-fg-5 au-micro">public</span>
            {/if}
          </div>
        {/if}
      {/snippet}
      {#snippet actions({ item })}
        <Button size="sm" variant="ghost" onclick={() => configApp = item}>Config</Button>
        <Button size="sm" variant="ghost" onclick={() => openEdit(item)}>Edit</Button>
        <Button size="sm" variant="ghost" onclick={() => confirmDelete = item}>Delete</Button>
      {/snippet}
      {#snippet empty()}No applications yet.{/snippet}
    </ResponsiveTable>
  {/if}
</div>

{#if editApp !== null}
  <Modal title={isEditing ? 'Edit application' : 'Add application'} onclose={() => editApp = null}>
    <div class="modal-form">
      <Input label="Name" bind:value={form.name} placeholder="My App" />
      <Input label="Slug" bind:value={form.slug} placeholder="my-app" />
      <Input label="Host pattern (regex)" bind:value={form.host_pattern} placeholder="^app\.example\.com$" />
      <Input label="Path prefix (optional)" bind:value={form.path_prefix} placeholder="/protected" />

      <div class="role-picker">
        <p class="au-nano au-fg-3">Required roles</p>
        <div class="role-options">
          {#each roles as role (role.id)}
            {@const checked = form.required_roles.includes(role.id)}
            <label class="role-option" class:checked>
              <input type="checkbox" {checked} onchange={() => toggleRole(role.id)} />
              <span class="au-small">{role.name}</span>
            </label>
          {/each}
        </div>
      </div>
    </div>
    {#snippet actions()}
      <Button variant="secondary" onclick={() => editApp = null}>Cancel</Button>
      <Button variant="primary" loading={saving} disabled={!form.name || !form.slug || !form.host_pattern || saving} onclick={handleSave}>
        {isEditing ? 'Save changes' : 'Create application'}
      </Button>
    {/snippet}
  </Modal>
{/if}

{#if configApp}
  <Modal title="Caddy forward auth config" width={640} onclose={() => configApp = null}>
    <div class="config-body">
      <p class="au-small au-fg-3">
        Drop this into your Caddyfile to protect <span class="au-mono">{configApp.name}</span> with authere.
        Replace <span class="au-mono">YOUR_UPSTREAM:8080</span> with the app's backend, and adjust the site
        hostname if the guess doesn't match your host pattern.
      </p>
      <pre class="snippet au-code-sm"><code>{buildCaddySnippet(configApp)}</code></pre>
      <p class="au-micro au-fg-4">
        Unauthenticated requests are automatically redirected to authere's login page.
        After signing in, users are sent back to the original URL. Make sure
        <span class="au-mono">AUTHERE_ORIGIN</span> is set on the server.
      </p>
    </div>
    {#snippet actions()}
      <Button variant="secondary" onclick={() => configApp = null}>Close</Button>
      <Button variant="primary" onclick={copyConfig}>
        <i class="ph ph-copy"></i> Copy snippet
      </Button>
    {/snippet}
  </Modal>
{/if}

{#if confirmDelete}
  <Modal title="Delete application" onclose={() => confirmDelete = null}>
    <p class="au-small au-fg-2">
      Delete <span class="au-mono">{confirmDelete.slug}</span>?
      Forward auth for this application will stop working immediately.
    </p>
    {#snippet actions()}
      <Button variant="secondary" onclick={() => confirmDelete = null}>Cancel</Button>
      <Button variant="danger" loading={deleting} onclick={() => handleDelete(confirmDelete!)}>
        Delete application
      </Button>
    {/snippet}
  </Modal>
{/if}

<style>
  .page { padding: var(--sp-6); max-width: 960px; margin: 0 auto; }
  .page-header { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: var(--sp-6); gap: var(--sp-3); }
  .page-loading { display: flex; align-items: center; gap: var(--sp-2); padding: var(--sp-8); }

  @media (max-width: 639.98px) {
    .page { padding: var(--sp-4); }
    .page-header {
      flex-direction: column;
      align-items: stretch;
      margin-bottom: var(--sp-4);
    }
  }

  .config-body { display: flex; flex-direction: column; gap: var(--sp-3); }
  .snippet {
    background: var(--bg-1);
    border: 1px solid var(--border-0);
    border-radius: var(--radius);
    padding: var(--sp-3);
    margin: 0;
    overflow-x: auto;
    color: var(--fg-2);
    white-space: pre;
  }
  .roles-cell { display: flex; align-items: center; flex-wrap: wrap; gap: var(--sp-1); }
  .modal-form { display: flex; flex-direction: column; gap: var(--sp-3); }
  .role-picker { display: flex; flex-direction: column; gap: var(--sp-2); }
  .role-options { display: flex; flex-wrap: wrap; gap: var(--sp-2); }
  .role-option {
    display: flex; align-items: center; gap: var(--sp-1);
    padding: var(--sp-1) var(--sp-2);
    border: 1px solid var(--border-1); border-radius: var(--radius);
    cursor: pointer; background: var(--bg-2); color: var(--fg-3);
  }
  .role-option.checked { border-color: var(--accent); color: var(--accent); background: var(--accent-subtle); }
  .role-option input { display: none; }
  .spin { animation: spin 0.7s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
