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
  import { toasts } from '../../lib/toast.svelte';

  let apps = $state<Application[]>([]);
  let roles = $state<Role[]>([]);
  let loading = $state(true);
  let editApp = $state<Partial<Application> | null>(null);
  let isEditing = $state(false); // false = create, true = update
  let confirmDelete = $state<Application | null>(null);
  let saving = $state(false);
  let deleting = $state(false);

  let form = $state({ name: '', slug: '', host_pattern: '', path_prefix: '', required_roles: [] as string[] });

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
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Slug</th>
            <th>Host pattern</th>
            <th>Required roles</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each apps as app (app.id)}
            <tr>
              <td class="au-fg-1 font-medium">{app.name}</td>
              <td class="au-mono au-code-sm au-fg-3">{app.slug}</td>
              <td class="au-code-sm au-fg-3">{app.host_pattern}</td>
              <td class="roles-cell">
                {#each app.required_roles as roleId}
                  <Badge>{roleMap[roleId] ?? roleId}</Badge>
                {/each}
                {#if app.required_roles.length === 0}
                  <span class="au-fg-5 au-micro">public</span>
                {/if}
              </td>
              <td class="actions-cell">
                <Button size="sm" variant="ghost" onclick={() => openEdit(app)}>Edit</Button>
                <Button size="sm" variant="ghost" onclick={() => confirmDelete = app}>Delete</Button>
              </td>
            </tr>
          {/each}
          {#if apps.length === 0}
            <tr><td colspan="5" class="empty-row au-fg-4 au-small">No applications yet.</td></tr>
          {/if}
        </tbody>
      </table>
    </div>
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
  .page { padding: var(--sp-6); max-width: 1040px; margin: 0 auto; }
  .page-header { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: var(--sp-6); }
  .page-loading { display: flex; align-items: center; gap: var(--sp-2); padding: var(--sp-8); }
  .table-wrap { border: 1px solid var(--border-0); border-radius: var(--radius); overflow: hidden; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead th {
    height: 32px; padding: 0 var(--sp-3); text-align: left;
    background: var(--bg-1); color: var(--fg-4);
    font-size: 11px; font-weight: 500; letter-spacing: 0.06em; text-transform: uppercase;
    border-bottom: 1px solid var(--border-0); white-space: nowrap;
  }
  tbody tr { height: 32px; border-bottom: 1px solid var(--border-0); transition: background var(--duration-micro) var(--ease-out); }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: var(--bg-1); }
  td { padding: 0 var(--sp-3); overflow: hidden; text-overflow: ellipsis; }
  .actions-cell { text-align: right; width: 120px; white-space: nowrap; }
  .roles-cell { display: flex; align-items: center; gap: var(--sp-1); }
  .empty-row { padding: var(--sp-8) !important; text-align: center; }
  .font-medium { font-weight: 500; }
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
