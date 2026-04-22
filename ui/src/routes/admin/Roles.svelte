<script lang="ts">
  import { onMount } from 'svelte';
  import { getRoles, createRole, deleteRole, type Role } from '../../lib/api';
  import Button from '../../lib/components/Button.svelte';
  import CopyId from '../../lib/components/CopyId.svelte';
  import Input from '../../lib/components/Input.svelte';
  import Modal from '../../lib/components/Modal.svelte';
  import { toasts } from '../../lib/toast.svelte';

  let roles = $state<Role[]>([]);
  let loading = $state(true);
  let showCreate = $state(false);
  let confirmDelete = $state<Role | null>(null);

  let newName = $state('');
  let newDescription = $state('');
  let creating = $state(false);
  let deleting = $state(false);

  const SYSTEM_ROLES = new Set(['admin', 'user']);

  onMount(async () => {
    try {
      roles = await getRoles();
    } catch {
      toasts.error('Failed to load roles.');
    } finally {
      loading = false;
    }
  });

  async function handleCreate() {
    if (creating) return;
    creating = true;
    try {
      const r = await createRole({ name: newName, description: newDescription || undefined });
      roles = [...roles, r];
      showCreate = false;
      newName = newDescription = '';
      toasts.success('Role created.');
    } catch (err: any) {
      toasts.error(`Failed to create role: ${err.message}`);
    } finally {
      creating = false;
    }
  }

  async function handleDelete(role: Role) {
    if (deleting) return;
    deleting = true;
    try {
      await deleteRole(role.id);
      roles = roles.filter(r => r.id !== role.id);
      confirmDelete = null;
      toasts.success('Role deleted.');
    } catch (err: any) {
      toasts.error(`Failed to delete role: ${err.message}`);
    } finally {
      deleting = false;
    }
  }
</script>

<div class="page">
  <header class="page-header">
    <div>
      <h1 class="au-h3">Roles</h1>
      <p class="au-micro au-fg-3">{roles.length} total</p>
    </div>
    <Button variant="primary" onclick={() => showCreate = true}>
      <i class="ph ph-plus"></i> Add role
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
            <th>Description</th>
            <th>ID</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each roles as role (role.id)}
            <tr data-testid={`row-${role.id}`}>
              <td class="au-fg-1 font-medium">{role.name}</td>
              <td class="au-fg-3 au-small">{role.description ?? '—'}</td>
              <td><CopyId id={role.id} /></td>
              <td class="actions-cell">
                {#if !SYSTEM_ROLES.has(role.name)}
                  <Button size="sm" variant="ghost" onclick={() => confirmDelete = role}>Delete</Button>
                {/if}
              </td>
            </tr>
          {/each}
          {#if roles.length === 0}
            <tr><td colspan="4" class="empty-row au-fg-4 au-small">No roles yet.</td></tr>
          {/if}
        </tbody>
      </table>
    </div>
  {/if}
</div>

{#if showCreate}
  <Modal title="Add role" onclose={() => showCreate = false}>
    <div class="modal-form">
      <Input label="Name" bind:value={newName} placeholder="viewer" />
      <Input label="Description" bind:value={newDescription} placeholder="Optional description" />
    </div>
    {#snippet actions()}
      <Button variant="secondary" onclick={() => showCreate = false}>Cancel</Button>
      <Button variant="primary" loading={creating} disabled={!newName || creating} onclick={handleCreate}>
        Create role
      </Button>
    {/snippet}
  </Modal>
{/if}

{#if confirmDelete}
  <Modal title="Delete role" onclose={() => confirmDelete = null}>
    <p class="au-small au-fg-2">
      Delete role <span class="au-mono">{confirmDelete.name}</span>?
      This removes the role from all users who have it.
    </p>
    {#snippet actions()}
      <Button variant="secondary" onclick={() => confirmDelete = null}>Cancel</Button>
      <Button variant="danger" loading={deleting} onclick={() => handleDelete(confirmDelete!)}>
        Delete role
      </Button>
    {/snippet}
  </Modal>
{/if}

<style>
  .page { padding: var(--sp-6); max-width: 960px; margin: 0 auto; }
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
  thead th:last-child { text-align: right; }
  tbody tr { height: 32px; border-bottom: 1px solid var(--border-0); transition: background var(--duration-micro) var(--ease-out); }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: var(--bg-1); }
  td { padding: 0 var(--sp-3); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .actions-cell { text-align: right; width: 80px; }
  .empty-row { padding: var(--sp-8) !important; text-align: center; }
  .font-medium { font-weight: 500; }
  .modal-form { display: flex; flex-direction: column; gap: var(--sp-3); }
  .spin { animation: spin 0.7s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
