<script lang="ts">
  import { onMount } from 'svelte';
  import { getRoles, createRole, deleteRole, type Role } from '../../lib/api';
  import Button from '../../lib/components/Button.svelte';
  import CopyId from '../../lib/components/CopyId.svelte';
  import Input from '../../lib/components/Input.svelte';
  import Modal from '../../lib/components/Modal.svelte';
  import ResponsiveTable from '../../lib/components/ResponsiveTable.svelte';
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
    <ResponsiveTable
      label="Roles"
      items={roles}
      getKey={(r) => r.id}
      hasActions={(r) => !SYSTEM_ROLES.has(r.name)}
      columns={[
        { key: 'name',        label: 'Name',        tdClass: 'au-fg-1 font-medium' },
        { key: 'description', label: 'Description', tdClass: 'au-fg-3 au-small' },
        { key: 'id',          label: 'ID' },
      ]}
    >
      {#snippet cell({ item, column })}
        {#if column.key === 'name'}{item.name}
        {:else if column.key === 'description'}{item.description ?? '—'}
        {:else if column.key === 'id'}<CopyId id={item.id} />
        {/if}
      {/snippet}
      {#snippet actions({ item })}
        <Button size="sm" variant="ghost" onclick={() => confirmDelete = item}>Delete</Button>
      {/snippet}
      {#snippet empty()}No roles yet.{/snippet}
    </ResponsiveTable>
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

  .modal-form { display: flex; flex-direction: column; gap: var(--sp-3); }
  .spin { animation: spin 0.7s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
