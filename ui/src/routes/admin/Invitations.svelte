<script lang="ts">
  import { onMount } from 'svelte';
  import { getInvitations, createInvitation, deleteInvitation, type Invitation } from '../../lib/api';
  import Badge from '../../lib/components/Badge.svelte';
  import Button from '../../lib/components/Button.svelte';
  import Input from '../../lib/components/Input.svelte';
  import Modal from '../../lib/components/Modal.svelte';
  import ResponsiveTable from '../../lib/components/ResponsiveTable.svelte';
  import { toasts } from '../../lib/toast.svelte';

  let invitations = $state<Invitation[]>([]);
  let loading = $state(true);
  let showCreate = $state(false);
  let confirmDelete = $state<Invitation | null>(null);
  let creating = $state(false);
  let deleting = $state(false);

  // Create form
  let newLabel = $state('');
  let newMaxUses = $state('');
  let newExpiresAt = $state('');

  onMount(async () => {
    try {
      invitations = await getInvitations();
    } catch {
      toasts.error('Failed to load invitations.');
    } finally {
      loading = false;
    }
  });

  function inviteUrl(id: string) {
    return `${window.location.origin}/register?invite=${id}`;
  }

  async function copyInviteLink(inv: Invitation) {
    try {
      await navigator.clipboard.writeText(inviteUrl(inv.id));
      toasts.success('Invite link copied.');
    } catch {
      toasts.error('Could not copy to clipboard.');
    }
  }

  function resetCreateForm() {
    newLabel = '';
    newMaxUses = '';
    newExpiresAt = '';
  }

  async function handleCreate() {
    if (creating) return;
    creating = true;
    try {
      const data: { label?: string; max_uses?: number; expires_at?: number } = {};
      if (newLabel.trim()) data.label = newLabel.trim();
      if (newMaxUses) data.max_uses = Number(newMaxUses);
      if (newExpiresAt) data.expires_at = Math.floor(new Date(newExpiresAt).getTime() / 1000);

      const inv = await createInvitation(data);
      invitations = [inv as unknown as Invitation, ...invitations];
      showCreate = false;
      resetCreateForm();
      toasts.success('Invitation created.');
    } catch (err: any) {
      toasts.error(`Failed to create invitation: ${err.message}`);
    } finally {
      creating = false;
    }
  }

  async function handleDelete() {
    if (!confirmDelete || deleting) return;
    deleting = true;
    try {
      await deleteInvitation(confirmDelete.id);
      invitations = invitations.filter(i => i.id !== confirmDelete!.id);
      confirmDelete = null;
      toasts.success('Invitation deleted.');
    } catch (err: any) {
      toasts.error(`Failed to delete: ${err.message}`);
    } finally {
      deleting = false;
    }
  }

  function formatDate(ts: number | null) {
    if (!ts) return '—';
    return new Date(ts * 1000).toLocaleDateString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
    });
  }

  function statusVariant(status: string): 'success' | 'warning' | 'default' {
    if (status === 'active') return 'success';
    if (status === 'exhausted') return 'warning';
    return 'default';
  }
</script>

<div class="page">
  <header class="page-header">
    <div>
      <h1 class="au-h3">Invitations</h1>
      <p class="au-micro au-fg-3">{invitations.length} total</p>
    </div>
    <Button variant="primary" onclick={() => showCreate = true}>
      <i class="ph ph-plus"></i> New invitation
    </Button>
  </header>

  {#if loading}
    <div class="page-loading au-fg-4 au-small">
      <i class="ph ph-circle-notch spin"></i> Loading…
    </div>
  {:else}
    <ResponsiveTable
      label="Invitations"
      items={invitations}
      getKey={(i) => i.id}
      columns={[
        { key: 'code',    label: 'Code' },
        { key: 'label',   label: 'Label',   tdClass: 'au-fg-2' },
        { key: 'uses',    label: 'Uses',    tdClass: 'au-fg-3' },
        { key: 'expires', label: 'Expires', tdClass: 'au-fg-3' },
        { key: 'created', label: 'Created', tdClass: 'au-fg-3' },
        { key: 'status',  label: 'Status' },
      ]}
    >
      {#snippet cell({ item, column })}
        {#if column.key === 'code'}
          <span class="code-cell">
            <span class="au-mono au-code-sm au-fg-4">{item.id.slice(0, 12)}…</span>
            <button
              class="icon-btn"
              onclick={() => copyInviteLink(item)}
              title="Copy invite link"
              aria-label={`Copy invite link for ${item.label ?? item.id}`}
            >
              <i class="ph ph-link"></i>
            </button>
          </span>
        {:else if column.key === 'label'}{item.label ?? '—'}
        {:else if column.key === 'uses'}{item.uses}{item.max_uses != null ? ` / ${item.max_uses}` : ''}
        {:else if column.key === 'expires'}{formatDate(item.expires_at)}
        {:else if column.key === 'created'}{formatDate(item.created_at)}
        {:else if column.key === 'status'}<Badge variant={statusVariant(item.status)}>{item.status}</Badge>
        {/if}
      {/snippet}
      {#snippet actions({ item })}
        <Button size="sm" variant="ghost" onclick={() => confirmDelete = item}>Delete</Button>
      {/snippet}
      {#snippet empty()}No invitations yet.{/snippet}
    </ResponsiveTable>
  {/if}
</div>

{#if showCreate}
  <Modal title="New invitation" onclose={() => { showCreate = false; resetCreateForm(); }}>
    <div class="modal-form">
      <Input label="Label" bind:value={newLabel} placeholder="Optional description" />
      <Input
        label="Max uses"
        type="number"
        bind:value={newMaxUses}
        placeholder="Unlimited"
      />
      <div class="field">
        <label class="au-small au-fg-2" for="expires-at">Expires at</label>
        <input
          id="expires-at"
          type="datetime-local"
          class="datetime-input au-small"
          bind:value={newExpiresAt}
        />
      </div>
    </div>
    {#snippet actions()}
      <Button variant="secondary" onclick={() => { showCreate = false; resetCreateForm(); }}>Cancel</Button>
      <Button variant="primary" loading={creating} disabled={creating} onclick={handleCreate}>Create</Button>
    {/snippet}
  </Modal>
{/if}

{#if confirmDelete}
  <Modal title="Delete invitation" onclose={() => confirmDelete = null}>
    <p class="au-small">
      Delete this invitation?
      {#if confirmDelete.label}<strong>{confirmDelete.label}</strong>{/if}
      Users who already registered with it are unaffected.
    </p>
    {#snippet actions()}
      <Button variant="secondary" onclick={() => confirmDelete = null}>Cancel</Button>
      <Button variant="danger" onclick={handleDelete} loading={deleting}>Delete</Button>
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

  .code-cell {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-2);
    white-space: nowrap;
  }

  .icon-btn {
    background: none;
    border: none;
    cursor: pointer;
    color: var(--fg-4);
    padding: var(--sp-1);
    border-radius: var(--radius);
    font-size: 14px;
    display: inline-flex;
    align-items: center;
    transition: color var(--duration-micro) var(--ease-out),
                background var(--duration-micro) var(--ease-out);
  }
  .icon-btn:hover { background: var(--bg-3); color: var(--fg-2); }

  .modal-form { display: flex; flex-direction: column; gap: var(--sp-3); }

  .field { display: flex; flex-direction: column; gap: var(--sp-1); }
  .field label { font-size: 13px; }

  .datetime-input {
    background: var(--bg-1);
    border: 1px solid var(--border-1);
    border-radius: var(--radius);
    color: var(--fg-1);
    padding: var(--sp-2) var(--sp-3);
    font-family: inherit;
    font-size: 16px;
    width: 100%;
    box-sizing: border-box;
    color-scheme: dark;
  }

  @media (min-width: 640px) {
    .datetime-input { font-size: 13px; }
  }
  .datetime-input:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 2px var(--accent-subtle);
  }

  .spin { animation: spin 0.7s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
