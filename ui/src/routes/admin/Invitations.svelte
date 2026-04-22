<script lang="ts">
  import { onMount } from 'svelte';
  import { getInvitations, createInvitation, deleteInvitation, type Invitation } from '../../lib/api';
  import Badge from '../../lib/components/Badge.svelte';
  import Button from '../../lib/components/Button.svelte';
  import Input from '../../lib/components/Input.svelte';
  import Modal from '../../lib/components/Modal.svelte';
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
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Code</th>
            <th>Label</th>
            <th>Uses</th>
            <th>Expires</th>
            <th>Created</th>
            <th>Status</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each invitations as inv (inv.id)}
            <tr data-testid={`row-${inv.id}`}>
              <td class="code-cell">
                <span class="au-mono au-code-sm au-fg-4">{inv.id.slice(0, 12)}…</span>
                <button
                  class="icon-btn"
                  onclick={() => copyInviteLink(inv)}
                  title="Copy invite link"
                  aria-label={`Copy invite link for ${inv.label ?? inv.id}`}
                >
                  <i class="ph ph-link"></i>
                </button>
              </td>
              <td class="au-fg-2">{inv.label ?? '—'}</td>
              <td class="au-fg-3">
                {inv.uses}{inv.max_uses != null ? ` / ${inv.max_uses}` : ''}
              </td>
              <td class="au-fg-3">{formatDate(inv.expires_at)}</td>
              <td class="au-fg-3">{formatDate(inv.created_at)}</td>
              <td>
                <Badge variant={statusVariant(inv.status)}>
                  {inv.status}
                </Badge>
              </td>
              <td class="actions-cell">
                <Button size="sm" variant="ghost" onclick={() => confirmDelete = inv}>Delete</Button>
              </td>
            </tr>
          {/each}
          {#if invitations.length === 0}
            <tr><td colspan="7" class="empty-row au-fg-4 au-small">No invitations yet.</td></tr>
          {/if}
        </tbody>
      </table>
    </div>
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

  .code-cell {
    display: flex;
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
    display: flex;
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
    font-size: 13px;
    width: 100%;
    box-sizing: border-box;
    color-scheme: dark;
  }
  .datetime-input:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 2px var(--accent-subtle);
  }

  .spin { animation: spin 0.7s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
