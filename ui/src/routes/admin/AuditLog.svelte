<script lang="ts">
  import { onMount } from 'svelte';
  import { getAuditLog, type AuditEntry } from '../../lib/api';
  import Button from '../../lib/components/Button.svelte';
  import Badge from '../../lib/components/Badge.svelte';
  import CopyId from '../../lib/components/CopyId.svelte';
  import Modal from '../../lib/components/Modal.svelte';
  import { toasts } from '../../lib/toast.svelte';

  let entries = $state<AuditEntry[]>([]);
  let loading = $state(true);
  let loadingMore = $state(false);
  let hasMore = $state(true);
  let selected = $state<AuditEntry | null>(null);
  const PAGE = 50;

  onMount(async () => {
    await load(0, true);
  });

  async function load(offset: number, reset = false) {
    try {
      if (offset === 0) loading = true; else loadingMore = true;
      const data = await getAuditLog({ limit: PAGE, offset });
      if (reset) {
        entries = data;
      } else {
        entries = [...entries, ...data];
      }
      hasMore = data.length === PAGE;
    } catch {
      toasts.error('Failed to load audit log.');
    } finally {
      loading = false;
      loadingMore = false;
    }
  }

  function loadMore() {
    load(entries.length);
  }

  function formatTime(ts: number) {
    return new Date(ts * 1000).toISOString().replace('T', ' ').replace('Z', ' UTC');
  }

  function eventVariant(type: string): 'success' | 'danger' | 'warning' | 'default' {
    if (type.includes('success') || type === 'user_created') return 'success';
    if (type.includes('fail') || type.includes('denied')) return 'danger';
    if (type.startsWith('admin_')) return 'warning';
    return 'default';
  }

  function detailsUsername(entry: AuditEntry): string | null {
    const d = entry.details;
    if (!d) return null;
    return typeof d.username === 'string' ? d.username : null;
  }

  function isNonexistentUser(entry: AuditEntry): boolean {
    return entry.details?.user_exists === false;
  }

  function hasActor(entry: AuditEntry): boolean {
    return entry.actor_id !== null;
  }

  function displayUser(entry: AuditEntry): { label: string; ghost?: boolean; id?: string } {
    if (entry.event_type === 'login_failed') {
      const name = detailsUsername(entry) ?? entry.username;
      if (name) return { label: name, ghost: isNonexistentUser(entry) };
    }
    if (entry.username) return { label: entry.username };
    if (entry.user_id) return { label: entry.user_id.slice(-12), id: entry.user_id };
    return { label: '—' };
  }
</script>

<div class="page">
  <header class="page-header">
    <div>
      <h1 class="au-h3">Audit log</h1>
      <p class="au-micro au-fg-3">Append-only security event feed</p>
    </div>
    <Button variant="secondary" onclick={() => load(0, true)}>
      <i class="ph ph-arrow-clockwise"></i> Refresh
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
            <th class="col-time">Time (UTC)</th>
            <th class="col-event">Event</th>
            <th class="col-user">User</th>
            <th class="col-ip">IP</th>
            <th class="col-ua">User agent</th>
          </tr>
        </thead>
        <tbody>
          {#each entries as entry (entry.id)}
            {@const ud = displayUser(entry)}
            {@const clickable = hasActor(entry)}
            <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_noninteractive_element_interactions -->
            <tr
              class:clickable
              onclick={clickable ? () => { selected = entry; } : undefined}
              title={clickable ? 'Click to view actor details' : undefined}
            >
              <td class="au-code-sm au-mono au-fg-3 au-tabular">{formatTime(entry.timestamp)}</td>
              <td>
                <Badge variant={eventVariant(entry.event_type)}>{entry.event_type}</Badge>
              </td>
              <td>
                {#if ud.id}
                  <CopyId id={ud.id} />
                {:else if ud.label === '—'}
                  <span class="au-code-sm au-fg-4">—</span>
                {:else}
                  <span class="au-code-sm" class:au-fg-4={ud.ghost}>{ud.label}</span>{#if ud.ghost}<span class="ghost-label au-micro au-fg-4"> (nonexistent)</span>{/if}
                {/if}
              </td>
              <td class="au-code-sm au-fg-3">{entry.ip_address ?? '—'}</td>
              <td class="ua-cell au-small au-fg-4">{entry.user_agent ?? '—'}</td>
            </tr>
          {/each}
          {#if entries.length === 0}
            <tr><td colspan="5" class="empty-row au-fg-4 au-small">No events recorded yet.</td></tr>
          {/if}
        </tbody>
      </table>
    </div>

    {#if hasMore}
      <div class="load-more">
        <Button variant="secondary" loading={loadingMore} onclick={loadMore}>
          Load more
        </Button>
      </div>
    {/if}
  {/if}
</div>

{#if selected}
  <Modal title="Event details" onclose={() => { selected = null; }}>
    <dl class="detail-list">
      <dt>Event</dt>
      <dd><Badge variant={eventVariant(selected.event_type)}>{selected.event_type}</Badge></dd>

      <dt>Time</dt>
      <dd class="au-code-sm au-mono">{formatTime(selected.timestamp)}</dd>

      <dt>Target user</dt>
      <dd class="au-code-sm">
        {#if selected.username}
          {selected.username}
          {#if selected.user_id}<span class="au-fg-4"> · {selected.user_id.slice(-12)}</span>{/if}
        {:else if selected.user_id}
          <CopyId id={selected.user_id} />
          <span class="au-fg-4 au-micro"> (deleted)</span>
        {:else if detailsUsername(selected)}
          {detailsUsername(selected)}{#if isNonexistentUser(selected)}<span class="au-fg-4"> (nonexistent)</span>{/if}
        {:else}
          <span class="au-fg-4">—</span>
        {/if}
      </dd>

      <dt>Acting admin</dt>
      <dd class="au-code-sm">
        {#if selected.actor_username}
          {selected.actor_username}
          {#if selected.actor_id}<span class="au-fg-4"> · {selected.actor_id.slice(-12)}</span>{/if}
        {:else if selected.actor_id}
          <CopyId id={selected.actor_id} />
          <span class="au-fg-4 au-micro"> (deleted)</span>
        {:else}
          <span class="au-fg-4">—</span>
        {/if}
      </dd>

      <dt>IP address</dt>
      <dd class="au-code-sm au-mono">{selected.ip_address ?? '—'}</dd>

      <dt>User agent</dt>
      <dd class="au-small au-fg-4">{selected.user_agent ?? '—'}</dd>

      {#if selected.details}
        <dt>Details</dt>
        <dd class="detail-json au-code-sm">{JSON.stringify(selected.details, null, 2)}</dd>
      {/if}
    </dl>
  </Modal>
{/if}

<style>
  .page { padding: var(--sp-6); max-width: 1200px; margin: 0 auto; }
  .page-header { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: var(--sp-6); }
  .page-loading { display: flex; align-items: center; gap: var(--sp-2); padding: var(--sp-8); }
  .table-wrap { border: 1px solid var(--border-0); border-radius: var(--radius); overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; min-width: 700px; }
  thead th {
    height: 32px; padding: 0 var(--sp-3); text-align: left;
    background: var(--bg-1); color: var(--fg-4);
    font-size: 11px; font-weight: 500; letter-spacing: 0.06em; text-transform: uppercase;
    border-bottom: 1px solid var(--border-0); white-space: nowrap;
  }
  tbody tr { height: 32px; border-bottom: 1px solid var(--border-0); transition: background var(--duration-micro) var(--ease-out); }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: var(--bg-1); }
  tbody tr.clickable { cursor: pointer; }
  td { padding: 0 var(--sp-3); white-space: nowrap; }
  .col-time { width: 220px; }
  .col-event { width: 200px; }
  .col-user { width: 140px; }
  .col-ip { width: 140px; }
  .ua-cell { overflow: hidden; text-overflow: ellipsis; max-width: 280px; }
  .empty-row { padding: var(--sp-8) !important; text-align: center; }
  .load-more { display: flex; justify-content: center; padding: var(--sp-4); }
  .spin { animation: spin 0.7s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .ghost-label { font-style: italic; }
  .detail-list { display: grid; grid-template-columns: 120px 1fr; gap: var(--sp-2) var(--sp-4); margin: 0; }
  .detail-list dt { color: var(--fg-4); font-size: 11px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.06em; display: flex; align-items: center; }
  .detail-list dd { margin: 0; display: flex; align-items: center; flex-wrap: wrap; gap: var(--sp-1); word-break: break-all; }
  .detail-json { white-space: pre-wrap; background: var(--bg-1); border: 1px solid var(--border-0); border-radius: var(--radius); padding: var(--sp-2); align-items: flex-start; }
</style>
