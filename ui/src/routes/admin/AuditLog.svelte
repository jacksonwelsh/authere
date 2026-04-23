<script lang="ts">
  import { onMount } from 'svelte';
  import {
    downloadAuditExport,
    getAuditEventTypes,
    getAuditLog,
    type AuditEntry,
    type AuditLogQuery,
  } from '../../lib/api';
  import Button from '../../lib/components/Button.svelte';
  import Badge from '../../lib/components/Badge.svelte';
  import CopyId from '../../lib/components/CopyId.svelte';
  import Input from '../../lib/components/Input.svelte';
  import Modal from '../../lib/components/Modal.svelte';
  import { toasts } from '../../lib/toast.svelte';

  const PAGE_SIZE = 50;

  let entries = $state<AuditEntry[]>([]);
  let total = $state(0);
  let page = $state(0); // 0-indexed
  let loading = $state(true);
  let selected = $state<AuditEntry | null>(null);

  // Filter inputs — bound to controls, applied on "Apply". Kept separate from
  // the active filters so typing in a field doesn't hammer the API.
  let eventTypes = $state<string[]>([]);
  let filterEventType = $state<string>('');
  let filterActor = $state<string>('');
  let filterUser = $state<string>('');
  let filterSince = $state<string>(''); // datetime-local "YYYY-MM-DDTHH:MM"
  let filterUntil = $state<string>('');

  // Active filters currently applied to the query. Diverges from the inputs
  // between typing and clicking "Apply".
  let active = $state<AuditLogQuery>({});

  const totalPages = $derived(Math.max(1, Math.ceil(total / PAGE_SIZE)));

  onMount(async () => {
    try {
      eventTypes = await getAuditEventTypes();
    } catch {
      // Non-fatal; filter dropdown just shows empty.
    }
    await load();
  });

  async function load() {
    loading = true;
    try {
      const resp = await getAuditLog({
        ...active,
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      });
      entries = resp.entries;
      total = resp.total;
    } catch {
      toasts.error('Failed to load audit log.');
    } finally {
      loading = false;
    }
  }

  /**
   * Convert a local datetime-local string ("YYYY-MM-DDTHH:MM") to unix seconds,
   * or return undefined for empty input. Uses local timezone (the user is
   * filtering from their admin console, so local time is the expected input).
   */
  function localDatetimeToUnix(s: string): number | undefined {
    if (!s) return undefined;
    const ms = new Date(s).getTime();
    if (Number.isNaN(ms)) return undefined;
    return Math.floor(ms / 1000);
  }

  function applyFilters() {
    active = {
      event_type: filterEventType ? [filterEventType] : undefined,
      actor_id: filterActor.trim() || undefined,
      user_id: filterUser.trim() || undefined,
      since: localDatetimeToUnix(filterSince),
      until: localDatetimeToUnix(filterUntil),
    };
    page = 0;
    load();
  }

  function clearFilters() {
    filterEventType = '';
    filterActor = '';
    filterUser = '';
    filterSince = '';
    filterUntil = '';
    active = {};
    page = 0;
    load();
  }

  function goToPage(p: number) {
    if (p < 0 || p >= totalPages) return;
    page = p;
    load();
  }

  function exportAs(format: 'json' | 'csv') {
    downloadAuditExport(format, active);
  }

  function formatTime(ts: number) {
    return new Date(ts * 1000).toISOString().replace('T', ' ').replace('Z', ' UTC');
  }

  function eventVariant(type: string): 'success' | 'danger' | 'warning' | 'default' {
    if (type.includes('success') || type === 'user_created' || type === 'user_registered') return 'success';
    if (type.includes('fail') || type.includes('denied') || type.includes('rejected')) return 'danger';
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

  /**
   * Render a compact page window: always first + last, up to 5 around the
   * current page, with gap markers when there's a jump.
   */
  function pageWindow(current: number, last: number): (number | '…')[] {
    if (last <= 7) return Array.from({ length: last + 1 }, (_, i) => i);
    const pages = new Set<number>([0, last, current, current - 1, current + 1, current - 2, current + 2]);
    const sorted = [...pages].filter((p) => p >= 0 && p <= last).sort((a, b) => a - b);
    const out: (number | '…')[] = [];
    let prev = -1;
    for (const p of sorted) {
      if (prev >= 0 && p - prev > 1) out.push('…');
      out.push(p);
      prev = p;
    }
    return out;
  }
</script>

<div class="page">
  <header class="page-header">
    <div>
      <h1 class="au-h3">Audit log</h1>
      <p class="au-micro au-fg-3">Append-only security event feed · {total.toLocaleString()} events</p>
    </div>
    <div class="header-actions">
      <Button variant="secondary" onclick={() => exportAs('csv')} disabled={total === 0}>
        <i class="ph ph-download-simple"></i> CSV
      </Button>
      <Button variant="secondary" onclick={() => exportAs('json')} disabled={total === 0}>
        <i class="ph ph-download-simple"></i> JSON
      </Button>
      <Button variant="secondary" onclick={() => load()}>
        <i class="ph ph-arrow-clockwise"></i> Refresh
      </Button>
    </div>
  </header>

  <div class="filters">
    <div class="field">
      <label class="field-label au-nano" for="filter-event-type">Event type</label>
      <select
        id="filter-event-type"
        class="au-input"
        value={filterEventType}
        onchange={(e) => (filterEventType = (e.currentTarget as HTMLSelectElement).value)}
      >
        <option value="">All events</option>
        {#each eventTypes as t (t)}
          <option value={t}>{t}</option>
        {/each}
      </select>
    </div>
    <div class="filter-input">
      <Input
        label="Actor ID"
        placeholder="UUID of acting admin"
        bind:value={filterActor}
      />
    </div>
    <div class="filter-input">
      <Input
        label="User ID"
        placeholder="UUID of target user"
        bind:value={filterUser}
      />
    </div>
    <div class="filter-input">
      <Input
        label="From"
        type="datetime-local"
        bind:value={filterSince}
      />
    </div>
    <div class="filter-input">
      <Input
        label="To"
        type="datetime-local"
        bind:value={filterUntil}
      />
    </div>
    <div class="filter-actions">
      <Button onclick={applyFilters}>Apply</Button>
      <Button variant="secondary" onclick={clearFilters}>Clear</Button>
    </div>
  </div>

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
              <td class="au-code-sm au-mono au-fg-3 au-tabular" data-label="Time (UTC)">{formatTime(entry.timestamp)}</td>
              <td data-label="Event">
                <Badge variant={eventVariant(entry.event_type)}>{entry.event_type}</Badge>
              </td>
              <td data-label="User">
                {#if ud.id}
                  <CopyId id={ud.id} />
                {:else if ud.label === '—'}
                  <span class="au-code-sm au-fg-4">—</span>
                {:else}
                  <span class="au-code-sm" class:au-fg-4={ud.ghost}>{ud.label}</span>{#if ud.ghost}<span class="ghost-label au-micro au-fg-4"> (nonexistent)</span>{/if}
                {/if}
              </td>
              <td class="au-code-sm au-fg-3" data-label="IP">{entry.ip_address ?? '—'}</td>
              <td class="ua-cell au-small au-fg-4" data-label="User agent">{entry.user_agent ?? '—'}</td>
            </tr>
          {/each}
          {#if entries.length === 0}
            <tr><td colspan="5" class="empty-row au-fg-4 au-small">No events match the current filters.</td></tr>
          {/if}
        </tbody>
      </table>
    </div>

    {#if totalPages > 1}
      <nav class="pager" aria-label="Pagination">
        <Button
          variant="secondary"
          disabled={page === 0}
          onclick={() => goToPage(page - 1)}
        >
          <i class="ph ph-caret-left"></i> Prev
        </Button>
        <ol class="pages">
          {#each pageWindow(page, totalPages - 1) as token, i (i)}
            {#if token === '…'}
              <li class="gap au-fg-4">…</li>
            {:else}
              <li>
                <button
                  type="button"
                  class="page-btn"
                  class:active={token === page}
                  onclick={() => goToPage(token)}
                  aria-current={token === page ? 'page' : undefined}
                >
                  {token + 1}
                </button>
              </li>
            {/if}
          {/each}
        </ol>
        <Button
          variant="secondary"
          disabled={page >= totalPages - 1}
          onclick={() => goToPage(page + 1)}
        >
          Next <i class="ph ph-caret-right"></i>
        </Button>
      </nav>
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
  .page { padding: var(--sp-6); max-width: 1120px; margin: 0 auto; }
  .page-header { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: var(--sp-6); gap: var(--sp-3); }
  .header-actions { display: flex; gap: var(--sp-2); flex-wrap: wrap; }
  .page-loading { display: flex; align-items: center; gap: var(--sp-2); padding: var(--sp-8); }

  .filters {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: var(--sp-3);
    padding: var(--sp-3);
    margin-bottom: var(--sp-4);
    border: 1px solid var(--border-0);
    border-radius: var(--radius);
    background: var(--bg-1);
    align-items: end;
  }
  .filter-input, .field { min-width: 0; }
  .field { display: flex; flex-direction: column; gap: var(--sp-1); }
  .field-label { color: var(--fg-3); letter-spacing: 0.06em; }
  .au-input {
    height: 40px;
    padding: 0 var(--sp-3);
    background: var(--bg-2);
    border: 1px solid var(--border-1);
    border-radius: var(--radius);
    color: var(--fg-1);
    font-family: inherit;
    font-size: 16px;
    outline: none;
    transition: border-color var(--duration-micro) var(--ease-out);
    width: 100%;
  }
  @media (min-width: 640px) {
    .au-input { height: 32px; font-size: 13px; }
  }
  .au-input:hover:not(:disabled) { border-color: var(--border-2); }
  .au-input:focus { border-color: var(--border-focus); box-shadow: 0 0 0 2px var(--accent-subtle) inset; }
  .filter-actions { display: flex; gap: var(--sp-2); align-items: end; }

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

  .pager {
    display: flex; align-items: center; justify-content: center;
    gap: var(--sp-2); padding: var(--sp-4); flex-wrap: wrap;
  }
  .pages { display: flex; list-style: none; gap: 2px; padding: 0; margin: 0; }
  .page-btn {
    min-width: 32px;
    height: 32px;
    padding: 0 var(--sp-2);
    background: var(--bg-2);
    border: 1px solid var(--border-1);
    border-radius: var(--radius);
    color: var(--fg-2);
    font-family: inherit;
    font-size: 13px;
    font-variant-numeric: tabular-nums;
    cursor: pointer;
    transition: border-color var(--duration-micro) var(--ease-out);
  }
  .page-btn:hover { border-color: var(--border-2); }
  .page-btn.active {
    background: var(--accent-subtle);
    border-color: var(--border-focus);
    color: var(--fg-1);
  }
  .gap { padding: 0 var(--sp-2); color: var(--fg-4); font-family: 'IBM Plex Mono', monospace; }

  .spin { animation: spin 0.7s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .ghost-label { font-style: italic; }
  .detail-list { display: grid; grid-template-columns: 120px 1fr; gap: var(--sp-2) var(--sp-4); margin: 0; }
  .detail-list dt { color: var(--fg-4); font-size: 11px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.06em; display: flex; align-items: center; }
  .detail-list dd { margin: 0; display: flex; align-items: center; flex-wrap: wrap; gap: var(--sp-1); word-break: break-all; }
  .detail-json { white-space: pre-wrap; background: var(--bg-1); border: 1px solid var(--border-0); border-radius: var(--radius); padding: var(--sp-2); align-items: flex-start; }

  @media (max-width: 639.98px) {
    .page { padding: var(--sp-4); }
    .page-header {
      flex-direction: column;
      align-items: stretch;
      gap: var(--sp-3);
      margin-bottom: var(--sp-4);
    }
    .filters { grid-template-columns: 1fr; }

    /* Collapse table into a stack of cards. */
    .table-wrap { border: none; overflow: visible; }
    table, thead, tbody, tr, th, td { display: block; }
    table { min-width: 0; }
    thead { display: none; }
    tbody tr {
      height: auto;
      border: 1px solid var(--border-0);
      border-radius: var(--radius);
      padding: var(--sp-3);
      margin-bottom: var(--sp-2);
      background: var(--bg-1);
    }
    tbody tr:hover { background: var(--bg-1); }
    tbody tr td {
      white-space: normal;
      padding: var(--sp-1) 0;
      display: flex;
      flex-direction: column;
      gap: 2px;
    }
    tbody tr td::before {
      content: attr(data-label);
      font-family: 'IBM Plex Mono', monospace;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--fg-4);
    }
    .ua-cell { max-width: none; }
    .col-time, .col-event, .col-user, .col-ip { width: auto; }
  }
</style>
