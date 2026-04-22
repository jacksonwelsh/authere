<script lang="ts" generics="T">
  import ActionMenu from './ActionMenu.svelte';

  interface Column {
    key: string;
    label: string;
    // Optional CSS class applied to the desktop <th>/<td> for that column.
    thClass?: string;
    tdClass?: string;
  }

  interface Props {
    columns: Column[];
    items: T[];
    getKey: (item: T) => string | number;
    /** Accessible label for the table (used by the card list's aria-label too). */
    label?: string;
    /** Renders a single cell's value for a given column. */
    cell: import('svelte').Snippet<[{ item: T; column: Column }]>;
    /** Optional inline actions. On desktop: rendered inline in the last column. On mobile: collapsed into an overflow menu. */
    actions?: import('svelte').Snippet<[{ item: T }]>;
    /** Per-row override — return false to suppress the action slot for specific rows. */
    hasActions?: (item: T) => boolean;
    /** Rendered when items is empty. */
    empty?: import('svelte').Snippet;
  }
  let { columns, items, getKey, label = 'Data', cell, actions, hasActions, empty }: Props = $props();

  function shouldShowActions(item: T): boolean {
    if (!actions) return false;
    if (hasActions) return hasActions(item);
    return true;
  }
</script>

<div class="responsive-table" role="region" aria-label={label}>
  <!-- Desktop / tablet: real table -->
  <div class="table-wrap" data-variant="table">
    <table>
      <thead>
        <tr>
          {#each columns as col (col.key)}
            <th class={col.thClass ?? ''}>{col.label}</th>
          {/each}
          {#if actions}<th class="col-actions" aria-label="Actions"></th>{/if}
        </tr>
      </thead>
      <tbody>
        {#each items as item (getKey(item))}
          <tr data-testid={`row-${getKey(item)}`}>
            {#each columns as col (col.key)}
              <td class={col.tdClass ?? ''}>
                {@render cell({ item, column: col })}
              </td>
            {/each}
            {#if actions}
              <td class="actions-cell">
                {#if shouldShowActions(item)}{@render actions({ item })}{/if}
              </td>
            {/if}
          </tr>
        {/each}
        {#if items.length === 0}
          <tr>
            <td colspan={columns.length + (actions ? 1 : 0)} class="empty-row au-fg-4 au-small">
              {#if empty}{@render empty()}{:else}No items.{/if}
            </td>
          </tr>
        {/if}
      </tbody>
    </table>
  </div>

  <!-- Mobile: card list -->
  <ul class="card-list" data-variant="cards" aria-label={label}>
    {#each items as item (getKey(item))}
      <li class="card" data-testid={`card-${getKey(item)}`}>
        <div class="card-body">
          <dl>
            {#each columns as col (col.key)}
              <div class="card-row">
                <dt class="au-nano au-fg-4">{col.label}</dt>
                <dd>{@render cell({ item, column: col })}</dd>
              </div>
            {/each}
          </dl>
        </div>
        {#if actions && shouldShowActions(item)}
          <div class="card-actions">
            <ActionMenu label="Actions for {getKey(item)}">
              {#snippet children()}
                {@render actions({ item })}
              {/snippet}
            </ActionMenu>
          </div>
        {/if}
      </li>
    {/each}
    {#if items.length === 0}
      <li class="card empty-card au-fg-4 au-small">
        {#if empty}{@render empty()}{:else}No items.{/if}
      </li>
    {/if}
  </ul>
</div>

<style>
  .responsive-table { width: 100%; }

  .table-wrap {
    display: block;
    border: 1px solid var(--border-0);
    border-radius: var(--radius);
    overflow: hidden;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }

  thead th {
    height: 32px;
    padding: 0 var(--sp-3);
    text-align: left;
    background: var(--bg-1);
    color: var(--fg-4);
    font-size: 11px;
    font-weight: 500;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    border-bottom: 1px solid var(--border-0);
    white-space: nowrap;
  }

  thead th:last-child { text-align: right; }

  tbody tr {
    height: 32px;
    border-bottom: 1px solid var(--border-0);
    transition: background var(--duration-micro) var(--ease-out);
  }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: var(--bg-1); }

  td {
    padding: 0 var(--sp-3);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .col-actions { width: 280px; }
  .actions-cell { text-align: right; white-space: nowrap; }
  .empty-row {
    padding: var(--sp-8) !important;
    text-align: center;
    white-space: normal;
  }

  .card-list { display: none; }

  @media (max-width: 639.98px) {
    .table-wrap { display: none; }
    .card-list {
      display: flex;
      flex-direction: column;
      gap: var(--sp-2);
      list-style: none;
      padding: 0;
    }
  }

  .card {
    position: relative;
    background: var(--bg-1);
    border: 1px solid var(--border-0);
    border-radius: var(--radius);
    padding: var(--sp-3) var(--sp-3);
  }

  .card-body { padding-right: 40px; }

  .card dl { display: flex; flex-direction: column; gap: var(--sp-2); margin: 0; }
  .card-row { display: flex; flex-direction: column; gap: 2px; }
  .card-row dt { margin: 0; }
  .card-row dd { margin: 0; font-size: 14px; color: var(--fg-1); word-break: break-word; }

  .card-actions {
    position: absolute;
    top: var(--sp-2);
    right: var(--sp-2);
  }

  .empty-card {
    text-align: center;
    padding: var(--sp-6) var(--sp-3);
  }
</style>
