<script lang="ts">
  interface Props {
    variant?: 'default' | 'success' | 'warning' | 'danger' | 'accent';
    children: import('svelte').Snippet;
  }
  let { variant = 'default', children }: Props = $props();
</script>

<span class="badge badge-{variant}">
  {@render children()}
</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    height: 18px;
    padding: 0 6px;
    border-radius: var(--radius);
    font-size: 11px;
    font-weight: 500;
    letter-spacing: 0.04em;
    white-space: nowrap;
  }
  .badge-default  { background: var(--bg-4); color: var(--fg-3); border: 1px solid var(--border-1); }
  .badge-success  { background: rgba(16,185,129,0.12); color: var(--success); border: 1px solid rgba(16,185,129,0.25); }
  .badge-warning  { background: rgba(245,158,11,0.12); color: var(--warning); border: 1px solid rgba(245,158,11,0.25); }
  .badge-danger   { background: rgba(239,68,68,0.12);  color: var(--danger);  border: 1px solid rgba(239,68,68,0.25); }
  .badge-accent   { background: var(--accent-subtle);   color: var(--accent);  border: 1px solid rgba(59,130,246,0.25); }
</style>
