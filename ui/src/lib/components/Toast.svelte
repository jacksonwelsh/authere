<script lang="ts">
  export interface ToastItem {
    id: string;
    message: string;
    variant: 'success' | 'danger' | 'default';
  }

  interface Props { items: ToastItem[]; onremove: (id: string) => void; }
  let { items, onremove }: Props = $props();
</script>

<div class="toast-stack" aria-live="polite">
  {#each items as item (item.id)}
    <div class="toast toast-{item.variant}" role="status">
      {#if item.variant === 'success'}
        <i class="ph ph-check-circle"></i>
      {:else if item.variant === 'danger'}
        <i class="ph ph-warning-circle"></i>
      {:else}
        <i class="ph ph-info"></i>
      {/if}
      <span class="au-small">{item.message}</span>
      <button class="dismiss" onclick={() => onremove(item.id)} aria-label="Dismiss">
        <i class="ph ph-x"></i>
      </button>
    </div>
  {/each}
</div>

<style>
  .toast-stack {
    position: fixed;
    bottom: var(--sp-6);
    right: var(--sp-6);
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    z-index: 200;
  }

  .toast {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    padding: var(--sp-2) var(--sp-3);
    border-radius: var(--radius);
    border: 1px solid var(--border-1);
    background: var(--bg-2);
    box-shadow: var(--shadow-raised);
    min-width: 240px;
    animation: slideUp var(--duration-default) var(--ease-out);
  }

  .toast-success { border-color: rgba(16,185,129,0.3); color: var(--success); }
  .toast-danger  { border-color: rgba(239,68,68,0.3);  color: var(--danger); }
  .toast-default { color: var(--fg-2); }

  .toast span { color: var(--fg-2); flex: 1; }

  .dismiss {
    background: none; border: none; color: var(--fg-4);
    cursor: pointer; padding: 2px; display: flex; align-items: center;
    border-radius: var(--radius);
  }
  .dismiss:hover { color: var(--fg-2); }

  @keyframes slideUp { from { opacity: 0; transform: translateY(8px); } }
</style>
