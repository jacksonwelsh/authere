<script lang="ts">
  interface Props {
    title: string;
    onclose: () => void;
    children: import('svelte').Snippet;
    actions?: import('svelte').Snippet;
    width?: number;
  }
  let { title, onclose, children, actions, width }: Props = $props();

  function onkeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') onclose();
  }
</script>

<svelte:window onkeydown={onkeydown} />

<!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
<div class="overlay" onclick={onclose}>
  <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
  <div class="modal" style={width ? `width: ${width}px;` : ''} onclick={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-labelledby="modal-title">
    <div class="modal-header">
      <h2 id="modal-title" class="au-h4">{title}</h2>
      <button class="close-btn" onclick={onclose} aria-label="Close">
        <i class="ph ph-x"></i>
      </button>
    </div>
    <div class="modal-body">
      {@render children()}
    </div>
    {#if actions}
      <div class="modal-actions">
        {@render actions()}
      </div>
    {/if}
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
    animation: fadeIn var(--duration-default) var(--ease-out);
  }

  .modal {
    background: var(--bg-2);
    border: 1px solid var(--border-1);
    border-radius: var(--radius);
    box-shadow: var(--shadow-raised);
    width: 480px;
    max-width: calc(100vw - 32px);
    animation: slideIn var(--duration-default) var(--ease-out);
  }

  .modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--sp-4) var(--sp-4) 0;
    margin-bottom: var(--sp-4);
  }

  .modal-body { padding: 0 var(--sp-4) var(--sp-4); }

  .modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--sp-2);
    padding: var(--sp-3) var(--sp-4);
    border-top: 1px solid var(--border-0);
    background: var(--bg-1);
  }

  .close-btn {
    background: none;
    border: none;
    color: var(--fg-4);
    cursor: pointer;
    padding: var(--sp-1);
    border-radius: var(--radius);
    font-size: 16px;
    display: flex;
    align-items: center;
  }
  .close-btn:hover { background: var(--bg-3); color: var(--fg-2); }

  @keyframes fadeIn { from { opacity: 0; } }
  @keyframes slideIn { from { opacity: 0; transform: translateY(-8px); } }
</style>
