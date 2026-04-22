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
    display: flex;
    flex-direction: column;
    max-height: calc(100vh - 32px);
    animation: slideIn var(--duration-default) var(--ease-out);
  }

  .modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--sp-4) var(--sp-4) 0;
    margin-bottom: var(--sp-4);
    flex-shrink: 0;
  }

  .modal-body {
    padding: 0 var(--sp-4) var(--sp-4);
    overflow-y: auto;
    flex: 1;
    min-height: 0;
  }

  .modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--sp-2);
    padding: var(--sp-3) var(--sp-4);
    border-top: 1px solid var(--border-0);
    background: var(--bg-1);
    flex-shrink: 0;
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

  /* Full-screen sheet on phones — maximises form room and keeps actions above keyboard.
     100dvh (dynamic viewport height) tracks mobile Safari's collapsing URL bar,
     so the action row lines up with the visible viewport bottom instead of being
     hidden underneath the address-bar pill. env(safe-area-inset-bottom) adds
     padding past the home indicator on devices that have one. */
  @media (max-width: 639.98px) {
    .overlay {
      align-items: flex-start;
      justify-content: center;
    }

    .modal {
      width: 100%;
      max-width: none;
      height: 100dvh;
      max-height: 100dvh;
      border: none;
      border-radius: 0;
      overflow-x: hidden;
      animation: slideInSheet var(--duration-default) var(--ease-out);
    }

    .modal-header {
      padding: var(--sp-3);
      margin-bottom: 0;
      border-bottom: 1px solid var(--border-0);
    }

    .modal-body {
      padding: var(--sp-4) var(--sp-3);
      overflow-x: hidden;
    }

    .modal-actions {
      padding: var(--sp-3);
      padding-bottom: max(var(--sp-3), env(safe-area-inset-bottom));
    }

    .modal-actions :global(> *) {
      flex: 1;
      min-width: 0;
    }
  }

  @keyframes slideInSheet { from { opacity: 0; transform: translateY(16px); } }
</style>
