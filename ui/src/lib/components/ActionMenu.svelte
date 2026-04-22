<script lang="ts">
  interface Props {
    label?: string;
    align?: 'left' | 'right';
    children: import('svelte').Snippet<[{ close: () => void }]>;
  }
  let { label = 'Actions', align = 'right', children }: Props = $props();

  let open = $state(false);
  let triggerEl: HTMLButtonElement | undefined = $state();
  let menuEl: HTMLDivElement | undefined = $state();

  function close() {
    open = false;
    triggerEl?.focus();
  }

  function toggle() {
    open = !open;
  }

  function onDocumentClick(e: MouseEvent) {
    if (!open) return;
    const target = e.target as Node | null;
    if (!target) return;
    if (menuEl?.contains(target) || triggerEl?.contains(target)) return;
    open = false;
  }

  function onKeydown(e: KeyboardEvent) {
    if (!open) return;
    if (e.key === 'Escape') {
      e.stopPropagation();
      close();
    }
  }

  // Auto-close when any button inside the menu is clicked.
  function onMenuClick(e: MouseEvent) {
    const btn = (e.target as HTMLElement | null)?.closest('button');
    if (btn && menuEl?.contains(btn)) {
      open = false;
    }
  }
</script>

<svelte:window onclick={onDocumentClick} onkeydown={onKeydown} />

<div class="action-menu">
  <button
    type="button"
    class="trigger"
    aria-label={label}
    aria-haspopup="menu"
    aria-expanded={open}
    bind:this={triggerEl}
    onclick={toggle}
    data-testid="action-menu-trigger"
  >
    <i class="ph ph-dots-three-vertical"></i>
  </button>
  {#if open}
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
    <div
      class="menu"
      class:align-left={align === 'left'}
      role="menu"
      tabindex="-1"
      bind:this={menuEl}
      onclick={onMenuClick}
      data-testid="action-menu"
    >
      {@render children({ close })}
    </div>
  {/if}
</div>

<style>
  .action-menu {
    position: relative;
    display: inline-flex;
  }

  .trigger {
    width: 36px;
    height: 36px;
    background: none;
    border: none;
    color: var(--fg-3);
    cursor: pointer;
    border-radius: var(--radius);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 18px;
  }
  .trigger:hover { background: var(--bg-3); color: var(--fg-1); }

  .menu {
    position: absolute;
    top: calc(100% + 4px);
    right: 0;
    z-index: 50;
    min-width: 160px;
    background: var(--bg-2);
    border: 1px solid var(--border-1);
    border-radius: var(--radius);
    box-shadow: var(--shadow-raised);
    padding: var(--sp-1);
    display: flex;
    flex-direction: column;
    gap: 2px;
    animation: fadeIn var(--duration-micro) var(--ease-out);
  }

  .menu.align-left { right: auto; left: 0; }

  /* Stretch all ghost buttons inside the menu. */
  .menu :global(.btn) {
    width: 100%;
    justify-content: flex-start;
  }

  @keyframes fadeIn { from { opacity: 0; transform: translateY(-4px); } }
</style>
