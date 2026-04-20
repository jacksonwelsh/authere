<script lang="ts">
  interface Props {
    variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
    size?: 'sm' | 'md' | 'lg';
    disabled?: boolean;
    loading?: boolean;
    type?: 'button' | 'submit' | 'reset';
    onclick?: (e: MouseEvent) => void;
    children: import('svelte').Snippet;
  }
  let { variant = 'secondary', size = 'md', disabled = false, loading = false, type = 'button', onclick, children }: Props = $props();
</script>

<button
  {type}
  {disabled}
  class="btn btn-{variant} btn-{size}"
  class:loading
  onclick={onclick}
  aria-busy={loading}
>
  {#if loading}
    <i class="ph ph-circle-notch spin" aria-hidden="true"></i>
  {/if}
  {@render children()}
</button>

<style>
  .btn {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-1);
    border-radius: var(--radius);
    font-family: inherit;
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    border: 1px solid transparent;
    white-space: nowrap;
    transition: background var(--duration-micro) var(--ease-out),
                border-color var(--duration-micro) var(--ease-out),
                color var(--duration-micro) var(--ease-out);
    line-height: 1;
  }

  .btn-sm { height: 26px; padding: 0 var(--sp-2); font-size: 12px; }
  .btn-md { height: 32px; padding: 0 var(--sp-3); }
  .btn-lg { height: 40px; padding: 0 var(--sp-4); font-size: 14px; }

  .btn-primary {
    background: var(--accent);
    color: #fff;
    border-color: var(--accent);
  }
  .btn-primary:hover:not(:disabled) { background: var(--accent-hover); border-color: var(--accent-hover); }
  .btn-primary:active:not(:disabled) { background: var(--accent-pressed); border-color: var(--accent-pressed); }

  .btn-secondary {
    background: var(--bg-3);
    color: var(--fg-2);
    border-color: var(--border-1);
  }
  .btn-secondary:hover:not(:disabled) { background: var(--bg-4); color: var(--fg-1); }
  .btn-secondary:active:not(:disabled) { background: var(--slate-4); }

  .btn-ghost {
    background: transparent;
    color: var(--fg-3);
    border-color: transparent;
  }
  .btn-ghost:hover:not(:disabled) { background: var(--bg-3); color: var(--fg-2); }

  .btn-danger {
    background: var(--danger);
    color: #fff;
    border-color: var(--danger);
  }
  .btn-danger:hover:not(:disabled) { background: var(--danger-hover); }

  .btn:disabled, .btn.loading {
    opacity: 0.45;
    cursor: not-allowed;
  }

  .btn:focus-visible {
    outline: none;
    box-shadow: 0 0 0 2px var(--border-focus) inset;
  }

  .spin { animation: spin 0.7s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
