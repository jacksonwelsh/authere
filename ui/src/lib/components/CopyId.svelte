<script lang="ts">
  import { toasts } from '../toast.svelte';

  interface Props {
    id: string;
  }
  let { id }: Props = $props();

  async function copy() {
    await navigator.clipboard.writeText(id);
    toasts.success(`Copied ${id}`);
  }
</script>

<button class="copy-id au-code-sm au-fg-4" onclick={copy} title={id}>
  …{id.slice(-12)}
</button>

<style>
  .copy-id {
    background: none;
    border: none;
    padding: 0;
    font-family: inherit;
    font-size: inherit;
    color: inherit;
    cursor: pointer;
    border-radius: var(--radius);
    transition: color var(--duration-micro) var(--ease-out);
  }
  .copy-id:hover { color: var(--fg-2); }
</style>
