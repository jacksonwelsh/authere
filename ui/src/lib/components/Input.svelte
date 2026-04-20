<script lang="ts">
  interface Props {
    value?: string;
    type?: string;
    placeholder?: string;
    label?: string;
    error?: string;
    disabled?: boolean;
    autofocus?: boolean;
    autocomplete?: string;
    id?: string;
    onchange?: (v: string) => void;
    oninput?: (v: string) => void;
    onkeydown?: (e: KeyboardEvent) => void;
    onblur?: () => void;
  }
  let {
    value = $bindable(''),
    type = 'text',
    placeholder = '',
    label = '',
    error = '',
    disabled = false,
    autofocus = false,
    autocomplete,
    id,
    onchange,
    oninput,
    onkeydown,
    onblur,
  }: Props = $props();

  const inputId = id ?? `input-${Math.random().toString(36).slice(2)}`;
</script>

<div class="field" class:has-error={!!error}>
  {#if label}
    <label for={inputId} class="field-label au-nano">{label}</label>
  {/if}
  <input
    {type}
    {placeholder}
    {disabled}
    {autofocus}
    {autocomplete}
    id={inputId}
    bind:value
    onchange={() => onchange?.(value)}
    oninput={() => oninput?.(value)}
    {onkeydown}
    {onblur}
    class="au-input"
  />
  {#if error}
    <p class="field-error au-small">{error}</p>
  {/if}
</div>

<style>
  .field { display: flex; flex-direction: column; gap: var(--sp-1); }

  .field-label {
    color: var(--fg-3);
    letter-spacing: 0.06em;
  }

  .au-input {
    height: 32px;
    padding: 0 var(--sp-3);
    background: var(--bg-2);
    border: 1px solid var(--border-1);
    border-radius: var(--radius);
    color: var(--fg-1);
    font-family: inherit;
    font-size: 13px;
    outline: none;
    transition: border-color var(--duration-micro) var(--ease-out);
    width: 100%;
  }

  .au-input::placeholder { color: var(--fg-5); }
  .au-input:hover:not(:disabled) { border-color: var(--border-2); }
  .au-input:focus { border-color: var(--border-focus); box-shadow: 0 0 0 2px var(--accent-subtle) inset; }
  .au-input:disabled { opacity: 0.45; cursor: not-allowed; }

  .has-error .au-input { border-color: var(--danger); }
  .field-error { color: var(--danger); margin-top: 2px; }
</style>
