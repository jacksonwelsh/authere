<script lang="ts">
  import { onMount } from 'svelte';
  import { listMyPasskeys, deleteMyPasskey, type Passkey } from '../api';
  import { supportsPasskeys, registerPasskey, passkeyError } from '../passkeys';
  import Button from './Button.svelte';
  import Input from './Input.svelte';
  import Modal from './Modal.svelte';
  import { toasts } from '../toast.svelte';

  const supported = supportsPasskeys();
  let passkeys = $state<Passkey[]>([]);
  let loading = $state(true);
  let loadError = $state('');
  let error = $state('');
  let adding = $state(false);
  let removing = $state<Passkey | null>(null);
  let name = $state('');
  let busy = $state(false);

  async function load() {
    loading = true;
    loadError = '';
    try { passkeys = await listMyPasskeys(); }
    catch { loadError = 'Could not load your passkeys.'; }
    finally { loading = false; }
  }
  onMount(load);

  async function add() {
    if (busy || !name.trim()) return;
    busy = true;
    error = '';
    try {
      const passkey = await registerPasskey(name.trim());
      passkeys = [passkey, ...passkeys];
      adding = false;
      name = '';
      toasts.success('Passkey added. You can now sign in without a password or authentication code.');
    } catch (err) { error = passkeyError(err); }
    finally { busy = false; }
  }

  async function remove() {
    if (busy || !removing) return;
    busy = true;
    error = '';
    try {
      await deleteMyPasskey(removing.id);
      window.location.href = '/login';
    } catch (err) { error = passkeyError(err); busy = false; }
  }

  function close() {
    if (busy) return;
    adding = false;
    removing = null;
    error = '';
  }
</script>

<section class="passkey-card" aria-labelledby="passkeys-heading">
  <div>
    <h2 id="passkeys-heading" class="au-h4">Passkeys <span class="au-micro au-fg-3">Recommended</span></h2>
    <p class="au-small au-fg-3">Your most secure sign-in method. Use your fingerprint, face, or device PIN. Passkeys satisfy two-factor authentication without an authenticator code.</p>
  </div>
  {#if loading}
    <p class="au-small au-fg-3">Loading passkeys…</p>
  {:else if loadError}
    <p class="au-small" role="alert">{loadError}</p>
    <Button onclick={load}>Try again</Button>
  {:else if passkeys.length === 0}
    <p class="au-small au-fg-3">No passkeys yet. Add one from your device, password manager, or security key.</p>
  {:else}
    <ul>
      {#each passkeys as passkey (passkey.id)}
        <li>
          <div class="key-info">
            <strong class="au-small">{passkey.name}</strong>
            <span class="au-micro au-fg-3">
              Added {new Date(passkey.created_at * 1000).toLocaleDateString()}
              · {passkey.last_used_at ? `Last used ${new Date(passkey.last_used_at * 1000).toLocaleDateString()}` : 'Not used yet'}
            </span>
          </div>
          <Button variant="ghost" onclick={() => { removing = passkey; error = ''; }}>Remove</Button>
        </li>
      {/each}
    </ul>
  {/if}
  {#if !supported}
    <p class="au-small au-fg-3">To add a passkey, open Authere over HTTPS in a browser that supports passkeys.</p>
  {/if}
  <div class="actions">
    <Button variant="primary" disabled={!supported || loading || !!loadError} onclick={() => { adding = true; error = ''; }}>Add passkey</Button>
  </div>
</section>

{#if adding}
  <Modal title="Add passkey" onclose={close}>
    <p class="au-small au-fg-3">Choose a name you will recognize. Your browser will help you choose where to save the passkey.</p>
    <Input label="Passkey name" bind:value={name} placeholder="Personal password manager" />
    {#if error}<p class="au-small error" role="alert">{error}</p>{/if}
    {#snippet actions()}
      <Button variant="ghost" disabled={busy} onclick={close}>Cancel</Button>
      <Button variant="primary" loading={busy} disabled={busy || !name.trim() || name.trim().length > 100} onclick={add}>Create passkey</Button>
    {/snippet}
  </Modal>
{/if}

{#if removing}
  <Modal title="Remove passkey" onclose={close}>
    <p class="au-small">Remove <strong>{removing.name}</strong>? This signs you out on all devices. You can sign in again with another passkey or your password{passkeys.length === 1 ? ' and your authenticator code if enabled' : ''}.</p>
    {#if error}<p class="au-small error" role="alert">{error}</p>{/if}
    {#snippet actions()}
      <Button variant="ghost" disabled={busy} onclick={close}>Cancel</Button>
      <Button variant="danger" loading={busy} disabled={busy} onclick={remove}>Remove passkey</Button>
    {/snippet}
  </Modal>
{/if}

<style>
  .passkey-card { border: 1px solid var(--border-0); border-radius: var(--radius); padding: var(--sp-5); background: var(--bg-1); display: flex; flex-direction: column; gap: var(--sp-4); }
  h2 { display: flex; align-items: baseline; flex-wrap: wrap; gap: var(--sp-2); margin-bottom: var(--sp-1); }
  ul { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: var(--sp-2); }
  li { display: flex; align-items: center; justify-content: space-between; gap: var(--sp-2); border: 1px solid var(--border-0); border-radius: var(--radius); padding: var(--sp-3); }
  .key-info { display: flex; flex-direction: column; gap: var(--sp-1); min-width: 0; overflow-wrap: anywhere; }
  .actions { display: flex; justify-content: flex-end; }
  .error { color: var(--danger); }
</style>
