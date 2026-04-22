<script lang="ts">
  import { onMount } from 'svelte';
  import {
    changeMyPassword,
    listMyAppPasswords,
    createMyAppPassword,
    deleteMyAppPassword,
    getSettings,
    ApiError,
    type AppPassword,
    type Settings,
  } from '../lib/api';
  import Button from '../lib/components/Button.svelte';
  import Input from '../lib/components/Input.svelte';
  import Modal from '../lib/components/Modal.svelte';
  import { toasts } from '../lib/toast.svelte';

  let currentPassword = $state('');
  let newPassword = $state('');
  let confirmPassword = $state('');
  let saving = $state(false);

  // App passwords
  let settings = $state<Settings | null>(null);
  let appPasswords = $state<AppPassword[]>([]);
  let loadingApp = $state(true);
  let showCreate = $state(false);
  let newName = $state('');
  let creating = $state(false);
  let revealed = $state<{ name: string; password: string } | null>(null);
  let deleting = $state<string | null>(null);

  const lengthError = $derived(
    newPassword.length > 0 && newPassword.length < 12
      ? 'Password must be at least 12 characters'
      : ''
  );

  const confirmError = $derived(
    confirmPassword.length > 0 && newPassword !== confirmPassword
      ? 'Passwords do not match'
      : ''
  );

  const canSave = $derived(
    !!currentPassword && !!newPassword && !!confirmPassword &&
    !lengthError && !confirmError && !saving
  );

  const appPasswordsAvailable = $derived(
    settings?.ldap.password_mode !== 'primary_only'
  );

  const appPasswordHelp = $derived.by(() => {
    const mode = settings?.ldap.password_mode;
    if (mode === 'app_only') {
      return 'Required for LDAP-based services like Jellyfin. Your account password will not work there.';
    }
    return 'Optional — use this if you would rather not type your account password into a third-party app. Required for accounts with two-factor authentication.';
  });

  onMount(async () => {
    try {
      settings = await getSettings();
      if (settings.ldap.password_mode !== 'primary_only') {
        appPasswords = await listMyAppPasswords();
      }
    } catch {
      // Silent — app passwords are optional.
    } finally {
      loadingApp = false;
    }
  });

  async function handleChangePassword() {
    if (!canSave) return;
    saving = true;
    try {
      await changeMyPassword({ current_password: currentPassword, new_password: newPassword });
      toasts.success('Password changed. Please sign in again.');
      window.location.href = '/login';
    } catch (err: any) {
      if (err instanceof ApiError && err.status === 401) {
        toasts.error('Current password is incorrect.');
      } else {
        toasts.error(`Failed to change password: ${err.message}`);
      }
      saving = false;
    }
  }

  async function handleCreateAppPassword() {
    if (!newName.trim() || creating) return;
    creating = true;
    try {
      const resp = await createMyAppPassword(newName.trim());
      appPasswords = [resp.app_password, ...appPasswords];
      revealed = { name: resp.app_password.name, password: resp.password };
      showCreate = false;
      newName = '';
    } catch (err: any) {
      toasts.error(`Failed to create: ${err.message}`);
    } finally {
      creating = false;
    }
  }

  async function handleDelete(id: string) {
    if (deleting) return;
    deleting = id;
    try {
      await deleteMyAppPassword(id);
      appPasswords = appPasswords.filter((p) => p.id !== id);
      toasts.success('Revoked.');
    } catch (err: any) {
      toasts.error(`Failed to revoke: ${err.message}`);
    } finally {
      deleting = null;
    }
  }

  function copy(text: string) {
    navigator.clipboard.writeText(text).then(() => toasts.success('Copied.'));
  }

  function formatDate(ts: number | null) {
    if (!ts) return '—';
    return new Date(ts * 1000).toLocaleDateString();
  }
</script>

<div class="page">
  <header class="page-header">
    <div>
      <h1 class="au-h3">Credentials</h1>
      <p class="au-micro au-fg-3">Manage your sign-in methods</p>
    </div>
  </header>

  <!-- Password credential card -->
  <div class="credential-card">
    <div class="credential-header">
      <div>
        <h2 class="au-h4">Password</h2>
        <p class="au-small au-fg-3">Change your sign-in password. All active sessions will be signed out.</p>
      </div>
    </div>
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div
      class="form-fields"
      role="group"
      onkeydown={(e) => { if (e.key === 'Enter' && canSave) handleChangePassword(); }}
    >
      <Input
        label="Current password"
        type="password"
        bind:value={currentPassword}
        autocomplete="current-password"
        placeholder="••••••••••••"
      />
      <Input
        label="New password"
        type="password"
        bind:value={newPassword}
        autocomplete="new-password"
        placeholder="Min. 12 characters"
        error={lengthError}
      />
      <Input
        label="Confirm new password"
        type="password"
        bind:value={confirmPassword}
        autocomplete="new-password"
        placeholder="••••••••••••"
        error={confirmError}
      />
    </div>
    <div class="card-actions">
      <Button variant="primary" loading={saving} disabled={!canSave} onclick={handleChangePassword}>
        Change password
      </Button>
    </div>
  </div>

  {#if appPasswordsAvailable}
    <div class="credential-card">
      <div class="credential-header">
        <div>
          <h2 class="au-h4">App passwords</h2>
          <p class="au-small au-fg-3">{appPasswordHelp}</p>
        </div>
        <Button variant="primary" size="sm" onclick={() => { showCreate = true; newName = ''; }}>
          New app password
        </Button>
      </div>
      {#if loadingApp}
        <p class="au-small au-fg-3">Loading…</p>
      {:else if appPasswords.length === 0}
        <p class="au-small au-fg-3">You haven't created any app passwords yet.</p>
      {:else}
        <ul class="app-pw-list">
          {#each appPasswords as p (p.id)}
            <li class="app-pw-row">
              <div class="app-pw-info">
                <span class="au-small font-medium">{p.name}</span>
                <span class="au-micro au-fg-3">
                  Created {formatDate(p.created_at)} · Last used {formatDate(p.last_used_at)}
                </span>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onclick={() => handleDelete(p.id)}
                loading={deleting === p.id}
              >
                Revoke
              </Button>
            </li>
          {/each}
        </ul>
      {/if}
    </div>
  {/if}
</div>

{#if showCreate}
  <Modal title="New app password" onclose={() => (showCreate = false)}>
    <p class="au-small au-fg-3">Give this password a name so you can recognise it later (e.g. "Jellyfin").</p>
    <div class="create-field">
      <Input
        label="Name"
        bind:value={newName}
        placeholder="Jellyfin"
        autofocus
        onkeydown={(e) => { if (e.key === 'Enter' && newName.trim()) handleCreateAppPassword(); }}
      />
    </div>
    {#snippet actions()}
      <Button variant="ghost" onclick={() => (showCreate = false)}>Cancel</Button>
      <Button variant="primary" onclick={handleCreateAppPassword} loading={creating} disabled={!newName.trim()}>
        Create
      </Button>
    {/snippet}
  </Modal>
{/if}

{#if revealed}
  <Modal title="App password created" onclose={() => (revealed = null)}>
    <p class="au-small">
      Copy this password now — it won't be shown again. Paste it into the LDAP client for
      <strong>{revealed.name}</strong>.
    </p>
    <div class="reveal-row">
      <code class="reveal-code au-code-sm">{revealed.password}</code>
      <Button variant="secondary" onclick={() => copy(revealed!.password)}>Copy</Button>
    </div>
    {#snippet actions()}
      <Button variant="primary" onclick={() => (revealed = null)}>Done</Button>
    {/snippet}
  </Modal>
{/if}

<style>
  .page { padding: var(--sp-6); max-width: 560px; margin: 0 auto; display: flex; flex-direction: column; gap: var(--sp-5); }

  .page-header { margin-bottom: var(--sp-2); }

  .credential-card {
    border: 1px solid var(--border-0);
    border-radius: var(--radius);
    padding: var(--sp-5);
    background: var(--bg-1);
    display: flex;
    flex-direction: column;
    gap: var(--sp-4);
  }

  .credential-header {
    display: flex;
    justify-content: space-between;
    gap: var(--sp-4);
    align-items: flex-start;
  }
  .credential-header h2 { margin-bottom: var(--sp-1); }

  .form-fields {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }

  .card-actions {
    display: flex;
    justify-content: flex-end;
  }

  .app-pw-list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
  }
  .app-pw-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: var(--sp-3);
    padding: var(--sp-3);
    border: 1px solid var(--border-0);
    border-radius: var(--radius);
    background: var(--bg-2);
  }
  .app-pw-info {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
    min-width: 0;
  }

  .create-field { margin-top: var(--sp-3); }

  .reveal-row {
    display: flex;
    gap: var(--sp-2);
    align-items: center;
    margin-top: var(--sp-3);
  }
  .reveal-code {
    flex: 1;
    padding: var(--sp-2) var(--sp-3);
    background: var(--bg-2);
    border: 1px solid var(--border-1);
    border-radius: var(--radius);
    font-family: var(--mono, ui-monospace, monospace);
    word-break: break-all;
  }
</style>
