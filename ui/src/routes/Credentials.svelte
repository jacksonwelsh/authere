<script lang="ts">
  import { changeMyPassword, ApiError } from '../lib/api';
  import Button from '../lib/components/Button.svelte';
  import Input from '../lib/components/Input.svelte';
  import { toasts } from '../lib/toast.svelte';

  let currentPassword = $state('');
  let newPassword = $state('');
  let confirmPassword = $state('');
  let saving = $state(false);

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

  <!-- Future credential types (TOTP, Passkeys) will be added as additional .credential-card sections here -->
</div>

<style>
  .page { padding: var(--sp-6); max-width: 480px; margin: 0 auto; }

  .page-header { margin-bottom: var(--sp-6); }

  .credential-card {
    border: 1px solid var(--border-0);
    border-radius: var(--radius);
    padding: var(--sp-5);
    background: var(--bg-1);
    display: flex;
    flex-direction: column;
    gap: var(--sp-4);
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
</style>
