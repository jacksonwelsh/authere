<script lang="ts">
  import { onMount } from 'svelte';
  import QRCode from 'qrcode';
  import {
    changeMyPassword,
    listMyAppPasswords,
    createMyAppPassword,
    deleteMyAppPassword,
    getSettings,
    getMyTotpStatus,
    enrollMyTotp,
    activateMyTotp,
    disableMyTotp,
    ApiError,
    type AppPassword,
    type Settings,
    type TotpStatus,
    type TotpEnrollResponse,
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

  // TOTP
  let totpStatus = $state<TotpStatus | null>(null);
  let totpLoading = $state(true);
  let totpEnroll = $state<TotpEnrollResponse | null>(null);
  let totpCode = $state('');
  let totpBusy = $state(false);
  let totpError = $state('');
  let totpRecoveryCodes = $state<string[] | null>(null);
  let totpQrSvg = $state('');
  let totpDisablePassword = $state('');
  let showDisableTotp = $state(false);

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
    try {
      totpStatus = await getMyTotpStatus();
    } catch {
      // Leave totpStatus null; the section will render a lightweight error state.
    } finally {
      totpLoading = false;
    }
  });

  async function handleStartEnroll() {
    totpBusy = true;
    totpError = '';
    try {
      totpEnroll = await enrollMyTotp();
      totpCode = '';
      totpStatus = { enabled: false, pending: true };
      // Render QR inline as SVG. `margin: 0` matches the container padding so the quiet
      // zone isn't duplicated; `width: 192` keeps it crisp on retina at 50% CSS width.
      totpQrSvg = await QRCode.toString(totpEnroll.otpauth_uri, {
        type: 'svg',
        errorCorrectionLevel: 'M',
        margin: 0,
        width: 192,
      });
    } catch (err: any) {
      totpError = err instanceof ApiError ? err.message : 'Could not start enrollment.';
    } finally {
      totpBusy = false;
    }
  }

  async function handleActivate() {
    if (!/^\d{6}$/.test(totpCode) || totpBusy) return;
    totpBusy = true;
    totpError = '';
    try {
      const resp = await activateMyTotp(totpCode);
      totpRecoveryCodes = resp.recovery_codes;
      totpEnroll = null;
      totpQrSvg = '';
      totpCode = '';
      totpStatus = { enabled: true, pending: false };
    } catch (err: any) {
      if (err instanceof ApiError && err.status === 401) {
        totpError = 'That code did not match. Try again — codes rotate every 30 seconds.';
      } else {
        totpError = err instanceof ApiError ? err.message : 'Could not activate TOTP.';
      }
    } finally {
      totpBusy = false;
    }
  }

  async function handleDisableTotp() {
    if (!totpDisablePassword || totpBusy) return;
    totpBusy = true;
    totpError = '';
    try {
      await disableMyTotp(totpDisablePassword);
      totpStatus = { enabled: false, pending: false };
      totpDisablePassword = '';
      showDisableTotp = false;
      toasts.success('Two-factor authentication disabled.');
    } catch (err: any) {
      if (err instanceof ApiError && err.status === 401) {
        totpError = 'Password is incorrect.';
      } else {
        totpError = err instanceof ApiError ? err.message : 'Could not disable TOTP.';
      }
    } finally {
      totpBusy = false;
    }
  }

  function cancelEnroll() {
    totpEnroll = null;
    totpQrSvg = '';
    totpCode = '';
    totpError = '';
    totpStatus = { enabled: false, pending: false };
  }

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

  <!-- TOTP / Two-factor authentication -->
  <div class="credential-card">
    <div class="credential-header">
      <div>
        <h2 class="au-h4">Two-factor authentication</h2>
        <p class="au-small au-fg-3">
          {#if totpStatus?.enabled}
            An authenticator app is required for every sign-in.
          {:else}
            Add an authenticator app (e.g. 1Password, Authy, Google Authenticator) for a second
            factor on sign-in. Optional.
          {/if}
        </p>
      </div>
      {#if totpStatus?.enabled && !totpEnroll}
        <Button variant="ghost" size="sm" onclick={() => { showDisableTotp = true; totpError = ''; }}>
          Disable
        </Button>
      {/if}
    </div>

    {#if totpLoading}
      <p class="au-small au-fg-3">Loading…</p>
    {:else if totpEnroll}
      <div class="totp-enroll">
        <p class="au-small">
          Scan the QR code with your authenticator app, or tap the link on your phone. Then
          enter the 6-digit code it shows to finish.
        </p>
        {#if totpQrSvg}
          <div class="totp-qr" aria-label="TOTP enrollment QR code">
            {@html totpQrSvg}
          </div>
        {/if}
        <details class="totp-manual">
          <summary class="au-small au-fg-3">Can't scan? Enter details manually</summary>
          <div class="totp-manual-body">
            <code class="au-code-sm totp-secret">{totpEnroll.secret}</code>
            <a class="au-code-sm totp-uri-link" href={totpEnroll.otpauth_uri}>
              Open in authenticator app
            </a>
          </div>
        </details>
        <Input
          label="6-digit code"
          bind:value={totpCode}
          placeholder="123456"
          autocomplete="one-time-code"
          onkeydown={(e) => { if (e.key === 'Enter' && /^\d{6}$/.test(totpCode)) handleActivate(); }}
          error={totpError}
        />
        <div class="card-actions totp-actions">
          <Button variant="ghost" onclick={cancelEnroll} disabled={totpBusy}>Cancel</Button>
          <Button
            variant="primary"
            onclick={handleActivate}
            loading={totpBusy}
            disabled={!/^\d{6}$/.test(totpCode) || totpBusy}
          >
            Verify and enable
          </Button>
        </div>
      </div>
    {:else if totpStatus?.enabled}
      <p class="au-small au-fg-3">
        <i class="ph ph-shield-check"></i>
        Active.
      </p>
    {:else}
      {#if totpError}
        <div class="form-error au-small" role="alert">
          <i class="ph ph-warning"></i>
          {totpError}
        </div>
      {/if}
      <div class="card-actions">
        <Button variant="primary" onclick={handleStartEnroll} loading={totpBusy} disabled={totpBusy}>
          Add authenticator app
        </Button>
      </div>
    {/if}
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

{#if totpRecoveryCodes}
  <Modal title="Save your recovery codes" onclose={() => (totpRecoveryCodes = null)}>
    <p class="au-small">
      Each code can be used <strong>once</strong> to sign in if you lose access to your
      authenticator. Store them somewhere safe — they won't be shown again.
    </p>
    <ul class="totp-recovery-list">
      {#each totpRecoveryCodes as code (code)}
        <li><code class="au-code-sm">{code}</code></li>
      {/each}
    </ul>
    <div class="reveal-row">
      <Button variant="secondary" onclick={() => copy(totpRecoveryCodes!.join('\n'))}>
        Copy all
      </Button>
    </div>
    {#snippet actions()}
      <Button variant="primary" onclick={() => (totpRecoveryCodes = null)}>
        I've saved them
      </Button>
    {/snippet}
  </Modal>
{/if}

{#if showDisableTotp}
  <Modal title="Disable two-factor authentication" onclose={() => { showDisableTotp = false; totpError = ''; totpDisablePassword = ''; }}>
    <p class="au-small">
      Confirm your password to turn off 2FA. You can always re-enable it later.
    </p>
    <div class="create-field">
      <Input
        label="Current password"
        type="password"
        bind:value={totpDisablePassword}
        autocomplete="current-password"
        placeholder="••••••••••••"
        error={totpError}
        onkeydown={(e) => { if (e.key === 'Enter' && totpDisablePassword) handleDisableTotp(); }}
      />
    </div>
    {#snippet actions()}
      <Button variant="ghost" onclick={() => { showDisableTotp = false; totpError = ''; totpDisablePassword = ''; }}>
        Cancel
      </Button>
      <Button
        variant="primary"
        onclick={handleDisableTotp}
        loading={totpBusy}
        disabled={!totpDisablePassword || totpBusy}
      >
        Disable 2FA
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

  @media (max-width: 639.98px) {
    .page { padding: var(--sp-4); gap: var(--sp-4); }
  }

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

  .form-error {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    color: var(--danger);
    background: var(--danger-subtle);
    border: 1px solid rgba(239,68,68,0.2);
    border-radius: var(--radius);
    padding: var(--sp-2) var(--sp-3);
  }

  .totp-enroll {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }

  .totp-qr {
    display: flex;
    justify-content: center;
    padding: var(--sp-4);
    background: #fff;
    border: 1px solid var(--border-1);
    border-radius: var(--radius);
  }
  .totp-qr :global(svg) {
    width: 192px;
    height: 192px;
    display: block;
  }

  .totp-manual {
    border: 1px solid var(--border-1);
    border-radius: var(--radius);
    padding: var(--sp-2) var(--sp-3);
    background: var(--bg-2);
  }
  .totp-manual summary {
    cursor: pointer;
    list-style: none;
  }
  .totp-manual summary::-webkit-details-marker { display: none; }
  .totp-manual summary::before {
    content: '▸ ';
    display: inline-block;
    transition: transform var(--duration-micro) var(--ease-out);
    margin-right: var(--sp-1);
  }
  .totp-manual[open] summary::before { transform: rotate(90deg); }
  .totp-manual-body {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    margin-top: var(--sp-3);
  }
  .totp-uri-link {
    color: var(--accent);
    text-decoration: underline;
    word-break: break-all;
  }

  .totp-secret {
    display: inline-block;
    padding: var(--sp-1) var(--sp-2);
    background: var(--bg-2);
    border: 1px solid var(--border-1);
    border-radius: var(--radius);
    letter-spacing: 0.1em;
  }

  .totp-actions {
    gap: var(--sp-2);
  }

  .totp-recovery-list {
    list-style: none;
    padding: var(--sp-3);
    margin: var(--sp-3) 0 0;
    background: var(--bg-2);
    border: 1px solid var(--border-1);
    border-radius: var(--radius);
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: var(--sp-2);
  }
  .totp-recovery-list li { text-align: center; }

  @media (max-width: 480px) {
    .totp-recovery-list { grid-template-columns: 1fr; }
  }
</style>
