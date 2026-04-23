<script lang="ts">
  import { onMount } from 'svelte';
  import {
    getSettings,
    updateSettings,
    regenerateLdapBindPassword,
    getRoles,
    listScimTokens,
    createScimToken,
    revokeScimToken,
    restartService,
    type Settings,
    type LdapPasswordMode,
    type Role,
    type ScimToken,
  } from '../../lib/api';
  import { toasts } from '../../lib/toast.svelte';
  import Button from '../../lib/components/Button.svelte';
  import Input from '../../lib/components/Input.svelte';
  import Modal from '../../lib/components/Modal.svelte';

  let settings = $state<Settings | null>(null);
  let roles = $state<Role[]>([]);
  let loading = $state(true);
  let saving = $state(false);

  // LDAP form state (editable copies). We only PATCH on blur/toggle so admins can edit
  // freely without each keystroke hitting the server.
  let ldapBaseDn = $state('');
  let ldapBindAddress = $state('');
  let baseDnError = $state('');
  let bindAddressError = $state('');

  // Session expiry presets. Admins pick from a fixed set rather than typing seconds;
  // this avoids them accidentally entering "60" and getting locked out every minute.
  const SESSION_EXPIRY_PRESETS: { label: string; value: number }[] = [
    { label: '1 hour', value: 60 * 60 },
    { label: '8 hours', value: 8 * 60 * 60 },
    { label: '1 day', value: 24 * 60 * 60 },
    { label: '7 days', value: 7 * 24 * 60 * 60 },
    { label: '30 days', value: 30 * 24 * 60 * 60 },
    { label: '90 days', value: 90 * 24 * 60 * 60 },
  ];

  // One-time reveal of the generated service bind password.
  let revealedPassword = $state<string | null>(null);
  let confirmRegenerate = $state(false);
  let regenerating = $state(false);

  // SCIM token management
  let scimTokens = $state<ScimToken[]>([]);
  let scimLoading = $state(true);
  let showCreateScimToken = $state(false);
  let scimTokenName = $state('');
  let creatingScimToken = $state(false);
  let revokingScimToken = $state<string | null>(null);
  let revealedScimToken = $state<{ name: string; token: string } | null>(null);

  // Restart
  let confirmRestart = $state(false);
  let restarting = $state(false);

  onMount(async () => {
    try {
      const [s, r] = await Promise.all([getSettings(), getRoles()]);
      settings = s;
      roles = r;
      ldapBaseDn = s.ldap.base_dn;
      ldapBindAddress = s.ldap.bind_address;
    } catch {
      toasts.error('Failed to load settings.');
    } finally {
      loading = false;
    }

    try {
      scimTokens = await listScimTokens();
    } catch {
      // SCIM tokens are optional — don't block the page
    } finally {
      scimLoading = false;
    }
  });

  async function handleSessionExpiryChange(value: number) {
    if (!settings || saving || settings.session_expiry_seconds === value) return;
    const prev = settings.session_expiry_seconds;
    settings = { ...settings, session_expiry_seconds: value };
    saving = true;
    try {
      settings = await updateSettings({ session_expiry_seconds: value });
      toasts.success('Session lifetime updated.');
    } catch (err: any) {
      settings = { ...settings!, session_expiry_seconds: prev };
      toasts.error(`Failed to save: ${err.message}`);
    } finally {
      saving = false;
    }
  }

  function formatSessionExpiry(seconds: number): string {
    const preset = SESSION_EXPIRY_PRESETS.find((p) => p.value === seconds);
    if (preset) return preset.label;
    if (seconds % 86400 === 0) return `${seconds / 86400} days`;
    if (seconds % 3600 === 0) return `${seconds / 3600} hours`;
    return `${seconds} seconds`;
  }

  async function handleRegistrationToggle() {
    if (!settings || saving) return;
    const prev = settings.open_registration;
    settings = { ...settings, open_registration: !prev };
    saving = true;
    try {
      settings = await updateSettings({ open_registration: !prev });
      toasts.success('Settings saved.');
    } catch (err: any) {
      settings = { ...settings!, open_registration: prev };
      toasts.error(`Failed to save: ${err.message}`);
    } finally {
      saving = false;
    }
  }

  async function handleLdapEnabledToggle() {
    if (!settings || saving) return;
    const prev = settings.ldap.enabled;
    settings = { ...settings, ldap: { ...settings.ldap, enabled: !prev } };
    saving = true;
    try {
      settings = await updateSettings({ ldap: { enabled: !prev } });
      toasts.success('LDAP ' + (!prev ? 'enabled' : 'disabled') + '. Restart required to apply.');
    } catch (err: any) {
      settings = { ...settings!, ldap: { ...settings!.ldap, enabled: prev } };
      toasts.error(`Failed to save: ${err.message}`);
    } finally {
      saving = false;
    }
  }

  async function saveBaseDn() {
    if (!settings) return;
    const trimmed = ldapBaseDn.trim();
    if (!trimmed) {
      baseDnError = 'Base DN cannot be empty.';
      return;
    }
    if (trimmed === settings.ldap.base_dn) return;
    saving = true;
    try {
      settings = await updateSettings({ ldap: { base_dn: trimmed } });
      ldapBaseDn = settings.ldap.base_dn;
      baseDnError = '';
      toasts.success('Base DN saved.');
    } catch (err: any) {
      baseDnError = err.message ?? 'Invalid Base DN';
    } finally {
      saving = false;
    }
  }

  async function saveBindAddress() {
    if (!settings) return;
    const trimmed = ldapBindAddress.trim();
    if (!trimmed) {
      bindAddressError = 'Bind address cannot be empty.';
      return;
    }
    if (trimmed === settings.ldap.bind_address) return;
    saving = true;
    try {
      settings = await updateSettings({ ldap: { bind_address: trimmed } });
      ldapBindAddress = settings.ldap.bind_address;
      bindAddressError = '';
      toasts.success('Bind address saved. Restart required.');
    } catch (err: any) {
      bindAddressError = err.message ?? 'Invalid bind address';
    } finally {
      saving = false;
    }
  }

  async function setPasswordMode(mode: LdapPasswordMode) {
    if (!settings || settings.ldap.password_mode === mode) return;
    saving = true;
    try {
      settings = await updateSettings({ ldap: { password_mode: mode } });
      toasts.success('Password policy updated.');
    } catch (err: any) {
      toasts.error(`Failed to save: ${err.message}`);
    } finally {
      saving = false;
    }
  }

  async function doRegenerate() {
    regenerating = true;
    try {
      const { password } = await regenerateLdapBindPassword();
      revealedPassword = password;
      // Re-fetch so service_password_set flips true.
      settings = await getSettings();
      confirmRegenerate = false;
    } catch (err: any) {
      toasts.error(`Failed to generate: ${err.message}`);
    } finally {
      regenerating = false;
    }
  }

  async function handleCreateScimToken() {
    if (!scimTokenName.trim() || creatingScimToken) return;
    creatingScimToken = true;
    try {
      const resp = await createScimToken(scimTokenName.trim());
      scimTokens = [{ id: resp.id, name: resp.name, created_at: resp.created_at, created_by: '', last_used_at: null, revoked_at: null }, ...scimTokens];
      revealedScimToken = { name: resp.name, token: resp.token };
      showCreateScimToken = false;
      scimTokenName = '';
    } catch (err: any) {
      toasts.error(`Failed to create: ${err.message}`);
    } finally {
      creatingScimToken = false;
    }
  }

  async function handleRevokeScimToken(id: string) {
    if (revokingScimToken) return;
    revokingScimToken = id;
    try {
      await revokeScimToken(id);
      scimTokens = scimTokens.filter((t) => t.id !== id);
      toasts.success('Token revoked.');
    } catch (err: any) {
      toasts.error(`Failed to revoke: ${err.message}`);
    } finally {
      revokingScimToken = null;
    }
  }

  async function handleRestart() {
    restarting = true;
    try {
      await restartService();
      confirmRestart = false;
      toasts.success('Restart initiated. The page will reload shortly.');
      setTimeout(() => window.location.reload(), 3000);
    } catch (err: any) {
      toasts.error(`Failed to restart: ${err.message}`);
    } finally {
      restarting = false;
    }
  }

  function copy(text: string) {
    navigator.clipboard.writeText(text).then(() => toasts.success('Copied.'));
  }

  function formatDate(ts: number | null) {
    if (!ts) return '—';
    return new Date(ts * 1000).toLocaleDateString();
  }

  const bindPort = $derived.by(() => {
    const addr = settings?.ldap.bind_address ?? '';
    const m = addr.match(/:(\d+)$/);
    return m ? m[1] : '';
  });

  const jellyfinConfig = $derived.by(() => {
    if (!settings) return '';
    const s = settings.ldap;
    return [
      `LDAP Server:     <your-authere-host>`,
      `Port:            ${bindPort}`,
      `Use SSL:         No`,
      `Bind DN:         ${s.service_account_dn}`,
      `Bind Password:   <generated once; store securely>`,
      `User Base DN:    ou=people,${s.base_dn}`,
      `User Filter:     (uid={0})`,
      `User UID Attr:   uid`,
      `Group Base DN:   ou=groups,${s.base_dn}`,
      `Group Filter:    (memberOf=cn=<role>,ou=groups,${s.base_dn})`,
    ].join('\n');
  });
</script>

<div class="page">
  <header class="page-header">
    <h1 class="au-h3">Settings</h1>
    <p class="au-small au-fg-3">System-wide configuration.</p>
  </header>

  {#if loading}
    <div class="loading au-small au-fg-3">Loading…</div>
  {:else if settings}
    <div class="settings-section">
      <div class="section-title au-small font-medium au-fg-2">Registration</div>
      <div class="settings-card">
        <div class="setting-row">
          <div class="setting-info">
            <span class="au-small font-medium">Open registration</span>
            <span class="au-micro au-fg-3">
              Allow anyone to create an account without an invitation.
            </span>
          </div>
          <button
            class="toggle"
            class:on={settings.open_registration}
            onclick={handleRegistrationToggle}
            disabled={saving}
            aria-label="Toggle open registration"
            aria-pressed={settings.open_registration}
          >
            <span class="toggle-thumb"></span>
          </button>
        </div>
      </div>
    </div>

    <div class="settings-section">
      <div class="section-title au-small font-medium au-fg-2">Sessions</div>
      <div class="settings-card">
        <div class="setting-row">
          <div class="setting-info">
            <span class="au-small font-medium">Session expiry</span>
            <span class="au-micro au-fg-3">
              How long a signed-in session stays valid before users must reauthenticate.
              Applies to new logins; existing sessions keep their current expiry.
              Currently: {formatSessionExpiry(settings.session_expiry_seconds)}.
            </span>
          </div>
          <select
            class="au-input session-expiry-select"
            value={settings.session_expiry_seconds}
            onchange={(e) => handleSessionExpiryChange(Number((e.currentTarget as HTMLSelectElement).value))}
            disabled={saving}
            aria-label="Session expiry"
          >
            {#each SESSION_EXPIRY_PRESETS as opt}
              <option value={opt.value}>{opt.label}</option>
            {/each}
            {#if !SESSION_EXPIRY_PRESETS.some((p) => p.value === settings.session_expiry_seconds)}
              <option value={settings.session_expiry_seconds}>
                Custom ({formatSessionExpiry(settings.session_expiry_seconds)})
              </option>
            {/if}
          </select>
        </div>
      </div>
    </div>

    <div class="settings-section">
      <div class="section-title au-small font-medium au-fg-2">LDAP</div>
      <div class="settings-card">
        <div class="setting-row">
          <div class="setting-info">
            <span class="au-small font-medium">Enable LDAP adapter</span>
            <span class="au-micro au-fg-3">
              Expose a minimal LDAP directory for homelab services. Restart required to start or stop the listener.
            </span>
          </div>
          <button
            class="toggle"
            class:on={settings.ldap.enabled}
            onclick={handleLdapEnabledToggle}
            disabled={saving}
            aria-label="Toggle LDAP"
            aria-pressed={settings.ldap.enabled}
          >
            <span class="toggle-thumb"></span>
          </button>
        </div>

        <div class="setting-block">
          <Input
            label="Base DN"
            bind:value={ldapBaseDn}
            error={baseDnError}
            placeholder="dc=authere,dc=local"
            onblur={saveBaseDn}
          />
          <p class="au-micro au-fg-3">Root of the directory tree. Users live under <code>ou=people</code>, groups under <code>ou=groups</code>.</p>
        </div>

        <div class="setting-block">
          <Input
            label="Bind address"
            bind:value={ldapBindAddress}
            error={bindAddressError}
            placeholder="0.0.0.0:3389"
            onblur={saveBindAddress}
          />
          <p class="au-micro au-fg-3">Host:port for the LDAP listener. Restart required.</p>
        </div>

        <div class="setting-block">
          <div class="subsection-title au-small font-medium au-fg-2">Password policy</div>
          <div class="radio-group">
            {#each [
              { value: 'primary_and_app' as LdapPasswordMode, title: 'Primary or app password (recommended)', help: "Easiest for users. Accounts with two-factor authentication must use an app password — their primary password is never accepted on LDAP." },
              { value: 'app_only' as LdapPasswordMode, title: 'App password only', help: 'All users must create a dedicated LDAP password. Strictest separation from web login.' },
              { value: 'primary_only' as LdapPasswordMode, title: 'Primary password only', help: 'App passwords are disabled. Accounts with two-factor authentication cannot use LDAP.' },
            ] as opt}
              <label class="radio-row">
                <input
                  type="radio"
                  name="password-mode"
                  value={opt.value}
                  checked={settings.ldap.password_mode === opt.value}
                  onchange={() => setPasswordMode(opt.value)}
                  disabled={saving}
                />
                <span class="radio-text">
                  <span class="au-small font-medium">{opt.title}</span>
                  <span class="au-micro au-fg-3">{opt.help}</span>
                </span>
              </label>
            {/each}
          </div>
        </div>

        <div class="setting-block">
          <div class="subsection-title au-small font-medium au-fg-2">Service account</div>
          <div class="service-row">
            <div class="service-info">
              <span class="au-small au-fg-3">Bind DN</span>
              <code class="au-code-sm au-fg-1">{settings.ldap.service_account_dn}</code>
              <span class="au-micro au-fg-3">
                {settings.ldap.service_password_set
                  ? 'A password has been generated. Regenerate to rotate — existing integrations will need updating.'
                  : 'No password set yet. Generate one before Jellyfin (or any LDAP client) can bind as the service account.'}
              </span>
            </div>
            <Button
              variant={settings.ldap.service_password_set ? 'secondary' : 'primary'}
              onclick={() => (confirmRegenerate = settings!.ldap.service_password_set) ? undefined : doRegenerate()}
              disabled={regenerating}
            >
              {settings.ldap.service_password_set ? 'Regenerate…' : 'Generate password'}
            </Button>
          </div>
        </div>

        <div class="setting-block">
          <div class="subsection-title au-small font-medium au-fg-2">Jellyfin configuration</div>
          <pre class="snippet">{jellyfinConfig}</pre>
          <p class="au-micro au-fg-3">
            For the admin filter, pick a role from:
            {#each roles as r, i}
              <code class="au-code-sm">(memberOf=cn={r.name},ou=groups,{settings.ldap.base_dn})</code>{i < roles.length - 1 ? ' ' : ''}
            {/each}
          </p>
        </div>
      </div>
    </div>

    <div class="settings-section">
      <div class="section-title au-small font-medium au-fg-2">SCIM provisioning</div>
      <div class="settings-card">
        <div class="setting-row">
          <div class="setting-info">
            <span class="au-small font-medium">Bearer tokens</span>
            <span class="au-micro au-fg-3">
              Create tokens for identity providers (Okta, Azure AD, OneLogin) to provision users via SCIM 2.0.
            </span>
          </div>
          <Button variant="primary" size="sm" onclick={() => { showCreateScimToken = true; scimTokenName = ''; }}>
            New token
          </Button>
        </div>
        {#if scimLoading}
          <div class="setting-block">
            <p class="au-small au-fg-3">Loading…</p>
          </div>
        {:else if scimTokens.length === 0}
          <div class="setting-block">
            <p class="au-small au-fg-3">No SCIM tokens yet. Create one to enable identity provider provisioning.</p>
          </div>
        {:else}
          <ul class="token-list">
            {#each scimTokens as t (t.id)}
              <li class="token-row">
                <div class="token-info">
                  <span class="au-small font-medium">{t.name}</span>
                  <span class="au-micro au-fg-3">
                    Created {formatDate(t.created_at)} · Last used {formatDate(t.last_used_at)}
                  </span>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onclick={() => handleRevokeScimToken(t.id)}
                  loading={revokingScimToken === t.id}
                >
                  Revoke
                </Button>
              </li>
            {/each}
          </ul>
        {/if}
      </div>
    </div>

    <div class="settings-section">
      <div class="section-title au-small font-medium au-fg-2">Danger zone</div>
      <div class="settings-card danger-card">
        <div class="setting-row">
          <div class="setting-info">
            <span class="au-small font-medium">Restart service</span>
            <span class="au-micro au-fg-3">
              Gracefully stop and restart the Authere process. Active sessions are preserved but in-flight requests will be dropped. Requires a process manager (systemd, Docker) configured to restart on exit code 75.
            </span>
          </div>
          <Button
            variant="danger"
            size="sm"
            onclick={() => (confirmRestart = true)}
          >
            Restart
          </Button>
        </div>
      </div>
    </div>
  {/if}
</div>

{#if confirmRestart}
  <Modal title="Restart service?" onclose={() => (confirmRestart = false)}>
    <p class="au-small">
      The service will shut down and restart. All active connections will be briefly interrupted. This page will reload automatically.
    </p>
    {#snippet actions()}
      <Button variant="ghost" onclick={() => (confirmRestart = false)}>Cancel</Button>
      <Button variant="danger" onclick={handleRestart} loading={restarting}>Restart now</Button>
    {/snippet}
  </Modal>
{/if}

{#if confirmRegenerate}
  <Modal title="Rotate service bind password?" onclose={() => (confirmRegenerate = false)}>
    <p class="au-small">
      The existing bind password will stop working immediately. Any LDAP clients (e.g., Jellyfin) using it will need to be reconfigured with the new password before they can bind.
    </p>
    {#snippet actions()}
      <Button variant="ghost" onclick={() => (confirmRegenerate = false)}>Cancel</Button>
      <Button variant="danger" onclick={doRegenerate} loading={regenerating}>Regenerate</Button>
    {/snippet}
  </Modal>
{/if}

{#if showCreateScimToken}
  <Modal title="New SCIM token" onclose={() => (showCreateScimToken = false)}>
    <p class="au-small au-fg-3">Give this token a name so you can recognise which IdP it belongs to (e.g. "Okta Production").</p>
    <div class="create-field">
      <Input
        label="Name"
        bind:value={scimTokenName}
        placeholder="Okta Production"
        autofocus
        onkeydown={(e) => { if (e.key === 'Enter' && scimTokenName.trim()) handleCreateScimToken(); }}
      />
    </div>
    {#snippet actions()}
      <Button variant="ghost" onclick={() => (showCreateScimToken = false)}>Cancel</Button>
      <Button variant="primary" onclick={handleCreateScimToken} loading={creatingScimToken} disabled={!scimTokenName.trim()}>
        Create
      </Button>
    {/snippet}
  </Modal>
{/if}

{#if revealedScimToken}
  <Modal title="SCIM token created" onclose={() => (revealedScimToken = null)}>
    <p class="au-small">
      Copy this token now — it won't be shown again. Paste it into the SCIM bearer token field for
      <strong>{revealedScimToken.name}</strong>.
    </p>
    <div class="reveal-row">
      <code class="reveal-code au-code-sm">{revealedScimToken.token}</code>
      <Button variant="secondary" onclick={() => copy(revealedScimToken!.token)}>Copy</Button>
    </div>
    {#snippet actions()}
      <Button variant="primary" onclick={() => (revealedScimToken = null)}>Done</Button>
    {/snippet}
  </Modal>
{/if}

{#if revealedPassword}
  <Modal title="New service bind password" onclose={() => (revealedPassword = null)}>
    <p class="au-small">
      This is the only time the password will be shown. Copy it now and paste it into your LDAP client configuration.
    </p>
    <div class="reveal-row">
      <code class="reveal-code au-code-sm">{revealedPassword}</code>
      <Button variant="secondary" onclick={() => copy(revealedPassword!)}>Copy</Button>
    </div>
    {#snippet actions()}
      <Button variant="primary" onclick={() => (revealedPassword = null)}>Done</Button>
    {/snippet}
  </Modal>
{/if}

<style>
  .page {
    padding: var(--sp-8);
    max-width: 720px;
    display: flex;
    flex-direction: column;
    gap: var(--sp-6);
  }

  @media (max-width: 639.98px) {
    .page { padding: var(--sp-4); gap: var(--sp-4); }
  }

  .page-header { display: flex; flex-direction: column; gap: var(--sp-1); }

  .loading { padding: var(--sp-4) 0; }

  .settings-section { display: flex; flex-direction: column; gap: var(--sp-2); }

  .section-title {
    font-weight: 500;
    color: var(--fg-2);
  }

  .settings-card {
    background: var(--bg-1);
    border: 1px solid var(--border-1);
    border-radius: var(--radius);
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }

  .setting-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--sp-4);
    padding: var(--sp-4);
    border-bottom: 1px solid var(--border-0);
  }
  .setting-row:last-child { border-bottom: none; }

  .setting-info {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
    min-width: 0;
  }

  .setting-block {
    padding: var(--sp-4);
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    border-bottom: 1px solid var(--border-0);
  }
  .setting-block:last-child { border-bottom: none; }

  .subsection-title { margin-bottom: var(--sp-1); }

  .radio-group {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }

  .radio-row {
    display: flex;
    gap: var(--sp-3);
    align-items: flex-start;
    cursor: pointer;
  }
  .radio-row input { margin-top: 3px; }
  .radio-text { display: flex; flex-direction: column; gap: var(--sp-1); }

  .service-row {
    display: flex;
    gap: var(--sp-3);
    align-items: flex-start;
    justify-content: space-between;
  }
  .service-info {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
    min-width: 0;
  }

  .snippet {
    background: var(--bg-2);
    border: 1px solid var(--border-1);
    border-radius: var(--radius);
    padding: var(--sp-3);
    font-family: var(--mono, ui-monospace, monospace);
    font-size: 12px;
    color: var(--fg-1);
    overflow-x: auto;
    white-space: pre;
    margin: 0;
  }

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

  .token-list {
    list-style: none;
    padding: 0;
    margin: 0;
  }

  .token-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--sp-4);
    padding: var(--sp-3) var(--sp-4);
    border-top: 1px solid var(--border-0);
  }

  .token-info {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
    min-width: 0;
  }

  .create-field {
    margin-top: var(--sp-3);
  }

  .danger-card {
    border-color: var(--danger, #EF4444);
  }

  .session-expiry-select {
    flex-shrink: 0;
    min-width: 140px;
  }

  /* Toggle switch */
  .toggle {
    flex-shrink: 0;
    width: 40px;
    height: 22px;
    border-radius: 11px;
    background: var(--bg-3);
    border: 1px solid var(--border-1);
    cursor: pointer;
    position: relative;
    transition: background var(--duration-micro) var(--ease-out),
                border-color var(--duration-micro) var(--ease-out);
    padding: 0;
  }

  .toggle:disabled { opacity: 0.6; cursor: not-allowed; }

  .toggle.on {
    background: var(--accent, #3B82F6);
    border-color: var(--accent, #3B82F6);
  }

  .toggle-thumb {
    position: absolute;
    top: 2px;
    left: 2px;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: var(--fg-3);
    transition: left var(--duration-micro) var(--ease-out),
                background var(--duration-micro) var(--ease-out);
  }

  .toggle.on .toggle-thumb {
    left: 20px;
    background: white;
  }
</style>
