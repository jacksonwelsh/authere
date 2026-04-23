<script lang="ts">
  import { onMount } from 'svelte';
  import {
    getApplications, getRoles, createApplication, updateApplication, deleteApplication,
    type Application, type AppType, type CreateApplicationResponse, type Role
  } from '../../lib/api';
  import Button from '../../lib/components/Button.svelte';
  import Badge from '../../lib/components/Badge.svelte';
  import Input from '../../lib/components/Input.svelte';
  import Modal from '../../lib/components/Modal.svelte';
  import ResponsiveTable from '../../lib/components/ResponsiveTable.svelte';
  import { toasts } from '../../lib/toast.svelte';

  let apps = $state<Application[]>([]);
  let roles = $state<Role[]>([]);
  let loading = $state(true);
  let editApp = $state<Partial<Application> | null>(null);
  let isEditing = $state(false);
  let confirmDelete = $state<Application | null>(null);
  let configApp = $state<Application | null>(null);
  let saving = $state(false);
  let deleting = $state(false);
  // Plaintext secret from the most recent create. Cleared when the modal closes.
  let freshClientSecret = $state<string | null>(null);

  // Form state. Branches on `app_type` — the modal renders forward-auth OR OIDC fields,
  // but both share name/slug/required_roles.
  let form = $state({
    name: '',
    slug: '',
    app_type: 'forward_auth' as AppType,
    host_pattern: '',
    path_prefix: '',
    required_roles: [] as string[],
    oidc_redirect_uris: '',
    oidc_post_logout_redirect_uris: '',
    oidc_confidential: true,
  });

  function guessHostname(pattern: string | null): string | null {
    if (!pattern) return null;
    let s = pattern.trim();
    if (s.startsWith('^')) s = s.slice(1);
    if (s.endsWith('$')) s = s.slice(0, -1);
    s = s.replace(/\\\./g, '.');
    if (/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i.test(s) && s.includes('.')) return s;
    return null;
  }

  function buildCaddySnippet(app: Application): string {
    const origin = window.location.origin;
    let upstreamHost = origin.replace(/^https?:\/\//, '');
    let tlsLines = '';
    try {
      const u = new URL(origin);
      upstreamHost = u.host;
      if (u.protocol === 'https:') {
        tlsLines = '\n        transport http {\n            tls\n        }';
      }
    } catch {}

    const host = guessHostname(app.host_pattern) ?? 'your-app.example.com';
    const patternComment = `# host_pattern: ${app.host_pattern}`;
    const pathComment = app.path_prefix ? `\n    # path_prefix: ${app.path_prefix}` : '';

    return `${patternComment}${pathComment}
${host} {
    route {
        reverse_proxy /.authere/* ${upstreamHost}${tlsLines}

        forward_auth ${upstreamHost} {
            uri /api/auth/verify
            copy_headers X-Auth-User X-Auth-Username X-Auth-Roles X-Auth-Email${tlsLines}
        }
        reverse_proxy YOUR_UPSTREAM:8080
    }
}`;
  }

  function buildOidcConfigText(app: Application): string {
    const origin = window.location.origin;
    const lines = [
      `# OIDC configuration for ${app.name}`,
      `issuer = ${origin}`,
      `discovery_url = ${origin}/.well-known/openid-configuration`,
      `jwks_uri = ${origin}/.well-known/jwks.json`,
      `authorization_endpoint = ${origin}/oauth/authorize`,
      `token_endpoint = ${origin}/oauth/token`,
      `userinfo_endpoint = ${origin}/oauth/userinfo`,
      `end_session_endpoint = ${origin}/oauth/end_session`,
      `client_id = ${app.oidc_client_id ?? ''}`,
    ];
    if (app.oidc_redirect_uris.length) {
      lines.push(`redirect_uris = ${app.oidc_redirect_uris.join(', ')}`);
    }
    lines.push('scopes = openid profile email roles');
    return lines.join('\n');
  }

  async function copyConfig() {
    if (!configApp) return;
    const text = configApp.app_type === 'oidc'
      ? buildOidcConfigText(configApp)
      : buildCaddySnippet(configApp);
    try {
      await navigator.clipboard.writeText(text);
      toasts.success('Copied.');
    } catch {
      toasts.error('Could not copy to clipboard.');
    }
  }

  async function copyClientSecret() {
    if (!freshClientSecret) return;
    try {
      await navigator.clipboard.writeText(freshClientSecret);
      toasts.success('Client secret copied.');
    } catch {
      toasts.error('Could not copy to clipboard.');
    }
  }

  onMount(async () => {
    try {
      [apps, roles] = await Promise.all([getApplications(), getRoles()]);
    } catch {
      toasts.error('Failed to load applications.');
    } finally {
      loading = false;
    }
  });

  function openCreate() {
    form = {
      name: '', slug: '', app_type: 'forward_auth',
      host_pattern: '', path_prefix: '', required_roles: [],
      oidc_redirect_uris: '', oidc_post_logout_redirect_uris: '',
      oidc_confidential: true,
    };
    editApp = {};
    isEditing = false;
    freshClientSecret = null;
  }

  function openEdit(app: Application) {
    form = {
      name: app.name,
      slug: app.slug,
      app_type: app.app_type,
      host_pattern: app.host_pattern ?? '',
      path_prefix: app.path_prefix ?? '',
      required_roles: [...app.required_roles],
      oidc_redirect_uris: app.oidc_redirect_uris.join('\n'),
      oidc_post_logout_redirect_uris: app.oidc_post_logout_redirect_uris.join('\n'),
      oidc_confidential: app.oidc_confidential,
    };
    editApp = app;
    isEditing = true;
  }

  function toggleRole(roleId: string) {
    form.required_roles = form.required_roles.includes(roleId)
      ? form.required_roles.filter(r => r !== roleId)
      : [...form.required_roles, roleId];
  }

  function parseLines(s: string): string[] {
    return s.split('\n').map(l => l.trim()).filter(Boolean);
  }

  function saveDisabled(): boolean {
    if (saving || !form.name || !form.slug) return true;
    if (form.app_type === 'forward_auth') {
      return !form.host_pattern;
    }
    return parseLines(form.oidc_redirect_uris).length === 0;
  }

  async function handleSave() {
    if (saveDisabled()) return;
    saving = true;
    try {
      if (isEditing && editApp && 'id' in editApp) {
        const data: Partial<Application> = {
          name: form.name,
          required_roles: form.required_roles,
        };
        if (form.app_type === 'forward_auth') {
          data.host_pattern = form.host_pattern;
          data.path_prefix = form.path_prefix || null;
        } else {
          data.oidc_redirect_uris = parseLines(form.oidc_redirect_uris);
          data.oidc_post_logout_redirect_uris = parseLines(form.oidc_post_logout_redirect_uris);
        }
        const updated = await updateApplication(editApp.id!, data);
        apps = apps.map(a => a.id === updated.id ? updated : a);
        toasts.success('Application updated.');
        editApp = null;
      } else {
        const data: Partial<Application> & { oidc_confidential?: boolean } = {
          name: form.name,
          slug: form.slug,
          app_type: form.app_type,
          required_roles: form.required_roles,
        };
        if (form.app_type === 'forward_auth') {
          data.host_pattern = form.host_pattern;
          data.path_prefix = form.path_prefix || null;
        } else {
          data.oidc_redirect_uris = parseLines(form.oidc_redirect_uris);
          data.oidc_post_logout_redirect_uris = parseLines(form.oidc_post_logout_redirect_uris);
          data.oidc_confidential = form.oidc_confidential;
        }
        const created: CreateApplicationResponse = await createApplication(data);
        const { oidc_client_secret, ...app } = created;
        apps = [...apps, app as Application];
        toasts.success('Application created.');
        // For OIDC clients, switch into the Config modal so the admin can copy the one-time
        // secret (confidential) or at least see the client_id (public).
        if (app.app_type === 'oidc') {
          freshClientSecret = oidc_client_secret ?? null;
          editApp = null;
          configApp = app as Application;
        } else {
          editApp = null;
        }
      }
    } catch (err: any) {
      toasts.error(`Failed to save: ${err.message}`);
    } finally {
      saving = false;
    }
  }

  async function handleDelete(app: Application) {
    if (deleting) return;
    deleting = true;
    try {
      await deleteApplication(app.id);
      apps = apps.filter(a => a.id !== app.id);
      confirmDelete = null;
      toasts.success('Application deleted.');
    } catch (err: any) {
      toasts.error(`Failed to delete: ${err.message}`);
    } finally {
      deleting = false;
    }
  }

  function closeConfig() {
    configApp = null;
    freshClientSecret = null;
  }

  const roleMap = $derived(Object.fromEntries(roles.map(r => [r.id, r.name])));
</script>

<div class="page">
  <header class="page-header">
    <div>
      <h1 class="au-h3">Applications</h1>
      <p class="au-micro au-fg-3">{apps.length} registered</p>
    </div>
    <Button variant="primary" onclick={openCreate}>
      <i class="ph ph-plus"></i> Add application
    </Button>
  </header>

  {#if loading}
    <div class="page-loading au-fg-4 au-small">
      <i class="ph ph-circle-notch spin"></i> Loading…
    </div>
  {:else}
    <ResponsiveTable
      label="Applications"
      items={apps}
      getKey={(a) => a.id}
      columns={[
        { key: 'name',    label: 'Name',    tdClass: 'au-fg-1 font-medium' },
        { key: 'type',    label: 'Type' },
        { key: 'slug',    label: 'Slug',    tdClass: 'au-mono au-code-sm au-fg-3' },
        { key: 'target',  label: 'Target' },
        { key: 'roles',   label: 'Required roles' },
      ]}
    >
      {#snippet cell({ item, column })}
        {#if column.key === 'name'}{item.name}
        {:else if column.key === 'type'}
          <Badge>{item.app_type === 'oidc' ? 'OIDC' : 'Forward auth'}</Badge>
        {:else if column.key === 'slug'}{item.slug}
        {:else if column.key === 'target'}
          {#if item.app_type === 'oidc'}
            <span class="au-mono au-code-sm au-fg-3">{item.oidc_client_id ?? ''}</span>
          {:else}
            <span class="au-code-sm au-fg-3">{item.host_pattern ?? ''}</span>
          {/if}
        {:else if column.key === 'roles'}
          <div class="roles-cell">
            {#each item.required_roles as roleId}
              <Badge>{roleMap[roleId] ?? roleId}</Badge>
            {/each}
            {#if item.required_roles.length === 0}
              <span class="au-fg-5 au-micro">public</span>
            {/if}
          </div>
        {/if}
      {/snippet}
      {#snippet actions({ item })}
        <Button size="sm" variant="ghost" onclick={() => configApp = item}>Config</Button>
        <Button size="sm" variant="ghost" onclick={() => openEdit(item)}>Edit</Button>
        <Button size="sm" variant="ghost" onclick={() => confirmDelete = item}>Delete</Button>
      {/snippet}
      {#snippet empty()}No applications yet.{/snippet}
    </ResponsiveTable>
  {/if}
</div>

{#if editApp !== null}
  <Modal title={isEditing ? 'Edit application' : 'Add application'} onclose={() => editApp = null}>
    <div class="modal-form">
      <Input label="Name" bind:value={form.name} placeholder="My App" />
      <Input label="Slug" bind:value={form.slug} placeholder="my-app" />

      <div class="type-picker">
        <label class="au-nano au-fg-3" for="app-type-select">Type</label>
        <select
          id="app-type-select"
          class="type-select au-small"
          bind:value={form.app_type}
          disabled={isEditing}
        >
          <option value="forward_auth">Forward auth (Caddy)</option>
          <option value="oidc">OIDC (OpenID Connect)</option>
        </select>
        {#if isEditing}
          <p class="au-nano au-fg-5">Type cannot be changed after creation.</p>
        {/if}
      </div>

      {#if form.app_type === 'forward_auth'}
        <Input label="Host pattern (regex)" bind:value={form.host_pattern} placeholder="^app\.example\.com$" />
        <Input label="Path prefix (optional)" bind:value={form.path_prefix} placeholder="/protected" />
      {:else}
        <div class="field">
          <label class="au-nano au-fg-3" for="redirect-uris">Redirect URIs (one per line)</label>
          <textarea
            id="redirect-uris"
            class="textarea au-small au-mono"
            bind:value={form.oidc_redirect_uris}
            placeholder={`https://app.example.com/cb\nhttp://localhost:8080/cb`}
            rows="3"
          ></textarea>
        </div>
        <div class="field">
          <label class="au-nano au-fg-3" for="post-logout-uris">Post-logout redirect URIs (optional)</label>
          <textarea
            id="post-logout-uris"
            class="textarea au-small au-mono"
            bind:value={form.oidc_post_logout_redirect_uris}
            placeholder={`https://app.example.com/logged-out`}
            rows="2"
          ></textarea>
        </div>
        {#if !isEditing}
          <label class="public-client">
            <input
              type="checkbox"
              checked={!form.oidc_confidential}
              onchange={(e) => form.oidc_confidential = !(e.currentTarget as HTMLInputElement).checked}
            />
            <span class="au-small">Public client (no client_secret, PKCE-only — for SPAs & native apps)</span>
          </label>
        {/if}
      {/if}

      <div class="role-picker">
        <p class="au-nano au-fg-3">Required roles</p>
        <div class="role-options">
          {#each roles as role (role.id)}
            {@const checked = form.required_roles.includes(role.id)}
            <label class="role-option" class:checked>
              <input type="checkbox" {checked} onchange={() => toggleRole(role.id)} />
              <span class="au-small">{role.name}</span>
            </label>
          {/each}
        </div>
      </div>
    </div>
    {#snippet actions()}
      <Button variant="secondary" onclick={() => editApp = null}>Cancel</Button>
      <Button variant="primary" loading={saving} disabled={saveDisabled()} onclick={handleSave}>
        {isEditing ? 'Save changes' : 'Create application'}
      </Button>
    {/snippet}
  </Modal>
{/if}

{#if configApp}
  <Modal
    title={configApp.app_type === 'oidc' ? 'OIDC client configuration' : 'Caddy forward auth config'}
    width={640}
    onclose={closeConfig}
  >
    <div class="config-body">
      {#if configApp.app_type === 'oidc'}
        {#if freshClientSecret}
          <div class="secret-box">
            <p class="au-small au-fg-1">
              <i class="ph ph-warning"></i>
              Copy the client secret now — it will not be shown again.
            </p>
            <pre class="snippet secret-snippet au-code-sm"><code>{freshClientSecret}</code></pre>
            <Button size="sm" variant="primary" onclick={copyClientSecret}>
              <i class="ph ph-copy"></i> Copy client secret
            </Button>
          </div>
        {/if}
        <p class="au-small au-fg-3">
          Point your RP at the discovery URL below; it exposes all endpoints and the signing
          keys. Configure the RP's redirect URI to exactly match one of the registered values.
        </p>
        <pre class="snippet au-code-sm"><code>{buildOidcConfigText(configApp)}</code></pre>
        <p class="au-micro au-fg-4">
          Flow: Authorization Code with PKCE (S256). ID tokens are signed with EdDSA. Verify
          tokens against <span class="au-mono">/.well-known/jwks.json</span>.
        </p>
      {:else}
        <p class="au-small au-fg-3">
          Drop this into your Caddyfile to protect <span class="au-mono">{configApp.name}</span> with authere.
          Replace <span class="au-mono">YOUR_UPSTREAM:8080</span> with the app's backend, and adjust the site
          hostname if the guess doesn't match your host pattern.
        </p>
        <pre class="snippet au-code-sm"><code>{buildCaddySnippet(configApp)}</code></pre>
        <p class="au-micro au-fg-4">
          Unauthenticated requests are automatically redirected to authere's login page.
          After signing in, users are sent back to the original URL. Make sure
          <span class="au-mono">AUTHERE_ORIGIN</span> is set on the server.
        </p>
      {/if}
    </div>
    {#snippet actions()}
      <Button variant="secondary" onclick={closeConfig}>Close</Button>
      <Button variant="primary" onclick={copyConfig}>
        <i class="ph ph-copy"></i> Copy config
      </Button>
    {/snippet}
  </Modal>
{/if}

{#if confirmDelete}
  <Modal title="Delete application" onclose={() => confirmDelete = null}>
    <p class="au-small au-fg-2">
      Delete <span class="au-mono">{confirmDelete.slug}</span>?
      {#if confirmDelete.app_type === 'oidc'}
        OIDC logins for this client will stop working immediately.
      {:else}
        Forward auth for this application will stop working immediately.
      {/if}
    </p>
    {#snippet actions()}
      <Button variant="secondary" onclick={() => confirmDelete = null}>Cancel</Button>
      <Button variant="danger" loading={deleting} onclick={() => handleDelete(confirmDelete!)}>
        Delete application
      </Button>
    {/snippet}
  </Modal>
{/if}

<style>
  .page { padding: var(--sp-6); max-width: 960px; margin: 0 auto; }
  .page-header { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: var(--sp-6); gap: var(--sp-3); }
  .page-loading { display: flex; align-items: center; gap: var(--sp-2); padding: var(--sp-8); }

  @media (max-width: 639.98px) {
    .page { padding: var(--sp-4); }
    .page-header {
      flex-direction: column;
      align-items: stretch;
      margin-bottom: var(--sp-4);
    }
  }

  .config-body { display: flex; flex-direction: column; gap: var(--sp-3); }
  .snippet {
    background: var(--bg-1);
    border: 1px solid var(--border-0);
    border-radius: var(--radius);
    padding: var(--sp-3);
    margin: 0;
    overflow-x: auto;
    color: var(--fg-2);
    white-space: pre;
  }
  .secret-box {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    padding: var(--sp-3);
    border: 1px solid var(--accent);
    background: var(--accent-subtle);
    border-radius: var(--radius);
  }
  .secret-snippet { font-weight: 500; }
  .roles-cell { display: flex; align-items: center; flex-wrap: wrap; gap: var(--sp-1); }
  .modal-form { display: flex; flex-direction: column; gap: var(--sp-3); }
  .role-picker { display: flex; flex-direction: column; gap: var(--sp-2); }
  .role-options { display: flex; flex-wrap: wrap; gap: var(--sp-2); }
  .role-option {
    display: flex; align-items: center; gap: var(--sp-1);
    padding: var(--sp-1) var(--sp-2);
    border: 1px solid var(--border-1); border-radius: var(--radius);
    cursor: pointer; background: var(--bg-2); color: var(--fg-3);
  }
  .role-option.checked { border-color: var(--accent); color: var(--accent); background: var(--accent-subtle); }
  .role-option input { display: none; }
  .type-picker { display: flex; flex-direction: column; gap: var(--sp-1); }
  .type-select {
    padding: var(--sp-2);
    border: 1px solid var(--border-1);
    border-radius: var(--radius);
    background: var(--bg-1);
    color: var(--fg-1);
    font: inherit;
  }
  .type-select:disabled { opacity: 0.6; cursor: not-allowed; }
  .field { display: flex; flex-direction: column; gap: var(--sp-1); }
  .textarea {
    padding: var(--sp-2);
    border: 1px solid var(--border-1);
    border-radius: var(--radius);
    background: var(--bg-1);
    color: var(--fg-1);
    font: inherit;
    resize: vertical;
    min-height: 72px;
  }
  .textarea:focus { outline: 2px solid var(--accent); outline-offset: -1px; }
  .public-client {
    display: flex; align-items: center; gap: var(--sp-2);
    padding: var(--sp-2);
    border: 1px solid var(--border-0);
    border-radius: var(--radius);
    background: var(--bg-2);
    color: var(--fg-3);
    cursor: pointer;
  }
  .spin { animation: spin 0.7s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
