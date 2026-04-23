<script lang="ts">
  import { onMount } from 'svelte';
  import {
    listProvisioningTargets,
    createProvisioningTarget,
    updateProvisioningTarget,
    deleteProvisioningTarget,
    listProvisioningJobs,
    retryProvisioningJob,
    type ProvisioningTarget,
    type ProvisioningJob,
  } from '../../lib/api';
  import Button from '../../lib/components/Button.svelte';
  import Badge from '../../lib/components/Badge.svelte';
  import Input from '../../lib/components/Input.svelte';
  import Modal from '../../lib/components/Modal.svelte';
  import ResponsiveTable from '../../lib/components/ResponsiveTable.svelte';
  import { toasts } from '../../lib/toast.svelte';

  let targets = $state<ProvisioningTarget[]>([]);
  let jobs = $state<ProvisioningJob[]>([]);
  let loading = $state(true);
  let refreshingJobs = $state(false);

  let editing = $state<Partial<ProvisioningTarget> | null>(null);
  let isEditMode = $state(false);
  let saving = $state(false);
  let confirmDelete = $state<ProvisioningTarget | null>(null);
  let deleting = $state(false);

  // Form fields. `auth_token` is write-only — we never echo the stored value.
  let form = $state({
    name: '',
    kind: 'generic_scim',
    base_url: '',
    auth_token: '',
    enabled: true,
    attribute_map: '',
    dead_letter_webhook_url: '',
  });

  async function refresh() {
    const [t, j] = await Promise.all([
      listProvisioningTargets(),
      listProvisioningJobs({ limit: 50 }),
    ]);
    targets = t;
    jobs = j;
  }

  onMount(async () => {
    try {
      await refresh();
    } catch (e: any) {
      toasts.error(`Failed to load provisioning state: ${e.message}`);
    } finally {
      loading = false;
    }
  });

  function openCreate() {
    form = {
      name: '',
      kind: 'generic_scim',
      base_url: '',
      auth_token: '',
      enabled: true,
      attribute_map: '',
      dead_letter_webhook_url: '',
    };
    editing = {};
    isEditMode = false;
  }

  function openEdit(t: ProvisioningTarget) {
    form = {
      name: t.name,
      kind: t.kind,
      base_url: t.base_url,
      auth_token: '',
      enabled: t.enabled,
      attribute_map: t.attribute_map ?? '',
      dead_letter_webhook_url: t.dead_letter_webhook_url ?? '',
    };
    editing = t;
    isEditMode = true;
  }

  async function save() {
    if (saving) return;
    saving = true;
    try {
      if (isEditMode && editing && 'id' in editing) {
        const payload: any = {
          name: form.name,
          base_url: form.base_url,
          enabled: form.enabled,
          // null → clear, absent → leave; here we always send the explicit value.
          attribute_map: form.attribute_map.trim() === '' ? null : form.attribute_map,
          dead_letter_webhook_url:
            form.dead_letter_webhook_url.trim() === '' ? null : form.dead_letter_webhook_url,
        };
        if (form.auth_token.trim() !== '') payload.auth_token = form.auth_token;
        const updated = await updateProvisioningTarget(editing.id as string, payload);
        targets = targets.map(x => (x.id === updated.id ? updated : x));
        toasts.success('Target updated.');
      } else {
        const input: any = {
          name: form.name,
          kind: form.kind,
          base_url: form.base_url,
          auth_token: form.auth_token,
          enabled: form.enabled,
        };
        if (form.attribute_map.trim() !== '') input.attribute_map = form.attribute_map;
        if (form.dead_letter_webhook_url.trim() !== '')
          input.dead_letter_webhook_url = form.dead_letter_webhook_url;
        const created = await createProvisioningTarget(input);
        targets = [...targets, created];
        toasts.success('Target created — backfill queued for active users.');
      }
      editing = null;
      // Re-fetch jobs so newly-enqueued backfill rows show up.
      await refresh();
    } catch (e: any) {
      toasts.error(`Save failed: ${e.message}`);
    } finally {
      saving = false;
    }
  }

  async function doDelete(t: ProvisioningTarget) {
    if (deleting) return;
    deleting = true;
    try {
      await deleteProvisioningTarget(t.id);
      targets = targets.filter(x => x.id !== t.id);
      confirmDelete = null;
      toasts.success('Target deleted.');
      await refresh();
    } catch (e: any) {
      toasts.error(`Delete failed: ${e.message}`);
    } finally {
      deleting = false;
    }
  }

  async function toggleEnabled(t: ProvisioningTarget) {
    try {
      const updated = await updateProvisioningTarget(t.id, { enabled: !t.enabled });
      targets = targets.map(x => (x.id === updated.id ? updated : x));
      toasts.success(updated.enabled ? 'Target enabled.' : 'Target disabled.');
      await refresh();
    } catch (e: any) {
      toasts.error(`Could not toggle: ${e.message}`);
    }
  }

  async function retry(id: string) {
    try {
      await retryProvisioningJob(id);
      toasts.success('Job requeued.');
      await refresh();
    } catch (e: any) {
      toasts.error(`Retry failed: ${e.message}`);
    }
  }

  async function refreshJobs() {
    refreshingJobs = true;
    try {
      jobs = await listProvisioningJobs({ limit: 50 });
    } catch (e: any) {
      toasts.error(`Failed to refresh jobs: ${e.message}`);
    } finally {
      refreshingJobs = false;
    }
  }

  const targetNameById = $derived(
    Object.fromEntries(targets.map(t => [t.id, t.name])),
  );

  function fmtAgo(ts: number | null): string {
    if (ts == null) return '—';
    const secs = Math.max(0, Math.floor(Date.now() / 1000 - ts));
    if (secs < 60) return `${secs}s ago`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
    return `${Math.floor(secs / 86400)}d ago`;
  }

  type BadgeVariant = 'default' | 'success' | 'warning' | 'danger' | 'accent';

  function healthVariant(t: ProvisioningTarget): BadgeVariant {
    if (!t.enabled) return 'default';
    if (t.consecutive_failures === 0) return 'success';
    if (t.consecutive_failures >= 3) return 'danger';
    return 'warning';
  }

  function statusVariant(status: string): BadgeVariant {
    if (status === 'succeeded') return 'success';
    if (status === 'dead' || status === 'failed') return 'danger';
    if (status === 'in_flight' || status === 'pending') return 'warning';
    return 'default';
  }
</script>

<div class="page">
  <header class="page-header">
    <div>
      <h1 class="au-h3">Provisioning</h1>
      <p class="au-micro au-fg-3">
        {targets.length} target{targets.length === 1 ? '' : 's'} — Authere pushes user lifecycle events downstream via SCIM 2.0.
      </p>
    </div>
    <Button variant="primary" onclick={openCreate}>
      <i class="ph ph-plus"></i> Add target
    </Button>
  </header>

  {#if loading}
    <div class="page-loading au-fg-4 au-small">
      <i class="ph ph-circle-notch spin"></i> Loading…
    </div>
  {:else}
    <section class="targets-section">
      <ResponsiveTable
        label="Targets"
        items={targets}
        getKey={(t) => t.id}
        columns={[
          { key: 'name',   label: 'Name' },
          { key: 'kind',   label: 'Kind',   tdClass: 'au-mono au-code-sm au-fg-3' },
          { key: 'url',    label: 'Base URL', tdClass: 'au-code-sm au-fg-3' },
          { key: 'state',  label: 'State' },
          { key: 'health', label: 'Health' },
        ]}
      >
        {#snippet cell({ item, column })}
          {#if column.key === 'name'}
            {item.name}
          {:else if column.key === 'kind'}
            {item.kind}
          {:else if column.key === 'url'}
            {item.base_url}
          {:else if column.key === 'state'}
            {#if item.enabled}
              <Badge variant="success">enabled</Badge>
            {:else}
              <Badge variant="default">disabled</Badge>
            {/if}
            {#if item.backfill_done_at == null && item.enabled}
              <Badge variant="warning">backfill pending</Badge>
            {/if}
          {:else if column.key === 'health'}
            {@const v = healthVariant(item)}
            <div class="health-cell">
              <Badge variant={v}>
                {#if v === 'success'}healthy
                {:else if v === 'warning'}{item.consecutive_failures} recent failure{item.consecutive_failures === 1 ? '' : 's'}
                {:else if v === 'danger'}broken ({item.consecutive_failures} fails)
                {:else}—{/if}
              </Badge>
              <span class="au-micro au-fg-4">
                last OK {fmtAgo(item.last_success_at)}
              </span>
            </div>
          {/if}
        {/snippet}
        {#snippet actions({ item })}
          <Button size="sm" variant="ghost" onclick={() => toggleEnabled(item)}>
            {item.enabled ? 'Disable' : 'Enable'}
          </Button>
          <Button size="sm" variant="ghost" onclick={() => openEdit(item)}>Edit</Button>
          <Button size="sm" variant="ghost" onclick={() => confirmDelete = item}>Delete</Button>
        {/snippet}
        {#snippet empty()}
          No targets yet. Add one to start provisioning downstream.
        {/snippet}
      </ResponsiveTable>
    </section>

    <section class="jobs-section">
      <header class="jobs-header">
        <h2 class="au-h4">Recent jobs</h2>
        <Button size="sm" variant="ghost" loading={refreshingJobs} onclick={refreshJobs}>
          <i class="ph ph-arrow-clockwise"></i> Refresh
        </Button>
      </header>
      <ResponsiveTable
        label="Jobs"
        items={jobs}
        getKey={(j) => j.id}
        columns={[
          { key: 'target', label: 'Target' },
          { key: 'event',  label: 'Event',   tdClass: 'au-mono au-code-sm' },
          { key: 'status', label: 'Status' },
          { key: 'tries',  label: 'Attempts' },
          { key: 'age',    label: 'Age',     tdClass: 'au-fg-4 au-micro' },
          { key: 'err',    label: 'Last error', tdClass: 'au-code-sm au-fg-3' },
        ]}
      >
        {#snippet cell({ item, column })}
          {#if column.key === 'target'}
            {targetNameById[item.target_id] ?? item.target_id.slice(0, 8)}
          {:else if column.key === 'event'}
            {item.event_type}
          {:else if column.key === 'status'}
            <Badge variant={statusVariant(item.status)}>{item.status}</Badge>
          {:else if column.key === 'tries'}
            {item.attempts}
          {:else if column.key === 'age'}
            {fmtAgo(item.updated_at)}
          {:else if column.key === 'err'}
            {item.last_error ?? ''}
          {/if}
        {/snippet}
        {#snippet actions({ item })}
          {#if item.status === 'failed' || item.status === 'dead'}
            <Button size="sm" variant="ghost" onclick={() => retry(item.id)}>Retry</Button>
          {/if}
        {/snippet}
        {#snippet empty()}No jobs yet.{/snippet}
      </ResponsiveTable>
    </section>
  {/if}
</div>

{#if editing !== null}
  <Modal title={isEditMode ? 'Edit target' : 'Add target'} onclose={() => editing = null} width={560}>
    <div class="modal-form">
      <Input label="Name" bind:value={form.name} placeholder="Prod Workspace" />
      {#if !isEditMode}
        <Input label="Kind" bind:value={form.kind} placeholder="generic_scim" />
      {/if}
      <Input label="Base URL" bind:value={form.base_url} placeholder="https://api.example.com/scim/v2" />
      <Input
        label={isEditMode ? 'Auth token (leave blank to keep current)' : 'Auth token'}
        bind:value={form.auth_token}
        placeholder="Bearer token"
        type="password"
      />
      <Input
        label="Attribute map (optional JSON)"
        bind:value={form.attribute_map}
        placeholder={'{"userName":"username"}'}
      />
      <Input
        label="Dead-letter webhook URL (optional)"
        bind:value={form.dead_letter_webhook_url}
        placeholder="https://alerts.example.com/hook"
      />
      <label class="checkbox-row">
        <input type="checkbox" bind:checked={form.enabled} />
        <span class="au-small">Enabled</span>
      </label>
    </div>
    {#snippet actions()}
      <Button variant="secondary" onclick={() => editing = null}>Cancel</Button>
      <Button
        variant="primary"
        loading={saving}
        disabled={saving || !form.name || !form.base_url || (!isEditMode && !form.auth_token)}
        onclick={save}
      >
        {isEditMode ? 'Save changes' : 'Create target'}
      </Button>
    {/snippet}
  </Modal>
{/if}

{#if confirmDelete}
  <Modal title="Delete target?" onclose={() => confirmDelete = null}>
    <p class="au-small">
      This will remove <strong>{confirmDelete.name}</strong> and drop its job history.
      Downstream users won't be deprovisioned — this only disconnects Authere.
    </p>
    {#snippet actions()}
      <Button variant="secondary" onclick={() => confirmDelete = null}>Cancel</Button>
      <Button
        variant="danger"
        loading={deleting}
        onclick={() => confirmDelete && doDelete(confirmDelete)}
      >
        Delete
      </Button>
    {/snippet}
  </Modal>
{/if}

<style>
  .page { display: flex; flex-direction: column; gap: 1.5rem; }
  .page-header { display: flex; justify-content: space-between; align-items: start; gap: 1rem; flex-wrap: wrap; }
  .page-loading { padding: 2rem; display: flex; justify-content: center; gap: 0.5rem; align-items: center; }
  .targets-section, .jobs-section { display: flex; flex-direction: column; gap: 0.5rem; }
  .jobs-header { display: flex; justify-content: space-between; align-items: center; }
  .health-cell { display: flex; flex-direction: column; gap: 0.125rem; }
  .modal-form { display: flex; flex-direction: column; gap: 0.75rem; }
  .checkbox-row { display: flex; align-items: center; gap: 0.5rem; cursor: pointer; }
  .spin { animation: spin 1s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
