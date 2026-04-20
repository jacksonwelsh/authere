<script lang="ts">
  import { onMount } from 'svelte';
  import { getSettings, updateSettings, type Settings } from '../../lib/api';
  import { toasts } from '../../lib/toast.svelte';

  let settings = $state<Settings | null>(null);
  let loading = $state(true);
  let saving = $state(false);

  onMount(async () => {
    try {
      settings = await getSettings();
    } catch {
      toasts.error('Failed to load settings.');
    } finally {
      loading = false;
    }
  });

  async function handleToggle() {
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
            onclick={handleToggle}
            disabled={saving}
            aria-label="Toggle open registration"
            aria-pressed={settings.open_registration}
          >
            <span class="toggle-thumb"></span>
          </button>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .page {
    padding: var(--sp-8);
    max-width: 720px;
    display: flex;
    flex-direction: column;
    gap: var(--sp-6);
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
  }

  .setting-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--sp-4);
    padding: var(--sp-4);
  }

  .setting-info {
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
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
