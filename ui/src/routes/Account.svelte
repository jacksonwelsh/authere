<script lang="ts">
  import { updateMe, type Me } from '../lib/api';
  import Button from '../lib/components/Button.svelte';
  import Input from '../lib/components/Input.svelte';
  import { toasts } from '../lib/toast.svelte';

  interface Props {
    me: Me;
  }
  let { me }: Props = $props();

  let name = $state(me.name ?? '');
  let username = $state(me.username ?? '');
  let email = $state(me.email ?? '');
  let saving = $state(false);

  async function handleSave() {
    if (saving) return;
    saving = true;
    try {
      await updateMe({ name, username, email: email || null });
      toasts.success('Profile updated.');
    } catch (err: any) {
      toasts.error(`Failed to update: ${err.message}`);
    } finally {
      saving = false;
    }
  }
</script>

<div class="page">
  <header class="page-header">
    <div>
      <h1 class="au-h3">Account</h1>
      <p class="au-micro au-fg-3">Manage your profile</p>
    </div>
  </header>

  <div class="form-card">
    <h2 class="au-h4 section-title">Profile</h2>
    <div class="form-fields" onkeydown={(e) => { if (e.key === 'Enter' && !saving) handleSave(); }}>
      <Input label="Full name" bind:value={name} placeholder="Jane Smith" />
      <Input label="Username" bind:value={username} placeholder="jane" />
      <Input label="Email" type="email" bind:value={email} placeholder="jane@example.com" />
    </div>
    <div class="form-actions">
      <Button variant="primary" loading={saving} disabled={!name || !username || saving} onclick={handleSave}>
        Save changes
      </Button>
    </div>
  </div>

  <div class="form-card security-card">
    <h2 class="au-h4 section-title">Security</h2>
    <p class="au-small au-fg-3">Manage your passwords, two-factor authentication, and other sign-in methods.</p>
    <div class="form-actions">
      <Button variant="secondary" onclick={() => window.location.href = '/credentials'}>
        Manage credentials
      </Button>
    </div>
  </div>
</div>

<style>
  .page { padding: var(--sp-6); max-width: 480px; margin: 0 auto; }

  @media (max-width: 639.98px) {
    .page { padding: var(--sp-4); }
  }

  .page-header {
    margin-bottom: var(--sp-6);
  }

  .form-card {
    border: 1px solid var(--border-0);
    border-radius: var(--radius);
    padding: var(--sp-5);
    background: var(--bg-1);
    display: flex;
    flex-direction: column;
    gap: var(--sp-4);
  }

  .section-title { color: var(--fg-2); }

  .form-fields {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }

  .form-actions {
    display: flex;
    justify-content: flex-end;
  }

  .security-card { margin-top: var(--sp-4); }
</style>
