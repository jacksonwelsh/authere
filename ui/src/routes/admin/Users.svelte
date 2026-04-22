<script lang="ts">
  import { onMount } from 'svelte';
  import {
    getUsers,
    getRoles,
    getUserRoles,
    createUser,
    updateUser,
    assignRole,
    removeRole,
    adminChangePassword,
    listUserAppPasswords,
    deleteUserAppPassword,
    type User,
    type Role,
    type AppPassword,
  } from '../../lib/api';
  import Button from '../../lib/components/Button.svelte';
  import CopyId from '../../lib/components/CopyId.svelte';
  import Input from '../../lib/components/Input.svelte';
  import Modal from '../../lib/components/Modal.svelte';
  import ResponsiveTable from '../../lib/components/ResponsiveTable.svelte';
  import { toasts } from '../../lib/toast.svelte';

  let users = $state<User[]>([]);
  let roles = $state<Role[]>([]);
  let loading = $state(true);
  let showCreate = $state(false);
  let showRoles = $state<string | null>(null); // user id
  let userRoles = $state<Record<string, Role[]>>({});
  let editUser = $state<User | null>(null);

  // Create form
  let newUsername = $state('');
  let newName = $state('');
  let newEmail = $state('');
  let newPassword = $state('');
  let creating = $state(false);

  // Edit form
  let editName = $state('');
  let editEmail = $state('');
  let editUsername = $state('');
  let saving = $state(false);

  function openEdit(user: User) {
    editUser = user;
    editName = user.name;
    editEmail = user.email ?? '';
    editUsername = user.username;
  }

  async function handleEdit() {
    if (saving || !editUser) return;
    saving = true;
    try {
      const updated = await updateUser(editUser.id, {
        name: editName,
        email: editEmail || null,
        username: editUsername,
      });
      users = users.map(u => u.id === updated.id ? updated : u);
      editUser = null;
      toasts.success('User updated.');
    } catch (err: any) {
      toasts.error(`Failed to update user: ${err.message}`);
    } finally {
      saving = false;
    }
  }

  onMount(async () => {
    try {
      [users, roles] = await Promise.all([getUsers(), getRoles()]);
    } catch {
      toasts.error('Failed to load users.');
    } finally {
      loading = false;
    }
  });

  async function loadUserRoles(userId: string) {
    if (userRoles[userId]) return;
    try {
      const r = await getUserRoles(userId);
      userRoles = { ...userRoles, [userId]: r };
    } catch {
      toasts.error('Failed to load roles.');
    }
  }

  async function openRoles(userId: string) {
    showRoles = userId;
    await loadUserRoles(userId);
  }

  async function handleAssign(userId: string, roleId: string) {
    const role = roles.find(r => r.id === roleId);
    const prev = userRoles[userId] ?? [];
    userRoles = { ...userRoles, [userId]: [...prev, role!] };
    try {
      await assignRole(userId, roleId);
      toasts.success(`Assigned ${role?.name ?? 'role'}.`);
    } catch {
      userRoles = { ...userRoles, [userId]: prev };
      toasts.error('Failed to assign role.');
    }
  }

  async function handleRemove(userId: string, roleId: string) {
    const role = roles.find(r => r.id === roleId);
    const prev = userRoles[userId] ?? [];
    userRoles = { ...userRoles, [userId]: prev.filter(r => r.id !== roleId) };
    try {
      await removeRole(userId, roleId);
      toasts.success(`Removed ${role?.name ?? 'role'}.`);
    } catch (err: any) {
      userRoles = { ...userRoles, [userId]: prev };
      toasts.error(err?.message ? `Failed to remove role: ${err.message}` : 'Failed to remove role.');
    }
  }

  async function handleCreate() {
    if (creating) return;
    creating = true;
    try {
      const u = await createUser({ username: newUsername, name: newName, email: newEmail, password: newPassword });
      users = [...users, u];
      showCreate = false;
      newUsername = newName = newEmail = newPassword = '';
      toasts.success('User created.');
    } catch (err: any) {
      toasts.error(`Failed to create user: ${err.message}`);
    } finally {
      creating = false;
    }
  }

  // Change password
  let changePasswordUser = $state<User | null>(null);
  let adminNewPassword = $state('');
  let adminConfirmPassword = $state('');
  let changingPassword = $state(false);

  const adminPasswordLengthError = $derived(
    adminNewPassword.length > 0 && adminNewPassword.length < 12
      ? 'Password must be at least 12 characters'
      : ''
  );
  const adminPasswordConfirmError = $derived(
    adminConfirmPassword.length > 0 && adminNewPassword !== adminConfirmPassword
      ? 'Passwords do not match'
      : ''
  );
  const canChangePassword = $derived(
    !!adminNewPassword && !!adminConfirmPassword &&
    !adminPasswordLengthError && !adminPasswordConfirmError && !changingPassword
  );

  function openChangePassword(user: User) {
    changePasswordUser = user;
    adminNewPassword = '';
    adminConfirmPassword = '';
  }

  async function handleChangePassword() {
    if (!canChangePassword || !changePasswordUser) return;
    changingPassword = true;
    try {
      await adminChangePassword(changePasswordUser.id, { new_password: adminNewPassword });
      changePasswordUser = null;
      toasts.success('Password changed and all sessions revoked.');
    } catch (err: any) {
      toasts.error(`Failed to change password: ${err.message}`);
    } finally {
      changingPassword = false;
    }
  }

  // App passwords (admin view)
  let appPasswordUser = $state<User | null>(null);
  let appPasswords = $state<AppPassword[]>([]);
  let loadingAppPws = $state(false);
  let revokingId = $state<string | null>(null);

  async function openAppPasswords(user: User) {
    appPasswordUser = user;
    loadingAppPws = true;
    try {
      appPasswords = await listUserAppPasswords(user.id);
    } catch {
      toasts.error('Failed to load app passwords.');
      appPasswords = [];
    } finally {
      loadingAppPws = false;
    }
  }

  async function handleRevokeAppPassword(id: string) {
    if (!appPasswordUser || revokingId) return;
    revokingId = id;
    try {
      await deleteUserAppPassword(appPasswordUser.id, id);
      appPasswords = appPasswords.filter((p) => p.id !== id);
      toasts.success('Revoked.');
    } catch (err: any) {
      toasts.error(`Failed to revoke: ${err.message}`);
    } finally {
      revokingId = null;
    }
  }

  function formatDate(ts: number | null) {
    if (!ts) return '—';
    return new Date(ts * 1000).toLocaleDateString();
  }

  const roleUser = $derived(showRoles ? users.find(u => u.id === showRoles) : null);
  const assignedRoleIds = $derived(
    showRoles ? new Set((userRoles[showRoles] ?? []).map(r => r.id)) : new Set<string>()
  );
</script>

<div class="page">
  <header class="page-header">
    <div>
      <h1 class="au-h3">Users</h1>
      <p class="au-micro au-fg-3">{users.length} total</p>
    </div>
    <Button variant="primary" onclick={() => showCreate = true}>
      <i class="ph ph-plus"></i> Add user
    </Button>
  </header>

  {#if loading}
    <div class="page-loading au-fg-4 au-small">
      <i class="ph ph-circle-notch spin"></i> Loading…
    </div>
  {:else}
    <ResponsiveTable
      label="Users"
      items={users}
      getKey={(u) => u.id}
      columns={[
        { key: 'name',     label: 'Name',     tdClass: 'au-fg-1 font-medium' },
        { key: 'username', label: 'Username', tdClass: 'au-fg-2 au-mono au-code-sm' },
        { key: 'email',    label: 'Email',    tdClass: 'au-fg-3 au-small' },
        { key: 'id',       label: 'ID',       thClass: 'col-id' },
      ]}
    >
      {#snippet cell({ item, column })}
        {#if column.key === 'name'}{item.name}
        {:else if column.key === 'username'}{item.username}
        {:else if column.key === 'email'}{item.email ?? ''}
        {:else if column.key === 'id'}<CopyId id={item.id} />
        {/if}
      {/snippet}
      {#snippet actions({ item })}
        <Button size="sm" variant="ghost" onclick={() => openEdit(item)}>Edit</Button>
        <Button size="sm" variant="ghost" onclick={() => openRoles(item.id)}>Roles</Button>
        <Button size="sm" variant="ghost" onclick={() => openChangePassword(item)}>Password</Button>
        <Button size="sm" variant="ghost" onclick={() => openAppPasswords(item)}>App PWs</Button>
      {/snippet}
      {#snippet empty()}No users yet. Add one to get started.{/snippet}
    </ResponsiveTable>
  {/if}
</div>

<!-- Create user modal -->
{#if showCreate}
  <Modal title="Add user" onclose={() => showCreate = false}>
    <div class="modal-form" onkeydown={(e) => { if (e.key === 'Enter' && !creating && newUsername && newName && newEmail && newPassword) handleCreate(); }}>
      <Input label="Username" bind:value={newUsername} placeholder="jane" />
      <Input label="Full name" bind:value={newName} placeholder="Jane Smith" />
      <Input label="Email" type="email" bind:value={newEmail} placeholder="jane@example.com" />
      <Input label="Password" type="password" bind:value={newPassword} placeholder="Min. 12 characters" />
    </div>
    {#snippet actions()}
      <Button variant="secondary" onclick={() => showCreate = false}>Cancel</Button>
      <Button
        variant="primary"
        loading={creating}
        disabled={!newUsername || !newName || !newEmail || !newPassword || creating}
        onclick={handleCreate}
      >
        Create user
      </Button>
    {/snippet}
  </Modal>
{/if}

<!-- Edit user modal -->
{#if editUser}
  <Modal title="Edit user" onclose={() => editUser = null}>
    <div class="modal-form" onkeydown={(e) => { if (e.key === 'Enter' && !saving) handleEdit(); }}>
      <Input label="Full name" bind:value={editName} placeholder="Jane Smith" />
      <Input label="Username" bind:value={editUsername} placeholder="jane" />
      <Input label="Email" type="email" bind:value={editEmail} placeholder="jane@example.com" />
    </div>
    {#snippet actions()}
      <Button variant="secondary" onclick={() => editUser = null}>Cancel</Button>
      <Button variant="primary" loading={saving} disabled={!editName || !editUsername || saving} onclick={handleEdit}>
        Save changes
      </Button>
    {/snippet}
  </Modal>
{/if}

<!-- Role assignment modal -->
{#if showRoles && roleUser}
  <Modal title="Roles — {roleUser.name}" onclose={() => showRoles = null}>
    <div class="roles-list">
      {#each roles as role (role.id)}
        {@const assigned = assignedRoleIds.has(role.id)}
        <button
          class="role-row"
          class:assigned
          onclick={() => assigned ? handleRemove(showRoles!, role.id) : handleAssign(showRoles!, role.id)}
        >
          <i class="{assigned ? 'ph-fill ph-check-circle' : 'ph ph-circle'} role-check"></i>
          <div class="role-info">
            <span class="au-small font-medium">{role.name}</span>
            {#if role.description}
              <span class="au-micro au-fg-4">{role.description}</span>
            {/if}
          </div>
        </button>
      {/each}
    </div>
    {#snippet actions()}
      <Button variant="secondary" onclick={() => showRoles = null}>Done</Button>
    {/snippet}
  </Modal>
{/if}

<!-- App passwords modal -->
{#if appPasswordUser}
  <Modal title="App passwords — {appPasswordUser.name}" onclose={() => appPasswordUser = null}>
    {#if loadingAppPws}
      <p class="au-small au-fg-3">Loading…</p>
    {:else if appPasswords.length === 0}
      <p class="au-small au-fg-3">This user has not created any app passwords.</p>
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
              size="sm"
              variant="ghost"
              loading={revokingId === p.id}
              onclick={() => handleRevokeAppPassword(p.id)}
            >
              Revoke
            </Button>
          </li>
        {/each}
      </ul>
    {/if}
    <p class="au-micro au-fg-4 admin-note">
      Only the account holder can create new app passwords. You can revoke from here.
    </p>
    {#snippet actions()}
      <Button variant="secondary" onclick={() => appPasswordUser = null}>Done</Button>
    {/snippet}
  </Modal>
{/if}

<!-- Change password modal -->
{#if changePasswordUser}
  <Modal title="Change password — {changePasswordUser.name}" onclose={() => changePasswordUser = null}>
    <div
      class="modal-form"
      onkeydown={(e) => { if (e.key === 'Enter' && canChangePassword) handleChangePassword(); }}
    >
      <Input
        label="New password"
        type="password"
        bind:value={adminNewPassword}
        placeholder="Min. 12 characters"
        error={adminPasswordLengthError}
      />
      <Input
        label="Confirm new password"
        type="password"
        bind:value={adminConfirmPassword}
        placeholder="••••••••••••"
        error={adminPasswordConfirmError}
      />
    </div>
    {#snippet actions()}
      <Button variant="secondary" onclick={() => changePasswordUser = null}>Cancel</Button>
      <Button
        variant="primary"
        loading={changingPassword}
        disabled={!canChangePassword}
        onclick={handleChangePassword}
      >
        Set password
      </Button>
    {/snippet}
  </Modal>
{/if}

<style>
  .page { padding: var(--sp-6); max-width: 960px; margin: 0 auto; }

  .page-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    margin-bottom: var(--sp-6);
    gap: var(--sp-3);
  }

  @media (max-width: 639.98px) {
    .page { padding: var(--sp-4); }
    .page-header {
      flex-direction: column;
      align-items: stretch;
      margin-bottom: var(--sp-4);
    }
  }

  .page-loading {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    padding: var(--sp-8);
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
    padding: var(--sp-2) var(--sp-3);
    border: 1px solid var(--border-0);
    border-radius: var(--radius);
    background: var(--bg-1);
  }
  .app-pw-info { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
  .admin-note { margin-top: var(--sp-3); }


  .modal-form { display: flex; flex-direction: column; gap: var(--sp-3); }

  .roles-list { display: flex; flex-direction: column; gap: 2px; }

  .role-row {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    padding: var(--sp-2) var(--sp-3);
    border-radius: var(--radius);
    background: var(--bg-1);
    border: 1px solid var(--border-0);
    width: 100%;
    text-align: left;
    cursor: pointer;
    transition: background var(--duration-micro) var(--ease-out),
                border-color var(--duration-micro) var(--ease-out);
  }

  .role-row:hover { background: var(--bg-2); }

  .role-row.assigned {
    background: var(--accent-subtle);
    border-color: rgba(59,130,246,0.3);
  }

  .role-row.assigned:hover { background: color-mix(in srgb, var(--accent-subtle) 80%, var(--bg-3)); }

  .role-check {
    font-size: 16px;
    flex-shrink: 0;
    color: var(--fg-4);
  }

  .role-row.assigned .role-check { color: var(--accent); }

  .role-info {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .role-row .role-info .au-small { color: var(--fg-1); }

  .spin { animation: spin 0.7s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
