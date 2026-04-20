<script lang="ts">
  import { onMount } from 'svelte';
  import { getUsers, getRoles, getUserRoles, createUser, updateUser, assignRole, removeRole, adminChangePassword, type User, type Role } from '../../lib/api';
  import Button from '../../lib/components/Button.svelte';
  import CopyId from '../../lib/components/CopyId.svelte';
  import Input from '../../lib/components/Input.svelte';
  import Modal from '../../lib/components/Modal.svelte';
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
    } catch {
      userRoles = { ...userRoles, [userId]: prev };
      toasts.error('Failed to remove role.');
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
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th class="col-name">Name</th>
            <th class="col-user">Username</th>
            <th class="col-email">Email</th>
            <th class="col-id">ID</th>
            <th class="col-actions"></th>
          </tr>
        </thead>
        <tbody>
          {#each users as user (user.id)}
            <tr>
              <td class="au-fg-1 font-medium">{user.name}</td>
              <td class="au-fg-2 au-mono au-code-sm">{user.username}</td>
              <td class="au-fg-3 au-small">{user.email}</td>
              <td><CopyId id={user.id} /></td>
              <td class="actions-cell">
                <Button size="sm" variant="ghost" onclick={() => openEdit(user)}>Edit</Button>
                <Button size="sm" variant="ghost" onclick={() => openRoles(user.id)}>Roles</Button>
                <Button size="sm" variant="ghost" onclick={() => openChangePassword(user)}>Password</Button>
              </td>
            </tr>
          {/each}
          {#if users.length === 0}
            <tr>
              <td colspan="5" class="empty-row au-fg-4 au-small">No users yet. Add one to get started.</td>
            </tr>
          {/if}
        </tbody>
      </table>
    </div>
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
  }

  .page-loading {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    padding: var(--sp-8);
  }

  .table-wrap {
    border: 1px solid var(--border-0);
    border-radius: var(--radius);
    overflow: hidden;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }

  thead th {
    height: 32px;
    padding: 0 var(--sp-3);
    text-align: left;
    background: var(--bg-1);
    color: var(--fg-4);
    font-size: 11px;
    font-weight: 500;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    border-bottom: 1px solid var(--border-0);
    white-space: nowrap;
  }

  thead th:last-child { text-align: right; }

  tbody tr {
    height: 32px;
    border-bottom: 1px solid var(--border-0);
    transition: background var(--duration-micro) var(--ease-out);
  }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: var(--bg-1); }

  td {
    padding: 0 var(--sp-3);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .col-id { width: 120px; }
  .col-actions { width: 210px; }
  .actions-cell { text-align: right; }

  .empty-row { padding: var(--sp-8) !important; text-align: center; }

  .font-medium { font-weight: 500; }

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
