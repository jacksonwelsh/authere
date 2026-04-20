<script lang="ts">
  import { onMount } from 'svelte';
  import { registerUser, validateInvite, ApiError } from '../lib/api';
  import Button from '../lib/components/Button.svelte';
  import Input from '../lib/components/Input.svelte';

  let username = $state('');
  let name = $state('');
  let email = $state('');
  let password = $state('');
  let confirmPassword = $state('');
  let inviteCode = $state('');
  let error = $state('');
  let loading = $state(false);
  let inviteValid = $state<boolean | null>(null);
  let checkingInvite = $state(false);

  const passwordMismatch = $derived(
    confirmPassword.length > 0 && password !== confirmPassword
  );

  onMount(async () => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('invite');
    if (code) {
      inviteCode = code;
      checkingInvite = true;
      try {
        const result = await validateInvite(code);
        inviteValid = result.valid;
      } catch {
        inviteValid = false;
      } finally {
        checkingInvite = false;
      }
    }
  });

  async function handleInviteBlur() {
    if (!inviteCode) {
      inviteValid = null;
      return;
    }
    checkingInvite = true;
    try {
      const result = await validateInvite(inviteCode);
      inviteValid = result.valid;
    } catch {
      inviteValid = false;
    } finally {
      checkingInvite = false;
    }
  }

  async function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    if (loading || passwordMismatch) return;
    error = '';
    loading = true;
    try {
      const result = await registerUser({
        username,
        name,
        email: email || undefined,
        password,
        confirm_password: confirmPassword,
        invite_code: inviteCode || undefined,
      });
      sessionStorage.setItem('authere:registrationSuccess', '1');
      window.location.href = result.redirect_uri ?? '/account';
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 429) {
          error = 'Too many registration attempts. Try again later.';
        } else if (err.status === 409) {
          error = 'Username is already taken.';
        } else if (err.status === 400) {
          error = err.message || 'Invalid input.';
        } else {
          error = `Registration failed (${err.status}).`;
        }
      } else {
        error = 'Network error. Check your connection.';
      }
    } finally {
      loading = false;
    }
  }
</script>

<div class="auth-bg au-dotgrid">
  <div class="auth-shell">
    <header class="auth-header">
      <div class="auth-logo">
        <svg width="28" height="28" viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg">
          <rect width="28" height="28" rx="4" fill="#3B82F6" fill-opacity="0.15"/>
          <path d="M14 5L21 9.5v9L14 23l-7-4.5v-9L14 5z" stroke="#3B82F6" stroke-width="1.5" stroke-linejoin="round" fill="none"/>
          <circle cx="14" cy="14" r="2.5" fill="#3B82F6"/>
        </svg>
        <span class="au-h4">authere</span>
      </div>
      <h1 class="au-h3">Create account</h1>
      <p class="au-small au-fg-3">Fill in the details below to get started.</p>
    </header>

    <form onsubmit={handleSubmit} novalidate>
      <div class="form-fields">
        <Input
          label="Username"
          bind:value={username}
          autocomplete="username"
          autofocus
          placeholder="you"
        />
        <Input
          label="Full name"
          bind:value={name}
          autocomplete="name"
          placeholder="Jane Smith"
        />
        <Input
          label="Email"
          type="email"
          bind:value={email}
          autocomplete="email"
          placeholder="jane@example.com"
        />
        <Input
          label="Password"
          type="password"
          bind:value={password}
          autocomplete="new-password"
          placeholder="••••••••••••"
        />
        <Input
          label="Confirm password"
          type="password"
          bind:value={confirmPassword}
          autocomplete="new-password"
          placeholder="••••••••••••"
          error={passwordMismatch ? 'Passwords do not match' : ''}
        />
        <div class="invite-field">
          <Input
            label="Invitation code"
            bind:value={inviteCode}
            placeholder="Optional"
            onblur={handleInviteBlur}
          />
          {#if checkingInvite}
            <span class="invite-status au-micro au-fg-3">
              <i class="ph ph-circle-notch spin"></i> Checking…
            </span>
          {:else if inviteCode && inviteValid === true}
            <span class="invite-status valid au-micro">
              <i class="ph ph-check-circle-fill"></i> Valid invitation
            </span>
          {:else if inviteCode && inviteValid === false}
            <span class="invite-status invalid au-micro">
              <i class="ph ph-x-circle-fill"></i> Invalid or expired
            </span>
          {/if}
        </div>
      </div>

      {#if error}
        <div class="form-error au-small" role="alert">
          <i class="ph ph-warning"></i>
          {error}
        </div>
      {/if}

      <Button
        variant="primary"
        size="lg"
        type="submit"
        {loading}
        disabled={!username || !name || !password || !confirmPassword || passwordMismatch || loading}
      >
        Create account
      </Button>
    </form>

    <footer class="auth-footer au-small au-fg-3">
      Already have an account?
      <a href="/login" class="au-link">Sign in</a>
    </footer>
  </div>
</div>

<style>
  .auth-bg {
    min-height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: var(--sp-8);
    background-color: var(--bg-0);
  }

  .auth-shell {
    width: 400px;
    background: var(--bg-1);
    border: 1px solid var(--border-1);
    border-radius: var(--radius);
    padding: var(--sp-8);
    display: flex;
    flex-direction: column;
    gap: var(--sp-6);
  }

  .auth-header { display: flex; flex-direction: column; gap: var(--sp-2); }

  .auth-logo {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    color: var(--fg-1);
    margin-bottom: var(--sp-2);
  }

  form {
    display: flex;
    flex-direction: column;
    gap: var(--sp-4);
  }

  .form-fields { display: flex; flex-direction: column; gap: var(--sp-3); }

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

  .invite-field { display: flex; flex-direction: column; gap: var(--sp-1); }

  .invite-status {
    display: flex;
    align-items: center;
    gap: var(--sp-1);
    padding-left: var(--sp-1);
  }

  .invite-status.valid { color: var(--success, #22c55e); }
  .invite-status.invalid { color: var(--danger); }

  @keyframes spin { to { transform: rotate(360deg); } }
  .spin { display: inline-block; animation: spin 0.8s linear infinite; }

  .auth-footer { text-align: center; }

  .au-link { color: var(--accent); text-decoration: none; }
  .au-link:hover { text-decoration: underline; }

  :global(.btn-lg) { width: 100%; justify-content: center; }
</style>
