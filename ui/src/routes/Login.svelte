<script lang="ts">
  import { login, ApiError } from '../lib/api';
  import Button from '../lib/components/Button.svelte';
  import Input from '../lib/components/Input.svelte';

  let username = $state('');
  let password = $state('');
  let error = $state('');
  let loading = $state(false);

  const rawRedirect = new URLSearchParams(window.location.search).get('redirect_uri') ?? '/';

  function sanitizeRedirect(raw: string): string {
    if (raw.startsWith('/') && !raw.startsWith('//')) return raw;
    try {
      const url = new URL(raw);
      if (url.protocol === 'https:' || (url.protocol === 'http:' && url.hostname === 'localhost')) {
        return url.href;
      }
    } catch {}
    return '/';
  }

  const redirectUri = sanitizeRedirect(rawRedirect);

  async function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    if (loading) return;
    error = '';
    loading = true;
    try {
      await login(username, password);
      window.location.href = redirectUri;
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 429) {
          error = 'Too many attempts. Wait a minute and try again.';
        } else if (err.status === 401) {
          error = 'Username or password is incorrect.';
        } else {
          error = `Sign-in failed (${err.status}).`;
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
      <h1 class="au-h3">Sign in</h1>
      <p class="au-small au-fg-3">Sign in to continue.</p>
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
          label="Password"
          type="password"
          bind:value={password}
          autocomplete="current-password"
          placeholder="••••••••••••"
        />
      </div>

      {#if error}
        <div class="form-error au-small" role="alert">
          <i class="ph ph-warning"></i>
          {error}
        </div>
      {/if}

      <Button variant="primary" size="lg" type="submit" {loading} disabled={!username || !password || loading}>
        Sign in
      </Button>
    </form>
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
    width: 100%;
    max-width: 400px;
    background: var(--bg-1);
    border: 1px solid var(--border-1);
    border-radius: var(--radius);
    padding: var(--sp-8);
    display: flex;
    flex-direction: column;
    gap: var(--sp-6);
  }

  @media (max-width: 639.98px) {
    .auth-bg { padding: var(--sp-4); }
    .auth-shell { padding: var(--sp-6) var(--sp-4); }
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

  :global(.btn-lg) { width: 100%; justify-content: center; }
</style>
