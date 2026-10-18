import {
  browserSupportsWebAuthn,
  startAuthentication,
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser';
import { ApiError, type Passkey } from './api';

export function supportsPasskeys(): boolean {
  // Do not require a built-in authenticator: USB keys and another device's
  // passkeys can work even when a platform authenticator is unavailable.
  return window.isSecureContext && browserSupportsWebAuthn();
}

async function ceremonyRequest<T>(path: string, body?: unknown): Promise<T> {
  // A direct fetch from the click handler preserves Safari's user gesture.
  // Never retry a verification request or interpose a session refresh here.
  const response = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) throw new ApiError(response.status, await response.text());
  return response.json();
}

export async function signInWithPasskey(): Promise<void> {
  const optionsJSON = await ceremonyRequest<PublicKeyCredentialRequestOptionsJSON>('/api/auth/passkeys/start');
  const credential = await startAuthentication({ optionsJSON });
  await ceremonyRequest('/api/auth/passkeys/finish', credential);
}

export async function registerPasskey(name: string): Promise<Passkey> {
  const optionsJSON = await ceremonyRequest<PublicKeyCredentialCreationOptionsJSON>(
    '/api/me/passkeys/register/start', { name },
  );
  const credential = await startRegistration({ optionsJSON });
  return ceremonyRequest<Passkey>('/api/me/passkeys/register/finish', credential);
}

export function passkeyError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 429) return 'Too many attempts. Wait a minute and try again.';
    if (error.status === 401) return 'Could not verify your passkey or your session expired. Try again, or sign in with your password.';
    if (error.status === 409) return 'This passkey is already registered. Choose a different passkey.';
    if (error.status === 400) return error.message;
    return 'Passkeys are temporarily unavailable. Try again, or sign in with your password.';
  }
  if (error instanceof Error) {
    if (error.name === 'NotAllowedError' || error.name === 'AbortError') {
      return 'Passkey request was cancelled or timed out. You can try again.';
    }
    if (error.name === 'InvalidStateError') return 'This device already has a passkey for your account. Try another device or password manager.';
    if (error.name === 'SecurityError') return 'Passkeys are unavailable at this address. Open Authere at its configured secure address.';
    if (error.name === 'NotSupportedError' || error.name === 'ConstraintError') return 'This device cannot create this passkey. Try another device or security key.';
  }
  return 'Could not complete the passkey request. Check your connection and try again.';
}
