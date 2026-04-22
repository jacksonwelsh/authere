import { spawn, type ChildProcess } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
// Repo root is two levels above ui/
const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..');
const SERVER_DIR = join(REPO_ROOT, 'server');
const BIN_PATH = join(SERVER_DIR, 'target', 'release', 'authere_server');
const WORKERS_DIR = resolve(__dirname, '..', '..', '.tmp', 'workers');

// A fixed 32-byte (64 hex-chars) key. Deterministic across runs so token
// decryption would behave identically — but since every worker gets a fresh DB
// and thus a fresh signing key on first startup, determinism here doesn't
// leak across runs in any meaningful way.
export const TEST_KEY_SECRET =
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

export const ADMIN_USERNAME = 'e2e_admin';
export const ADMIN_PASSWORD = 'E2E-Admin-Password-1';
export const ADMIN_NAME = 'E2E Admin';

export interface WorkerServer {
  baseURL: string;
  port: number;
  dbPath: string;
  stop(): Promise<void>;
}

function workerDir(workerIndex: number): string {
  return join(WORKERS_DIR, String(workerIndex));
}

async function waitForReady(baseURL: string, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastErr: unknown = null;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${baseURL}/api/me`);
      // Readiness signal: server responds 401 to /api/me (auth routes online,
      // DB migrations complete, signing key loaded). A 2xx would be suspicious.
      if (r.status === 401) return;
      lastErr = new Error(`unexpected status ${r.status}`);
    } catch (err) {
      lastErr = err;
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(
    `server at ${baseURL} did not become ready within ${timeoutMs}ms: ${String(lastErr)}`,
  );
}

function spawnBin(
  args: string[],
  env: NodeJS.ProcessEnv,
  label: string,
): ChildProcess {
  const child = spawn(BIN_PATH, args, {
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout?.on('data', (buf) => {
    if (process.env.E2E_SERVER_LOGS) process.stdout.write(`[${label}] ${buf}`);
  });
  child.stderr?.on('data', (buf) => {
    if (process.env.E2E_SERVER_LOGS) process.stderr.write(`[${label}] ${buf}`);
  });
  return child;
}

function runBinToCompletion(
  args: string[],
  env: NodeJS.ProcessEnv,
  label: string,
): Promise<void> {
  return new Promise((ok, fail) => {
    const child = spawnBin(args, env, label);
    let stderr = '';
    child.stderr?.on('data', (buf) => {
      stderr += String(buf);
    });
    child.on('exit', (code) => {
      if (code === 0) ok();
      else fail(new Error(`${label} exited ${code}: ${stderr}`));
    });
    child.on('error', fail);
  });
}

export async function startWorkerServer(workerIndex: number): Promise<WorkerServer> {
  const port = 3100 + workerIndex;
  const dir = workerDir(workerIndex);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });

  const dbPath = join(dir, 'data.db');
  const databaseUrl = `sqlite:${dbPath}?mode=rwc`;
  const baseURL = `http://127.0.0.1:${port}`;

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    DATABASE_URL: databaseUrl,
    AUTHERE_KEY_SECRET: TEST_KEY_SECRET,
    AUTHERE_BIND_ADDR: `127.0.0.1:${port}`,
    AUTHERE_ALLOWED_ORIGINS: baseURL,
    // Relax rate limits for tests. Real rate-limit behavior is exercised via
    // the unit test (Login.test.ts: 429 branch) — there's no value in asking
    // the E2E harness to verify the counter math, since that would force every
    // other E2E test into a deliberately-narrow time budget.
    AUTHERE_LOGIN_MAX_REQUESTS: '1000',
    AUTHERE_REGISTER_MAX_REQUESTS: '1000',
    RUST_LOG: 'warn',
  };

  // Seed admin before starting serve, using the same binary. init-admin runs
  // migrations + inserts, then exits — a clean one-shot that avoids
  // race conditions with the HTTP server booting.
  await runBinToCompletion(
    [
      'init-admin',
      '--username', ADMIN_USERNAME,
      '--password', ADMIN_PASSWORD,
      '--name', ADMIN_NAME,
    ],
    env,
    `init-admin-w${workerIndex}`,
  );

  const child = spawnBin(['serve'], env, `serve-w${workerIndex}`);

  child.on('exit', (code, signal) => {
    if (process.env.E2E_SERVER_LOGS) {
      process.stderr.write(`[serve-w${workerIndex}] exited code=${code} signal=${signal}\n`);
    }
  });

  try {
    await waitForReady(baseURL);
  } catch (err) {
    child.kill('SIGKILL');
    throw err;
  }

  return {
    baseURL,
    port,
    dbPath,
    async stop() {
      if (child.exitCode !== null) return;
      child.kill('SIGTERM');
      await new Promise<void>((resolveStop) => {
        const t = setTimeout(() => {
          child.kill('SIGKILL');
          resolveStop();
        }, 3000);
        child.on('exit', () => {
          clearTimeout(t);
          resolveStop();
        });
      });
    },
  };
}
