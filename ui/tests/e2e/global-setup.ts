import { execSync } from 'node:child_process';
import { existsSync, statSync, readdirSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, '..', '..', '..');
const UI_DIR = join(REPO_ROOT, 'ui');
const SERVER_DIR = join(REPO_ROOT, 'server');
const BIN_PATH = join(SERVER_DIR, 'target', 'release', 'authere_server');
const DIST_INDEX = join(UI_DIR, 'dist', 'index.html');

// Check whether a rebuild is worth skipping. We don't try to do full
// cache-invalidation here — cargo and vite already handle that. We only skip
// to save startup time when nothing looks stale.
function upToDate(artifactPath: string, sourcesDir: string): boolean {
  if (!existsSync(artifactPath)) return false;
  const artifactMtime = statSync(artifactPath).mtimeMs;
  let newestSource = 0;
  function walk(p: string) {
    for (const entry of readdirSync(p, { withFileTypes: true })) {
      if (entry.name === 'target' || entry.name === 'node_modules' || entry.name === 'dist') continue;
      const child = join(p, entry.name);
      if (entry.isDirectory()) walk(child);
      else {
        const m = statSync(child).mtimeMs;
        if (m > newestSource) newestSource = m;
      }
    }
  }
  walk(sourcesDir);
  return artifactMtime >= newestSource;
}

export default async function globalSetup() {
  const uiDirty = !upToDate(DIST_INDEX, join(UI_DIR, 'src'));
  if (uiDirty) {
    console.log('[global-setup] building UI (vite)...');
    execSync('npm run build', { cwd: UI_DIR, stdio: 'inherit' });
  } else {
    console.log('[global-setup] UI dist up to date, skipping vite build');
  }

  // The Rust binary embeds dist/ at compile time via rust-embed. Rebuild if
  // Rust sources OR the UI dist are newer than the binary we have.
  const rustDirty =
    uiDirty ||
    !upToDate(BIN_PATH, join(SERVER_DIR, 'src')) ||
    !upToDate(BIN_PATH, join(UI_DIR, 'dist'));
  if (rustDirty) {
    console.log('[global-setup] building release Rust server...');
    execSync('cargo build --release --bin authere_server', {
      cwd: SERVER_DIR,
      stdio: 'inherit',
    });
  } else {
    console.log('[global-setup] Rust server up to date, skipping cargo build');
  }
}
