import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

export default defineConfig({
  plugins: [svelte()],
  // Proxy API calls to Rust server in dev
  server: {
    proxy: {
      '/auth': 'http://localhost:3000',
      '/user': 'http://localhost:3000',
      '/users': 'http://localhost:3000',
      '/roles': 'http://localhost:3000',
      '/applications': 'http://localhost:3000',
      '/audit': 'http://localhost:3000',
      '/me': 'http://localhost:3000',
    },
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
  },
})
