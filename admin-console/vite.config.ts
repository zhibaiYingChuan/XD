import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { readFileSync } from 'fs'
import { resolve } from 'path'

// 从 pyproject.toml 读取版本号（SSOT: Cargo.toml → sync_version.py → pyproject.toml）
function readVersion(): string {
  try {
    const toml = readFileSync(resolve(__dirname, '..', 'pyproject.toml'), 'utf-8')
    const m = toml.match(/^version\s*=\s*"([^"]+)"/m)
    return m ? m[1] : '0.0.0'
  } catch { return '0.0.0' }
}

export default defineConfig({
  plugins: [react()],
  define: {
    'import.meta.env.VITE_APP_VERSION': JSON.stringify(readVersion()),
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:18766',
      '/health': 'http://127.0.0.1:18766',
      '/metrics': 'http://127.0.0.1:18766',
    }
  }
})
