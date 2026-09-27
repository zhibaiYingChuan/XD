import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

/** 从 personal/pyproject.toml 读取版本号（版本号 SSOT 链：pyproject.toml → vite 注入 → UI 展示） */
function readVersion(): string {
  try {
    const raw = readFileSync(resolve(__dirname, '../pyproject.toml'), 'utf-8');
    const m = raw.match(/^version\s*=\s*"([^"]+)"/m);
    return m ? m[1] : '0.0.0';
  } catch {
    return '0.0.0';
  }
}

export default defineConfig({
  plugins: [react()],
  define: {
    // 必须用 JSON.stringify 包裹：esbuild 的 define 值必须是实体名或合法 JSON。
    // 直接注入裸字符串（如 0.1.0-alpha）会被解析为表达式导致构建失败。
    'import.meta.env.VITE_APP_VERSION': JSON.stringify(readVersion()),
  },
  server: {
    port: 1420,
    strictPort: true,
    // Tauri dev 期望固定端口；本地代理由 Python 侧运行在 18765
  },
  build: {
    outDir: 'dist',
    target: 'es2021',
    sourcemap: false,
  },
});
