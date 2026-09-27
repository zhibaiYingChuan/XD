/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   Tauri 环境垫片。

   个人版前端需要同时支持两种运行：
   - Tauri 桌面应用（npm run tauri dev / 打包后）
   - 纯浏览器开发（npm run dev 预览 UI）

   本模块屏蔽差异：Tauri 环境用 IPC，浏览器环境直连本地代理 HTTP。
*/

import type { InvokeArgs } from '@tauri-apps/api/core';

/** 是否运行在 Tauri 环境中 */
export function isTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

/** 统一的 invoke 包装（Tauri 环境）。 */
export async function invoke<T>(cmd: string, args?: InvokeArgs): Promise<T> {
  if (!isTauri()) {
    throw new Error(
      `命令 ${cmd} 仅在 Tauri 桌面环境可用（当前为浏览器开发模式，已自动回退 HTTP）`,
    );
  }
  const mod = await import('@tauri-apps/api/core');
  return mod.invoke<T>(cmd, args);
}

/** 应用版本（仅 Tauri 环境可用）。 */
export async function getAppVersion(): Promise<string> {
  if (!isTauri()) {
    return import.meta.env.VITE_APP_VERSION ?? '0.1.0-alpha';
  }
  try {
    const mod = await import('@tauri-apps/api/app');
    return await mod.getVersion();
  } catch {
    return import.meta.env.VITE_APP_VERSION ?? '0.1.0-alpha';
  }
}

/** 打开外部链接。 */
export async function openExternal(url: string): Promise<void> {
  if (isTauri()) {
    try {
      // 用变量而非字面量导入，避免 TS 在 webview-only 构建时报模块缺失
      const specifier = '@tauri-apps/plugin-shell';
      const mod = (await import(/* @vite-ignore */ specifier)) as {
        open: (u: string) => Promise<void>;
      };
      await mod.open(url);
      return;
    } catch {
      /* 回退到浏览器方式 */
    }
  }
  window.open(url, '_blank', 'noopener,noreferrer');
}

/** 复制到剪贴板。 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* 回退到 execCommand */
  }
  try {
    const el = document.createElement('textarea');
    el.value = text;
    el.style.position = 'fixed';
    el.style.opacity = '0';
    document.body.appendChild(el);
    el.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(el);
    return ok;
  } catch {
    return false;
  }
}

/** 下载文本文件。返回是否成功触发下载。 */
export function downloadText(filename: string, content: string, mime = 'text/plain'): boolean {
  try {
    const blob = new Blob([content], { type: `${mime};charset=utf-8` });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    // 立即 revoke 会让部分 WebView 拿不到内容，延后释放
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
    return true;
  } catch {
    return false;
  }
}

// ══════════════════════════════════════════════════════════════
// 托盘（仅 Tauri 环境可用）
// ══════════════════════════════════════════════════════════════

/** 托盘状态（与 Rust 侧 TrayState 对齐） */
export type TrayState = 'safe' | 'suspect' | 'danger' | 'paused';

/**
 * 下发托盘持续态。
 *
 * 这是「两段式变色」的持续段：表达「今天累计有几次危险」。
 * 瞬时脉冲段（刚刚被拦截）由 Rust 侧独立轮询日志触发，
 * 不依赖前端 —— 前端窗口隐藏时依然生效。
 */
export async function setTrayState(state: TrayState, detail: string): Promise<void> {
  if (!isTauri()) return;
  try {
    const mod = await import('@tauri-apps/api/core');
    await mod.invoke('set_tray_state', { state, detail });
  } catch {
    /* 托盘不可用不应影响主流程 */
  }
}

/** 读取当前托盘状态（自检用）。 */
export async function getTrayState(): Promise<TrayState | null> {
  if (!isTauri()) return null;
  try {
    const mod = await import('@tauri-apps/api/core');
    return (await mod.invoke<string>('get_tray_state')) as TrayState;
  } catch {
    return null;
  }
}
