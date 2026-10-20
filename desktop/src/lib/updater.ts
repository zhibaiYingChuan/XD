/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   自动更新（Tauri updater）前端封装。

   设计原则：
     ① 只在用户**显式点击**时联网检查，不做后台轮询、不上报任何标识；
     ② 更新包必须通过内置公钥验签，验不过直接失败，不提供「跳过校验」；
     ③ 下载/安装进度如实展示，安装完成后重启应用。

   ★ 为什么要单独一层封装：
    浏览器预览（npm run dev）没有 Tauri IPC，直接 import 插件会在
    模块加载期就抛错，把整个设置页打崩。这里用动态 import + isTauri()
     双重保护，浏览器里只返回「仅桌面版支持」。
*/

import { isTauri } from './tauriShim';

export type UpdateCheck =
  | { kind: 'unavailable'; reason: string }
  | { kind: 'latest'; current: string }
  | {
    kind: 'available';
    current: string;
    version: string;
    notes: string;
    /** 下载并安装；完成后自动重启应用 */
    install: (onProgress?: (percent: number) => void) => Promise<void>;
  };

/** 检查更新。不会下载任何东西。 */
export async function checkForUpdate(): Promise<UpdateCheck> {
  if (!isTauri()) {
    return { kind: 'unavailable', reason: '浏览器预览模式不支持自动更新' };
  }
  try {
    const [{ check }, app] = await Promise.all([
      import('@tauri-apps/plugin-updater'),
      import('@tauri-apps/api/app'),
    ]);
    const current = await app.getVersion();
    const update = await check();
    if (!update) return { kind: 'latest', current };

    return {
      kind: 'available',
      current,
      version: update.version,
      notes: update.body ?? '',
      install: async (onProgress) => {
        let total = 0;
        let received = 0;
        await update.downloadAndInstall((event) => {
          const e = event as {
            event: string;
            data?: { contentLength?: number; chunkLength?: number };
          };
          if (e.event === 'Started') {
            total = e.data?.contentLength ?? 0;
          } else if (e.event === 'Progress') {
            received += e.data?.chunkLength ?? 0;
            if (total > 0) {
              // 留 1% 给「安装中」，避免停在 100% 却还没装完
              onProgress?.(Math.min(99, Math.round((received / total) * 100)));
            }
          } else if (e.event === 'Finished') {
            onProgress?.(100);
          }
        });
        // 安装完成必须重启才能生效。用自家命令而不是 plugin-process ——
        // 后者需要新增 Rust 依赖（本机网络拉不到）。
        const { invoke } = await import('./tauriShim');
        await invoke('restart_app');
      },
    };
  } catch (e) {
    return {
      kind: 'unavailable',
      reason: e instanceof Error ? e.message : String(e),
    };
  }
}
