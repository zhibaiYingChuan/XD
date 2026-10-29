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
  | {
      kind: 'unavailable';
      reason: string;
      /**
       * 手动下载页（P1-9）。
       *
       * ★ 国内网络直连 GitHub 常常失败。此时只把 reqwest 的原文
       *   （`error sending request for url (...)`）抛给用户，
       *   等于告诉他一件事，却不告诉他能做什么。
       *   有它就渲染「打开下载页」按钮，让用户一步走下去。
       */
      downloadUrl?: string;
    }
  | { kind: 'latest'; current: string }
  | {
      kind: 'available';
      current: string;
      version: string;
      notes: string;
      /** 下载并安装；完成后自动重启应用 */
      install: (onProgress?: (percent: number) => void) => Promise<void>;
    };

/** 「发现新版本」的载荷。弹窗与设置页共用同一个类型，避免两处字段漂移。 */
export type AvailableUpdate = Extract<UpdateCheck, { kind: 'available' }>;

/** 下载安装的「无进展」上限：超过这段时间没有任何进度事件就报错退出等待。 */
const UPDATE_STALL_TIMEOUT_MS = 120_000;

/**
 * 检查更新的**硬超时**（P1-9）。
 *
 * ★ 为什么必须有：`check()` 直连 GitHub 的 latest.json。国内网络下
 *   常见的是「连上了但永远不回」或 DNS 卡住 —— reqwest 的默认超时
 *   不是没有就是不覆盖整条链路。结果就是点「检查更新」后按钮一直转，
 *   用户既不知道要等多久，也不知道能不能重试。
 *   15 秒足够一次正常往返，超过就当作「连不上」，给可执行的下一步。
 */
const UPDATE_CHECK_TIMEOUT_MS = 15_000;

/** 手动下载页：与 README / tauri.conf.json 的更新端点同一仓库。 */
export const DOWNLOAD_PAGE_URL =
  'https://github.com/zhibaiYingChuan/XD/releases/latest';

/** 把底层网络错误翻译成「用户能照做」的一句话。 */
function describeCheckFailure(e: unknown): string {
  const raw = e instanceof Error ? e.message : String(e);
  // reqwest / fetch 的网络层失败关键词（不同平台措辞不同，全部收下）
  const looksNetworky = /timeout|timed out|超时|request|connect|dns|network|sending|resolve|tls|ssl|proxy/i
    .test(raw);
  if (looksNetworky) {
    return (
      '无法连接 GitHub（常见于国内网络，直连 github.com 会被阻断或超时）。'
      + `请手动下载：${DOWNLOAD_PAGE_URL}`
    );
  }
  return raw;
}

/** 给一个 Promise 加硬超时（超时即 reject，不依赖底层是否响应）。 */
async function withTimeout<T>(
  work: Promise<T>,
  ms: number,
  message: string,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(message)), ms);
  });
  try {
    return await Promise.race([work, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/** 检查更新。不会下载任何东西。 */
export async function checkForUpdate(): Promise<UpdateCheck> {
  if (!isTauri()) {
    return {
      kind: 'unavailable',
      reason: '浏览器预览模式不支持自动更新',
      downloadUrl: DOWNLOAD_PAGE_URL,
    };
  }
  try {
    const [{ check }, app] = await Promise.all([
      import('@tauri-apps/plugin-updater'),
      import('@tauri-apps/api/app'),
    ]);
    // ★ P1-9：整条检查（含 import 后的 getVersion 与 check）都在超时之内 ——
    //   任何一段挂住都算「这次检查失败」，不能让按钮永久转圈。
    const result = await withTimeout(
      (async () => {
        const current = await app.getVersion();
        const update = await check();
        return { current, update };
      })(),
      UPDATE_CHECK_TIMEOUT_MS,
      `检查更新超时（${UPDATE_CHECK_TIMEOUT_MS / 1000} 秒无响应）`,
    );
    const { current, update } = result;
    if (!update) return { kind: 'latest', current };

    return {
      kind: 'available',
      current,
      version: update.version,
      notes: update.body ?? '',
      install: async (onProgress) => {
        let total = 0;
        let received = 0;
        // ★ P1-18：下载可能一直不返回（网络半断、CDN 不响应），
        //   此前没有任何超时，界面会永久停在某个百分比且按钮锁死。
        //   这里用一个「无进展看门狗」：每收到一次进度就重新计时，
        //   连续 UPDATE_STALL_TIMEOUT_MS 没有事件即报错退出等待。
        let stallTimer: ReturnType<typeof setTimeout> | null = null;
        let settled = false;
        let abortStall: ((e: Error) => void) | null = null;
        const stall = new Promise<never>((_, reject) => {
          abortStall = reject;
        });
        const armStall = () => {
          if (settled) return;
          if (stallTimer) clearTimeout(stallTimer);
          stallTimer = setTimeout(() => {
            if (settled) return;
            abortStall?.(
              new Error(
                `下载已 ${Math.round(UPDATE_STALL_TIMEOUT_MS / 1000)} 秒没有进展，`
                + '已停止等待。请检查网络后重试（更新包未安装，应用保持当前版本）。',
              ),
            );
          }, UPDATE_STALL_TIMEOUT_MS);
        };
        const stopStall = () => {
          settled = true;
          if (stallTimer) clearTimeout(stallTimer);
          stallTimer = null;
        };
        armStall();
        try {
          await Promise.race([
            update.downloadAndInstall((event) => {
              const e = event as {
                event: string;
                data?: { contentLength?: number; chunkLength?: number };
              };
              armStall();
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
            }),
            stall,
          ]);
          // 安装完成必须重启才能生效。用自家命令而不是 plugin-process ——
          // 后者需要新增 Rust 依赖（本机网络拉不到）。
          const { invoke } = await import('./tauriShim');
          await invoke('restart_app');
        } finally {
          stopStall();
        }
      },
    };
  } catch (e) {
    // ★ P1-9：不把 reqwest / fetch 的原文直接甩给用户 ——
    //   一句 `error sending request for url (...)` 既不是中文，
    //   也没有告诉他接下来能做什么。
    return {
      kind: 'unavailable',
      reason: describeCheckFailure(e),
      downloadUrl: DOWNLOAD_PAGE_URL,
    };
  }
}

// ══════════════════════════════════════════════════════════════
// 自动提示更新的本地状态（纯本地，不联网、不上报）
// ══════════════════════════════════════════════════════════════

const UPDATE_PREFS_KEY = 'xuandun-update-prefs';

/** 两次自动检查的最小间隔：一天一次足够，再多就是骚扰。 */
const AUTO_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;

type UpdatePrefs = {
  /** 上次自动检查的时间戳（毫秒） */
  lastCheckAt: number;
  /** 用户明确「跳过这个版本」的版本号 */
  skipped: string[];
};

function readPrefs(): UpdatePrefs {
  const empty: UpdatePrefs = { lastCheckAt: 0, skipped: [] };
  try {
    const raw = localStorage.getItem(UPDATE_PREFS_KEY);
    if (!raw) return empty;
    const parsed = JSON.parse(raw) as Partial<UpdatePrefs>;
    return {
      lastCheckAt: Number(parsed.lastCheckAt) || 0,
      skipped: Array.isArray(parsed.skipped)
        ? parsed.skipped.filter((v): v is string => typeof v === 'string')
        : [],
    };
  } catch {
    // 存储损坏时按「从未检查过」处理：多检查一次无害，
    // 返回「刚检查过」会让用户永远收不到更新提示。
    return empty;
  }
}

function writePrefs(p: UpdatePrefs): void {
  try {
    localStorage.setItem(UPDATE_PREFS_KEY, JSON.stringify(p));
  } catch {
    // 存储不可用（隐私模式 / 配额满）时退化为「每次启动都检查」。
    // 宁可多查一次静态 JSON，也不要让更新提示永久消失。
  }
}

/**
 * 启动时是否该做一次自动检查。
 *
 * ★ 这不违反「不做后台轮询」：只在桌面端、且距上次检查超过 24 小时时
 *   检查一次；只 GET 一个静态 latest.json，不带设备标识、不上报任何信息。
 *   失败完全静默 —— 网络不通时不该在启动瞬间弹一个用户无法处理的错误。
 */
export function shouldAutoCheck(now: number = Date.now()): boolean {
  return now - readPrefs().lastCheckAt >= AUTO_CHECK_INTERVAL_MS;
}

/**
 * 记录「刚做过一次自动检查」。
 *
 * ★ 必须连失败一起记：否则网络长期不通时，每次启动都要先卡一次检查超时，
 *   而用户对此毫无感知，只觉得「玄盾启动变慢了」。
 */
export function markAutoChecked(now: number = Date.now()): void {
  writePrefs({ ...readPrefs(), lastCheckAt: now });
}

/** 该版本是否已被用户「跳过」。 */
export function isVersionSkipped(version: string): boolean {
  return readPrefs().skipped.includes(version);
}

/**
 * 「跳过这个版本」。
 *
 * ★ 只影响**启动时的自动提示**；用户在设置页手动点「检查更新」
 *   仍然会看到该版本 —— 那是他主动问的，不该被旧决定挡回去。
 */
export function skipVersion(version: string): void {
  const p = readPrefs();
  if (p.skipped.includes(version)) return;
  // 只留最近 20 个：跳过列表是偏好不是账本，无限增长没有意义。
  writePrefs({ ...p, skipped: [...p.skipped, version].slice(-20) });
}
