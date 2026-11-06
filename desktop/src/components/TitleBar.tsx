/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   自绘标题栏。

   为什么不用系统标题栏
   ────────────────────────────────────────────────────────────
   系统标题栏由 Windows 主题绘制：浅色主题下是白底黑字，
   与产品的深色朱砂体系完全割裂；标题字体、图标间距、按钮尺寸
   也都由系统决定，改不了。产品级视觉必须从窗口最外沿开始统一。

   因此 tauri.conf.json 里设 decorations: false，由本组件接管：
     · 左侧品牌区（与侧栏同宽，视觉上连成一条竖线）
     · 中间拖拽区（data-tauri-drag-region，双击最大化由 Tauri 处理）
     · 右侧最小化 / 最大化 / 关闭

   浏览器开发模式（npm run dev）下没有窗口可控制，
   按钮点击静默无效，不报错 —— 否则纯前端预览会被一堆异常打断。
*/

import { useEffect, useState } from 'react';
import { Minus, Square, Copy, X } from 'lucide-react';
import { BrandMark } from './BrandMark';
import { isTauri } from '../lib/tauriShim';

async function currentWindow() {
  const mod = await import('@tauri-apps/api/window');
  return mod.getCurrentWindow();
}

export function TitleBar() {
  const [maximized, setMaximized] = useState(false);

  useEffect(() => {
    if (!isTauri()) return;
    let unlisten: (() => void) | undefined;
    let disposed = false;

    void (async () => {
      try {
        const w = await currentWindow();
        const sync = async () => {
          if (!disposed) setMaximized(await w.isMaximized());
        };
        await sync();
        unlisten = await w.onResized(() => void sync());
      } catch {
        // 窗口 API 不可用（浏览器预览）时保持默认图标，不影响渲染
      }
    })();

    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  const act = (fn: (w: Awaited<ReturnType<typeof currentWindow>>) => Promise<void>) => {
    if (!isTauri()) return;
    void currentWindow().then(fn).catch(() => undefined);
  };

  return (
    <header className="titlebar">
      <div className="titlebar-brand" data-tauri-drag-region>
        <BrandMark size={18} />
        <span className="titlebar-title">玄盾</span>
        <span className="titlebar-sub">个人版</span>
      </div>

      {/* 拖拽区：双击最大化由 Tauri 的 drag-region 处理 */}
      <div className="titlebar-drag" data-tauri-drag-region />

      <div className="titlebar-controls">
        <button
          type="button"
          className="titlebar-btn"
          title="最小化"
          aria-label="最小化"
          onClick={() => act((w) => w.minimize())}
        >
          <Minus size={14} strokeWidth={1.5} />
        </button>
        <button
          type="button"
          className="titlebar-btn"
          title={maximized ? '还原' : '最大化'}
          aria-label={maximized ? '还原' : '最大化'}
          onClick={() => act((w) => w.toggleMaximize())}
        >
          {maximized ? (
            <Copy size={12} strokeWidth={1.5} />
          ) : (
            <Square size={12} strokeWidth={1.5} />
          )}
        </button>
        <button
          type="button"
          className="titlebar-btn close"
          title="关闭"
          aria-label="关闭"
          onClick={() => act((w) => w.close())}
        >
          <X size={15} strokeWidth={1.5} />
        </button>
      </div>
    </header>
  );
}
