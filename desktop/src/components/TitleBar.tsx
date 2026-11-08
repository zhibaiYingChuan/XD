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
import { useToast } from './Toast';
import { useI18n } from '../i18n';

async function currentWindow() {
  const mod = await import('@tauri-apps/api/window');
  return mod.getCurrentWindow();
}

export function TitleBar() {
  const { t } = useI18n();
  const toast = useToast();
  const [maximized, setMaximized] = useState(false);
  const [closing, setClosing] = useState(false);

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
    // ★ 2026-11-09：此前这里把异常整个吞掉，导致「点了没反应」时
    //   既没有界面反馈、也没有任何日志可查。权限缺失（capabilities
    //   未授予 allow-close / allow-minimize / allow-toggle-maximize）
    //   正是这样被藏了整整一个版本。现在至少留下可排查的痕迹。
    void currentWindow().then(fn).catch((e) => {
      console.error('[titlebar] 窗口操作失败：', e);
    });
  };

  /**
   * 关闭窗口 = 隐藏到托盘，防护继续运行。
   *
   * ★ 2026-11-09：Rust 侧 on_window_event 会 prevent_close + hide，
   *   但用户看不到任何解释，会以为「关不掉」。这里先给一句提示，
   *   留 1.2 秒可见时间再隐藏，避免「窗口突然消失、不知道还在跑」。
   */
  const handleClose = () => {
    if (closing) return;
    setClosing(true);
    toast.info(t('已最小化到托盘，防护继续运行；右键托盘图标可退出'));
    window.setTimeout(() => {
      act((w) => w.close());
      // ★ 窗口只是隐藏、组件不会卸载；不复位的话，
      //   从托盘重新打开后关闭按钮会永久失效。
      setClosing(false);
    }, 1200);
  };

  return (
    <header className="titlebar">
      <div className="titlebar-brand" data-tauri-drag-region>
        <BrandMark size={18} />
        <span className="titlebar-title">{t('勘合')}</span>
        <span className="titlebar-sub">{t('个人版')}</span>
      </div>

      {/* 拖拽区：双击最大化由 Tauri 的 drag-region 处理 */}
      <div className="titlebar-drag" data-tauri-drag-region />

      <div className="titlebar-controls">
        <button
          type="button"
          className="titlebar-btn"
          title={t('最小化')}
          aria-label={t('最小化')}
          onClick={() => act((w) => w.minimize())}
        >
          <Minus size={14} strokeWidth={1.5} />
        </button>
        <button
          type="button"
          className="titlebar-btn"
          title={maximized ? t('还原') : t('最大化')}
          aria-label={maximized ? t('还原') : t('最大化')}
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
          title={t('关闭窗口（防护继续在托盘运行）')}
          aria-label={t('关闭')}
          onClick={handleClose}
        >
          <X size={15} strokeWidth={1.5} />
        </button>
      </div>
    </header>
  );
}
