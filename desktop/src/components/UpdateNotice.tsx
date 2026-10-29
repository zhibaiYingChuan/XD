/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   启动时的更新提示弹窗。

   ★ 为什么需要它
   ────────────────────────────────────────────────────────────
   在此之前，「有没有新版本」只有用户主动点进
   设置 → 检查更新 才会知道。绝大多数人不会点 —— 于是修好的问题
   一直留在他们机器上，而发布页那边显示「已修复」。

   这里补上主动提示，但把「主动」限制在最克制的形态：
     · 一天最多查一次，只在启动后 4 秒查一次，不轮询、不上报；
     · 只在新版本确实存在时弹窗；检查失败完全静默（不打扰）；
     · 用户可以说「以后再说」（本次不再弹）、「跳过这个版本」（该版本不再自动弹）；
     · 更新内容必须是**人话条目**，不是 Markdown 原文堆给用户看。
*/

import { useCallback, useEffect, useRef, useState } from 'react';
import { Download, ExternalLink, Sparkles } from 'lucide-react';

import { isTauri, openExternal } from '../lib/tauriShim';
import {
  DOWNLOAD_PAGE_URL,
  checkForUpdate,
  isVersionSkipped,
  markAutoChecked,
  shouldAutoCheck,
  skipVersion,
  type AvailableUpdate,
} from '../lib/updater';
import { FALLBACK_NOTE, parseUpdateNotes } from '../lib/updateNotes';

/** 启动后延迟多久检查：先让界面渲染完，不要和首屏抢网络与 CPU。 */
const AUTO_CHECK_DELAY_MS = 4_000;

export default function UpdateNotice() {
  const [info, setInfo] = useState<AvailableUpdate | null>(null);
  const [visible, setVisible] = useState(false);
  const [busy, setBusy] = useState(false);
  const [pct, setPct] = useState(0);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const aliveRef = useRef(true);

  // ── 启动时静默检查一次 ────────────────────────────────────
  useEffect(() => {
    aliveRef.current = true;
    if (!isTauri() || !shouldAutoCheck()) {
      return () => {
        aliveRef.current = false;
      };
    }
    const timer = setTimeout(() => {
      void (async () => {
        const result = await checkForUpdate();
        if (!aliveRef.current) return;
        // ★ 先记账再判结果：失败也要记，否则网络长期不通时
        //   每次启动都要先卡一次检查超时，用户只感觉「启动变慢了」。
        markAutoChecked();
        if (result.kind === 'available' && !isVersionSkipped(result.version)) {
          setInfo(result);
          setVisible(true);
        }
      })();
    }, AUTO_CHECK_DELAY_MS);
    return () => {
      aliveRef.current = false;
      clearTimeout(timer);
    };
  }, []);

  // ── Esc 关闭（仅非安装中）────────────────────────────────
  useEffect(() => {
    if (!visible || busy) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setVisible(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [visible, busy]);

  const handleLater = useCallback(() => {
    if (busy) return;
    // 「以后再说」只关这一次：下次启动仍会提示（一天最多一次）。
    setVisible(false);
  }, [busy]);

  const handleSkip = useCallback(() => {
    if (busy || !info) return;
    skipVersion(info.version);
    setVisible(false);
  }, [busy, info]);

  const handleInstall = useCallback(async () => {
    if (!info || busy || done) return;
    setBusy(true);
    setError(null);
    setPct(0);
    try {
      await info.install((p) => {
        if (aliveRef.current) setPct(p);
      });
      // 安装成功后由 updater 触发重启；这里先把按钮锁住，
      // 否则重启前的那一瞬间用户会看到「立即更新」又可以点。
      if (aliveRef.current) setDone(true);
    } catch (e) {
      if (aliveRef.current) {
        setError(e instanceof Error ? e.message : String(e));
      }
    } finally {
      if (aliveRef.current) setBusy(false);
    }
  }, [info, busy, done]);

  if (!visible || !info) return null;

  const notes = parseUpdateNotes(info.notes);
  const items = notes.length > 0 ? notes : [FALLBACK_NOTE];

  return (
    <div
      className="modal-overlay"
      role="presentation"
      onClick={() => {
        if (!busy) setVisible(false);
      }}
    >
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="xd-update-title"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-title" id="xd-update-title">
          <Sparkles size={18} strokeWidth={1.6} />
          有新版本 v{info.version}
        </div>
        <div className="modal-text">
          你现在用的是 v{info.current}。这一版改了什么：
        </div>

        <ul className="modal-notes">
          {items.map((text, i) => (
            <li key={i}>{text}</li>
          ))}
        </ul>

        <div className="field-hint">
          更新包会用内置公钥验签，验不过不会安装；安装完成后应用自动重启。
        </div>

        {busy && (
          <div className="update-progress">
            <div className="update-progress-bar" style={{ width: `${pct}%` }} />
            <span className="update-progress-text">
              {done ? '安装完成，正在重启…' : `正在下载并安装 ${pct}%`}
            </span>
          </div>
        )}

        {error && (
          <div className="alert danger" style={{ marginTop: 12 }}>
            更新没有完成：{error}
            <div className="mt-8">
              你可以稍后再试，或手动下载：
              <button
                className="btn ghost"
                style={{ marginLeft: 8 }}
                onClick={() => void openExternal(DOWNLOAD_PAGE_URL)}
              >
                <ExternalLink size={14} strokeWidth={1.5} />
                打开下载页
              </button>
            </div>
          </div>
        )}

        <div className="modal-actions mt-16">
          <button className="btn ghost" onClick={handleSkip} disabled={busy}>
            跳过这个版本
          </button>
          <button className="btn secondary" onClick={handleLater} disabled={busy}>
            以后再说
          </button>
          <button className="btn" onClick={() => void handleInstall()} disabled={busy || done}>
            <Download size={14} strokeWidth={1.5} />
            {done ? '正在重启…' : busy ? `更新中 ${pct}%` : '立即更新'}
          </button>
        </div>
      </div>
    </div>
  );
}
