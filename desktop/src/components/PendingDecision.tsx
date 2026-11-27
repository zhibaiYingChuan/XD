/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   高危拦截的人工裁决弹窗。

   ★ 为什么需要它
   ────────────────────────────────────────────────────────────
   在此之前，高危拦截只有「直接拦下」一条路：用户正干到一半的任务
   被硬生生打断，明知是误报也只能事后去日志里标记。
   引擎现在会在阻断前把请求挂起最多 45 秒，这里把这个「选择」
   真正交给用户：拦截 / 仅本次允许 / 始终允许。

   ★ 轮询就是心跳
   引擎按 /api/pending 的轮询时间判断桌面端是否在场：超过 10 秒
   没有任何轮询（例如用户只用 CLI、没开桌面端），就不再等待，
   直接按原逻辑阻断 —— 不能让命令行里的请求白等 45 秒。
*/

import { useCallback, useEffect, useRef, useState } from 'react';
import { ShieldAlert } from 'lucide-react';

import { api } from '../services/api';
import type { PendingDecision as Decision, PendingItem } from '../services/api';
import { useI18n } from '../i18n';

/** 轮询间隔。必须明显小于引擎的 10 秒无人值守宽限期。 */
const POLL_MS = 1500;

export default function PendingDecision() {
  const { t } = useI18n();
  const [items, setItems] = useState<PendingItem[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // 倒计时每秒刷新一次（不依赖轮询节奏）
  const [, setTick] = useState(0);
  const busyRef = useRef(false);
  // 已裁决的 id：裁决后引擎要等下一轮轮询（最多 0.2s）才移除该项，
  // 期间在途的轮询响应可能把它又带回来 —— 用本地集合挡住这次回闪。
  const decidedRef = useRef<Set<string>>(new Set());

  // 轮询：用 setTimeout 链而不是 setInterval ——
  // 上一次还没回来时不会叠出第二个请求。
  useEffect(() => {
    let alive = true;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const res = await api.listPending();
        if (!alive) return;
        setItems(
          (res.items || []).filter((x) => !decidedRef.current.has(x.id)),
        );
        setError(null);
      } catch {
        // 引擎未就绪 / 重启中：静默，下一轮再试。
        // ★ 不能在这里清空 items：一次网络抖动不该让正在等待的弹窗消失。
      }
      if (alive) timer = window.setTimeout(poll, POLL_MS);
    };
    void poll();
    return () => {
      alive = false;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, []);

  const open = items.length > 0;
  useEffect(() => {
    if (!open) return;
    const id = window.setInterval(() => setTick((n) => n + 1), 1000);
    return () => window.clearInterval(id);
  }, [open]);

  const decide = useCallback(
    async (decision: Decision) => {
      const item = items[0];
      if (!item || busyRef.current) return;
      busyRef.current = true;
      setBusy(true);
      setError(null);
      decidedRef.current.add(item.id);
      try {
        await api.decidePending(item.id, decision);
        setItems((prev) => prev.filter((x) => x.id !== item.id));
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        // 404 = 已超时或已被裁决：引擎那边已经结束了，移出列表即可
        if (msg.includes('超时') || msg.includes('不存在')) {
          setItems((prev) => prev.filter((x) => x.id !== item.id));
        } else {
          // 其它错误（网络抖动 / 引擎重启）：保留这一项让用户重试，
          // 同时解除本地屏蔽，否则轮询会把它永久过滤掉。
          decidedRef.current.delete(item.id);
          setError(msg);
        }
      } finally {
        busyRef.current = false;
        setBusy(false);
      }
    },
    [items],
  );

  if (!open) return null;

  const item = items[0];
  const remain = Math.max(0, Math.ceil(item.expires_at - Date.now() / 1000));
  const extra = items.length - 1;
  const details = (item.findings || []).filter((f) => f.detail).slice(0, 3);

  return (
    <div className="modal-overlay" data-xd-pending="1">
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label={t('高危拦截待确认')}
        style={{ maxWidth: 560 }}
      >
        <div className="modal-title">
          <ShieldAlert size={20} style={{ color: 'var(--xd-danger)' }} />
          {t('检测到高危响应，需要你决定')}
        </div>
        <div className="modal-text" style={{ whiteSpace: 'pre-line' }}>
          {item.summary}
        </div>
        {details.length > 0 && (
          <ul
            style={{
              margin: '0 0 16px',
              paddingLeft: 20,
              color: 'var(--xd-text-dim)',
              fontSize: 13,
              lineHeight: 1.6,
            }}
          >
            {details.map((f, i) => (
              <li key={`${f.category}-${i}`}>{f.detail}</li>
            ))}
          </ul>
        )}
        <div className="field-hint">
          {t('来源')}：{item.domain || t('未知')} · {t('剩余')} {remain}{' '}
          {t('秒，超时将自动拦截')}
          {extra > 0 ? ` · ${t('还有')} ${extra} ${t('项等待处理')}` : ''}
        </div>
        <div className="field-hint" style={{ marginTop: 4 }}>
          {t('「始终允许」会记住这组判据，之后不再询问；可在设置页撤销。')}
        </div>
        {error && (
          <div className="field-hint" style={{ color: 'var(--xd-danger)' }}>
            {error}
          </div>
        )}
        <div className="modal-actions" style={{ marginTop: 18 }}>
          <button
            className="btn danger"
            disabled={busy}
            onClick={() => void decide('deny')}
            data-xd-pending-deny="1"
          >
            {t('拦截这次')}
          </button>
          <button
            className="btn secondary"
            disabled={busy}
            onClick={() => void decide('allow_always')}
            data-xd-pending-always="1"
          >
            {t('始终允许')}
          </button>
          <button
            className="btn primary"
            disabled={busy}
            onClick={() => void decide('allow_once')}
            data-xd-pending-once="1"
          >
            {t('仅本次允许')}
          </button>
        </div>
      </div>
    </div>
  );
}
