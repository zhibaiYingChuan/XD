/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   首页 — 设计原则：用户打开应用，3 秒内知道"现在安全吗"。

   信息层级：
     ① 英雄区：大字状态 + 今日概览
     ② KPI 三卡：安全 / 可疑 / 危险
     ③ 最近拦截：最近 5 条非安全事件
     ④ 当前中转站：信誉评分
     ⑤ 快速操作：暂停防护 / 打开日志 / 分享诊断
*/

import { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Clock,
  PauseCircle,
  FileText,
  Share2,
  Copy,
  CheckCircle2,
  AlertTriangle,
  Info,
  ChevronDown,
} from 'lucide-react';
import {
  api,
  STATE_LABELS,
  currentProxyPort,
  formatTime,
  actionBadgeClass,
  type StateResponse,
  type LogEntry,
  type RelayReputation,
} from '../services/api';
import { useToast } from '../components/Toast';
import { copyToClipboard } from '../lib/tauriShim';

// ══════════════════════════════════════════════════════════════
// 英雄区图标（按状态）
// ══════════════════════════════════════════════════════════════

const STATE_ICON: Record<string, typeof ShieldCheck> = {
  protecting: ShieldCheck,
  learning: Clock,
  suspect: AlertTriangle,
  danger: ShieldX,
  paused: PauseCircle,
};

const RELAY_LEVEL_TEXT: Record<string, string> = {
  safe: '信誉良好',
  normal: '正常',
  risky: '存在风险',
  malicious: '高危中转站',
};

/**
 * 信誉评分扣分明细（Phase 7）。
 *
 * ★ 权重必须与后端 `_compute_score` 严格一致：
 *   这里是给用户看的「为什么是这个分」，一旦后端调权重而前端没跟上，
 *   界面就会给出一套自相矛盾的解释，比不给解释更糟。
 */
const SCORE_WEIGHTS = {
  danger: 20,
  suspect: 4,
  latencyAnomaly: 8,
  watermark: 10,
  suspiciousPattern: 15,
} as const;

// ══════════════════════════════════════════════════════════════
// 页面
// ══════════════════════════════════════════════════════════════

export default function Dashboard() {
  const toast = useToast();
  const [state, setState] = useState<StateResponse | null>(null);
  const [recent, setRecent] = useState<LogEntry[]>([]);
  const [relays, setRelays] = useState<RelayReputation[]>([]);
  const [currentDomain, setCurrentDomain] = useState<string>('');
  // ★ Phase 7：信誉详情默认收起。首页要在 3 秒内回答「现在安全吗」，
  //   评分明细是用户主动追问时才需要的信息，常开会把首屏挤成表格。
  const [showRepDetail, setShowRepDetail] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const failRef = useRef(0);
  const mountedRef = useRef(true);

  // ★ P2-11 修复所需：当前配置的中转站域名。
  //   /api/relays 按信誉分升序返回（最差在前），直接取 [0]
  //   会把「信誉最差的中转站」当成「当前中转站」展示，语义完全相反。
  useEffect(() => {
    let cancelled = false;
    api
      .getDiagnostics()
      .then((d) => {
        if (!cancelled) setCurrentDomain(d.relay_domain ?? '');
      })
      .catch(() => {
        /* 诊断信息仅用于定位当前中转站，失败则回退到最高分 */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // ── 数据加载（保留上次成功数据，避免闪空）──
  const load = useCallback(async () => {
    try {
      const [s, logs, r] = await Promise.all([
        api.getState(),
        api.getLogs({ limit: 5, action: 'block' }).catch(() => null),
        api.getRelays().catch(() => null),
      ]);
      if (!mountedRef.current) return;
      setState(s);
      setLoadError(null);
      failRef.current = 0;
      if (logs) {
        // 首页只展示非"安全"事件：阻断 + 告警
        const all = await api
          .getLogs({ limit: 8 })
          .then((x) => x.entries.filter((e) => e.action !== 'pass'))
          .catch(() => logs.entries);
        if (mountedRef.current) setRecent(all.slice(0, 5));
      }
      if (r && mountedRef.current) setRelays(r.relays);
    } catch (e) {
      if (!mountedRef.current) return;
      setLoadError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  // ── 轮询（成功 3s，失败指数退避至 30s）──
  useEffect(() => {
    mountedRef.current = true;
    let timer: ReturnType<typeof setTimeout>;

    const schedule = async () => {
      await load();
      if (!mountedRef.current) return;
      const delay =
        loadError === null ? 3000 : Math.min(3000 * 2 ** (failRef.current + 1), 30000);
      if (loadError !== null) failRef.current = Math.min(failRef.current + 1, 3);
      timer = setTimeout(schedule, delay);
    };

    schedule();
    return () => {
      mountedRef.current = false;
      clearTimeout(timer);
    };
  }, [load, loadError]);

  // ── 操作：暂停防护（P1-6：5 / 30 / 永久 三档）──
  const handlePause = async (durationMin: number) => {
    if (busy) return;
    setBusy(true);
    try {
      await api.pause(durationMin);
      toast.info(
        durationMin > 0 ? `防护已暂停 ${durationMin} 分钟` : '防护已永久暂停，直到手动恢复',
      );
      await load();
    } catch (e) {
      toast.error(`暂停失败：${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  const handleResume = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await api.resume();
      toast.success('防护已恢复');
      await load();
    } catch (e) {
      toast.error(`恢复失败：${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  // ── 操作：分享诊断报告（脱敏后复制）──
  const handleShareDiagnostics = async () => {
    if (busy) return;
    setBusy(true);
    try {
      const d = await api.getDiagnostics();
      const report = [
        '道体·玄盾 个人版 — 诊断报告',
        `版本: ${d.version}`,
        // ★ P2-4 修复：原硬编码 127.0.0.1:18765，
        //   用户改过端口后报告会给出错误的排查指引
        `代理端口: ${d.server?.host ?? '127.0.0.1'}:${d.server?.port ?? '-'}`,
        `中转站: ${d.relay_domain || '(未配置)'}`,
        `安全级别: ${d.verifier?.level ?? '-'}`,
        `企业版护栏: ${d.verifier?.guardrail_available ? '已加载' : '未加载'}`,
        `日志总数: ${d.storage?.total_logs ?? 0}`,
        `已知中转站: ${d.reputation?.total_relays ?? 0}`,
        '',
        '（本报告不含任何对话内容与 API 密钥）',
      ].join('\n');
      const ok = await copyToClipboard(report);
      if (ok) toast.success('诊断报告已复制到剪贴板');
      else toast.error('复制失败，请手动截图');
    } catch (e) {
      toast.error(`生成诊断报告失败：${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  // ══════════════════════════════════════════════════════════
  // 渲染
  // ══════════════════════════════════════════════════════════

  if (loadError && !state) {
    return (
      <div>
        <div className="page-header">
          <h1 className="page-title">首页</h1>
        </div>
        <div className="alert danger">
          <ShieldAlert size={17} strokeWidth={1.5} className="alert-icon" />
          <div>
            <b>无法连接本地代理</b>
            <div className="mt-8">{loadError}</div>
            <div className="mt-8 faint">
              请确认玄盾代理已启动（默认 127.0.0.1:{currentProxyPort()}）。
              若尚未配置中转站，请前往「设置」页面完成配置。
            </div>
          </div>
        </div>
        <button className="btn" onClick={() => load()}>
          重试
        </button>
      </div>
    );
  }

  const s = state?.state ?? 'learning';
  const StateIcon = STATE_ICON[s] ?? ShieldCheck;
  const today = state?.today;
  // ★ P2-11 修复：按域名匹配当前配置的中转站；匹配不到时退而取
  //   信誉最高者（relays 按分数升序 → 最后一个），而不是最差的那个。
  const primaryRelay =
    (currentDomain ? relays.find((r) => r.domain === currentDomain) : undefined) ??
    relays[relays.length - 1];
  // ★ P2-11 配套：首日 last_seen - first_seen 不足 1 天，
  //   原 `Math.max(1, ...)` 会向用户谎报「已使用 1 天」
  const usedDays = primaryRelay
    ? Math.floor((primaryRelay.last_seen - primaryRelay.first_seen) / 86400)
    : 0;
  const usedLabel =
    usedDays >= 1
      ? `已使用 ${usedDays} 天`
      : primaryRelay
        ? '今天开始使用'
        : '';

  // ── Phase 7：评分扣分明细 ──
  // 只列出**实际发生**的扣分项。全列出来等于用 0 填充噪声，
  // 用户会以为每项都检测过而误判检测覆盖面。
  const repDeductions = primaryRelay
    ? [
        {
          key: 'malicious',
          label: '命中已知恶意中转站库',
          detail: '信誉直接归零',
          points: primaryRelay.known_malicious ? primaryRelay.score : 0,
          hit: primaryRelay.known_malicious,
        },
        {
          key: 'danger',
          label: '危险响应',
          detail: `${primaryRelay.danger_count} 次 × ${SCORE_WEIGHTS.danger} 分`,
          points: primaryRelay.danger_count * SCORE_WEIGHTS.danger,
          hit: primaryRelay.danger_count > 0,
        },
        {
          key: 'suspect',
          label: '可疑响应',
          detail: `${primaryRelay.suspect_count} 次 × ${SCORE_WEIGHTS.suspect} 分`,
          points: primaryRelay.suspect_count * SCORE_WEIGHTS.suspect,
          hit: primaryRelay.suspect_count > 0,
        },
        {
          key: 'latency',
          label: '响应延迟突变',
          detail: `${primaryRelay.latency_anomalies ?? 0} 次 × ${SCORE_WEIGHTS.latencyAnomaly} 分（条件触发型攻击信号）`,
          points: (primaryRelay.latency_anomalies ?? 0) * SCORE_WEIGHTS.latencyAnomaly,
          hit: (primaryRelay.latency_anomalies ?? 0) > 0,
        },
        {
          key: 'watermark',
          label: '数据保留迹象',
          detail: `响应中出现中转站自述留存 · ${SCORE_WEIGHTS.watermark} 分`,
          points: primaryRelay.watermark_detected ? SCORE_WEIGHTS.watermark : 0,
          hit: primaryRelay.watermark_detected,
        },
        {
          key: 'pattern',
          label: '域名高风险模式',
          detail: `免费顶级域名等滥用高发特征 · ${SCORE_WEIGHTS.suspiciousPattern} 分`,
          points: primaryRelay.notes.some((n) => n.startsWith('高风险模式'))
            ? SCORE_WEIGHTS.suspiciousPattern
            : 0,
          hit: primaryRelay.notes.some((n) => n.startsWith('高风险模式')),
        },
      ].filter((d) => d.hit)
    : [];

  return (
    <div>
      {/* ① 英雄区 */}
      <div className="card hero">
        <div className={`hero-state ${s}`}>{STATE_LABELS[s]}</div>
        <div className="hero-message">{state?.message ?? '正在获取状态...'}</div>

        {today && (
          <div className="kpi-row" style={{ maxWidth: 460, margin: '0 auto' }}>
            <div className="kpi">
              <div className="kpi-value safe">{today.safe_count}</div>
              <div className="kpi-label">安全</div>
            </div>
            <div className="kpi">
              <div className="kpi-value suspect">{today.suspect_count}</div>
              <div className="kpi-label">可疑</div>
            </div>
            <div className="kpi">
              <div className="kpi-value danger">{today.danger_count}</div>
              <div className="kpi-label">危险</div>
            </div>
          </div>
        )}
      </div>

      {/* ② 最近拦截 */}
      <div className="card">
        <div className="card-title">
          <span>最近拦截</span>
          <Link to="/logs" className="btn ghost sm">
            查看全部
            <span style={{ transform: 'translateX(1px)' }}>→</span>
          </Link>
        </div>

        {recent.length === 0 ? (
          <div className="empty">
            <div className="empty-icon">
              <CheckCircle2 size={34} strokeWidth={1.5} />
            </div>
            <div className="empty-text">
              {today && today.total_calls > 0
                ? '今天还没有发现可疑响应，你的 AI 对话很安全'
                : '还没有检测记录 — 使用 AI 工具发起一次对话试试'}
            </div>
          </div>
        ) : (
          <div className="list">
            {recent.map((entry) => (
              <div key={entry.id} className="list-item">
                <span className={`list-icon ${actionBadgeClass(entry)}`}>
                  {entry.action === 'block' ? (
                    <ShieldX size={14} strokeWidth={1.5} />
                  ) : entry.severity === 'medium' ? (
                    <AlertTriangle size={14} strokeWidth={1.5} />
                  ) : (
                    <Info size={14} strokeWidth={1.5} />
                  )}
                </span>
                <span className="list-time">{formatTime(entry.timestamp)}</span>
                <span className="list-text" title={entry.summary}>
                  {entry.summary}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ③ 当前中转站 */}
      <div className="card">
        <div className="card-title">当前中转站</div>
        {primaryRelay ? (
          <>
            <div className="flex items-center justify-between gap-12">
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 15, fontWeight: 500 }}>{primaryRelay.domain}</div>
                <div className="faint" style={{ fontSize: 12, marginTop: 2 }}>
                  {usedLabel}
                  {usedLabel && ' · '}
                  {primaryRelay.total_calls} 次调用
                  {primaryRelay.danger_count > 0 && (
                    <>
                      {' · '}
                      <span style={{ color: 'var(--xd-danger)' }}>
                        {primaryRelay.danger_count} 次危险
                      </span>
                    </>
                  )}
                  {primaryRelay.watermark_detected && (
                    <>
                      {' · '}
                      <span style={{ color: 'var(--xd-suspect)' }}>检测到数据保留迹象</span>
                    </>
                  )}
                </div>
              </div>
              <div style={{ textAlign: 'right', flexShrink: 0 }}>
                <div className={`rep-score ${primaryRelay.level}`}>
                  {primaryRelay.score}
                  <span style={{ fontSize: 13, fontWeight: 400 }}>/100</span>
                </div>
                <div className="faint" style={{ fontSize: 11 }}>
                  {RELAY_LEVEL_TEXT[primaryRelay.level]}
                </div>
              </div>
            </div>

          {/* Phase 7：评分明细展开 */}
          <div className="mt-16">
            <button
              className="btn ghost sm"
              onClick={() => setShowRepDetail((v) => !v)}
              aria-expanded={showRepDetail}
            >
              <ChevronDown
                size={14}
                strokeWidth={1.5}
                style={{
                  transform: showRepDetail ? 'rotate(180deg)' : 'none',
                  transition: 'transform .15s ease',
                }}
              />
              {showRepDetail ? '收起评分明细' : '为什么是这个分数？'}
            </button>

            {showRepDetail && (
              <div className="rep-detail mt-12">
                {repDeductions.length === 0 ? (
                  <div className="faint" style={{ fontSize: 12, lineHeight: 1.7 }}>
                    本次使用未触发任何扣分项 —
                    没有危险或可疑响应、没有检测到数据保留迹象，域名也不在风险特征库中。
                  </div>
                ) : (
                  <>
                    <div className="table" style={{ marginBottom: 12 }}>
                      <div className="rep-row rep-row-head">
                        <span>扣分项</span>
                        <span className="faint">依据</span>
                        <span style={{ textAlign: 'right' }}>扣分</span>
                      </div>
                      {repDeductions.map((d) => (
                        <div key={d.key} className="rep-row">
                          <span>{d.label}</span>
                          <span className="faint">{d.detail}</span>
                          <span style={{ textAlign: 'right', color: 'var(--xd-danger)' }}>
                            −{d.points}
                          </span>
                        </div>
                      ))}
                      <div className="rep-row rep-row-total">
                        <span>当前信誉分</span>
                        <span className="faint">满分 100</span>
                        <span style={{ textAlign: 'right' }}>{primaryRelay.score}</span>
                      </div>
                    </div>

                    {primaryRelay.notes.length > 0 && (
                      <div className="faint" style={{ fontSize: 12, lineHeight: 1.7 }}>
                        证据：
                        {primaryRelay.notes.map((n) => (
                          <div key={n}>· {n}</div>
                        ))}
                      </div>
                    )}

                    <div className="faint" style={{ fontSize: 12, lineHeight: 1.7, marginTop: 8 }}>
                      平均响应延迟{' '}
                      <span className="mono">
                        {primaryRelay.latency_samples > 0
                          ? `${Math.round(primaryRelay.avg_latency_ms)} ms`
                          : '暂无样本'}
                      </span>
                      （{primaryRelay.latency_samples} 次采样）
                    </div>
                  </>
                )}
              </div>
            )}
          </div>
          </>
        ) : (
          <div className="empty" style={{ padding: '24px 20px' }}>
            <div className="empty-icon">
              <Info size={30} strokeWidth={1.5} />
            </div>
            <div className="empty-text">
              尚未配置中转站
              <div className="mt-8">
                <Link to="/settings" className="btn sm">
                  前往设置
                </Link>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ④ 快速操作 */}
      <div className="card">
        <div className="card-title">快速操作</div>
        <div className="btn-row">
          {s === 'paused' ? (
            <button className="btn" onClick={handleResume} disabled={busy}>
              <ShieldCheck size={15} strokeWidth={1.5} />
              恢复防护
            </button>
          ) : (
            <>
              <button className="btn secondary" onClick={() => handlePause(5)} disabled={busy}>
                <PauseCircle size={15} strokeWidth={1.5} />
                暂停 5 分钟
              </button>
              <button className="btn secondary" onClick={() => handlePause(30)} disabled={busy}>
                <PauseCircle size={15} strokeWidth={1.5} />
                暂停 30 分钟
              </button>
              <button className="btn secondary" onClick={() => handlePause(0)} disabled={busy}>
                <PauseCircle size={15} strokeWidth={1.5} />
                永久暂停
              </button>
            </>
          )}
          <Link to="/logs" className="btn secondary">
            <FileText size={15} strokeWidth={1.5} />
            打开日志
          </Link>
          <button className="btn secondary" onClick={handleShareDiagnostics} disabled={busy}>
            <Share2 size={15} strokeWidth={1.5} />
            分享诊断报告
          </button>
        </div>
        {s === 'paused' && (
          <div className="alert suspect mt-16" style={{ marginBottom: 0 }}>
            <PauseCircle size={17} strokeWidth={1.5} className="alert-icon" />
            <div>
              防护已暂停，你的 AI 对话当前<b>不受任何检测保护</b>。
              中转站可以自由篡改返回内容、截留你的数据。
            </div>
          </div>
        )}
      </div>

      {/* 状态图标引用（避免未使用告警，同时用于语义化留档） */}
      <span hidden aria-hidden>
        <StateIcon size={1} />
        <Copy size={1} />
      </span>
    </div>
  );
}
