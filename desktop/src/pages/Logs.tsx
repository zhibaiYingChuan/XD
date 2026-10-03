/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   日志页 — 设计原则：用户想知道"我的数据被谁看过、被改过没有"。

   功能：
     ① 搜索（防抖 300ms）+ 类型/结果筛选
     ② 分页列表
     ③ 点击行 → 右侧详情抽屉（触发规则 / 原始片段 / 脱敏记录）
*/

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Search,
  ShieldX,
  AlertTriangle,
  Eye,
  Info,
  CheckCircle2,
  X,
  Trash2,
  Copy,
  Check,
  Download,
  ShieldOff,
  ShieldCheck,
  Filter,
} from 'lucide-react';
import {
  api,
  ACTION_LABELS,
  LOG_TYPE_LABELS,
  CATEGORY_LABELS,
  findingExplanation,
  formatDateTime,
  actionBadgeClass,
  type LogEntry,
  type LogDetail,
  type LogBreakdown,
  type LogFilterParams,
  type LogType,
} from '../services/api';
import { useToast } from '../components/Toast';
import { copyToClipboard, downloadText } from '../lib/tauriShim';

const PAGE_SIZE = 20;
const SEARCH_DEBOUNCE = 300;

const TYPE_OPTIONS = [
  { value: '', label: '全部类型' },
  { value: 'response_verify', label: '响应验证' },
  { value: 'request_sanitize', label: '请求脱敏' },
  { value: 'proxy_error', label: '代理错误' },
  { value: 'relay', label: '正常转发' },
];

const ACTION_OPTIONS = [
  { value: '', label: '全部结果' },
  { value: 'block', label: '已拦截' },
  { value: 'alert', label: '已告警' },
  { value: 'redact', label: '已打码' },
  { value: 'pass', label: '安全' },
];

// 时间范围（产品文档 4.3 线框图中的「今天▾」）
const TIME_OPTIONS = [
  { value: '', label: '全部时间' },
  { value: '1', label: '今天' },
  { value: '7', label: '近 7 天' },
  { value: '30', label: '近 30 天' },
];

// ★ 只看误报（2026-10-03）
//   三档而非两档：用户既想清掉「已确认误报」，也想排除它们看剩下的。
//   两档的话，「不看误报」只能靠逐条取消，954 条里若有 40 条误报就是 40 次操作。
const MARKED_OPTIONS = [
  { value: '', label: '全部记录' },
  { value: 'only', label: '仅看误报' },
  { value: 'exclude', label: '排除误报' },
];

// ══════════════════════════════════════════════════════════════
// 详情抽屉
// ══════════════════════════════════════════════════════════════

function DetailDrawer({
  logId,
  onClose,
  onDeleted,
  onMarkedSafe,
}: {
  logId: number;
  onClose: () => void;
  onDeleted: () => void;
  onMarkedSafe: () => void;
}) {
  const toast = useToast();
  const [detail, setDetail] = useState<LogDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);
  const [marking, setMarking] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const d = await api.getLogDetail(logId);
        if (!cancelled) setDetail(d);
      } catch (e) {
        if (!cancelled) {
          toast.error(`加载详情失败：${e instanceof Error ? e.message : String(e)}`);
          onClose();
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [logId, onClose, toast]);

  // ESC 关闭
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const findings = useMemo(() => {
    if (!detail) return [];
    try {
      const parsed = JSON.parse(detail.entry.detail_json);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }, [detail]);

  const handleCopy = async () => {
    if (!detail) return;
    const text = [
      `时间: ${formatDateTime(detail.entry.timestamp)}`,
      `类型: ${LOG_TYPE_LABELS[detail.entry.log_type]}`,
      `中转站: ${detail.entry.relay_domain}`,
      `结果: ${ACTION_LABELS[detail.entry.action]}`,
      `摘要: ${detail.entry.summary}`,
      '',
      ...findings.map((f: { detail?: string }, i: number) => `${i + 1}. ${f.detail ?? ''}`),
    ].join('\n');
    const ok = await copyToClipboard(text);
    if (ok) {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } else {
      toast.error('复制失败');
    }
  };

  const handleMarkSafe = async () => {
    if (marking) return;
    setMarking(true);
    try {
      await api.markLogSafe(logId);
      toast.success('已标记为误报，今日「危险/可疑」计数已减去这一条');
      onMarkedSafe();
      onClose();
    } catch (e) {
      toast.error(`标记失败：${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setMarking(false);
    }
  };

  const handleUnmarkSafe = async () => {
    if (marking) return;
    setMarking(true);
    try {
      await api.unmarkLogSafe(logId);
      toast.success('已撤销标记，计数已加回');
      onMarkedSafe();
      onClose();
    } catch (e) {
      toast.error(`撤销失败：${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setMarking(false);
    }
  };

  const handleDelete = async () => {
    try {
      await api.deleteLog(logId);
      toast.success('日志已删除');
      onDeleted();
      onClose();
    } catch (e) {
      toast.error(`删除失败：${e instanceof Error ? e.message : String(e)}`);
    }
  };

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="日志详情">
        <div className="drawer-header">
          <span className="drawer-title">日志详情</span>
          <button className="btn ghost" onClick={onClose} aria-label="关闭">
            <X size={16} strokeWidth={1.5} />
          </button>
        </div>

        <div className="drawer-body">
          {loading || !detail ? (
            <div className="loading">
              <span className="spinner" />
              加载中...
            </div>
          ) : (
            <>
              <div className="detail-row">
                <span className="detail-key">时间</span>
                <span className="detail-val mono">{formatDateTime(detail.entry.timestamp)}</span>
              </div>
              <div className="detail-row">
                <span className="detail-key">类型</span>
                <span className="detail-val">{LOG_TYPE_LABELS[detail.entry.log_type]}</span>
              </div>
              <div className="detail-row">
                <span className="detail-key">中转站</span>
                <span className="detail-val mono">{detail.entry.relay_domain || '—'}</span>
              </div>
              <div className="detail-row">
                <span className="detail-key">结果</span>
                <span className="detail-val">
                  <span className={`badge ${actionBadgeClass(detail.entry)}`}>
                    {ACTION_LABELS[detail.entry.action]}
                  </span>
                </span>
              </div>
              {detail.entry.model && (
                <div className="detail-row">
                  <span className="detail-key">模型</span>
                  <span className="detail-val mono">{detail.entry.model}</span>
                </div>
              )}

              {detail.entry.marked_safe && (
                <div className="alert safe mt-16" style={{ marginBottom: 0 }}>
                  <CheckCircle2 size={17} strokeWidth={1.5} className="alert-icon" />
                  <div>你已将此条标记为<b>误报</b>，今日「危险/可疑」计数已减去这一条。</div>
                </div>
              )}

              {findings.length > 0 && (
                <div className="mt-24">
                  {/* ★ 标题从「触发规则」改为「发现了什么」。
                      「规则」是实现视角；用户关心的是「出了什么事」。
                      统计类命中额外标出「不影响使用」——
                      否则用户看到红色就以为防护坏了。 */}
                  <div className="field-label">发现了什么</div>
                  {findings.map((f: { category?: string; detail?: string; severity?: string; evidence?: string }, i: number) => {
                    const explain = findingExplanation(f.category);
                    const advisory = f.category === 'length_anomaly'
                      || f.category === 'structure_anomaly';
                    return (
                    <div key={i} className="detail-row" style={{ alignItems: 'flex-start' }}>
                      <span className="detail-key" style={{ paddingTop: 1 }}>
                        <span
                          className="badge"
                          style={{
                            background:
                              f.severity === 'high'
                                ? 'var(--xd-danger-dim)'
                                : f.severity === 'medium'
                                  ? 'var(--xd-suspect-dim)'
                                  : 'var(--xd-paused-dim)',
                            color:
                              f.severity === 'high'
                                ? 'var(--xd-danger)'
                                : f.severity === 'medium'
                                  ? 'var(--xd-suspect)'
                                  : 'var(--xd-text-dim)',
                          }}
                        >
                          {f.severity === 'high' ? '高危' : f.severity === 'medium' ? '中危' : '低危'}
                        </span>
                      </span>
                      <span className="detail-val">
                        {/* 先说人话，再给技术细节。
                            ★ 技术 detail 收进 <details>：直接摊在页面上
                              「偏离历史均值 1742 达 124.0σ」会让人以为在报故障，
                              而用户判断「是不是我自己的问题」只需要第一句话。 */}
                        <div style={{ fontWeight: explain ? 500 : undefined }}>
                          {explain ? explain.title : f.detail}
                        </div>
                        {explain && (
                          <div className="faint" style={{ fontSize: 12, marginTop: 2, lineHeight: 1.7 }}>
                            {explain.meaning}
                          </div>
                        )}
                        {advisory && (
                          <div
                            className="faint"
                            style={{ fontSize: 11, marginTop: 2, color: 'var(--xd-text-dim)' }}
                          >
                            这类检查只作记录，不会拦下你的对话。
                          </div>
                        )}
                        {/* 掩码后的命中片段：给愿意核对的人看，不给不愿看的人添堵 */}
                        {f.evidence && (
                          <details style={{ marginTop: 4 }}>
                            <summary
                              className="faint"
                              style={{ fontSize: 11, cursor: 'pointer', listStyle: 'none' }}
                            >
                              查看技术细节
                            </summary>
                            <div className="mono faint" style={{ fontSize: 11, marginTop: 2 }}>
                              {f.detail}
                            </div>
                            <div className="mono faint" style={{ fontSize: 11 }}>
                              片段：{f.evidence}
                            </div>
                          </details>
                        )}
                      </span>
                    </div>
                    );
                  })}
                </div>
              )}

              {detail.entry.text_preview && (
                <div className="mt-24">
                  <div className="field-label">内容片段</div>
                  <div className="code-block">{detail.entry.text_preview}</div>
                </div>
              )}

              {detail.redactions.length > 0 && (
                <div className="mt-24">
                  <div className="field-label">
                    {detail.entry.action === 'block'
                      ? `拦截依据（${detail.redactions.length} 处）`
                      : `脱敏记录（${detail.redactions.length} 处）`}
                  </div>
                  {detail.redactions.map((r) => (
                    <div key={r.id} className="detail-row">
                      <span className="detail-key" style={{ width: 68 }}>
                        {CATEGORY_LABELS[r.category] ?? r.category}
                      </span>
                      <span className="detail-val">
                        <div className="mono" style={{ color: 'var(--xd-safe)' }}>
                          {r.redacted}
                        </div>
                        {/* ★ 不再截断。
                            _mask_value 的输出形如
                            `sk-a…9f⟪118 字符⟫`，长度标记⟪n 字符⟫
                            是用户判断「这是不是我的Key」的关键信息。
                            此处按 40 字截断会把 ⟪118 字符⟫ 切成
                            「…⟪11」—— 用户看到的是个坏掉的数字，
                            反而更容易误判成误报。 */}
                        <div
                          className="mono faint"
                          style={{ fontSize: 11, textDecoration: 'line-through' }}
                        >
                          {r.original}
                        </div>
                      </span>
                    </div>
                  ))}
                  {detail.entry.action === 'block' && (
                    <div className="faint" style={{ fontSize: 11, marginTop: 8, lineHeight: 1.7 }}>
                      片段为掩码后内容（保留首尾与长度），原文从未离开本机。
                      若确认是误报，可点下方「标记为安全」。
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>

        <div className="drawer-footer">
          <button className="btn secondary" onClick={handleCopy} disabled={loading}>
            {copied ? (
              <Check size={15} strokeWidth={1.5} />
            ) : (
              <Copy size={15} strokeWidth={1.5} />
            )}
            {copied ? '已复制' : '复制详情'}
          </button>
          {detail?.entry.marked_safe ? (
            <button
              className="btn secondary"
              onClick={handleUnmarkSafe}
              disabled={loading || marking}
            >
              <ShieldCheck size={15} strokeWidth={1.5} />
              {marking ? '撤销中...' : '撤销标记'}
            </button>
          ) : (
            <button
              className="btn secondary"
              onClick={handleMarkSafe}
              disabled={loading || marking}
            >
              <ShieldOff size={15} strokeWidth={1.5} />
              {marking ? '标记中...' : '标记为误报'}
            </button>
          )}
          <button className="btn danger" onClick={handleDelete} disabled={loading}>
            <Trash2 size={15} strokeWidth={1.5} />
            删除
          </button>
        </div>
      </aside>
    </>
  );
}

// ══════════════════════════════════════════════════════════════
// 页面
// ══════════════════════════════════════════════════════════════

export default function Logs() {
  const toast = useToast();
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [logType, setLogType] = useState('');
  const [action, setAction] = useState('');
  const [days, setDays] = useState('');
  const [markedFilter, setMarkedFilter] = useState('');
  const [stats, setStats] = useState<LogBreakdown | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [exporting, setExporting] = useState(false);
  const requestIdRef = useRef(0);
  const mountedRef = useRef(true);

  // ★★ 当前筛选条件必须是**唯一一份**（2026-10-03）
  //   列表查询与「按筛选删除」都从这里取。
  //   原实现列表在 load() 里现拼一套，删除若另拼一套，
  //   两者一旦漂移就会出现「我看到的」与「我删掉的」不是同一批 ——
  //   而删除不可恢复，这种错必须从结构上杜绝，不能靠记得对齐。
  const currentFilters = useMemo<LogFilterParams>(() => ({
    log_type: logType || undefined,
    action: action || undefined,
    search: debouncedSearch || undefined,
    days: days ? Number(days) : undefined,
    marked_safe:
      markedFilter === 'only'
        ? true
        : markedFilter === 'exclude'
          ? false
          : undefined,
  }), [logType, action, debouncedSearch, days, markedFilter]);

  // 概览统计：与筛选无关，回答「我这些日志都是些什么」
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const s = await api.getLogStats();
        if (!cancelled) setStats(s);
      } catch {
        // 概览是辅助信息，取不到不该影响主功能
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [total]);

  // 搜索防抖
  useEffect(() => {
    const t = setTimeout(() => {
      setDebouncedSearch(search);
      setOffset(0);
    }, SEARCH_DEBOUNCE);
    return () => clearTimeout(t);
  }, [search]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const load = useCallback(async () => {
    const rid = ++requestIdRef.current;
    setLoading(true);
    try {
      const res = await api.getLogs({
        limit: PAGE_SIZE,
        offset,
        ...currentFilters,
      });
      if (rid !== requestIdRef.current) return;   // 丢弃过时响应
      setEntries(res.entries);
      setTotal(res.total);
      setLoadError(null);
    } catch (e) {
      if (rid !== requestIdRef.current) return;
      setLoadError(e instanceof Error ? e.message : String(e));
      // 不清空 entries，保留上次成功数据
    } finally {
      if (rid === requestIdRef.current && mountedRef.current) setLoading(false);
    }
  }, [offset, currentFilters]);

  useEffect(() => {
    load();
  }, [load]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  const handleExport = async () => {
    if (exporting) return;
    setExporting(true);
    try {
      const r = await api.exportLogs('csv');
      const ok = downloadText(
        r.filename,
        r.content,
        r.filename.endsWith('.json') ? 'application/json' : 'text/csv',
      );
      if (ok) toast.success(`已导出 ${r.filename}`);
      else toast.error('导出失败，无法写入文件');
    } catch (e) {
      toast.error(`导出失败：${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setExporting(false);
    }
  };

  const handleClearAll = async () => {
    if (!window.confirm('确定清空全部安全日志吗？\n\n此操作不可恢复。\n（脱敏记录会一并删除，本地不留存任何原始敏感值）')) {
      return;
    }
    try {
      const r = await api.clearLogs(0);
      toast.success(`已清空 ${r.deleted} 条日志`);
      setOffset(0);
      load();
    } catch (e) {
      toast.error(`清空失败：${e instanceof Error ? e.message : String(e)}`);
    }
  };

  /**
   * ★ 按当前筛选条件删除（两步确认，2026-10-03）。
   *
   * 第一步只问「有多少条会被删」，用户看清范围再决定 ——
   * 删除不可恢复，而「当前筛选条件」对用户是隐式的，
   * 他可能以为筛出了几十条，实际会删掉全部。
   */
  const handleDeleteFiltered = async () => {
    if (deleting) return;
    setDeleting(true);
    try {
      const probe = await api.countFilteredLogs(currentFilters);
      if (probe.matched === 0) {
        toast.error('当前筛选条件下没有可删除的记录');
        return;
      }
      const all = !currentFilters.log_type && !currentFilters.action
        && !currentFilters.search && !currentFilters.days
        && currentFilters.marked_safe === undefined;
      const scope = all ? '全部日志' : '当前筛选结果';
      if (!window.confirm(
        `将删除${scope}中的 ${probe.matched} 条记录。\n\n`
        + '此操作不可恢复（脱敏记录会一并删除）。\n'
        + '确定继续吗？',
      )) {
        return;
      }
      const r = await api.deleteFilteredLogs(currentFilters);
      toast.success(`已删除 ${r.deleted} 条记录`);
      setOffset(0);
      load();
    } catch (e) {
      toast.error(`删除失败：${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div>
      <div className="page-header flex items-center justify-between">
        <div>
          <h1 className="page-title">安全日志</h1>
          <p className="page-subtitle">
            记录每一次请求转发与响应验证，所有数据仅存于本机
          </p>
        </div>
        <div className="btn-row">
          <button className="btn secondary" onClick={handleExport} disabled={total === 0 || exporting}>
            <Download size={15} strokeWidth={1.5} />
            {exporting ? '导出中...' : '导出'}
          </button>
          {/* ★ 按筛选删除（2026-10-03）。
              此前只有「清空全部」一条路：想清理筛选结果就只能全清，
              于是要么留着垃圾、要么把有用记录一起删掉。 */}
          <button
            className="btn secondary"
            onClick={handleDeleteFiltered}
            disabled={total === 0 || deleting}
          >
            <Filter size={15} strokeWidth={1.5} />
            {deleting ? '处理中...' : '删除筛选结果'}
          </button>
          <button className="btn secondary" onClick={handleClearAll} disabled={total === 0}>
            <Trash2 size={15} strokeWidth={1.5} />
            清空
          </button>
        </div>
      </div>

      {/* ★ 概览统计（2026-10-03）。
          此前界面上只有分页器需要的一个总数，
          用户想知道「我这些日志都是些什么」只能自己翻。 */}
      {stats && stats.total > 0 && (
        <div className="log-overview">
          <div className="log-overview-item">
            <span className="log-overview-num mono">{stats.total}</span>
            <span className="log-overview-label">条记录</span>
          </div>
          {stats.marked_safe > 0 && (
            <div className="log-overview-item">
              <span className="log-overview-num mono">{stats.marked_safe}</span>
              <span className="log-overview-label">已标记误报</span>
            </div>
          )}
          <div className="log-overview-item">
            <span className="log-overview-num mono">
              {Object.entries(stats.by_type)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 2)
                .map(([k, v]) => `${LOG_TYPE_LABELS[k as LogType] ?? k} ${v}`)
                .join(' · ')}
            </span>
            <span className="log-overview-label">主要构成</span>
          </div>
          {stats.top_domains[0] && (
            <div className="log-overview-item">
              <span className="log-overview-num mono truncate">
                {stats.top_domains[0].domain || '—'}
              </span>
              <span className="log-overview-label">
                主要中转站（{stats.top_domains[0].count} 条）
              </span>
            </div>
          )}
        </div>
      )}

      {/* 工具栏 */}
      <div className="toolbar">
        <div style={{ position: 'relative', flex: 1 }}>
          <Search
            size={15}
            strokeWidth={1.5}
            style={{
              position: 'absolute',
              left: 11,
              top: '50%',
              transform: 'translateY(-50%)',
              color: 'var(--xd-text-faint)',
              pointerEvents: 'none',
            }}
          />
          <input
            className="input"
            style={{ paddingLeft: 34 }}
            placeholder="搜索摘要或内容片段..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <select
          className="select"
          value={logType}
          onChange={(e) => {
            setLogType(e.target.value);
            setOffset(0);
          }}
        >
          {TYPE_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        <select
          className="select"
          value={action}
          onChange={(e) => {
            setAction(e.target.value);
            setOffset(0);
          }}
        >
          {ACTION_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        <select
          className="select"
          value={days}
          onChange={(e) => {
            setDays(e.target.value);
            setOffset(0);
          }}
        >
          {TIME_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        <select
          className="select"
          value={markedFilter}
          onChange={(e) => {
            setMarkedFilter(e.target.value);
            setOffset(0);
          }}
        >
          {MARKED_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </div>

      {loadError && (
        <div className="alert danger">
          <AlertTriangle size={17} strokeWidth={1.5} className="alert-icon" />
          <div>
            加载日志失败：{loadError}
            <button className="btn ghost sm mt-8" onClick={load}>
              重试
            </button>
          </div>
        </div>
      )}

      {/* 列表 */}
      {entries.length === 0 ? (
        <div className="card">
          <div className="empty">
            <div className="empty-icon">
              {loading ? (
                <span className="spinner" style={{ margin: '0 auto' }} />
              ) : debouncedSearch ? (
                <Search size={34} strokeWidth={1.5} />
              ) : (
                <CheckCircle2 size={34} strokeWidth={1.5} />
              )}
            </div>
            <div className="empty-text">
              {loading
                ? '加载中...'
                : debouncedSearch
                  ? '未找到匹配的日志，试试其他关键词'
                  : '暂无日志记录 — 使用 AI 工具发起一次对话后即可看到'}
            </div>
          </div>
        </div>
      ) : (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 78 }}>时间</th>
                <th style={{ width: 92 }}>类型</th>
                <th>内容</th>
                <th style={{ width: 150 }}>中转站</th>
                <th style={{ width: 78 }}>结果</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr
                  key={e.id}
                  className={selectedId === e.id ? 'selected' : ''}
                  onClick={() => setSelectedId(e.id)}
                >
                  <td className="mono faint">{formatDateTime(e.timestamp).slice(-8)}</td>
                  <td>
                    <span className="faint" style={{ fontSize: 12 }}>
                      {LOG_TYPE_LABELS[e.log_type]}
                    </span>
                  </td>
                  <td>
                    <div className="flex items-center gap-8">
                      <span className={`list-icon ${actionBadgeClass(e)}`} style={{ width: 20, height: 20 }}>
                        {e.action === 'block' ? (
                          <ShieldX size={11} strokeWidth={1.5} />
                        ) : e.action === 'alert' || e.severity === 'medium' ? (
                          <AlertTriangle size={11} strokeWidth={1.5} />
                        ) : e.action === 'redact' ? (
                          <Eye size={11} strokeWidth={1.5} />
                        ) : (
                          <Info size={11} strokeWidth={1.5} />
                        )}
                      </span>
                      <span className="truncate" title={e.summary}>
                        {e.summary}
                      </span>
                    </div>
                  </td>
                  <td className="mono faint truncate" style={{ maxWidth: 150 }}>
                    {e.relay_domain || '—'}
                  </td>
                  <td>
                    <span className={`badge ${actionBadgeClass(e)}`}>
                      {ACTION_LABELS[e.action]}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* 分页 */}
      {totalPages > 1 && (
        <div className="pagination">
          <button
            className="btn ghost sm"
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            disabled={offset === 0}
          >
            上一页
          </button>
          <span>
            {currentPage} / {totalPages}（共 {total} 条）
          </span>
          <button
            className="btn ghost sm"
            onClick={() => setOffset(offset + PAGE_SIZE)}
            disabled={offset + PAGE_SIZE >= total}
          >
            下一页
          </button>
        </div>
      )}

      {selectedId !== null && (
        <DetailDrawer
          logId={selectedId}
          onClose={() => setSelectedId(null)}
          onDeleted={load}
          onMarkedSafe={load}
        />
      )}
    </div>
  );
}
