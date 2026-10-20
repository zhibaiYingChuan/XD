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
  displayDomain,
  formatDateTime,
  actionBadgeClass,
  humanizeLoadError,
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
  // 与 LOG_TYPE_LABELS 保持同一说法，否则筛选里叫「代理错误」、
  // 列表里却显示「转发中断」，同一类记录两套名字会让人对不上。
  { value: 'proxy_error', label: '转发中断' },
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

/**
 * 把脱敏记录里的**原文**打码后再显示。
 *
 * ★ 2026-10-20：此前这里把 r.original 原样渲染（只加了一条删除线），
 *   而紧挨着的说明写的是「只保留开头、结尾和长度」——
 *   说明与实现相反：实测截图里用户的手机号是完整可见的。
 *   只存本机不等于可以整屏展示：一旦截图、录屏或投屏，
 *   这句「已打码」就成了谎报。现在让显示与说明一致。
 */
function maskOriginal(value: string): string {
  const s = (value || '').trim();
  if (!s) return '';
  if (s.length <= 6) return `${s.slice(0, 1)}…（共 ${s.length} 位）`;
  return `${s.slice(0, 3)}…${s.slice(-3)}（共 ${s.length} 位）`;
}

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
  // 删除在飞标志：删除不可恢复，期间必须锁住按钮防重复触发
  const [deleting, setDeleting] = useState(false);
  // ★ 抽屉标题引用：打开时把焦点移入，让读屏用户立刻知道
  //   「弹出了一个对话框、它是什么」，而不是把焦点留在触发的表格行上。
  const titleRef = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    titleRef.current?.focus();
  }, []);

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
      `中转站: ${displayDomain(detail.entry.relay_domain)}`,
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
      toast.success('已标记为误报，今日「危险/提示」计数已减去这一条');
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
    if (deleting) return;
    // ★ 删除不可恢复（脱敏记录会一并删除），必须先确认。
    //   此前是单击即删 —— 用户本想点「复制详情」，手一抖就永久丢了一条记录，
    //   而界面上没有任何挽回入口。
    if (!window.confirm('确定删除这条日志吗？\n\n此操作不可恢复。')) return;
    setDeleting(true);
    try {
      await api.deleteLog(logId);
      toast.success('日志已删除');
      onDeleted();
      onClose();
    } catch (e) {
      toast.error(`删除失败：${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setDeleting(false);
    }
  };

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label="日志详情">
        <div className="drawer-header">
          {/* tabIndex=-1：仅为可编程聚焦用，不进入 Tab 顺序；
              配合上面的 mount 效果让焦点落在标题上。 */}
          <span className="drawer-title" ref={titleRef} tabIndex={-1}>
            日志详情
          </span>
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
                <span className="detail-val mono">{displayDomain(detail.entry.relay_domain) || '—'}</span>
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
                  <div>你已将此条标记为<b>误报</b>，今日「危险/提示」计数已减去这一条。</div>
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
                  {/* ★ 标题必须区分「这两件事是不是一回事」（2026-10-20）。
                      脱敏记录来自**请求侧**；响应侧被拦时（比如模型不一致），
                      它只是这次请求顺带做的处理，跟拦截原因毫无关系。
                      此前一律写成「拦截依据」——用户看到一条「模型不一致」的
                      拦截，依据里却列着「手机号」，完全对不上。 */}
                  <div className="field-label">
                    {detail.entry.log_type === 'request_sanitize'
                      && detail.entry.action === 'block'
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
                        {/* ★ 只显示打码后的原文（头 3 + 尾 3 + 长度）。
                            完整原文仍在本地库里，但不该整屏铺开 —— 
                            截图/录屏/投屏时它就是一次泄露。 */}
                        <div
                          className="mono faint"
                          style={{ fontSize: 11, textDecoration: 'line-through' }}
                        >
                          {maskOriginal(r.original)}
                        </div>
                      </span>
                    </div>
                  ))}
                  <div className="faint" style={{ fontSize: 11, marginTop: 8, lineHeight: 1.7 }}>
                    {detail.entry.log_type === 'request_sanitize'
                      && detail.entry.action === 'block'
                      ? '这里显示的是打过码的片段（只保留开头、结尾和长度），原文没有离开你的电脑。若确认是误报，点下方「标记为误报」。'
                      : '这些是本次请求里被替换掉的内容，与上面判定的原因无关。只保留开头、结尾和长度，原文没有离开你的电脑。'}
                  </div>
                </div>
              )}

              {/* ★ 明细已被隐私清除时，也要把「打了几处」如实说出来。
                  否则用户看到状态栏写着「已打码 322 处」，
                  点开一条日志却什么都没有 —— 只能认为数字是假的。 */}
              {detail.redactions.length === 0
                && (detail.entry.redaction_count ?? 0) > 0 && (
                <div className="mt-24">
                  <div className="field-label">
                    脱敏记录（{detail.entry.redaction_count} 处）
                  </div>
                  <div className="faint" style={{ fontSize: 11, lineHeight: 1.7 }}>
                    本次请求有 {detail.entry.redaction_count} 处内容被打码。
                    原始值在响应还原后已按隐私策略清除，本地不再保留明文；
                    这条日志上只保留「打了几处」这个计数。
                  </div>
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
          <button className="btn danger" onClick={handleDelete} disabled={loading || deleting}>
            <Trash2 size={15} strokeWidth={1.5} />
            {deleting ? '删除中...' : '删除'}
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
  // ★ 抽成独立回调（2026-10-19）：标记/撤销误报**不改变 total**，
  //   而这里原本只依赖 [total] —— 于是标记成功后概览里
  //   「已标记误报」的数字永远停在旧值，用户以为操作没生效。
  //   现在标记成功后显式再调一次它（见 handleMarkedSafe）。
  const loadStats = useCallback(async () => {
    try {
      const s = await api.getLogStats();
      if (mountedRef.current) setStats(s);
    } catch {
      // 概览是辅助信息，取不到不该影响主功能
    }
  }, []);

  useEffect(() => {
    loadStats();
  }, [loadStats, total]);

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

  // ★ 标记/撤销误报成功后：列表与概览**都要**刷新。
  //   列表刷新负责行状态与误报筛选；概览刷新负责「已标记误报」数字 ——
  //   标记不改变 total，不显式刷新就会一直显示旧值。
  const handleMarkedSafe = useCallback(() => {
    load();
    loadStats();
  }, [load, loadStats]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  const handleExport = async () => {
    if (exporting) return;
    setExporting(true);
    try {
      // ★ 2026-10-19：导出当前筛选结果，而非全量。
      //   用户先筛出「今天 / 告警」再点导出，得到的就该是这批，
      //   与他在列表里看到的范围一致。
      const r = await api.exportLogs('csv', currentFilters);
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

  // 原始报错（如 `GET /api/logs → HTTP 500`）不该直接摆给用户，
  // 先翻译成「怎么了 + 怎么办」，原始信息收进折叠的技术细节。
  const loadErr = loadError ? humanizeLoadError(loadError) : null;

  // ★ 一键回到默认视图（2026-10-20）。
  //   四个下拉 + 搜索框，用户调乱了之后只能逐个改回「全部 XX」——
  //   而他往往已经忘了自己动过哪几个。没有重置入口，
  //   「筛不出东西」就会被当成软件坏了。
  const hasFilters = Boolean(
    logType || action || search.trim() || days || markedFilter,
  );
  const resetFilters = () => {
    setLogType('');
    setAction('');
    setSearch('');
    setDebouncedSearch('');
    setDays('');
    setMarkedFilter('');
    setOffset(0);
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
          {/* ★ 「清空」与「导出 / 删除筛选结果」此前是三个一模一样的灰色按钮。
              它不可恢复且会清掉全部记录，必须与普通操作在视觉上分开 ——
              用红色文字而不是实心红块：足够警示，又不会喧宾夺主。 */}
          <button
            className="btn secondary"
            style={{ color: 'var(--xd-danger)' }}
            onClick={handleClearAll}
            disabled={total === 0}
          >
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
            {/* ★ 「全部记录」：这个数是**全部时间**的，而状态栏的
                「今日检查 N 次」只算今天。两者放在同一屏却不标范围，
                用户自然会拿它们对账，然后发现「对不上」。 */}
            <span className="log-overview-label">全部记录</span>
          </div>
          {stats.marked_safe > 0 && (
            <div className="log-overview-item">
              <span className="log-overview-num mono">{stats.marked_safe}</span>
              <span className="log-overview-label">已标记误报（不计入今日统计）</span>
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
                {displayDomain(stats.top_domains[0].domain) || '—'}
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
            // ★ 搜索框有图标、无可见 label，必须补 aria-label，
            //   否则读屏用户只会听到「编辑框」，不知道搜的是什么。
            aria-label="搜索日志"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <select
          className="select"
          aria-label="按类型筛选"
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
          aria-label="按结果筛选"
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
          aria-label="按时间范围筛选"
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
          aria-label="按误报标记筛选"
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
        {/* ★ 只有动过筛选才出现：平时不占位置，动过之后一眼就能回到默认。 */}
        {hasFilters && (
          <button className="btn ghost sm" onClick={resetFilters}>
            重置筛选
          </button>
        )}
      </div>

      {loadErr && (
        <div className="alert danger">
          <AlertTriangle size={17} strokeWidth={1.5} className="alert-icon" />
          <div>
            <b>加载日志失败</b>
            <div className="mt-8">{loadErr.message}</div>
            <details className="mt-8">
              <summary
                className="faint"
                style={{ cursor: 'pointer', fontSize: 12, listStyle: 'none' }}
              >
                技术细节
              </summary>
              <div className="mono faint" style={{ fontSize: 12, marginTop: 4 }}>
                {loadErr.detail}
              </div>
            </details>
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
          {/* 横向滚动容器：窗口变窄时表格不再被挤压截断，而是出现横向滚动条。
              外层 card 的 overflow:hidden 只负责裁圆角，滚动交给这一层。 */}
          <div className="table-scroll">
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
                    // ★ 键盘可达（2026-10-19）：此前只有 onClick，纯键盘用户
                    //   根本无法打开详情。tabIndex + role + Enter/Space 让
                    //   「打开详情」不再只依赖鼠标；焦点轮廓由 styles.css 的
                    //   .table tbody tr:focus-visible 负责勾出来。
                    tabIndex={0}
                    role="button"
                    aria-label={`查看日志详情：${e.summary}`}
                    onClick={() => setSelectedId(e.id)}
                    onKeyDown={(ev) => {
                      if (ev.key === 'Enter' || ev.key === ' ') {
                        ev.preventDefault(); // 空格默认会滚动页面，需拦掉
                        setSelectedId(e.id);
                      }
                    }}
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
                      {displayDomain(e.relay_domain) || '—'}
                    </td>
                    <td>
                      <span className={`badge ${actionBadgeClass(e)}`}>
                        {ACTION_LABELS[e.action]}
                      </span>
                      {/* ★ 打码与「结果」是两个维度：一条正常转发的请求
                          也可能有 3 处被遮盖。此前只有状态栏说「已打码 N 处」，
                          列表里却完全看不出来 —— 点「已打码」筛选还筛不到东西。 */}
                      {(e.redaction_count ?? 0) > 0 && (
                        <div className="faint" style={{ fontSize: 10, marginTop: 2 }}>
                          打码 {e.redaction_count} 处
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
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
          onMarkedSafe={handleMarkedSafe}
        />
      )}
    </div>
  );
}
