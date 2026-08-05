import { useState, useEffect, useCallback, useRef } from 'react';
import { api, StatusResponse, LearningStatus, TrendPoint, RealtimeMetrics, ComparisonStats, OutputStats, OutputHistoryEntry, OutputTrendPoint } from '../services/tauriApi';
// 设计系统规范 v2.0：仪表盘图表统一使用克制的深色主题（品牌色+状态色+国风辅助色），禁用高饱和糖果色
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';
import {
  AlertTriangle, Zap,
  Activity, ShieldCheck, ShieldAlert, Info, ChevronDown,
  TrendingUp, TrendingDown,
} from 'lucide-react';

// 设计系统规范 v2.0 §2：图表色板（克制的深色主题，状态色唯一性）
// 请求=道体蓝、拦截=朱砂红、安全=玄盾青、警告=琥珀金、中性=水墨灰/信息灰
const CHART = {
  request: '#2B5FD7',        // 道体蓝（请求/通过）
  danger: '#E54D4D',         // 朱砂红（拦截/危险）
  success: '#00D4AA',        // 玄盾青（安全）
  warning: '#F5A623',        // 琥珀金（警告）
  info: '#6B7A8F',           // 信息灰（中性/不可用）
  ink: '#8B9DBD',            // 水墨灰（次要/基线对比）
  grid: 'rgba(255,255,255,0.06)',   // 规范§2.4 分割线
  axis: '#A0ABB8',           // 规范§2.4 次级文本（坐标轴刻度）
  tickLabel: '#E8EDF2',      // 规范§2.4 主要文本（tooltip数值）
  tooltipBg: '#1C2330',      // 规范§2.4 卡片背景（tooltip底）
  tooltipBorder: 'rgba(255,255,255,0.08)', // 规范§7.2 输入框边框
} as const;

// 输出护栏三级处置：拦截=朱砂红、打码=琥珀金、告警=水墨灰（规范§2 状态色唯一性）
// 与输入侧拦截色一致，保证"拦截"语义跨区块统一
const OUTPUT_ACTION_META: Record<'block' | 'redact' | 'alert', { label: string; color: string; statsKey: 'blocked' | 'redacted' | 'alerted' }> = {
  block: { label: '拦截', color: CHART.danger, statsKey: 'blocked' },
  redact: { label: '打码', color: CHART.warning, statsKey: 'redacted' },
  alert: { label: '告警', color: CHART.ink, statsKey: 'alerted' },
};

// 信任等级分布已从仪表盘移除：随"进阶指标"精简不再展示，避免首屏信息过载。
// 如需恢复，可在此处基于日志重新聚合（原实现引用 formatTrustLevel）。

// 设计系统规范 §3.4/§8.2：图表 Tooltip 统一样式
// 采用紧凑浅色浮层：浅底+深色文字+细描边+柔和投影，比大面积深色块更精致
function DarkTooltip({ active, payload, label }: any) {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <div style={{
      background: '#FFFFFF',
      border: '1px solid rgba(26,34,51,0.10)',
      borderRadius: 6,
      padding: '6px 10px',
      boxShadow: '0 6px 20px rgba(0,0,0,0.18)',
      fontSize: 12,
      lineHeight: '18px',
    }}>
      {label !== undefined && (
        <div style={{ color: '#1A2233', fontWeight: 600, marginBottom: 2, fontSize: 11 }}>
          {label}
        </div>
      )}
      {payload.map((p: any, i: number) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ width: 7, height: 7, borderRadius: 2, background: p.color || p.payload?.fill || CHART.info, flexShrink: 0 }} />
          <span style={{ color: '#5A6474' }}>{p.name}</span>
          <span style={{ color: '#1A2233', fontWeight: 600, fontFamily: 'var(--font-family-mono, JetBrains Mono, monospace)' }}>
            {typeof p.value === 'number' ? p.value.toLocaleString() : p.value}
          </span>
        </div>
      ))}
    </div>
  );
}

// 设计系统规范 §8.2：KPI 卡片趋势箭头
// 正向=玄盾青、负向=朱砂红；invert=true 用于拦截类指标（上涨=风险上升=负向）
function TrendBadge({ value, invert = false }: { value: number | null; invert?: boolean }) {
  if (value === null || !isFinite(value) || Math.abs(value) < 0.01) return null;
  const up = value >= 0;
  const good = invert ? !up : up;
  const Icon = up ? TrendingUp : TrendingDown;
  return (
    <span className={`stat-trend ${good ? 'trend-good' : 'trend-bad'}`}>
      <Icon size={12} strokeWidth={2} />
      {Math.abs(value).toFixed(1)}%
    </span>
  );
}

const TIME_RANGES = [
  { key: '1h', label: '1小时', hours: 1 },
  { key: '24h', label: '24小时', hours: 24 },
  { key: '7d', label: '7天', hours: 24 * 7 },
  { key: '30d', label: '30天', hours: 24 * 30 },
];

// 环比变化百分比（base 为 0 或无数据时返回 null）
const pctChange = (cur: number, base: number): number | null => {
  if (!isFinite(cur) || !isFinite(base) || base === 0) return null;
  return ((cur - base) / base) * 100;
};

function isoTimeAgo(hours: number): string {
  return new Date(Date.now() - hours * 3600 * 1000).toISOString();
}

function isoNow(): string {
  return new Date().toISOString();
}

const formatUptime = (s: number) => {
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = Math.floor(s % 60);
  return `${h}h ${m}m ${sec}s`;
};

interface HistoryPoint {
  time: string;
  requests: number;
  blocked: number;
  rate: number;
}

export default function Dashboard() {
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryPoint[]>([]);
  const [learning, setLearning] = useState<LearningStatus | null>(null);
  // learning 状态保留用于数据轮询（后续版本可能恢复仪表盘学习进度展示）
  void learning;
  const [timeRange, setTimeRange] = useState('24h');
  const [trendData, setTrendData] = useState<TrendPoint[]>([]);
  const [realtimeMetrics, setRealtimeMetrics] = useState<RealtimeMetrics | null>(null);
  const [comparison, setComparison] = useState<ComparisonStats | null>(null);
  // P1-5 修复：周度对比/输出护栏独立错误态，失败不再静默吞掉导致卡片消失或永久"加载中"
  const [comparisonError, setComparisonError] = useState<string | null>(null);
  // 输出护栏（模型→用户）数据：stats / trend / history
  const [outputStats, setOutputStats] = useState<OutputStats | null>(null);
  const [outputTrend, setOutputTrend] = useState<OutputTrendPoint[]>([]);
  const [outputHistory, setOutputHistory] = useState<OutputHistoryEntry[]>([]);
  const [outputGuardrailError, setOutputGuardrailError] = useState<string | null>(null);
  // 信息架构重构：进阶指标折叠区（周度对比）默认收起；攻击分布/信任分布/最近拦截记录
  // 已随本版精简移除，首屏只保留主趋势图，避免信息过载
  const [advancedOpen, setAdvancedOpen] = useState(false);
  // P1-12 修复：趋势数据独立 loading 状态，时间范围切换时仅刷新趋势图表
  const [trendLoading, setTrendLoading] = useState(false);
  const prevRequests = useRef(0);
  const prevBlocked = useRef(0);
  const fetchingRef = useRef(false);
  // G-12 修复：指数退避状态（与 StatusBar 一致）
  const pollIntervalRef = useRef(2000); // 当前轮询间隔，失败时翻倍
  const pollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // G-19 修复：保留上次状态快照，避免 UI 雪崩闪烁
  const statusSnapshotRef = useRef<StatusResponse | null>(null);
  // R-04 修复：mountedRef 守卫，防止组件卸载后幽灵轮询
  const mountedRef = useRef(true);
  // P1-5 修复：趋势/实时指标请求序列号，防止快速切换或轮询产生竞态导致旧请求覆盖新数据
  const trendRequestIdRef = useRef(0);
  const realtimeRequestIdRef = useRef(0);

  const fetchStatus = useCallback(async () => {
    if (fetchingRef.current) return;
    fetchingRef.current = true;
    try {
      const s = await api.getStatus();
      setStatus(s);
      // 同步快照，供失败时回退使用
      statusSnapshotRef.current = s;
      setError(null);

      const delta = s.total_requests - prevRequests.current;
      const deltaBlocked = s.total_blocked - prevBlocked.current;
      if (prevRequests.current > 0 && delta >= 0) {
        const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        setHistory(prev => {
          const next = [...prev, { time: now, requests: delta, blocked: deltaBlocked, rate: delta > 0 ? deltaBlocked / delta : 0 }];
          return next.slice(-30);
        });
      }
      prevRequests.current = s.total_requests;
      prevBlocked.current = s.total_blocked;

      // 成功：重置轮询间隔为初始值
      pollIntervalRef.current = 2000;
    } catch {
      // G-19 修复：失败时保留上次快照，避免 status=null 导致 UI 雪崩
      // 仅当从未获取过状态时才设为 null（首次启动场景）
      if (statusSnapshotRef.current === null) {
        setStatus(null);
      }
      // 否则保留上次有效的 status，仅更新 error 提示
      setError('无法连接到引擎');
      // G-12 修复：指数退避 2s→4s→8s→16s→30s（上限 30s）
      pollIntervalRef.current = Math.min(pollIntervalRef.current * 2, 30000);
    } finally {
      fetchingRef.current = false;
    }
  }, []);

  const fetchLearning = useCallback(async () => {
    try {
      const l = await api.getLearningStatus();
      setLearning(l);
    } catch {
      // ignore
    }
  }, []);

  const fetchTrend = useCallback(async (range: string) => {
    const rangeCfg = TIME_RANGES.find(r => r.key === range) ?? TIME_RANGES[1];
    const start = isoTimeAgo(rangeCfg.hours);
    const end = isoNow();
    // P1-5 修复：每次请求递增序列号，仅最新请求的结果会更新 state
    const requestId = ++trendRequestIdRef.current;
    try {
      const trend = await api.getTrendStats(range, start, end);
      // P1-5 修复：竞态守卫，丢弃过时请求的结果
      if (requestId !== trendRequestIdRef.current) return;
      setTrendData(trend.points);
    } catch {
      // stats tables may be empty initially
    }
  }, []);

  const fetchRealtimeMetrics = useCallback(async () => {
    // P1-5 修复：每次请求递增序列号，仅最新请求的结果会更新 state
    const requestId = ++realtimeRequestIdRef.current;
    try {
      const m = await api.getRealtimeMetrics();
      // P1-5 修复：竞态守卫，丢弃过时请求的结果
      if (requestId !== realtimeRequestIdRef.current) return;
      setRealtimeMetrics(m);
    } catch {
      // ignore
    }
  }, []);

  const fetchComparison = useCallback(async () => {
    try {
      const now = isoNow();
      const weekAgo = isoTimeAgo(24 * 7);
      const twoWeeksAgo = isoTimeAgo(24 * 14);
      const cmp = await api.getComparisonStats(weekAgo, now, twoWeeksAgo, weekAgo);
      if (!mountedRef.current) return;
      setComparison(cmp);
      setComparisonError(null);
    } catch (err) {
      // P1-5 修复：不再静默吞掉，记录错误态供卡片展示"加载失败"而非凭空消失
      if (!mountedRef.current) return;
      setComparisonError(String((err as any)?.message ?? err));
    }
  }, []);

  // 输出护栏数据：stats（累计）+ trend（趋势）+ history（最近处置）。数据为内存准实时。
  const fetchOutputGuardrail = useCallback(async () => {
    try {
      const [stats, trendRes, historyRes] = await Promise.all([
        api.getOutputStats(),
        api.getOutputTrend('hour'),
        api.getOutputHistory(20),
      ]);
      // P1-5 修复：竞态守卫，丢弃卸载/重渲染时的过期结果
      if (!mountedRef.current) return;
      setOutputStats(stats);
      setOutputTrend(trendRes.points || []);
      setOutputHistory(historyRes.history || []);
      setOutputGuardrailError(null);
    } catch (err) {
      // P1-5 修复：不再静默吞掉，记录错误态供卡片展示"加载失败"而非永久"加载中"
      if (!mountedRef.current) return;
      setOutputGuardrailError(String((err as any)?.message ?? err));
    }
  }, []);

  useEffect(() => {
    // R-04 修复：mountedRef 守卫，防止组件卸载后幽灵轮询和 setState
    mountedRef.current = true;
    fetchStatus();
    fetchLearning();
    fetchRealtimeMetrics();
    // P1-12 修复：timeRange 已拆分到独立 useEffect，此处不再调用 fetchTrend
    fetchComparison();
    fetchOutputGuardrail();

    // G-12 修复：使用 setTimeout 递归实现指数退避，替代固定 setInterval
    // 失败时间隔翻倍（2s→4s→8s→16s→30s），成功时重置为 2s
    // R-04 修复：递归前检查 mountedRef，组件卸载后不再调度新轮询
    const scheduleNextPoll = () => {
      pollTimerRef.current = setTimeout(async () => {
        if (!mountedRef.current) return;
        await fetchStatus();
        if (!mountedRef.current) return;
        scheduleNextPoll();
      }, pollIntervalRef.current);
    };
    scheduleNextPoll();

    // 其他低频轮询保持固定间隔（无需退避，失败静默）
    const learningInterval = setInterval(fetchLearning, 5000);
    const realtimeInterval = setInterval(fetchRealtimeMetrics, 3000);
    const outputInterval = setInterval(fetchOutputGuardrail, 5000);
    return () => {
      // R-04 修复：卸载时设置 mountedRef=false，阻止幽灵轮询
      mountedRef.current = false;
      if (pollTimerRef.current !== null) {
        clearTimeout(pollTimerRef.current);
        pollTimerRef.current = null;
      }
      clearInterval(learningInterval);
      clearInterval(realtimeInterval);
      clearInterval(outputInterval);
    };
  }, [fetchStatus, fetchLearning, fetchRealtimeMetrics, fetchComparison, fetchOutputGuardrail]);

  // P1-12 修复：timeRange 变化仅触发趋势数据刷新，避免重新拉取所有 fetch
  useEffect(() => {
    if (!mountedRef.current) return;
    setTrendLoading(true);
    fetchTrend(timeRange).finally(() => {
      if (mountedRef.current) setTrendLoading(false);
    });
  }, [timeRange, fetchTrend]);

  // P0-1/3 修复：KPI 行"实时 QPS"改为引擎瞬时值（realtimeMetrics.qps），
  // 不再用 total/uptime 平均值——避免与"平均 QPS"口径混淆。平均值口径已废弃。

  // 周度对比（本周 vs 上周）：KPI 卡片趋势箭头
  const reqTrend = comparison ? pctChange(comparison.current.total_requests, comparison.baseline.total_requests) : null;
  const blkTrend = comparison ? pctChange(comparison.current.total_blocked, comparison.baseline.total_blocked) : null;

  // 时间轴刻度：1h/24h 显示 HH:mm，7d/30d 显示 MM-DD（规范§3.3 数字格式）
  const formatTickTime = (t: string) =>
    timeRange === '1h' || timeRange === '24h' ? t.slice(11, 16) : t.slice(5, 10);
  const trendSeries = trendData.map(p => ({
    time: formatTickTime(p.time),
    requests: p.total_requests,
    blocked: p.total_blocked,
  }));

  // 周度对比柱状图：本周=道体蓝/朱砂红、上周=水墨灰（基线对比）
  const weekData = comparison ? [
    { name: '本周请求', value: comparison.current.total_requests, color: CHART.request },
    { name: '上周请求', value: comparison.baseline.total_requests, color: CHART.ink },
    { name: '本周拦截', value: comparison.current.total_blocked, color: CHART.danger },
    { name: '上周拦截', value: comparison.baseline.total_blocked, color: CHART.ink },
  ] : [];

  // ── 输出护栏计算 ──
  // 处置分布：拦截/打码/告警 三级（按处置色语义着色）
  const outputActionData = outputStats
    ? (['block', 'redact', 'alert'] as const)
        .map(k => ({ name: OUTPUT_ACTION_META[k].label, value: outputStats[OUTPUT_ACTION_META[k].statsKey], color: OUTPUT_ACTION_META[k].color }))
        .filter(d => d.value > 0)
    : [];
  const outputActionTotal = outputActionData.reduce((s, d) => s + d.value, 0);
  // 处置率：有处置动作的样本占已检查样本的比例（blocked+redacted+alerted / total_checks）
  const outputHandled = outputStats ? outputStats.blocked + outputStats.redacted + outputStats.alerted : 0;
  const outputHandledRate = outputStats && outputStats.total_checks > 0
    ? (outputHandled / outputStats.total_checks) * 100
    : null;
  // 趋势序列：时间轴与输入侧一致（HH:mm）
  const outputTrendSeries = outputTrend.map(p => ({
    time: formatTickTime(p.time),
    checked: p.checked,
    blocked: p.blocked,
    redacted: p.redacted,
    alerted: p.alerted,
  }));

  return (
    <div className="page dashboard-page">
      {error && (
        <div className="alert-banner alert-danger">
          <AlertTriangle size={16} strokeWidth={1.5} className="alert-icon" />
          <span>{error} — 请检查引擎是否正常运行</span>
        </div>
      )}

      {status && !status.healthy && status.running && (
        <div className="alert-banner alert-warning">
          <Zap size={16} strokeWidth={1.5} className="alert-icon" />
          <span>引擎运行异常，部分功能可能受限</span>
        </div>
      )}

      {/* 设计系统规范 §3.3/§3.4：页面唯一 H1，左对齐 + 极淡装饰线 */}
      <div className="page-header">
        <h1 className="page-title">安全总览</h1>
      </div>

      <div className="status-card-row">
        <div className={`status-hero-card ${status?.running ? 'online' : 'offline'}`}>
          <div className="status-hero-indicator">
            <span className={`status-dot ${status?.running ? 'dot-online' : 'dot-offline'}`}></span>
          </div>
          <div className="status-hero-info">
            <div className="status-hero-label">引擎状态</div>
            <div className="status-hero-value">
              {status?.running ? '在线运行' : status?.startup_error ? '启动失败' : '启动中...'}
            </div>
            {/* 启动失败提示：仅当引擎未运行但存在启动错误时展示可跳转日志按钮。
                引擎在线时即使有版本警告也不显示"启动失败"，避免与"在线运行"状态矛盾。 */}
            {!status?.running && status?.startup_error && (
              <button
                className="status-hero-error-link"
                onClick={() => {
                  api.openEngineLog().catch((e) => console.error('打开日志失败:', e));
                }}
                title="点击打开引擎日志文件"
              >
                引擎启动失败，点击查看日志 →
              </button>
            )}
          </div>
        </div>

        <div className="status-hero-card mode-card">
          <div className="status-hero-info">
            <div className="status-hero-label">当前模式</div>
            <div className="status-hero-value">
              {status?.mode === 'high_security' ? '高安全' : status?.mode === 'balanced' ? '平衡' : status?.mode === 'low_false_positive' ? '低误报' : status?.mode ?? '--'}
            </div>
          </div>
        </div>

        <div className="status-hero-card uptime-card">
          <div className="status-hero-info">
            <div className="status-hero-label">运行时间</div>
            <div className="status-hero-value">{status ? formatUptime(status.uptime) : '--'}</div>
          </div>
        </div>
      </div>

      {/* 学习模式 banner 已隐藏：产品决策不再在仪表盘展示学习进度，
          活性防护模式的详情统一在 Settings 页面查看 */}

      {/* 设计系统规范 §8.2：核心 KPI 卡片（数字 Mono 等宽 + 环比趋势箭头）
          信息架构重构：移除"实时 QPS"（与实时监控卡重复，见进阶指标折叠区） */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">总请求数</div>
          <div className="stat-value">{status?.total_requests?.toLocaleString() ?? '--'}</div>
          {reqTrend !== null && <TrendBadge value={reqTrend} />}
        </div>
        <div className="stat-card">
          <div className="stat-label">拦截次数</div>
          <div className="stat-value highlight">{status?.total_blocked?.toLocaleString() ?? '--'}</div>
          {blkTrend !== null && <TrendBadge value={blkTrend} invert />}
        </div>
        <div className="stat-card">
          <div className="stat-label">拦截率</div>
          <div className="stat-value">{status ? `${(status.block_rate * 100).toFixed(1)}%` : '--'}</div>
        </div>
        <div className="stat-card">
          {/* P0-3 修复：口径统一为引擎瞬时 QPS（realtimeMetrics.qps），与实时监控一致，
              不再显示 total/uptime 平均值，避免"实时 QPS"名不副实 */}
          <div className="stat-label">瞬时 QPS</div>
          <div className="stat-value">{realtimeMetrics ? realtimeMetrics.qps.toFixed(2) : '--'}</div>
        </div>
      </div>

      {/* 信息架构重构：输入侧（用户→模型）Section —— 持久化历史统计，可筛选时间范围 */}
      <div className="dashboard-section">
        <div className="section-title">
          <span className="direction-badge input">用户 → 模型</span>
          输入侧检测
          <span className="stale-note" title="输入侧数据由引擎持久化统计，支持历史时间范围筛选，引擎重启不清零">
            <Info size={13} strokeWidth={1.5} style={{ verticalAlign: '-2px', marginRight: 4 }} />
            历史统计 · 可筛选
          </span>
        </div>

        {/* 核心洞察：请求与拦截趋势（全宽常驻）。攻击分布/信任分布/最近拦截记录
            已收进下方"进阶指标"折叠区，首屏只保留一张主趋势图，避免信息过载。 */}
        <div className="card">
          <div className="card-header">
            <h3>请求与拦截趋势</h3>
            <div className="time-range-selector">
              {TIME_RANGES.map(r => (
                <button
                  key={r.key}
                  className={`time-range-btn ${timeRange === r.key ? 'active' : ''}`}
                  onClick={() => setTimeRange(r.key)}
                >
                  {r.label}
                </button>
              ))}
            </div>
          </div>
          <div className="card-body">
            {/* P1-12 修复：切换时间范围时显示 loading 占位符，避免显示旧数据 */}
            {trendLoading ? (
              <div style={{ padding: '20px' }}>
                <div className="skeleton skeleton-text" style={{ width: '100%', height: '200px' }}></div>
              </div>
            ) : trendData.length > 0 ? (
              <ResponsiveContainer width="100%" height={240}>
                <AreaChart data={trendSeries}>
                  <defs>
                    {/* 请求=道体蓝渐变、拦截=朱砂红渐变（规范§1.1 流动的线条、渐变过渡） */}
                    <linearGradient id="gradRequests" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={CHART.request} stopOpacity={0.30} />
                      <stop offset="100%" stopColor={CHART.request} stopOpacity={0.02} />
                    </linearGradient>
                    <linearGradient id="gradBlocked" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={CHART.danger} stopOpacity={0.30} />
                      <stop offset="100%" stopColor={CHART.danger} stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke={CHART.grid} vertical={false} />
                  <XAxis dataKey="time" tick={{ fontSize: 11, fill: CHART.axis }} axisLine={{ stroke: CHART.grid }} tickLine={false} minTickGap={24} />
                  <YAxis tick={{ fontSize: 11, fill: CHART.axis }} axisLine={false} tickLine={false} width={48} />
                  <Tooltip content={<DarkTooltip />} />
                  <Area type="monotone" dataKey="requests" name="请求" stroke={CHART.request} strokeWidth={2} fill="url(#gradRequests)" />
                  <Area type="monotone" dataKey="blocked" name="拦截" stroke={CHART.danger} strokeWidth={2} fill="url(#gradBlocked)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : history.length >= 2 ? (
              <ResponsiveContainer width="100%" height={240}>
                <AreaChart data={history}>
                  <defs>
                    <linearGradient id="gradRequests" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={CHART.request} stopOpacity={0.30} />
                      <stop offset="100%" stopColor={CHART.request} stopOpacity={0.02} />
                    </linearGradient>
                    <linearGradient id="gradBlocked" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={CHART.danger} stopOpacity={0.30} />
                      <stop offset="100%" stopColor={CHART.danger} stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke={CHART.grid} vertical={false} />
                  <XAxis dataKey="time" tick={{ fontSize: 11, fill: CHART.axis }} tickFormatter={(t: string) => t.slice(0, 5)} axisLine={{ stroke: CHART.grid }} tickLine={false} minTickGap={24} />
                  <YAxis tick={{ fontSize: 11, fill: CHART.axis }} axisLine={false} tickLine={false} width={48} />
                  <Tooltip content={<DarkTooltip />} />
                  <Area type="monotone" dataKey="requests" name="请求" stroke={CHART.request} strokeWidth={2} fill="url(#gradRequests)" />
                  <Area type="monotone" dataKey="blocked" name="拦截" stroke={CHART.danger} strokeWidth={2} fill="url(#gradBlocked)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="empty-state-enhanced">
                <div className="empty-state-enhanced-icon">
                  <Activity size={28} strokeWidth={1.5} />
                </div>
                <div className="empty-state-enhanced-title">数据采集中</div>
                <div className="empty-state-enhanced-desc">玄盾正在收集流量数据，请稍候...</div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 信息架构重构：进阶指标折叠区（默认收起）—— 周度对比 / 实时监控详情 / 信任等级分布 */}
      <div className="advanced-section">
        <button
          className={`advanced-toggle ${advancedOpen ? 'open' : ''}`}
          onClick={() => setAdvancedOpen(v => !v)}
          aria-expanded={advancedOpen}
        >
          进阶指标
          <ChevronDown size={14} strokeWidth={2} className="chevron" />
        </button>
        <div className="advanced-body" style={{ maxHeight: advancedOpen ? '4200px' : '0px' }}>
{comparisonError ? (
        <div className="card">
          <div className="card-header">
            <h3>周度对比（本周 vs 上周）</h3>
          </div>
          <div className="card-body">
            <div className="empty-state-enhanced">
              <div className="empty-state-enhanced-title">周度对比数据加载失败</div>
              <div className="empty-state-enhanced-desc">接口暂不可用，请稍后自动重试。原因：{comparisonError}</div>
            </div>
          </div>
        </div>
      ) : comparison && (
        <div className="card">
          <div className="card-header">
            <h3>周度对比（本周 vs 上周）</h3>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={weekData}>
                <CartesianGrid strokeDasharray="3 3" stroke={CHART.grid} vertical={false} />
                <XAxis dataKey="name" tick={{ fontSize: 11, fill: CHART.axis }} axisLine={{ stroke: CHART.grid }} tickLine={false} />
                <YAxis tick={{ fontSize: 11, fill: CHART.axis }} axisLine={false} tickLine={false} width={48} />
                <Tooltip content={<DarkTooltip />} cursor={false} />
                <Bar dataKey="value" name="数量" radius={[4, 4, 0, 0]} barSize={36}>
                  {weekData.map((d, i) => <Cell key={i} fill={d.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* P0-1 修复：删除折叠区"实时监控"卡——其瞬时 QPS 已并入 KPI 行（瞬时 QPS），
          引擎健康/运行时长已并入状态行，累计请求/拦截/拦截率与 KPI 行重复。
          消除 5 个指标在页面出现两次且口径不一致的问题。 */}
      {/* P1-5 修复：信任等级分布已上移至输入侧 Section，与攻击类型分布归并为"分布"分组，
          折叠区仅保留周度对比（分析性低频指标）。 */}

        {/* 输出侧护栏（模型→用户）：与周度对比同属"进阶指标"折叠区 ——
          首屏仅保留输入侧单一视觉主线（道体蓝请求 + 朱砂红拦截），
          输出侧多色处置（打码=琥珀金/告警=水墨灰）收进折叠区，
          消除"色块突变 + 又一堆数据"造成的视觉过载。 */}
      <div className="advanced-inner-section">
        <div className="section-title">
          <span className="direction-badge output">模型 → 用户</span>
          输出侧护栏
          <span className="output-guardrail-note" title="数据由引擎在内存中按分钟采集，仅保留近实时视图，引擎重启后清零，不持久化为历史统计">
            <Info size={13} strokeWidth={1.5} style={{ verticalAlign: '-2px', marginRight: 4 }} />
            自引擎启动起 · 准实时
          </span>
        </div>

      {/* ── 输出护栏（模型→用户）区块 ──
          双向闭环的输出侧。处置色：拦截=朱砂红、打码=琥珀金、告警=水墨灰。
          数据为引擎内存准实时采集，重启清零，故标注"自启动起"，不提供历史时间范围。 */}
      <div className="card output-guardrail-card">
        {/* P0-2 修复：删除卡片内重复的方向徽章与时效标注——方向徽章与时效标注
            已在 Section 标题（上方）展示一次，卡片内不再重复，与输入侧结构对齐 */}
        <div className="card-header">
          <h3>输出护栏</h3>
        </div>
        <div className="card-body">
          {outputGuardrailError ? (
            // P1-5 修复：失败不再静默吞掉导致永久"加载中"，展示错误态并自动重试
            <div className="empty-state-enhanced">
              <div className="empty-state-enhanced-title">输出护栏数据加载失败</div>
              <div className="empty-state-enhanced-desc">接口暂不可用，将自动重试。原因：{outputGuardrailError}</div>
            </div>
          ) : !outputStats ? (
            <div className="empty-state-enhanced">
              <div className="empty-state-enhanced-desc">输出护栏数据加载中...</div>
            </div>
          ) : outputStats.enabled === false ? (
            <div className="empty-state-enhanced">
              <div className="empty-state-enhanced-icon">
                <ShieldAlert size={28} strokeWidth={1.5} />
              </div>
              <div className="empty-state-enhanced-title">输出护栏未启用</div>
              <div className="empty-state-enhanced-desc">
                输出侧检测已关闭，仅保留输入侧防护。如需开启，请到「系统设置 → 专家模式 → 输出护栏配置」启用。
              </div>
            </div>
          ) : outputStats.total_checks === 0 ? (
            <div className="empty-state-enhanced">
              <div className="empty-state-enhanced-icon">
                <ShieldAlert size={28} strokeWidth={1.5} />
              </div>
              <div className="empty-state-enhanced-title">尚无输出检测记录</div>
              <div className="empty-state-enhanced-desc">模型输出经检测后，此处将展示检查与处置概况（数据自引擎启动起统计）</div>
            </div>
          ) : (
            <>
              {/* 输出护栏 KPI：检查数为主指标，突出"引擎持续工作"；处置率供参考 */}
              <div className="stats-grid output-stats-grid">
                <div className="stat-card">
                  <div className="stat-label">检查输出数</div>
                  <div className="stat-value">{outputStats.total_checks.toLocaleString()}</div>
                </div>
                <div className="stat-card">
                  <div className="stat-label">拦截输出</div>
                  <div className="stat-value highlight">{outputStats.blocked.toLocaleString()}</div>
                </div>
                <div className="stat-card">
                  <div className="stat-label">打码输出</div>
                  <div className="stat-value">{outputStats.redacted.toLocaleString()}</div>
                </div>
                <div className="stat-card">
                  <div className="stat-label">处置率</div>
                  <div className="stat-value">{outputHandledRate !== null ? `${outputHandledRate.toFixed(1)}%` : '--'}</div>
                </div>
              </div>

              {/* 双栏：处置分布环形图 + 处置趋势面积图 */}
              <div className="dashboard-chart-row">
                {outputActionData.length > 0 && (
                  <div className="card-inner">
                    <div className="subcard-title">处置分布</div>
                    <ResponsiveContainer width="100%" height={200}>
                      <PieChart>
                        <Pie
                          data={outputActionData}
                          dataKey="value"
                          nameKey="name"
                          cx="50%" cy="50%"
                          innerRadius={52} outerRadius={80}
                          paddingAngle={2} cornerRadius={4} stroke="none"
                        >
                          {outputActionData.map((d, i) => <Cell key={i} fill={d.color} />)}
                        </Pie>
                        <Tooltip content={<DarkTooltip />} />
                        <text x="50%" y="47%" textAnchor="middle" dominantBaseline="middle" fill={CHART.tickLabel} className="pie-center-value">
                          {outputActionTotal.toLocaleString()}
                        </text>
                        <text x="50%" y="61%" textAnchor="middle" dominantBaseline="middle" fill={CHART.axis} className="pie-center-label">
                          处置总数
                        </text>
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="chart-legend">
                      {(Object.keys(OUTPUT_ACTION_META) as Array<'block' | 'redact' | 'alert'>).map((k) => {
                        const v = outputStats ? outputStats[OUTPUT_ACTION_META[k].statsKey] : 0;
                        return (
                          <div className="chart-legend-item" key={k}>
                            <span className="chart-legend-dot" style={{ background: OUTPUT_ACTION_META[k].color }} />
                            <span className="chart-legend-name">{OUTPUT_ACTION_META[k].label}</span>
                            <span className="chart-legend-value">{v.toLocaleString()}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                <div className="card-inner">
                  <div className="subcard-title">处置趋势</div>
                  {outputTrendSeries.length > 0 ? (
                    <ResponsiveContainer width="100%" height={200}>
                      <AreaChart data={outputTrendSeries}>
                        <defs>
                          <linearGradient id="gradOutBlocked" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor={CHART.danger} stopOpacity={0.30} />
                            <stop offset="100%" stopColor={CHART.danger} stopOpacity={0.02} />
                          </linearGradient>
                          <linearGradient id="gradOutRedacted" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor={CHART.warning} stopOpacity={0.30} />
                            <stop offset="100%" stopColor={CHART.warning} stopOpacity={0.02} />
                          </linearGradient>
                          <linearGradient id="gradOutAlerted" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor={CHART.ink} stopOpacity={0.30} />
                            <stop offset="100%" stopColor={CHART.ink} stopOpacity={0.02} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke={CHART.grid} vertical={false} />
                        <XAxis dataKey="time" tick={{ fontSize: 11, fill: CHART.axis }} axisLine={{ stroke: CHART.grid }} tickLine={false} minTickGap={24} />
                        <YAxis tick={{ fontSize: 11, fill: CHART.axis }} axisLine={false} tickLine={false} width={48} />
                        <Tooltip content={<DarkTooltip />} />
                        <Area type="monotone" dataKey="checked" name="检查" stroke={CHART.success} strokeWidth={2} fillOpacity={0} />
                        <Area type="monotone" dataKey="blocked" name="拦截" stroke={CHART.danger} strokeWidth={2} fill="url(#gradOutBlocked)" />
                        <Area type="monotone" dataKey="redacted" name="打码" stroke={CHART.warning} strokeWidth={2} fill="url(#gradOutRedacted)" />
                        <Area type="monotone" dataKey="alerted" name="告警" stroke={CHART.ink} strokeWidth={1.5} fill="url(#gradOutAlerted)" />
                      </AreaChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="empty-state-enhanced">
                      <div className="empty-state-enhanced-icon">
                        <Activity size={24} strokeWidth={1.5} />
                      </div>
                      <div className="empty-state-enhanced-title">数据采集中</div>
                      <div className="empty-state-enhanced-desc">输出护栏正在收集处置趋势，请稍候...</div>
                    </div>
                  )}
                </div>
              </div>

              {/* 最近处置记录 */}
              <div className="output-history-section">
                <div className="subcard-title">最近处置记录</div>
                {outputHistory.length === 0 ? (
                  <div className="empty-state-enhanced">
                    <div className="empty-state-enhanced-icon">
                      <ShieldCheck size={24} strokeWidth={1.5} />
                    </div>
                    <div className="empty-state-enhanced-desc">尚无处置动作，模型输出均正常放行</div>
                  </div>
                ) : (
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>时间</th>
                        <th>处置</th>
                        <th>风险级别</th>
                        <th>输出预览（已脱敏）</th>
                      </tr>
                    </thead>
                    <tbody>
                      {outputHistory.map((entry, idx) => {
                        const meta = entry.action === 'block' || entry.action === 'redact' || entry.action === 'alert'
                          ? OUTPUT_ACTION_META[entry.action]
                          : null;
                        return (
                          <tr key={idx}>
                            <td className="mono">{entry.time ? entry.time.slice(11, 19) : '--'}</td>
                            <td>
                              {meta ? (
                                <span className="output-action-badge" style={{ color: meta.color, borderColor: meta.color }}>
                                  {meta.label}
                                </span>
                              ) : entry.action}
                            </td>
                            <td>
                              {entry.risk_level === 'high'
                                ? <span className="trust-badge trust-high">高危</span>
                                : entry.risk_level === 'medium'
                                  ? <span className="trust-badge trust-medium">中危</span>
                                  : <span className="trust-badge trust-low">低危</span>}
                            </td>
                            <td className="text-preview">{entry.preview || '--'}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                )}
              </div>
            </>
          )}
        </div>
      </div>
      </div>
      </div>
      </div>
    </div>
  );
}
