import { useState, useEffect, useCallback, useRef } from 'react';
import { api, StatusResponse, LogEntry, LearningStatus, TrendPoint, AttackCategoryStat, RealtimeMetrics, ComparisonStats, formatTrustLevel } from '../services/tauriApi';
// 设计系统规范 v2.0：仪表盘图表统一使用克制的深色主题（品牌色+状态色+国风辅助色），禁用高饱和糖果色
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';
import {
  AlertTriangle, Zap,
  GraduationCap, Activity, ShieldCheck,
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

// 攻击类型环形图：品牌主色+国风辅助色（规范§2.5 国风辅助色使用比例≤5%，克制不刺眼）
const PIE_COLORS = [
  '#2B5FD7', '#00D4AA', '#F5A623', '#D4A853',
  '#4A7BBF', '#8B9DBD', '#C44A4A', '#6B7A8F',
];

// 信任等级柱状图：高信任=朱砂红（受检严格）、中信任=琥珀、低信任=玄盾青、其余=信息灰
const trustBarColor = (name: string): string => {
  if (name.includes('高')) return CHART.danger;
  if (name.includes('中')) return CHART.warning;
  if (name.includes('低')) return CHART.success;
  return CHART.info;
};

// 设计系统规范 §3.4/§8.2：深色主题自定义Tooltip
// 背景=卡片色#1C2330、边框=rgba(255,255,255,0.08)、数值=Mono等宽、名称=次级文本
function DarkTooltip({ active, payload, label }: any) {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <div style={{
      background: CHART.tooltipBg,
      border: `1px solid ${CHART.tooltipBorder}`,
      borderRadius: 8,
      padding: '10px 14px',
      boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
      fontSize: 12,
      lineHeight: '20px',
    }}>
      {label !== undefined && (
        <div style={{ color: CHART.tickLabel, fontWeight: 500, marginBottom: 4 }}>{label}</div>
      )}
      {payload.map((p: any, i: number) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ width: 8, height: 8, borderRadius: 2, background: p.color || p.payload?.fill || CHART.info, flexShrink: 0 }} />
          <span style={{ color: CHART.axis }}>{p.name}</span>
          <span style={{ color: CHART.tickLabel, fontFamily: 'var(--font-family-mono, JetBrains Mono, monospace)' }}>
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

const ATTACK_CATEGORY_NAMES: Record<string, string> = {
  direct_prompt_injection: '直接提示注入',
  indirect_prompt_injection: '间接提示注入',
  jailbreak: '越狱攻击',
  encoding_obfuscation: '编码混淆',
  agent_attack: 'Agent攻击',
  data_leakage: '数据泄露',
  other: '其他',
};

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
  const [recentBlocked, setRecentBlocked] = useState<LogEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryPoint[]>([]);
  const [trustDist, setTrustDist] = useState<{ name: string; count: number }[]>([]);
  const [learning, setLearning] = useState<LearningStatus | null>(null);
  const [timeRange, setTimeRange] = useState('24h');
  const [trendData, setTrendData] = useState<TrendPoint[]>([]);
  const [attackDist, setAttackDist] = useState<AttackCategoryStat[]>([]);
  const [realtimeMetrics, setRealtimeMetrics] = useState<RealtimeMetrics | null>(null);
  const [comparison, setComparison] = useState<ComparisonStats | null>(null);
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

  const fetchRecentBlocked = useCallback(async () => {
    try {
      const res = await api.getLogs(false, 5, 0);
      setRecentBlocked(res.entries.filter(e => !e.allowed));
      const allRes = await api.getLogs(undefined, 100, 0);
      const dist: Record<string, number> = {};
      allRes.entries.forEach(e => {
        const level = formatTrustLevel(e.trust_level);
        dist[level] = (dist[level] || 0) + 1;
      });
      setTrustDist(Object.entries(dist).map(([name, count]) => ({ name, count })));
    } catch {
      // ignore
    }
  }, []);

  const fetchTrendAndDist = useCallback(async (range: string) => {
    const rangeCfg = TIME_RANGES.find(r => r.key === range) ?? TIME_RANGES[1];
    const start = isoTimeAgo(rangeCfg.hours);
    const end = isoNow();
    // P1-5 修复：每次请求递增序列号，仅最新请求的结果会更新 state
    const requestId = ++trendRequestIdRef.current;
    try {
      const [trend, dist] = await Promise.all([
        api.getTrendStats(range, start, end),
        api.getAttackDistribution(start, end),
      ]);
      // P1-5 修复：竞态守卫，丢弃过时请求的结果
      if (requestId !== trendRequestIdRef.current) return;
      setTrendData(trend.points);
      setAttackDist(dist);
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
      setComparison(cmp);
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    // R-04 修复：mountedRef 守卫，防止组件卸载后幽灵轮询和 setState
    mountedRef.current = true;
    fetchStatus();
    fetchRecentBlocked();
    fetchLearning();
    fetchRealtimeMetrics();
    // P1-12 修复：timeRange 已拆分到独立 useEffect，此处不再调用 fetchTrendAndDist
    fetchComparison();

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
    return () => {
      // R-04 修复：卸载时设置 mountedRef=false，阻止幽灵轮询
      mountedRef.current = false;
      if (pollTimerRef.current !== null) {
        clearTimeout(pollTimerRef.current);
        pollTimerRef.current = null;
      }
      clearInterval(learningInterval);
      clearInterval(realtimeInterval);
    };
  }, [fetchStatus, fetchRecentBlocked, fetchLearning, fetchRealtimeMetrics, fetchComparison]);

  // P1-12 修复：timeRange 变化仅触发趋势数据刷新，避免重新拉取所有 fetch
  useEffect(() => {
    if (!mountedRef.current) return;
    setTrendLoading(true);
    fetchTrendAndDist(timeRange).finally(() => {
      if (mountedRef.current) setTrendLoading(false);
    });
  }, [timeRange, fetchTrendAndDist]);

  const qps = status
    ? status.uptime > 0
      ? (status.total_requests / status.uptime).toFixed(2)
      : '0.00'
    : '--';

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

  // 攻击类型环形图数据
  const pieData = attackDist.map(d => ({
    name: ATTACK_CATEGORY_NAMES[d.category] || d.category,
    value: d.blocked,
  }));
  const totalBlockedInRange = pieData.reduce((s, d) => s + d.value, 0);

  // 周度对比柱状图：本周=道体蓝/朱砂红、上周=水墨灰（基线对比）
  const weekData = comparison ? [
    { name: '本周请求', value: comparison.current.total_requests, color: CHART.request },
    { name: '上周请求', value: comparison.baseline.total_requests, color: CHART.ink },
    { name: '本周拦截', value: comparison.current.total_blocked, color: CHART.danger },
    { name: '上周拦截', value: comparison.baseline.total_blocked, color: CHART.ink },
  ] : [];

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
            {status?.startup_error && (
              <div className="status-hero-error">
                引擎启动失败，请查看日志：%LOCALAPPDATA%/com.daoti.xuandun-desktop/engine.log
              </div>
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

      {learning && learning.mode === 'observing' && (
        <div className="learning-progress-banner">
          <div className="learning-banner-left">
            <GraduationCap size={20} strokeWidth={1.5} className="learning-banner-icon" />
            <div className="learning-banner-info">
              <div className="learning-banner-title">观察模式（学习中）</div>
              <div className="learning-banner-sub">
                已学习 {learning.sample_count} / {learning.min_samples_for_switch} 条正常对话，
                模拟拦截 {learning.would_block_count} 条
              </div>
            </div>
          </div>
          <div className="learning-banner-bar">
            <div
              className="learning-banner-fill"
              style={{ width: `${Math.round(learning.learning_progress * 100)}%` }}
            ></div>
          </div>
          {/* K3-移除learning路由，详情跳转至Settings的活性防护卡片 */}
          <a href="#/settings" className="learning-banner-link">查看详情 →</a>
        </div>
      )}

      {/* 设计系统规范 §8.2：核心 KPI 卡片（数字 Mono 等宽 + 环比趋势箭头） */}
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
          <div className="stat-label">实时 QPS</div>
          <div className="stat-value">{qps}</div>
        </div>
      </div>

      {/* 设计系统规范 §8.2：趋势面积图（宽）+ 攻击类型环形图（窄）双栏布局 */}
      <div className="dashboard-chart-row">
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
              <ResponsiveContainer width="100%" height={220}>
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
              <ResponsiveContainer width="100%" height={220}>
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

        {attackDist.length > 0 && (
          <div className="card">
            <div className="card-header">
              <h3>攻击类型分布</h3>
            </div>
            <div className="card-body attack-dist-body">
              {/* 环形图：中心显示总拦截数（规范§8.2），色板克制 */}
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={pieData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={52}
                    outerRadius={80}
                    paddingAngle={2}
                    cornerRadius={4}
                    stroke="none"
                  >
                    {pieData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                  </Pie>
                  <Tooltip content={<DarkTooltip />} />
                  <text x="50%" y="47%" textAnchor="middle" dominantBaseline="middle" fill={CHART.tickLabel} className="pie-center-value">
                    {totalBlockedInRange.toLocaleString()}
                  </text>
                  <text x="50%" y="61%" textAnchor="middle" dominantBaseline="middle" fill={CHART.axis} className="pie-center-label">
                    总拦截
                  </text>
                </PieChart>
              </ResponsiveContainer>
              {/* 图例：名称 + Mono 数量（克制不刺眼） */}
              <div className="chart-legend">
                {pieData.slice(0, 6).map((d, i) => (
                  <div className="chart-legend-item" key={d.name}>
                    <span className="chart-legend-dot" style={{ background: PIE_COLORS[i % PIE_COLORS.length] }} />
                    <span className="chart-legend-name">{d.name}</span>
                    <span className="chart-legend-value">{d.value.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {comparison && (
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
                <Tooltip content={<DarkTooltip />} />
                <Bar dataKey="value" name="数量" radius={[4, 4, 0, 0]} barSize={36}>
                  {weekData.map((d, i) => <Cell key={i} fill={d.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {realtimeMetrics && (
        <div className="card">
          <div className="card-header">
            <h3>实时监控</h3>
          </div>
          <div className="card-body realtime-metrics-grid">
            <div className="realtime-metric-item">
              <div className="realtime-metric-label">实时 QPS</div>
              <div className="realtime-metric-value">{realtimeMetrics.qps.toFixed(2)}</div>
            </div>
            <div className="realtime-metric-item">
              <div className="realtime-metric-label">累计请求</div>
              <div className="realtime-metric-value">{realtimeMetrics.total_requests.toLocaleString()}</div>
            </div>
            <div className="realtime-metric-item">
              <div className="realtime-metric-label">累计拦截</div>
              <div className="realtime-metric-value highlight">{realtimeMetrics.total_blocked.toLocaleString()}</div>
            </div>
            <div className="realtime-metric-item">
              <div className="realtime-metric-label">拦截率</div>
              <div className="realtime-metric-value">{(realtimeMetrics.block_rate * 100).toFixed(1)}%</div>
            </div>
            <div className="realtime-metric-item">
              <div className="realtime-metric-label">引擎健康</div>
              <div className="realtime-metric-value">
                <span className={`status-dot ${realtimeMetrics.healthy ? 'dot-online' : 'dot-offline'}`}></span>
                {realtimeMetrics.healthy ? '正常' : '异常'}
              </div>
            </div>
            <div className="realtime-metric-item">
              <div className="realtime-metric-label">运行时长</div>
              <div className="realtime-metric-value">{formatUptime(realtimeMetrics.uptime_secs)}</div>
            </div>
          </div>
        </div>
      )}

      {trustDist.length > 0 && (
        <div className="card">
          <div className="card-header">
            <h3>信任等级分布</h3>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={trustDist}>
                <CartesianGrid strokeDasharray="3 3" stroke={CHART.grid} vertical={false} />
                <XAxis dataKey="name" tick={{ fontSize: 11, fill: CHART.axis }} axisLine={{ stroke: CHART.grid }} tickLine={false} />
                <YAxis tick={{ fontSize: 11, fill: CHART.axis }} axisLine={false} tickLine={false} width={48} />
                <Tooltip content={<DarkTooltip />} />
                <Bar dataKey="count" name="数量" radius={[4, 4, 0, 0]} barSize={28}>
                  {trustDist.map((d, i) => <Cell key={i} fill={trustBarColor(d.name)} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h3>最近拦截记录</h3>
        </div>
        <div className="card-body">
          {recentBlocked.length === 0 ? (
            <div className="empty-state-enhanced">
              <div className="empty-state-enhanced-icon">
                <ShieldCheck size={28} strokeWidth={1.5} />
              </div>
              <div className="empty-state-enhanced-title">暂无拦截记录</div>
              <div className="empty-state-enhanced-desc">系统运行正常，尚未检测到攻击行为</div>
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>时间</th>
                  <th>文本摘要</th>
                  <th>信任等级</th>
                  <th>拦截阶段</th>
                </tr>
              </thead>
              <tbody>
                {recentBlocked.map((entry) => (
                  <tr key={entry.id}>
                    <td className="mono">{new Date(entry.timestamp).toLocaleTimeString()}</td>
                    <td className="text-preview">{entry.text_preview}</td>
                    <td><span className={`trust-badge trust-${(entry.trust_level || 'unknown').toLowerCase()}`}>{formatTrustLevel(entry.trust_level)}</span></td>
                    <td>{entry.reject_stage ?? '--'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
