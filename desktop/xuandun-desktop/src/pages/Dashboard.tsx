import { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, StatusResponse, LogEntry, LearningStatus, TrendPoint, AttackCategoryStat, RealtimeMetrics, ComparisonStats } from '../services/tauriApi';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar } from 'recharts';
import OnboardingWizard from '../components/OnboardingWizard';

const ONBOARDING_GUIDES = [
  {
    id: 'proxy',
    icon: '🔌',
    title: '配置 AI 工具代理',
    desc: '将玄盾设为 Claude Desktop / Cursor 等 AI 工具的安全代理',
    steps: [
      '打开 AI 工具的设置页面，找到网络/代理配置项',
      '将 HTTP 代理地址设为 127.0.0.1:18765',
      '或使用 MCP Server 模式：在 Claude Desktop 配置中添加 xuandun_protect 工具',
      '配置完成后，所有 AI 请求将自动经过玄盾检测',
    ],
  },
  {
    id: 'sdk',
    icon: '📦',
    title: 'SDK 集成到你的服务',
    desc: '使用 Python SDK 将玄盾集成到 FastAPI / Flask 等应用',
    steps: [
      '安装 SDK：pip install daoti-xuandun==1.1.0',
      '在代码中引入：from daoti_xuandun import XuanDun',
      '创建实例：shield = XuanDun()  # 默认启用观察模式',
      '调用检测：result = shield.protect("用户输入")',
    ],
  },
  {
    id: 'test',
    icon: '🧪',
    title: '运行模拟测试',
    desc: '使用内置 200+ 攻击样本验证防护效果',
    steps: [
      '在左侧导航栏点击"模拟测试"',
      '选择"快速验证"模式，点击"运行测试"',
      '15 秒内生成拦截率/误报率报告',
      '确认防护效果后即可正式接入',
    ],
  },
];

const TIME_RANGES = [
  { key: '1h', label: '1小时', hours: 1 },
  { key: '24h', label: '24小时', hours: 24 },
  { key: '7d', label: '7天', hours: 24 * 7 },
  { key: '30d', label: '30天', hours: 24 * 30 },
];

const PIE_COLORS = ['#ff6b6b', '#4ecdc4', '#45b7d1', '#f9ca24', '#6c5ce7', '#a29bfe', '#fd79a8', '#00cec9'];

const ATTACK_CATEGORY_NAMES: Record<string, string> = {
  direct_prompt_injection: '直接提示注入',
  indirect_prompt_injection: '间接提示注入',
  jailbreak: '越狱攻击',
  encoding_obfuscation: '编码混淆',
  agent_attack: 'Agent攻击',
  data_leakage: '数据泄露',
  other: '其他',
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
  const navigate = useNavigate();
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
  const [showWizard, setShowWizard] = useState(() => {
    return localStorage.getItem('xuandun_onboarding_skip') !== 'true';
  });
  const prevRequests = useRef(0);
  const prevBlocked = useRef(0);
  const fetchingRef = useRef(false);

  const fetchStatus = useCallback(async () => {
    if (fetchingRef.current) return;
    fetchingRef.current = true;
    try {
      const s = await api.getStatus();
      setStatus(s);
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
    } catch {
      setStatus(null);
      setError('无法连接到引擎');
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
        const level = e.trust_level || 'UNKNOWN';
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
    try {
      const [trend, dist] = await Promise.all([
        api.getTrendStats(range, start, end),
        api.getAttackDistribution(start, end),
      ]);
      setTrendData(trend.points);
      setAttackDist(dist);
    } catch {
      // stats tables may be empty initially
    }
  }, []);

  const fetchRealtimeMetrics = useCallback(async () => {
    try {
      const m = await api.getRealtimeMetrics();
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
    fetchStatus();
    fetchRecentBlocked();
    fetchLearning();
    fetchRealtimeMetrics();
    fetchTrendAndDist(timeRange);
    fetchComparison();
    const interval = setInterval(fetchStatus, 2000);
    const learningInterval = setInterval(fetchLearning, 5000);
    const realtimeInterval = setInterval(fetchRealtimeMetrics, 3000);
    return () => {
      clearInterval(interval);
      clearInterval(learningInterval);
      clearInterval(realtimeInterval);
    };
  }, [fetchStatus, fetchRecentBlocked, fetchLearning, fetchRealtimeMetrics, fetchTrendAndDist, fetchComparison, timeRange]);

  const qps = status
    ? status.uptime > 0
      ? (status.total_requests / status.uptime).toFixed(2)
      : '0.00'
    : '--';

  return (
    <div className="page dashboard-page">
      {error && (
        <div className="alert-banner alert-danger">
          <span className="alert-icon">⚠️</span>
          <span>{error} — 请检查引擎是否正常运行</span>
        </div>
      )}

      {status && !status.healthy && status.running && (
        <div className="alert-banner alert-warning">
          <span className="alert-icon">⚡</span>
          <span>引擎运行异常，部分功能可能受限</span>
        </div>
      )}

      {status && status.running && status.total_requests === 0 && (
        <div className="onboarding-banner">
          <div className="onboarding-banner-header">
            <span className="onboarding-banner-icon">🚀</span>
            <div className="onboarding-banner-text">
              <div className="onboarding-banner-title">玄盾已就绪，但尚未检测到任何流量</div>
              <div className="onboarding-banner-desc">
                玄盾需要接入 AI 工具的流量才能发挥保护作用。建议使用接入向导完成配置。
              </div>
            </div>
            <button
              className="btn btn-primary btn-sm"
              onClick={() => setShowWizard(true)}
            >
              📋 启动接入向导
            </button>
          </div>
          <div className="onboarding-guides-grid">
            {ONBOARDING_GUIDES.map((g) => (
              <div key={g.id} className="onboarding-guide-card" onClick={() => setShowWizard(true)}>
                <div className="onboarding-guide-icon">{g.icon}</div>
                <div className="onboarding-guide-title">{g.title}</div>
                <div className="onboarding-guide-desc">{g.desc}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {showWizard && (!status || status.total_requests === 0) && (
        <OnboardingWizard
          totalRequests={status?.total_requests ?? 0}
          engineRunning={status?.running ?? false}
          onSkip={() => {
            localStorage.setItem('xuandun_onboarding_skip', 'true');
            setShowWizard(false);
          }}
          onNavigate={(path) => navigate(path)}
        />
      )}

      {status && status.running && status.total_requests > 0 && (
        <div className="onboarding-connected-banner">
          <span className="onboarding-connected-icon">✅</span>
          <span>玄盾已接入流量，正在保护您的 AI 应用</span>
        </div>
      )}

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
            <span className="learning-banner-icon">🎓</span>
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
          <a href="#/learning" className="learning-banner-link">查看详情 →</a>
        </div>
      )}

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">总请求数</div>
          <div className="stat-value">{status?.total_requests ?? '--'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">拦截次数</div>
          <div className="stat-value highlight">{status?.total_blocked ?? '--'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">拦截率</div>
          <div className="stat-value">{status ? `${(status.block_rate * 100).toFixed(1)}%` : '--'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">QPS</div>
          <div className="stat-value">{qps}</div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>请求趋势</h3>
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
          {trendData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={trendData.map(p => ({ time: p.time.slice(11, 16), requests: p.total_requests, blocked: p.total_blocked, rate: p.block_rate }))}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color, #333)" />
                <XAxis dataKey="time" tick={{ fontSize: 10 }} stroke="var(--text-secondary, #999)" />
                <YAxis tick={{ fontSize: 10 }} stroke="var(--text-secondary, #999)" />
                <Tooltip />
                <Area type="monotone" dataKey="requests" stroke="var(--accent)" fill="var(--accent-glow)" name="请求" />
                <Area type="monotone" dataKey="blocked" stroke="var(--danger)" fill="var(--danger-bg)" name="拦截" />
              </AreaChart>
            </ResponsiveContainer>
          ) : history.length >= 2 ? (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={history}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color, #333)" />
                <XAxis dataKey="time" tick={{ fontSize: 10 }} stroke="var(--text-secondary, #999)" />
                <YAxis tick={{ fontSize: 10 }} stroke="var(--text-secondary, #999)" />
                <Tooltip />
                <Area type="monotone" dataKey="requests" stroke="var(--accent)" fill="var(--accent-glow)" name="请求" />
                <Area type="monotone" dataKey="blocked" stroke="var(--danger)" fill="var(--danger-bg)" name="拦截" />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state">数据采集中，请稍候...</div>
          )}
        </div>
      </div>

      {attackDist.length > 0 && (
        <div className="card">
          <div className="card-header">
            <h3>攻击类型分布</h3>
          </div>
          <div className="card-body attack-dist-container">
            <div className="attack-dist-pie">
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie data={attackDist.map(d => ({ name: ATTACK_CATEGORY_NAMES[d.category] || d.category, value: d.blocked }))} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label={(entry: any) => `${entry.name}: ${entry.value}`}>
                    {attackDist.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="attack-dist-radar">
              <ResponsiveContainer width="100%" height={220}>
                <RadarChart data={attackDist.map(d => ({ category: ATTACK_CATEGORY_NAMES[d.category] || d.category, count: d.blocked }))}>
                  <PolarGrid />
                  <PolarAngleAxis dataKey="category" tick={{ fontSize: 10 }} />
                  <PolarRadiusAxis tick={{ fontSize: 9 }} />
                  <Radar dataKey="count" stroke="var(--accent)" fill="var(--accent)" fillOpacity={0.5} />
                  <Tooltip />
                </RadarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {comparison && (
        <div className="card">
          <div className="card-header">
            <h3>周度对比（本周 vs 上周）</h3>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={[
                { name: '本周请求', value: comparison.current.total_requests },
                { name: '上周请求', value: comparison.baseline.total_requests },
                { name: '本周拦截', value: comparison.current.total_blocked },
                { name: '上周拦截', value: comparison.baseline.total_blocked },
              ]}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color, #333)" />
                <XAxis dataKey="name" tick={{ fontSize: 11 }} stroke="var(--text-secondary, #999)" />
                <YAxis tick={{ fontSize: 10 }} stroke="var(--text-secondary, #999)" />
                <Tooltip />
                <Bar dataKey="value" fill="var(--accent)" name="数量" radius={[4, 4, 0, 0]} />
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
              <div className="realtime-metric-value">{realtimeMetrics.total_requests}</div>
            </div>
            <div className="realtime-metric-item">
              <div className="realtime-metric-label">累计拦截</div>
              <div className="realtime-metric-value highlight">{realtimeMetrics.total_blocked}</div>
            </div>
            <div className="realtime-metric-item">
              <div className="realtime-metric-label">拦截率</div>
              <div className="realtime-metric-value">{(realtimeMetrics.block_rate * 100).toFixed(1)}%</div>
            </div>
            <div className="realtime-metric-item">
              <div className="realtime-metric-label">引擎健康</div>
              <div className="realtime-metric-value">{realtimeMetrics.healthy ? '✅ 正常' : '❌ 异常'}</div>
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
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={trustDist}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color, #333)" />
                <XAxis dataKey="name" tick={{ fontSize: 11 }} stroke="var(--text-secondary, #999)" />
                <YAxis tick={{ fontSize: 10 }} stroke="var(--text-secondary, #999)" />
                <Tooltip />
                <Bar dataKey="count" fill="var(--accent)" name="数量" radius={[4, 4, 0, 0]} />
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
            <div className="empty-state">暂无拦截记录</div>
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
                    <td><span className={`trust-badge trust-${(entry.trust_level || 'unknown').toLowerCase()}`}>{entry.trust_level || '—'}</span></td>
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
