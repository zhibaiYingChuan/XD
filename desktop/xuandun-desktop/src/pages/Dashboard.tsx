import { useState, useEffect, useCallback, useRef } from 'react';
import { api, StatusResponse, LogEntry } from '../services/tauriApi';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';

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

  useEffect(() => {
    fetchStatus();
    fetchRecentBlocked();
    const interval = setInterval(fetchStatus, 2000);
    return () => clearInterval(interval);
  }, [fetchStatus, fetchRecentBlocked]);

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

      <div className="status-card-row">
        <div className={`status-hero-card ${status?.running ? 'online' : 'offline'}`}>
          <div className="status-hero-indicator">
            <span className={`status-dot ${status?.running ? 'dot-online' : 'dot-offline'}`}></span>
          </div>
          <div className="status-hero-info">
            <div className="status-hero-label">引擎状态</div>
            <div className="status-hero-value">{status?.running ? '在线运行' : '离线'}</div>
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
        </div>
        <div className="card-body">
          {history.length < 2 ? (
            <div className="empty-state">数据采集中，请稍候...</div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={history}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color, #333)" />
                <XAxis dataKey="time" tick={{ fontSize: 10 }} stroke="var(--text-secondary, #999)" />
                <YAxis tick={{ fontSize: 10 }} stroke="var(--text-secondary, #999)" />
                <Tooltip />
                <Area type="monotone" dataKey="requests" stroke="#3b82f6" fill="#3b82f620" name="请求" />
                <Area type="monotone" dataKey="blocked" stroke="#ef4444" fill="#ef444420" name="拦截" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

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
                <Bar dataKey="count" fill="#8b5cf6" name="数量" radius={[4, 4, 0, 0]} />
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
                    <td><span className={`trust-badge trust-${entry.trust_level.toLowerCase()}`}>{entry.trust_level}</span></td>
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
