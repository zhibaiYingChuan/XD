import { useState, useEffect, useCallback, useRef } from 'react';
import { api, StatusResponse, LearningStatus, LogEntry, RealtimeMetrics, MESSAGE_TIMEOUT_MS } from '../services/tauriApi';
import { AlertTriangle, Zap, ShieldCheck, Clock, Activity } from 'lucide-react';
import ReportExportDialog from '../components/ReportExportDialog';

const formatUptime = (s: number) => {
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = Math.floor(s % 60);
  return `${h}h ${m}m ${sec}s`;
};

export default function Dashboard() {
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [learning, setLearning] = useState<LearningStatus | null>(null);
  const [realtimeMetrics, setRealtimeMetrics] = useState<RealtimeMetrics | null>(null);
  const [trafficEvents, setTrafficEvents] = useState<LogEntry[]>([]);
  const [trafficError, setTrafficError] = useState<string | null>(null);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [reportDialogOpen, setReportDialogOpen] = useState(false);

  const showMessage = useCallback((type: 'success' | 'error', text: string) => {
    setMessage({ type, text });
    setTimeout(() => {
      if (mountedRef.current) setMessage(null);
    }, MESSAGE_TIMEOUT_MS);
  }, []);

  const fetchingRef = useRef(false);
  const pollIntervalRef = useRef(2000);
  const pollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const statusSnapshotRef = useRef<StatusResponse | null>(null);
  const mountedRef = useRef(true);

  const fetchStatus = useCallback(async () => {
    if (fetchingRef.current) return;
    fetchingRef.current = true;
    try {
      const s = await api.getStatus();
      if (!mountedRef.current) return;
      setStatus(s);
      statusSnapshotRef.current = s;
      setError(null);
      pollIntervalRef.current = 2000;
    } catch {
      if (statusSnapshotRef.current === null) setStatus(null);
      setError('无法连接到引擎');
      pollIntervalRef.current = Math.min(pollIntervalRef.current * 2, 30000);
    } finally {
      fetchingRef.current = false;
    }
  }, []);

  const fetchLearning = useCallback(async () => {
    try {
      const l = await api.getLearningStatus();
      if (!mountedRef.current) return;
      setLearning(l);
    } catch (e) {
      if (import.meta.env.DEV) console.warn('[Dashboard] fetchLearning failed:', e);
      /* ignore */ }
  }, []);

  const fetchRealtimeMetrics = useCallback(async () => {
    try {
      const m = await api.getRealtimeMetrics();
      if (!mountedRef.current) return;
      setRealtimeMetrics(m);
    } catch { /* ignore */ }
  }, []);

  // 实时流量看板 — 拉取最近50条日志
  const fetchTrafficFeed = useCallback(async () => {
    try {
      const res = await api.getLogs(undefined, 50, 0, 'proxy');
      if (!mountedRef.current) return;
      setTrafficEvents(res.entries);
      setTrafficError(null);
    } catch {
      setTrafficError('流量数据加载失败');
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    fetchStatus();
    fetchLearning();
    fetchRealtimeMetrics();
    fetchTrafficFeed();

    const scheduleNextPoll = () => {
      pollTimerRef.current = setTimeout(async () => {
        if (!mountedRef.current) return;
        await fetchStatus();
        if (!mountedRef.current) return;
        scheduleNextPoll();
      }, pollIntervalRef.current);
    };
    scheduleNextPoll();

    const learningInterval = setInterval(fetchLearning, 5000);
    const realtimeInterval = setInterval(fetchRealtimeMetrics, 3000);
    const trafficInterval = setInterval(fetchTrafficFeed, 3000);

    return () => {
      mountedRef.current = false;
      if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
      clearInterval(learningInterval);
      clearInterval(realtimeInterval);
      clearInterval(trafficInterval);
    };
  }, [fetchStatus, fetchLearning, fetchRealtimeMetrics, fetchTrafficFeed]);

  // ── 拦截理由"人话化"映射（严格对齐设计文档 §3.7）──
  const humanReason = (entry: LogEntry): string => {
    if (entry.allowed) {
      // 放行 + 低延迟 → "安全请求，已放行"
      const lat = entry.latency_ms != null ? `（延迟 ${Math.round(entry.latency_ms)}ms）` : '';
      return `安全请求，已放行${lat}`;
    }
    const stage = entry.reject_stage || '';
    const category = entry.attack_category || '';
    const dist = entry.domain_distance;  // 域距离（luoshu_attack 代理）

    // outer_gate 外门拦截 ← design doc §3.7
    if (stage === 'outer_gate') {
      if (category === 'chinese_harmful_content') return '检测到危险内容组合（外门拦截）';
      if (category === 'strong_attack') return '检测到强攻击关键词（外门拦截）';
      if (category === 'roleplay_attack') return '检测到异常角色扮演（外门拦截）';
      return '检测到可疑内容（外门拦截）';
    }

    // inner_gate 内门精判 ← design doc §3.7
    if (stage === 'inner_gate') {
      // domain_distance < 0.3 → luoshu_attack < 0.3 代理 → "检测到已知攻击模式"
      if (dist != null && dist < 0.3) return '检测到已知攻击模式（内门精判）';
      // attack_category 含 intent 相关 → trigger_intent > 0.8 代理 → "检测到越狱攻击意图"
      if (category && (category.includes('intent') || category.includes('jailbreak')))
        return '检测到越狱攻击意图（内门精判）';
      // trust_level=LOW → fused_anomaly > 0.7 代理 → "检测到异常行为模式"
      if ((entry.trust_level || '').toLowerCase() === 'low') return '检测到异常行为模式（内门精判）';
      return '检测到异常请求（内门精判）';
    }

    // 时序检测（统一顺序：timing_checker 先于 output_guardrail，与 Detect.tsx 一致）
    if (stage === 'timing_checker') return '检测到时序异常（时序检测）';

    // output_guardrail 输出护栏 ← design doc §3.7
    if (stage === 'output_guardrail') return '输出内容含违规信息（输出护栏）';

    return '安全拦截';
  };

  // ── 第1层：状态行 ──
  const statusDot = status?.running ? 'status-dot dot-online' : 'status-dot dot-offline';
  const statusText = status?.running ? '在线运行' : status?.startup_error ? '启动失败' : '离线';
  const modeLabel = learning?.mode === 'protecting' ? '保护模式' : learning?.mode === 'observing' ? '观察模式' : status?.mode ?? '--';
  const sampleInfo = learning ? `${learning.sample_count ?? 0} / ${learning.min_samples_for_switch ?? 1000}` : '--';
  const uptime = status ? formatUptime(status.uptime) : '--';

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

      {message && (
        <div className={`alert-banner ${message.type === 'success' ? 'alert-success' : 'alert-danger'}`}>
          <span>{message.text}</span>
        </div>
      )}

      <div className="page-header">
        <h1 className="page-title">安全总览</h1>
      </div>

      {/* 第1层：状态行 */}
      <div className="dashboard-status-bar">
        <div className="status-bar-item">
          <span className={statusDot}></span>
          <span className="status-bar-label">引擎</span>
          <span className="status-bar-value">{statusText}</span>
        </div>
        <div className="status-bar-divider">|</div>
        <div className="status-bar-item">
          <ShieldCheck size={14} strokeWidth={1.5} style={{ marginRight: '4px' }} />
          <span className="status-bar-label">模式</span>
          <span className="status-bar-value">{modeLabel}</span>
        </div>
        <div className="status-bar-divider">|</div>
        <div className="status-bar-item">
          <Activity size={14} strokeWidth={1.5} style={{ marginRight: '4px' }} />
          <span className="status-bar-label">样本</span>
          <span className="status-bar-value">{sampleInfo}</span>
        </div>
        <div className="status-bar-divider">|</div>
        <div className="status-bar-item">
          <Clock size={14} strokeWidth={1.5} style={{ marginRight: '4px' }} />
          <span className="status-bar-label">运行</span>
          <span className="status-bar-value">{uptime}</span>
        </div>
      </div>

      {/* 第2层：4个KPI卡片 */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">检测总数</div>
          <div className="stat-value">{status?.total_requests?.toLocaleString() ?? '--'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">拦截次数</div>
          <div className="stat-value highlight">{status?.total_blocked?.toLocaleString() ?? '--'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">拦截率</div>
          <div className="stat-value">{status ? `${(status.block_rate * 100).toFixed(1)}%` : '--'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">瞬时 QPS</div>
          <div className="stat-value">{realtimeMetrics ? realtimeMetrics.qps.toFixed(2) : '--'}</div>
        </div>
      </div>

      {/* 第3层：实时流量看板 */}
      <div className="card">
        <div className="card-header">
          <h3>实时流量</h3>
          <span className="card-subtitle">最近请求的检测结果</span>
        </div>
        <div className="card-body" style={{ padding: '0' }}>
          {trafficError && !trafficEvents.length && (
            <div className="empty-state">{trafficError}</div>
          )}
          {!trafficError && !trafficEvents.length && (
            <div className="empty-state">暂无流量数据，引擎可能刚启动</div>
          )}
          {trafficEvents.length > 0 && (
            <div className="traffic-feed-list">
              {trafficEvents.slice(0, 20).map((event, idx) => (
                <div
                  key={idx}
                  className={`traffic-event ${event.allowed ? 'traffic-pass' : 'traffic-block'}`}
                >
                  <span className="traffic-time">
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </span>
                  <span className="traffic-user" title={event.session_id || ''}>
                    {event.session_id?.slice(0, 8) || '--'}
                  </span>
                  <span className="traffic-text" title={event.text_preview}>
                    {event.text_preview.slice(0, 50)}
                  </span>
                  <span className="traffic-reason" title={humanReason(event)}>
                    {humanReason(event)}
                  </span>
                  <span className={`traffic-result-tag ${event.allowed ? 'tag-allowed' : 'tag-blocked'}`}>
                    {event.allowed ? '放行' : '拦截'}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* 第4层：操作按钮区 */}
      <div className="dashboard-actions">
        <button
          className="btn btn-danger"
          onClick={async () => {
            if (!status?.running) {
              showMessage('error', '引擎未运行，无法标记');
              return;
            }
            const text = prompt('请输入要标记为安全的文本内容：');
            if (!text || !text.trim()) return;
            try {
              await api.markAsSafe(text.trim());
              showMessage('success', '已上报引擎，该样本将加入良性原型库');
            } catch (e: any) {
              showMessage('error', `标记失败：${String(e?.message || e)}`);
            }
          }}
        >
          标记为安全
        </button>
        <button
          className="btn btn-primary"
          onClick={() => setReportDialogOpen(true)}
        >
          生成报告
        </button>
        <a href="#/logs" className="btn btn-secondary">
          查看全部日志
        </a>
      </div>

      {/* v1.3.4: 周报导出对话框 */}
      <ReportExportDialog
        open={reportDialogOpen}
        onClose={() => setReportDialogOpen(false)}
        engineRunning={!!status?.running}
        onShowMessage={showMessage}
      />
    </div>
  );
}
