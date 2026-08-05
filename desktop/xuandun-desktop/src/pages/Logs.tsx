import { useState, useEffect, useCallback, useRef } from 'react';
import { GraduationCap, AlertTriangle, RefreshCw } from 'lucide-react';
import { api, LogEntry, OutputHistoryEntry, LearningStatus, formatInvokeError, formatTrustLevel } from '../services/tauriApi';

// 输出侧处置动作 → 中文标签 + 颜色（与 Dashboard 输出护栏保持一致：拦截=朱砂红/打码=琥珀金/告警=水墨灰）
const OUTPUT_ACTION_LABEL: Record<OutputHistoryEntry['action'], string> = {
  block: '拦截',
  redact: '打码',
  alert: '告警',
  pass: '放行',
};
const OUTPUT_ACTION_CLASS: Record<OutputHistoryEntry['action'], string> = {
  block: 'output-action-block',
  redact: 'output-action-redact',
  alert: 'output-action-alert',
  pass: 'output-action-pass',
};

// 输出侧风险等级：语义与输入侧"信任"相反（high=高风险=红/medium=中=黄/low=低=绿/pass=无=青）
const OUTPUT_RISK_LABEL: Record<string, string> = {
  high: '高风险',
  medium: '中风险',
  low: '低风险',
  pass: '无风险',
};
const OUTPUT_RISK_CLASS: Record<string, string> = {
  high: 'output-risk-high',
  medium: 'output-risk-medium',
  low: 'output-risk-low',
  pass: 'output-risk-pass',
};

const PAGE_SIZE = 20;

export default function Logs() {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [filter, setFilter] = useState<'all' | 'blocked' | 'allowed'>('all');
  const [rejectStageFilter, setRejectStageFilter] = useState<string>('all');
  const [searchText, setSearchText] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [loading, setLoading] = useState(false);
  const [learning, setLearning] = useState<LearningStatus | null>(null);
  // 日志来源：input=输入侧（用户→模型，SQLite 持久化）；output=输出护栏（模型→用户，引擎内存准实时）
  const [source, setSource] = useState<'input' | 'output'>('input');
  const [outputEntries, setOutputEntries] = useState<OutputHistoryEntry[]>([]);
  const [outputLoading, setOutputLoading] = useState(false);
  // P1-06 修复：加载错误状态，区分"加载失败"和"无数据"
  const [loadError, setLoadError] = useState<string | null>(null);
  // P1-05 修复：请求序列号，防止快速翻页产生竞态导致旧请求覆盖新数据
  const requestIdRef = useRef(0);
  // GAP-S5-06 修复：mountedRef 守卫，组件卸载后不再 setState（与 Dashboard 一致）
  const mountedRef = useRef(true);

  const fetchLearning = useCallback(async () => {
    try {
      const l = await api.getLearningStatus();
      // GAP-S5-06 修复：卸载后不更新 state
      if (!mountedRef.current) return;
      setLearning(l);
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    fetchLearning();
    const interval = setInterval(fetchLearning, 5000);
    return () => {
      mountedRef.current = false;
      clearInterval(interval);
    };
  }, [fetchLearning]);

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(searchText), 300);
    return () => clearTimeout(timer);
  }, [searchText]);

  const fetchLogs = useCallback(async () => {
    // P1-05 修复：每次请求递增序列号，仅最新请求的结果会更新 state
    const requestId = ++requestIdRef.current;
    setLoading(true);
    setLoadError(null);
    try {
      const filterAllowed = filter === 'all' ? undefined : filter === 'allowed';
      const hasClientFilter = rejectStageFilter !== 'all' || debouncedSearch.trim() !== '';

      if (hasClientFilter) {
        const res = await api.getLogs(filterAllowed, 10000, 0);
        // P1-05 修复：竞态守卫，丢弃过时请求的结果
        if (requestId !== requestIdRef.current) return;
        let filtered = res.entries;
        if (rejectStageFilter !== 'all') {
          filtered = filtered.filter(e => e.reject_stage === rejectStageFilter);
        }
        if (debouncedSearch.trim()) {
          const q = debouncedSearch.toLowerCase();
          filtered = filtered.filter(e =>
            e.text_preview.toLowerCase().includes(q) ||
            (e.session_id && e.session_id.toLowerCase().includes(q))
          );
        }
        setEntries(filtered.slice(offset, offset + PAGE_SIZE));
        setTotal(filtered.length);
      } else {
        const res = await api.getLogs(filterAllowed, PAGE_SIZE, offset);
        // P1-05 修复：竞态守卫
        if (requestId !== requestIdRef.current) return;
        setEntries(res.entries);
        setTotal(res.total);
      }
    } catch (e) {
      // P1-06 修复：不再静默吞错，记录错误状态供 UI 显示
      if (requestId !== requestIdRef.current) return;
      setLoadError(formatInvokeError(e, '加载日志'));
      // 不清空 entries，保留上次成功的数据（避免空白闪烁）
    } finally {
      // P1-05 修复：仅最新请求才更新 loading 状态
      // GAP-S5-06 修复：组件卸载后不更新 state
      if (requestId === requestIdRef.current && mountedRef.current) {
        setLoading(false);
      }
    }
  }, [filter, offset, rejectStageFilter, debouncedSearch]);

  // 输出侧处置记录：引擎内存准实时，最多 200 条，无分页
  const fetchOutputHistory = useCallback(async () => {
    setOutputLoading(true);
    setLoadError(null);
    try {
      const res = await api.getOutputHistory(200);
      if (!mountedRef.current) return;
      setOutputEntries(res.history || []);
    } catch (e) {
      if (!mountedRef.current) return;
      setLoadError(formatInvokeError(e, '加载输出护栏记录'));
    } finally {
      if (mountedRef.current) setOutputLoading(false);
    }
  }, []);

  // 来源切换：input 走输入侧日志（支持分页/搜索/筛选），output 走输出护栏处置记录
  const handleSourceChange = (s: 'input' | 'output') => {
    setSource(s);
    setOffset(0);
  };

  useEffect(() => {
    if (source === 'input') {
      fetchLogs();
    } else {
      fetchOutputHistory();
    }
  }, [source, fetchLogs, fetchOutputHistory]);

  const totalPages = Math.ceil(total / PAGE_SIZE);
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  const handleFilterChange = (f: 'all' | 'blocked' | 'allowed') => {
    setFilter(f);
    setOffset(0);
  };

  const handleRejectStageChange = (stage: string) => {
    setRejectStageFilter(stage);
    setOffset(0);
  };

  const handleSearch = (text: string) => {
    setSearchText(text);
    setOffset(0);
  };

  return (
    <div className="page logs-page">
      {/* P0-4 修复：每页唯一 H1，符合 WCAG AA 规范 §3.3/§3.4 */}
      <div className="page-header">
        <h1 className="page-title">防护日志</h1>
      </div>
      {learning && learning.mode === 'observing' && (
        <div className="alert-banner alert-warning observing-banner">
          <GraduationCap size={18} strokeWidth={1.5} className="alert-icon" />
          <span>
            当前为<strong>观察模式</strong>，所有请求均已放行。
            观察期间检测到 <strong>{learning.would_block_count}</strong> 条潜在攻击（如开启保护将被拦截），
            {/* K1-企业精简版：learning路由已移除，详情跳转至Settings的活性防护卡片 */}
            <a href="#/settings" className="banner-link">查看系统设置 → 活性防护模式</a>
          </span>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h3>日志查看</h3>
          <div className="filter-group">
            {/* 日志来源：输入侧（持久化）/ 输出护栏（引擎内存准实时） */}
            <div className="source-toggle" role="group" aria-label="日志来源">
              {(['input', 'output'] as const).map((s) => (
                <button
                  key={s}
                  className={`filter-btn ${source === s ? 'active' : ''}`}
                  onClick={() => handleSourceChange(s)}
                >
                  {s === 'input' ? '输入侧' : '输出护栏'}
                </button>
              ))}
            </div>
            {(['all', 'blocked', 'allowed'] as const).map((f) => (
              <button
                key={f}
                className={`filter-btn ${filter === f ? 'active' : ''}`}
                onClick={() => handleFilterChange(f)}
              >
                {f === 'all' ? '全部' : f === 'blocked' ? '拦截' : '放行'}
              </button>
            ))}
          </div>
        </div>
        <div className="card-body">
          {/* 输入侧日志筛选区：仅来源为「输入侧」时显示 */}
          {source === 'input' && (
          <div style={{ display: 'flex', gap: '8px', marginBottom: '12px', flexWrap: 'wrap' }}>
            <select
              value={rejectStageFilter}
              onChange={(e) => handleRejectStageChange(e.target.value)}
              style={{
                padding: '4px 8px',
                borderRadius: 'var(--radius-md)',
                border: '1px solid var(--border)',
                background: 'var(--bg-card)',
                color: 'var(--text-primary)',
                fontSize: '0.85em',
              }}
            >
              <option value="all">全部阶段</option>
              <option value="reject_gate">reject_gate</option>
              <option value="timing_checker">timing_checker</option>
            </select>
            <input
              type="text"
              placeholder="搜索文本/会话ID..."
              value={searchText}
              onChange={(e) => handleSearch(e.target.value)}
              style={{
                padding: '4px 8px',
                borderRadius: 'var(--radius-md)',
                border: '1px solid var(--border)',
                background: 'var(--bg-card)',
                color: 'var(--text-primary)',
                fontSize: '0.85em',
                flex: 1,
                minWidth: '120px',
              }}
            />
          </div>
          )}

          {/* P1-06 修复：加载失败时显示错误提示和重试按钮，区分"加载失败"和"无数据" */}
          {loadError && (
            <div className="alert-banner alert-danger" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <AlertTriangle size={18} strokeWidth={1.5} />
                <span>{loadError}</span>
              </span>
              <button className="btn btn-sm btn-secondary" onClick={() => (source === 'input' ? fetchLogs() : fetchOutputHistory())}>
                <RefreshCw size={14} strokeWidth={1.5} /> 重试
              </button>
            </div>
          )}

          {/* ── 输出护栏处置记录（模型→用户，引擎内存准实时） ── */}
          {source === 'output' && (
            outputLoading && outputEntries.length === 0 ? (
              <div className="empty-state">加载中...</div>
            ) : !loadError && outputEntries.length === 0 ? (
              <div className="empty-state">暂无输出护栏处置记录（打码/拦截/告警均未发生）</div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>时间</th>
                    <th>处置动作</th>
                    <th>风险等级</th>
                    <th>处置原因</th>
                    <th>输出预览（已脱敏）</th>
                  </tr>
                </thead>
                <tbody>
                  {outputEntries.map((entry, idx) => (
                    <tr key={idx}>
                      <td className="mono">{new Date(entry.time).toLocaleTimeString()}</td>
                      <td>
                        <span className={`output-action-badge ${OUTPUT_ACTION_CLASS[entry.action]}`}>
                          {OUTPUT_ACTION_LABEL[entry.action]}
                        </span>
                      </td>
                      <td>
                        <span className={`output-risk-badge ${OUTPUT_RISK_CLASS[(entry.risk_level || 'pass').toLowerCase()] || 'output-risk-pass'}`}>
                          {OUTPUT_RISK_LABEL[(entry.risk_level || 'pass').toLowerCase()] || entry.risk_level}
                        </span>
                      </td>
                      <td className="text-preview" title={entry.reason}>{entry.reason}</td>
                      <td className="mono text-preview" style={{ fontSize: '0.8em' }}>{entry.preview || '--'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          )}

          {/* ── 输入侧日志（用户→模型，SQLite 持久化） ── */}
          {source === 'input' && (
            loading && entries.length === 0 ? (
              <div className="empty-state">加载中...</div>
            ) : !loadError && entries.length === 0 ? (
              // P1 修复：区分"搜索无匹配"与"确实无日志"，避免用户误以为数据丢失
              <div className="empty-state">{debouncedSearch.trim() ? '未找到匹配的日志，请调整搜索关键词' : '暂无日志记录'}</div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>时间</th>
                    <th>文本摘要</th>
                    <th>结果</th>
                    <th>信任等级</th>
                    <th>拦截阶段</th>
                    <th>会话</th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map((entry) => (
                    <tr key={entry.id}>
                      <td className="mono">{new Date(entry.timestamp).toLocaleTimeString()}</td>
                      <td className="text-preview">{entry.text_preview}</td>
                      <td>
                        <span className={`result-tag ${entry.allowed ? 'tag-allowed' : 'tag-blocked'}`}>
                          {entry.allowed ? '放行' : '拦截'}
                        </span>
                      </td>
                      <td><span className={`trust-badge trust-${(entry.trust_level || 'unknown').toLowerCase()}`}>{formatTrustLevel(entry.trust_level)}</span></td>
                      <td>{entry.reject_stage ?? '--'}</td>
                      <td className="mono" style={{ fontSize: '0.8em' }}>{entry.session_id ?? '--'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          )}

          {/* 输入侧日志分页：仅输入侧显示 */}
          {source === 'input' && totalPages > 1 && (
            <div className="pagination">
              <button
                className="btn btn-secondary btn-sm"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
              >
                上一页
              </button>
              <span className="pagination-info">
                {currentPage} / {totalPages}
              </span>
              <button
                className="btn btn-secondary btn-sm"
                disabled={offset + PAGE_SIZE >= total}
                onClick={() => setOffset(offset + PAGE_SIZE)}
              >
                下一页
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
