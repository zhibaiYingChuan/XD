import { useState, useEffect, useCallback, useRef } from 'react';
import { GraduationCap, AlertTriangle, RefreshCw } from 'lucide-react';
import { api, LogEntry, LearningStatus, formatInvokeError, formatTrustLevel } from '../services/tauriApi';

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

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

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
      {learning && learning.mode === 'observing' && (
        <div className="alert-banner alert-warning observing-banner">
          <GraduationCap size={18} strokeWidth={1.5} className="alert-icon" />
          <span>
            当前为<strong>观察模式</strong>，所有请求均已放行。
            观察期间检测到 <strong>{learning.would_block_count}</strong> 条潜在攻击（如开启保护将被拦截），
            <a href="#/learning" className="banner-link">查看模拟拦截详情 →</a>
          </span>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h3>日志查看</h3>
          <div className="filter-group">
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

          {/* P1-06 修复：加载失败时显示错误提示和重试按钮，区分"加载失败"和"无数据" */}
          {loadError && (
            <div className="alert-banner alert-danger" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <AlertTriangle size={18} strokeWidth={1.5} />
                <span>{loadError}</span>
              </span>
              <button className="btn btn-sm btn-secondary" onClick={() => fetchLogs()}>
                <RefreshCw size={14} strokeWidth={1.5} /> 重试
              </button>
            </div>
          )}

          {loading && entries.length === 0 ? (
            <div className="empty-state">加载中...</div>
          ) : !loadError && entries.length === 0 ? (
            <div className="empty-state">暂无日志记录</div>
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
          )}

          {totalPages > 1 && (
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
