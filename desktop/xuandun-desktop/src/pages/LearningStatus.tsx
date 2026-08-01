import { useState, useEffect, useCallback } from 'react';
import { api, LearningStatus, formatTrustLevel } from '../services/tauriApi';
// 设计系统规范：图标统一使用 lucide-react，strokeWidth=1.5，禁止 emoji
import {
  CheckCircle, AlertTriangle, BarChart3, Phone, Search,
  ClipboardList, Shield,
} from 'lucide-react';
import { ConfirmModal, useConfirmModal } from '../components/ConfirmModal';

export default function LearningStatusPage() {
  const [status, setStatus] = useState<LearningStatus | null>(null);
  const [details, setDetails] = useState<any>(null);
  const [switching, setSwitching] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const { modalProps: confirmModalProps, confirm } = useConfirmModal();

  const fetchStatus = useCallback(async () => {
    try {
      const s = await api.getLearningStatus();
      setStatus(s);
      const d = await api.getLearningDetails();
      setDetails(d);
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 3000);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  const handleSwitch = async (target: string) => {
    // P1-07 修复：观察模式下样本不足时切换到保护模式，强制二次确认
    if (target === 'protecting' && status && status.mode === 'observing' &&
        status.sample_count < status.min_samples_for_switch) {
      const confirmed = await confirm(
        `当前样本数不足（${status.sample_count}/${status.min_samples_for_switch}）。\n\n` +
        '提前切换到保护模式可能导致：\n' +
        '• 误报率升高（正常请求被误拦截）\n' +
        '• 防护规则不完整\n\n' +
        '建议继续观察模式直到学习完成。确定要强制切换吗？'
      );
      if (!confirmed) return;
    }
    setSwitching(true);
    try {
      await api.switchLearningMode(target);
      setMessage({ type: 'success', text: `已切换到${target === 'protecting' ? '保护' : '观察'}模式` });
      await fetchStatus();
    } catch {
      setMessage({ type: 'error', text: '模式切换失败，请确认引擎正常运行后重试' });
    } finally {
      setSwitching(false);
      setTimeout(() => setMessage(null), 3000);
    }
  };

  if (!status) {
    return <div className="page"><div className="empty-state">加载中...</div></div>;
  }

  const isObserving = status.mode === 'observing';
  const progress = Math.round(status.learning_progress * 100);

  return (
    <div className="page learning-status-page">
      {message && (
        <div className={`alert-banner ${message.type === 'success' ? 'alert-success' : 'alert-danger'}`}>
          <span className="alert-icon">
            {message.type === 'success' ? <CheckCircle size={16} strokeWidth={1.5} /> : <AlertTriangle size={16} strokeWidth={1.5} />}
          </span>
          <span>{message.text}</span>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h3><BarChart3 size={18} strokeWidth={1.5} className="h3-icon" />学习状态</h3>
        </div>
        <div className="card-body">
          <div className="learning-mode-display">
            <span className={`mode-badge ${isObserving ? 'mode-observing' : 'mode-protecting'}`}>
              {isObserving ? (
                <><span className="status-dot dot-observing" /> 观察模式（学习中）</>
              ) : (
                <><Shield size={16} strokeWidth={1.5} style={{ verticalAlign: 'middle' }} /> 保护模式</>
              )}
            </span>
          </div>

          {isObserving && (
            <>
              <div className="learning-progress-section">
                <div className="learning-progress-label">
                  已学习：{status.sample_count} / {status.min_samples_for_switch} 条正常对话
                </div>
                <div className="learning-progress-bar-large">
                  <div className="learning-progress-fill-large" style={{ width: `${progress}%` }}>
                    <span className="learning-progress-text">{progress}%</span>
                  </div>
                </div>
              </div>

              <div className="learning-estimate">
                {progress < 100 ? (
                  <span>还需约 {Math.ceil((status.min_samples_for_switch - status.sample_count) / 10)} 分钟（按当前流量估算）</span>
                ) : (
                  <span><CheckCircle size={16} strokeWidth={1.5} style={{ verticalAlign: 'middle', marginRight: 6 }} />学习完成，已自动切换到保护模式</span>
                )}
              </div>
            </>
          )}

          <div className="learning-prototypes-grid">
            <div className="prototype-card">
              <div className="prototype-icon"><span className="status-dot dot-online" style={{ width: 16, height: 16 }} /></div>
              <div className="prototype-info">
                <div className="prototype-label">安全原型</div>
                <div className="prototype-value">{status.safe_prototypes}</div>
              </div>
            </div>
            <div className="prototype-card">
              <div className="prototype-icon"><span className="status-dot dot-offline" style={{ width: 16, height: 16 }} /></div>
              <div className="prototype-info">
                <div className="prototype-label">攻击原型</div>
                <div className="prototype-value">{status.attack_prototypes}</div>
                {status.builtin_attacks_loaded > 0 && (
                  <div className="prototype-sub">含 {status.builtin_attacks_loaded} 条内置</div>
                )}
              </div>
            </div>
            <div className="prototype-card">
              <div className="prototype-icon"><Phone size={22} strokeWidth={1.5} /></div>
              <div className="prototype-info">
                <div className="prototype-label">总调用数</div>
                <div className="prototype-value">{status.call_count}</div>
              </div>
            </div>
            <div className="prototype-card">
              <div className="prototype-icon"><Search size={22} strokeWidth={1.5} /></div>
              <div className="prototype-info">
                <div className="prototype-label">模拟拦截</div>
                <div className="prototype-value">{status.would_block_count}</div>
              </div>
            </div>
          </div>

          {details && (
            <div className="learning-details-section">
              <h4>原型统计详情</h4>
              <div className="details-grid">
                <div className="detail-item">
                  <span className="detail-label">域字符数：</span>
                  <span className="detail-value">{details.domain_char_count ?? 0}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">拒绝4-gram数：</span>
                  <span className="detail-value">{details.rejected_fourgram_count ?? 0}</span>
                </div>
                {details.recent_input_count !== undefined && (
                  <div className="detail-item">
                    <span className="detail-label">已记录输入：</span>
                    <span className="detail-value">{details.recent_input_count}</span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {details && details.prototype_examples && Object.keys(details.prototype_examples).length > 0 && (
        <div className="card">
          <div className="card-header">
            <h3><ClipboardList size={18} strokeWidth={1.5} className="h3-icon" />原型典型输入示例</h3>
            <span className="card-subtitle">每个安全原型对应的最近输入样本（用于理解学习到的语言模式）</span>
          </div>
          <div className="card-body">
            {Object.entries(details.prototype_examples).map(([protoIdx, examples]: [string, any]) => (
              <div key={protoIdx} className="proto-example-group">
                <div className="proto-example-header">
                  <span className="proto-badge">原型 #{protoIdx}</span>
                  <span className="proto-hit-count">
                    命中 {details.safe_prototypes?.hit_counts?.[parseInt(protoIdx)] ?? 0} 次
                  </span>
                </div>
                <div className="proto-example-list">
                  {examples.map((ex: any, i: number) => (
                    <div key={i} className={`proto-example-item ${ex.decision === 'PASS' ? 'example-pass' : 'example-reject'}`}>
                      <span className="example-text">{ex.text}</span>
                      <span className={`example-decision ${ex.decision === 'PASS' ? 'decision-pass' : 'decision-reject'}`}>
                        {ex.decision === 'PASS' ? '放行' : '拒绝'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {isObserving && status.would_block_preview && status.would_block_preview.length > 0 && (
        <div className="card">
          <div className="card-header">
            <h3><Search size={18} strokeWidth={1.5} className="h3-icon" />模拟拦截预览</h3>
            <span className="card-subtitle">观察模式下，这些请求如果开启保护会被拦截</span>
          </div>
          <div className="card-body">
            <table className="data-table">
              <thead>
                <tr>
                  <th>时间</th>
                  <th>文本摘要</th>
                  <th>信任等级</th>
                  <th>距离</th>
                </tr>
              </thead>
              <tbody>
                {status.would_block_preview.slice().reverse().map((item, i) => (
                  <tr key={i}>
                    <td className="mono">{item.timestamp}</td>
                    <td className="text-preview">{item.text_preview}</td>
                    <td><span className={`trust-badge trust-${(item.trust_level || 'unknown').toLowerCase()}`}>{formatTrustLevel(item.trust_level)}</span></td>
                    <td className="mono">{item.distance}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h3>手动模式切换</h3>
        </div>
        <div className="card-body">
          <div className="mode-switch-buttons">
            <button
              className={`btn ${status.mode === 'observing' ? 'btn-warning' : 'btn-secondary'}`}
              onClick={() => handleSwitch('observing')}
              disabled={switching || status.mode === 'observing'}
            >
              <span className="status-dot dot-observing" style={{ marginRight: 6 }} /> {switching ? '切换中...' : '切换到观察模式'}
            </button>
            <button
              className={`btn ${status.mode === 'protecting' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => handleSwitch('protecting')}
              disabled={switching || status.mode === 'protecting'}
            >
              <Shield size={16} strokeWidth={1.5} style={{ verticalAlign: 'middle', marginRight: 6 }} /> {switching ? '切换中...' : '切换到保护模式'}
            </button>
          </div>
          {isObserving && status.sample_count < status.min_samples_for_switch && (
            <div className="mode-switch-warning">
              <AlertTriangle size={16} strokeWidth={1.5} style={{ verticalAlign: 'middle', marginRight: 6 }} />
              样本不足（{status.sample_count}/{status.min_samples_for_switch}），提前切换到保护模式可能导致误报率升高
            </div>
          )}
        </div>
      </div>
      <ConfirmModal {...confirmModalProps} />
    </div>
  );
}
