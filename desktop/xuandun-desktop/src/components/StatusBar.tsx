import { useState, useEffect } from 'react';
import { api, LearningStatus } from '../services/tauriApi';

export default function StatusBar() {
  const [status, setStatus] = useState<LearningStatus | null>(null);

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const s = await api.getLearningStatus();
        setStatus(s);
      } catch {
        // ignore
      }
    };
    fetchStatus();
    const interval = setInterval(fetchStatus, 3000);
    return () => clearInterval(interval);
  }, []);

  if (!status) return null;

  const isObserving = status.mode === 'observing';
  const progress = Math.round(status.learning_progress * 100);
  const safeProto = status.safe_prototypes;
  const attackProto = status.attack_prototypes;

  return (
    <div className={`status-bar ${isObserving ? 'status-bar-observing' : 'status-bar-protecting'}`}>
      <div className="status-bar-left">
        <span className={`status-bar-dot ${isObserving ? 'dot-observing' : 'dot-protecting'}`}></span>
        <span className="status-bar-mode">
          {isObserving ? '🟡 观察模式（学习中）' : '🛡️ 保护模式'}
        </span>
        {isObserving && (
          <>
            <span className="status-bar-progress-text">
              已学习 {status.sample_count} / {status.min_samples_for_switch} 条 ({progress}%)
            </span>
            <div className="status-bar-progress-bar">
              <div className="status-bar-progress-fill" style={{ width: `${progress}%` }}></div>
            </div>
          </>
        )}
      </div>
      <div className="status-bar-right">
        <span className="status-bar-stat">安全原型: {safeProto}</span>
        <span className="status-bar-stat">攻击原型: {attackProto}</span>
        {isObserving && status.would_block_count > 0 && (
          <span className="status-bar-stat status-bar-warn">
            模拟拦截: {status.would_block_count}
          </span>
        )}
      </div>
    </div>
  );
}
