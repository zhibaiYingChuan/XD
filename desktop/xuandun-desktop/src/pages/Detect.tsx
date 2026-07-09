import { useState } from 'react';
import { api, ProtectResponse } from '../services/tauriApi';

export default function Detect() {
  const [text, setText] = useState('');
  const [mode, setMode] = useState('balanced');
  const [result, setResult] = useState<ProtectResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleDetect = async () => {
    if (!text.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.protect(text, 'default', mode);
      setResult(res);
    } catch {
      setError('检测失败，请检查引擎状态');
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  const modes = [
    { key: 'high_security', label: '高安全' },
    { key: 'balanced', label: '平衡' },
    { key: 'low_false_positive', label: '低误报' },
  ];

  return (
    <div className="page detect-page">
      <div className="card">
        <div className="card-header">
          <h3>安全检测</h3>
        </div>
        <div className="card-body">
          <div className="form-group">
            <label className="form-label">检测模式</label>
            <div className="mode-selector">
              {modes.map((m) => (
                <button
                  key={m.key}
                  className={`mode-btn ${mode === m.key ? 'active' : ''}`}
                  onClick={() => setMode(m.key)}
                >
                  {m.label}
                </button>
              ))}
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">输入文本</label>
            <textarea
              className="form-textarea"
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="输入要检测的文本内容..."
              rows={5}
            />
          </div>

          <button
            className="btn btn-primary"
            onClick={handleDetect}
            disabled={loading || !text.trim()}
          >
            {loading ? '检测中...' : '开始检测'}
          </button>

          {error && (
            <div className="alert-banner alert-danger" style={{ marginTop: 16 }}>
              <span className="alert-icon">⚠️</span>
              <span>{error}</span>
            </div>
          )}

          {result && (
            <div className={`result-card ${result.allowed ? 'pass' : 'block'}`}>
              <div className="result-header">
                <span className="result-icon">{result.allowed ? '✅' : '🚫'}</span>
                <span className="result-text">{result.allowed ? '通过' : '已拦截'}</span>
              </div>
              <div className="result-details">
                <span>信任等级: <span className={`trust-badge trust-${result.trust_level.toLowerCase()}`}>{result.trust_level}</span></span>
                {result.reject_stage && <span>拦截阶段: {result.reject_stage}</span>}
                {result.domain_distance != null && (
                  <span>域距离: {result.domain_distance.toFixed(4)}</span>
                )}
                {result.timing_distance != null && (
                  <span>时序距离: {result.timing_distance.toFixed(4)}</span>
                )}
                {result.fallback && <span className="fallback-tag">回退模式</span>}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
