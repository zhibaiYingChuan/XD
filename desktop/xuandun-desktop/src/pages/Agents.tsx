import { useState, useEffect, useCallback } from 'react';
import { api, AgentInfo } from '../services/tauriApi';

const MODE_LABELS: Record<string, string> = {
  high_security: '高安全',
  balanced: '平衡',
  low_false_positive: '低误报',
};

export default function Agents() {
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchAgents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await api.discoverAgents();
      setAgents(list);
    } catch {
      setError('无法发现 Agent');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAgents();
    const interval = setInterval(fetchAgents, 10000);
    return () => clearInterval(interval);
  }, [fetchAgents]);

  const handlePolicyChange = async (agentName: string, mode: string) => {
    try {
      await api.setConfig(`agent_policy_${agentName}`, mode);
      setAgents(prev => prev.map(a =>
        a.name === agentName ? { ...a, policy_mode: mode } : a
      ));
    } catch {
      // ignore
    }
  };

  const runningCount = agents.filter(a => a.running).length;
  const installedNotRunningCount = agents.filter(a => a.installed && !a.running).length;

  return (
    <div className="page agents-page">
      <div className="card">
        <div className="card-header">
          <h3>Agent 发现</h3>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <span style={{ fontSize: '0.85em', color: 'var(--text-secondary)' }}>
              {runningCount} 个运行中 / {installedNotRunningCount} 个已安装
            </span>
            <button className="btn btn-secondary btn-sm" onClick={fetchAgents} disabled={loading}>
              {loading ? '刷新中...' : '🔄 刷新'}
            </button>
          </div>
        </div>
        <div className="card-body">
          {error && (
            <div className="alert-banner alert-danger">
              <span className="alert-icon">⚠️</span>
              <span>{error}</span>
            </div>
          )}

          {agents.length === 0 && !error && (
            <div className="empty-state">未发现任何 Agent</div>
          )}

          {agents.length > 0 && (
            <table className="data-table">
              <thead>
                <tr>
                  <th>名称</th>
                  <th>进程名</th>
                  <th>PID</th>
                  <th>状态</th>
                  <th>防护策略</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((agent) => (
                  <tr key={agent.name}>
                    <td className="font-medium">{agent.name}</td>
                    <td className="mono">{agent.process_name || '--'}</td>
                    <td className="mono">{agent.pid ?? '--'}</td>
                    <td>
                      <span className="agent-status">
                        {agent.running ? (
                          <>
                            <span className="status-dot dot-online"></span>
                            运行中
                          </>
                        ) : agent.installed ? (
                          <>
                            <span className="status-dot" style={{ background: 'var(--warning)' }}></span>
                            已安装
                          </>
                        ) : (
                          <>
                            <span className="status-dot dot-offline"></span>
                            未安装
                          </>
                        )}
                      </span>
                    </td>
                    <td>
                      <select
                        value={agent.policy_mode || 'balanced'}
                        onChange={(e) => handlePolicyChange(agent.name, e.target.value)}
                        style={{
                          padding: '2px 6px',
                          borderRadius: 'var(--radius-sm)',
                          border: '1px solid var(--border)',
                          background: 'var(--bg-card)',
                          color: 'var(--text-primary)',
                          fontSize: '0.8em',
                        }}
                      >
                        <option value="high_security">{MODE_LABELS.high_security}</option>
                        <option value="balanced">{MODE_LABELS.balanced}</option>
                        <option value="low_false_positive">{MODE_LABELS.low_false_positive}</option>
                      </select>
                    </td>
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
