import { useState, useEffect, useCallback, useRef } from 'react';
import { api, AgentInfo, formatInvokeError } from '../services/tauriApi';
import { RefreshCw, AlertTriangle, CheckCircle } from 'lucide-react';

const MODE_LABELS: Record<string, string> = {
  high_security: '高安全',
  balanced: '平衡',
  low_false_positive: '低误报',
};

export default function Agents() {
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // P1-02 修复：Agent 防护策略切换状态，避免静默失败
  const [switchingAgent, setSwitchingAgent] = useState<string | null>(null);
  const [policyMessage, setPolicyMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  // P1-14 修复：标记用户正在编辑的 agent，定时刷新时不覆盖该行的 policy_mode
  const editingAgentRef = useRef<string | null>(null);
  // P1-14 修复：使用 ref 镜像 agents，避免 fetchAgents 依赖 agents 导致定时器频繁重建
  const agentsRef = useRef<AgentInfo[]>([]);
  agentsRef.current = agents;

  const fetchAgents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await api.discoverAgents();
      // P1-14 修复：如果用户正在编辑某个 agent 的策略，保留本地编辑状态避免被打断
      if (editingAgentRef.current) {
        const editingLocal = agentsRef.current.find(a => a.name === editingAgentRef.current);
        if (editingLocal) {
          const idx = list.findIndex(a => a.name === editingAgentRef.current);
          if (idx >= 0) {
            list[idx] = { ...list[idx], policy_mode: editingLocal.policy_mode };
          }
        }
      }
      setAgents(list);
    } catch (e) {
      setError(formatInvokeError(e, '发现 Agent'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAgents();
    const interval = setInterval(fetchAgents, 10000);
    return () => clearInterval(interval);
  }, [fetchAgents]);

  // P1-02 修复：策略切换增加 loading + 错误反馈 + 成功提示
  const handlePolicyChange = async (agentName: string, mode: string) => {
    setSwitchingAgent(agentName);
    setPolicyMessage(null);
    try {
      await api.setConfig(`agent_policy_${agentName}`, mode);
      setAgents(prev => prev.map(a =>
        a.name === agentName ? { ...a, policy_mode: mode } : a
      ));
      setPolicyMessage({ type: 'success', text: `${agentName} 策略已切换为 ${MODE_LABELS[mode] || mode}` });
      // 3 秒后自动清除成功提示
      setTimeout(() => setPolicyMessage(null), 3000);
    } catch (e) {
      // P1-02 修复：不再静默吞错，回滚 select 视觉状态并提示用户
      setPolicyMessage({ type: 'error', text: formatInvokeError(e, `${agentName} 策略切换`) });
      // 触发 agents 重新拉取以回滚 select 显示
      fetchAgents();
    } finally {
      setSwitchingAgent(null);
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
              {loading ? '刷新中...' : (<><RefreshCw size={16} strokeWidth={1.5} /> 刷新</>)}
            </button>
          </div>
        </div>
        <div className="card-body">
          {error && (
            <div className="alert-banner alert-danger">
              <span className="alert-icon"><AlertTriangle size={18} strokeWidth={1.5} /></span>
              <span>{error}</span>
            </div>
          )}

          {/* P1-02 修复：策略切换反馈提示 */}
          {policyMessage && (
            <div className={`alert-banner ${policyMessage.type === 'success' ? 'alert-success' : 'alert-danger'}`}>
              <span className="alert-icon">
                {policyMessage.type === 'success'
                  ? <CheckCircle size={18} strokeWidth={1.5} />
                  : <AlertTriangle size={18} strokeWidth={1.5} />}
              </span>
              <span>{policyMessage.text}</span>
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
                        onFocus={() => { editingAgentRef.current = agent.name; }}
                        onBlur={() => { editingAgentRef.current = null; }}
                        disabled={switchingAgent === agent.name}
                        style={{
                          padding: '2px 6px',
                          borderRadius: 'var(--radius-sm)',
                          border: '1px solid var(--border)',
                          background: 'var(--bg-card)',
                          color: 'var(--text-primary)',
                          fontSize: '0.8em',
                          opacity: switchingAgent === agent.name ? 0.6 : 1,
                          cursor: switchingAgent === agent.name ? 'wait' : 'pointer',
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
