import { useEffect, useState, useCallback } from 'react'
import { api } from '../services/api'

interface AuditEntry {
  id: number; timestamp: string; session_id: string
  event: string; text_preview: string; allowed: boolean
  reason: string | null; stage: string | null; latency_ms: number
  model_id: string | null; routed_to: string | null
  client_ip?: string; current_hash?: string
}

export default function AuditLogs() {
  const [logs, setLogs] = useState<AuditEntry[]>([])
  const [pgConnected, setPgConnected] = useState(false)
  const [chainVerified, setChainVerified] = useState<boolean | null>(null)
  const [error, setError] = useState('')
  const [verifying, setVerifying] = useState(false)

  const fetchLogs = useCallback(async () => {
    try {
      // 优先使用真实审计日志端点（需 PostgreSQL），降级使用 stats 快照
      const resp = await api.getAudit()
      if (resp.connected && resp.records.length > 0) {
        setPgConnected(true)
        setLogs(resp.records.map((r: any) => ({
          id: r.id, timestamp: r.timestamp, session_id: r.session_id,
          event: r.event, text_preview: r.text_preview || '', allowed: r.allowed,
          reason: r.reason, stage: r.stage, latency_ms: r.latency_ms,
          model_id: r.model_id, routed_to: r.routed_to,
          client_ip: r.client_ip, current_hash: r.current_hash,
        })))
      } else {
        setPgConnected(false)
        // 降级：stats 快照 + 内存中的 protect 调用记录
        const s = await api.getStats()
        const entry: AuditEntry = {
          id: Date.now(), timestamp: new Date().toISOString(),
          session_id: '-', event: 'stats_snapshot', text_preview: '',
          allowed: true, reason: null, stage: null, latency_ms: 0,
          model_id: null, routed_to: null,
        }
        setLogs(prev => [entry, ...prev.slice(0, 49)])
      }
      setError('')
    } catch (e) { setError(String(e)) }
  }, [])

  const verifyChain = async () => {
    setVerifying(true)
    try {
      const r = await api.verifyAuditChain()
      setChainVerified(r.valid)
      if (!r.valid) {
        setError(`哈希链断裂: ${r.reason || '未知原因'}`)
      }
    } catch (e) { setError(String(e)) } finally { setVerifying(false) }
  }

  useEffect(() => { fetchLogs(); const t = setInterval(fetchLogs, 10000); return () => clearInterval(t) }, [fetchLogs])

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <h2 style={{ fontSize: 18, fontWeight: 600 }}>审计日志</h2>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          {/* PostgreSQL 连接状态 */}
          <span style={{
            padding: '2px 8px', borderRadius: 4, fontSize: 11,
            background: pgConnected ? '#166534' : '#334155',
            color: pgConnected ? '#4ade80' : '#64748b',
          }}>
            {pgConnected ? 'PostgreSQL 已连接' : '内存模式'}
          </span>
          {/* 哈希链验证 */}
          {pgConnected && (
            <button
              onClick={verifyChain}
              disabled={verifying}
              style={{
                padding: '4px 12px', background: '#334155', border: '1px solid #475569',
                borderRadius: 4, fontSize: 12, color: '#38bdf8', cursor: verifying ? 'not-allowed' : 'pointer',
              }}
            >
              {verifying ? '验证中...' : chainVerified === null ? '验证哈希链' : chainVerified ? '哈希链完整' : '哈希链断裂!'}
            </button>
          )}
          <span style={{ fontSize: 13, color: '#64748b' }}>
            自动刷新 (10s) | <button onClick={fetchLogs} style={{ background: '#334155', border: 'none', color: '#38bdf8', borderRadius: 4, padding: '2px 8px', cursor: 'pointer' }}>立即刷新</button>
          </span>
        </div>
      </div>

      {error && <div style={{ padding: 12, marginBottom: 16, background: '#7f1d1d33', borderRadius: 6, fontSize: 13, color: '#f87171' }}>{error}</div>}

      <div style={{ background: '#1e293b', borderRadius: 8, border: '1px solid #334155', overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ background: '#0f172a' }}>
              {['时间', '事件', '文本预览', '结果', '延迟', '路由目标'].map(h => (
                <th key={h} style={{ padding: '10px 12px', textAlign: 'left', fontWeight: 600, color: '#94a3b8', borderBottom: '1px solid #334155' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {logs.length === 0 && !error && (
              <tr><td colSpan={6} style={{ padding: 32, textAlign: 'center', color: '#64748b' }}>
                {pgConnected ? '暂无审计记录。在安全检测页面执行测试后将出现在这里。' : 'PostgreSQL 未连接，显示内存统计快照。启用方式: XUANDUN_PG_ENABLED=1'}
              </td></tr>
            )}
            {logs.map(l => (
              <tr key={l.id} style={{ borderBottom: '1px solid #1e293b' }}>
                <td style={{ padding: '8px 12px', color: '#64748b', whiteSpace: 'nowrap' }}>
                  {new Date(l.timestamp).toLocaleTimeString('zh-CN')}
                </td>
                <td style={{ padding: '8px 12px' }}>{l.event}</td>
                <td style={{ padding: '8px 12px', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{l.text_preview || '-'}</td>
                <td style={{ padding: '8px 12px' }}>
                  <span style={{ padding: '2px 6px', borderRadius: 4, fontSize: 11, background: l.allowed ? '#166534' : '#7f1d1d', color: l.allowed ? '#4ade80' : '#f87171' }}>
                    {l.allowed ? '放行' : '拦截'}
                  </span>
                </td>
                <td style={{ padding: '8px 12px', color: '#94a3b8' }}>{l.latency_ms?.toFixed(1)}ms</td>
                <td style={{ padding: '8px 12px', color: '#64748b' }}>{l.routed_to || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div style={{ marginTop: 24, padding: 20, background: '#1e293b', borderRadius: 8, border: '1px solid #334155', fontSize: 13, color: '#94a3b8' }}>
        <strong style={{ color: '#e2e8f0' }}>审计日志说明：</strong>
        <ul style={{ marginTop: 8, paddingLeft: 20, display: 'flex', flexDirection: 'column', gap: 6 }}>
          <li>启用 PostgreSQL 后，每条请求的完整审计记录（含 SHA256 哈希链）将持久化到 <code>audit_logs</code> 表。</li>
          <li>哈希链验证可确认审计日志未被篡改——每条记录 SHA256 链接前一条，断裂即告警。</li>
          <li>启用方式：环境变量 <code>XUANDUN_PG_ENABLED=1</code> 并配置 <code>XUANDUN_PG_DSN</code>。</li>
        </ul>
      </div>
    </div>
  )
}
