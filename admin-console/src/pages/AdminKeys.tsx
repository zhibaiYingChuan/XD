import { useEffect, useState, useCallback } from 'react'
import { api } from '../services/api'

interface KeyEntry {
  jti: string
  sub: string
  tier: string
  quota: number
  exp: number
  usage: number
  revoked: boolean
}

const tierLabel: Record<string, string> = {
  basic: '基础版', pro: '专业版', enterprise: '企业版',
}

export default function AdminKeys() {
  const [configured, setConfigured] = useState(false)
  const [keys, setKeys] = useState<KeyEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const r = await api.listKeys()
      setConfigured(r.configured)
      setKeys(r.keys)
      setError('')
    } catch (e: any) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const handleRevoke = async (entry: KeyEntry) => {
    const ok = window.confirm(
      `确认吊销企业「${entry.sub || entry.jti}」的授权（${tierLabel[entry.tier] || entry.tier}）？\n\n吊销后该企业密钥立即失效，不可恢复。请先联系对方确认。`)
    if (!ok) return
    try {
      await api.revokeKey(entry.jti)
      setMsg(`已吊销企业「${entry.sub || entry.jti}」的授权`)
      await load()
    } catch (e: any) {
      setError(String(e))
    }
  }

  const fmtExp = (ts: number) =>
    ts ? new Date(ts * 1000).toLocaleString() : '不限'

  const fmtTier = (t: string) => tierLabel[t] || t || '—'

  return (
    <div>
      <h2 style={{ fontSize: 20, fontWeight: 700, margin: '0 0 4px' }}>企业授权（API Key）</h2>
      <p style={{ fontSize: 13, color: '#64748b', margin: '0 0 24px' }}>
        企业 API Key 由玄盾（供应商）离线签发，用于企业客户接入本网关。网关只负责验签与计量，不提供自建。
        此处仅展示已在本网关产生流量的企业授权及其用量、有效期与吊销状态。
      </p>

      {(error || msg) && (
        <div style={{
          padding: '10px 14px', borderRadius: 6, marginBottom: 16, fontSize: 13,
          background: error ? '#3f1d1d' : '#13243b',
          border: `1px solid ${error ? '#f87171' : '#3b82f6'}`,
          color: error ? '#fca5a5' : '#93c5fd',
        }}>
          {error || msg}
        </div>
      )}

      {!configured && (
        <div style={{
          border: '1px solid #f59e0b', borderRadius: 8, padding: 14, background: '#2a2315', marginBottom: 24,
        }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: '#fbbf24', marginBottom: 6 }}>
            企业密钥公钥未配置
          </div>
          <div style={{ fontSize: 13, color: '#d6c69a', lineHeight: 1.6 }}>
            网关尚未配置用于验签的企业密钥公钥，所有企业 API Key 请求将被拒绝（fail-closed）。
            请设置环境变量 <code style={{ color: '#7dd3fc' }}>XUANDUN_PUBLIC_KEY</code>（公钥内容）
            或 <code style={{ color: '#7dd3fc' }}>XUANDUN_PUBLIC_KEY_PATH</code>（公钥文件路径）后重启网关。
          </div>
        </div>
      )}

      {/* 企业授权列表 */}
      <div style={{ border: '1px solid #334155', borderRadius: 8, overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ background: '#1e293b', color: '#94a3b8', textAlign: 'left' }}>
              <th style={{ padding: '10px 14px' }}>企业</th>
              <th style={{ padding: '10px 14px' }}>套餐</th>
              <th style={{ padding: '10px 14px' }}>有效期至</th>
              <th style={{ padding: '10px 14px' }}>用量/配额</th>
              <th style={{ padding: '10px 14px' }}>状态</th>
              <th style={{ padding: '10px 14px' }}></th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={6} style={{ padding: 20, textAlign: 'center', color: '#64748b' }}>加载中...</td></tr>
            )}
            {!loading && keys.length === 0 && (
              <tr><td colSpan={6} style={{ padding: 20, textAlign: 'center', color: '#64748b' }}>
                暂无企业授权。企业 API Key 由玄盾离线签发，客户接入本网关后即可在此看到用量记录。
              </td></tr>
            )}
            {keys.map(k => (
              <tr key={k.jti} style={{ borderTop: '1px solid #1e293b', background: k.revoked ? '#111827' : 'transparent' }}>
                <td style={{ padding: '10px 14px', color: '#e2e8f0' }}>{k.sub || '未知企业'}</td>
                <td style={{ padding: '10px 14px' }}>
                  <span style={{
                    padding: '2px 8px', borderRadius: 4, fontSize: 11,
                    background: '#13243b', color: '#93c5fd', border: '1px solid #334155',
                  }}>{fmtTier(k.tier)}</span>
                </td>
                <td style={{ padding: '10px 14px', color: '#94a3b8' }}>{fmtExp(k.exp)}</td>
                <td style={{ padding: '10px 14px', color: '#7dd3fc' }}>
                  {k.usage}{k.quota ? ` / ${k.quota}` : ''}
                </td>
                <td style={{ padding: '10px 14px' }}>
                  <span style={{ color: k.revoked ? '#f87171' : '#4ade80' }}>
                    {k.revoked ? '已吊销' : '有效'}
                  </span>
                </td>
                <td style={{ padding: '10px 14px', textAlign: 'right' }}>
                  {!k.revoked && (
                    <button onClick={() => handleRevoke(k)} style={{
                      padding: '5px 12px', background: '#3f1d1d', color: '#fca5a5',
                      border: '1px solid #7f1d1d', borderRadius: 5, fontSize: 12, cursor: 'pointer',
                    }}>吊销</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
