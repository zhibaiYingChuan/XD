import { useRef, useState } from 'react'

interface Props {
  onAuth: (key: string) => void
}

export default function Login({ onAuth }: Props) {
  const [key, setKey] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  // 网关端 P1 修复「登录双提交」：state 更新是异步的，快速连点/连按 Enter 时
  // loading 闭包值尚未翻转，会重复发起验证请求 —— 用 ref 同步防重入
  const submittingRef = useRef(false)

  const handleSubmit = async (e: React.FormEvent | React.KeyboardEvent) => {
    e.preventDefault()
    if (submittingRef.current) return
    if (!key.trim()) { setError('请输入 API Key'); return }
    submittingRef.current = true
    setLoading(true)
    setError('')
    try {
      // 用 /api/v1/stats（管理端点）验证 key
      const resp = await fetch('/api/v1/stats', { headers: { 'X-API-Key': key } })
      if (!resp.ok) {
        if (resp.status === 401) { setError('API Key 无效'); return }
        if (resp.status === 403) { setError('该密钥无管理权限'); return }
        if (resp.status === 503) {
          setError('网关未配置管理员密钥。请在启动环境设置 XUANDUN_ADMIN_KEY 后重启网关。')
          return
        }
        throw new Error(`HTTP ${resp.status}`)
      }
      onAuth(key)
    } catch (e) {
      setError(`验证失败: ${e}`)
    } finally {
      submittingRef.current = false
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh', background: '#0f172a', display: 'flex',
      alignItems: 'center', justifyContent: 'center',
    }}>
      <form onSubmit={handleSubmit} style={{
        width: 400, background: '#1e293b', borderRadius: 12, padding: 40,
        border: '1px solid #334155',
      }}>
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <img src="/logo.png" alt="玄盾" style={{ width: 56, height: 56, marginBottom: 8, objectFit: 'contain' }} />
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0', margin: 0 }}>
            <span style={{ color: '#38bdf8' }}>玄盾</span> AI安全网关
          </h1>
          <p style={{ fontSize: 13, color: '#64748b', margin: '12px 0 0' }}>
            管理控制台 · 请输入 API Key 登录
          </p>
        </div>

        <div style={{ marginBottom: 20 }}>
          <input
            type="password"
            value={key}
            onChange={(e) => { setKey(e.target.value); setError('') }}
            onKeyDown={(e) => { if (e.key === 'Enter') handleSubmit(e) }}
            placeholder="API Key"
            autoFocus
            disabled={loading}
            style={{
              width: '100%', boxSizing: 'border-box',
              padding: '12px 16px', background: '#0f172a', color: '#e2e8f0',
              border: `1px solid ${error ? '#f87171' : '#334155'}`,
              borderRadius: 8, fontSize: 15, fontFamily: 'monospace',
              outline: 'none',
            }}
          />
          {error && <p style={{ color: '#f87171', fontSize: 13, margin: '8px 0 0' }}>{error}</p>}
        </div>

        <button
          type="submit"
          disabled={loading}
          style={{
            width: '100%', padding: '12px', background: loading ? '#1e3a5f' : '#1d4ed8',
            color: '#fff', border: 'none', borderRadius: 8, fontSize: 15, fontWeight: 600,
            cursor: loading ? 'not-allowed' : 'pointer',
          }}
        >
          {loading ? '验证中...' : '登录'}
        </button>

        <p style={{ fontSize: 12, color: '#475569', marginTop: 20, textAlign: 'center', lineHeight: 1.6 }}>
          请输入<b style={{ color: '#64748b' }}>管理密钥</b>登录。<br />
          管理密钥通过启动环境变量设置：<br />
          <code style={{ background: '#0f172a', padding: '2px 6px', borderRadius: 3 }}>XUANDUN_ADMIN_KEY</code><br />
          <span style={{ color: '#475569' }}>未配置时管理端点拒绝访问（安全默认）</span>
        </p>
      </form>
    </div>
  )
}
