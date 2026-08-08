import { useEffect, useState, useCallback } from 'react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Area, AreaChart } from 'recharts'
import { api, Stats, Health, Status } from '../services/api'

type DataPoint = { time: string; blocks: number; passes: number; latency: number }

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [health, setHealth] = useState<Health | null>(null)
  const [status, setStatus] = useState<Status | null>(null)
  const [history, setHistory] = useState<DataPoint[]>([])
  const [error, setError] = useState('')

  const fetchAll = useCallback(async () => {
    try {
      const [s, h, st] = await Promise.all([api.getStats(), api.getHealth(), api.getStatus()])
      setStats(s); setHealth(h); setStatus(st); setError('')
      setHistory(prev => {
        const next = [...prev, { time: new Date().toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' }), blocks: s.blocks_total, passes: s.passes_total, latency: s.p50_latency_ms }]
        return next.length > 30 ? next.slice(-30) : next
      })
    } catch (e) { setError(String(e)) }
  }, [])

  useEffect(() => { fetchAll(); const t = setInterval(fetchAll, 5000); return () => clearInterval(t) }, [fetchAll])

  const card = (label: string, value: string | number, unit: string, color: string) => (
    <div style={{ background: '#1e293b', borderRadius: 8, padding: '20px', border: '1px solid #334155' }}>
      <div style={{ fontSize: 13, color: '#94a3b8', marginBottom: 8 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700, color }}>{value}<span style={{ fontSize: 14, fontWeight: 400, color: '#64748b', marginLeft: 4 }}>{unit}</span></div>
    </div>
  )

  if (error) return <div style={{ padding: 24, color: '#f87171' }}>连接网关失败: {error} <button onClick={fetchAll} style={{ marginLeft: 12, padding: '4px 12px', borderRadius: 4, background: '#334155', border: 'none', color: '#e2e8f0', cursor: 'pointer' }}>重试</button></div>

  // 首次加载无数据时显示引导提示
  const isFirstLoad = !stats || stats.requests_total === 0

  return (
    <div>
      {isFirstLoad && (
        <div style={{ marginBottom: 20, padding: '14px 20px', background: '#1e3a5f', borderRadius: 8, border: '1px solid #1d4ed8', fontSize: 13, color: '#93c5fd', display: 'flex', alignItems: 'center', gap: 10 }}>
          <img src="/logo.png" alt="玄盾" style={{ width: 18, height: 18, objectFit: 'contain' }} />
          <span>欢迎使用玄盾 AI安全网关！请在 <a href="/detect" style={{ color: '#38bdf8', textDecoration: 'underline' }}>安全检测</a> 页面输入测试文本验证防护效果，或查看 <a href="/settings" style={{ color: '#38bdf8', textDecoration: 'underline' }}>高级配置</a> 调整防护策略。</span>
        </div>
      )}
      {/* 状态栏 */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 24, alignItems: 'center', fontSize: 13 }}>
        <StatusBadge label="引擎" ok={health?.engine_ready} detail={health?.version} />
        <StatusBadge label="Redis" ok={status?.redis?.connected} detail={status?.redis?.backend} />
        <StatusBadge label="PostgreSQL" ok={status?.postgres?.connected} detail={status?.postgres?.backend} />
        <span style={{ color: '#64748b', marginLeft: 'auto' }}>运行 {stats ? formatUptime(stats.uptime_seconds) : '...'}</span>
      </div>

      {/* 指标卡片 */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
        {card('请求总数', stats?.requests_total ?? 0, '', '#38bdf8')}
        {card('拦截数', stats?.blocks_total ?? 0, '', '#f87171')}
        {card('拦截率', stats?.block_rate?.toFixed(1) ?? '0.0', '%', stats && stats.block_rate > 30 ? '#f87171' : '#4ade80')}
        {card('P95 延迟', stats?.p95_latency_ms?.toFixed(2) ?? '0.00', 'ms', '#a78bfa')}
      </div>

      {/* 趋势图 */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 24 }}>
        <Panel title="请求趋势">
          <ResponsiveContainer width="100%" height={240}>
            <AreaChart data={history}>
              <defs><linearGradient id="colorBlocks" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#f87171" stopOpacity={0.3}/><stop offset="95%" stopColor="#f87171" stopOpacity={0}/></linearGradient></defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
              <YAxis stroke="#64748b" fontSize={11} />
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 6, fontSize: 12 }} />
              <Area type="monotone" dataKey="blocks" stroke="#f87171" fill="url(#colorBlocks)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </Panel>
        <Panel title="P50 延迟趋势 (ms)">
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={history}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
              <YAxis stroke="#64748b" fontSize={11} />
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 6, fontSize: 12 }} />
              <Line type="monotone" dataKey="latency" stroke="#38bdf8" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </Panel>
      </div>

      {/* 底部信息 */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Panel title="引擎状态">
          {health && (
            <div style={{ fontSize: 13, display: 'flex', flexDirection: 'column', gap: 8 }}>
              <Row label="版本" value={health.version} />
              <Row label="状态" value={health.message} />
              <Row label="健康" value={health.status === 'ok' ? '正常' : health.status} color={health.status === 'ok' ? '#4ade80' : '#f87171'} />
            </div>
          )}
        </Panel>
        <Panel title="集群信息">
          {status && (
            <div style={{ fontSize: 13, display: 'flex', flexDirection: 'column', gap: 8 }}>
              <Row label="路由策略" value={status.router.strategy} />
              <Row label="模型数" value={String(status.router.model_count)} />
              <Row label="全局计数器" value={Object.entries(status.global_counters).map(([k, v]) => `${k}=${v}`).join(', ') || '无'} />
            </div>
          )}
        </Panel>
      </div>
    </div>
  )
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ background: '#1e293b', borderRadius: 8, border: '1px solid #334155', overflow: 'hidden' }}>
      <div style={{ padding: '12px 16px', fontSize: 14, fontWeight: 600, color: '#94a3b8', borderBottom: '1px solid #334155' }}>{title}</div>
      <div style={{ padding: 16 }}>{children}</div>
    </div>
  )
}

function Row({ label, value, color }: { label: string; value: string; color?: string }) {
  return <div style={{ display: 'flex', justifyContent: 'space-between' }}><span style={{ color: '#64748b' }}>{label}</span><span style={{ color: color || '#e2e8f0' }}>{value}</span></div>
}

function StatusBadge({ label, ok, detail }: { label: string; ok?: boolean; detail?: string }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '4px 10px', background: '#1e293b', borderRadius: 4, border: '1px solid #334155' }}>
      <span style={{ width: 8, height: 8, borderRadius: 4, background: ok ? '#4ade80' : '#f87171' }} />
      {label}
      <span style={{ color: '#64748b' }}>{detail || '...'}</span>
    </span>
  )
}

function formatUptime(s: number): string {
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60)
  return h > 0 ? `${h}h ${m}m` : `${m}m ${Math.floor(s % 60)}s`
}
