import { useEffect, useState, useCallback } from 'react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Area, AreaChart } from 'recharts'
import { api, Stats, Health, Status } from '../services/api'

type DataPoint = { time: string; blocks: number; passes: number; latency: number; _bt: number; _pt: number }

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [health, setHealth] = useState<Health | null>(null)
  const [status, setStatus] = useState<Status | null>(null)
  const [history, setHistory] = useState<DataPoint[]>([])
  const [error, setError] = useState('')
  const [reportOpen, setReportOpen] = useState(false)

  // 网关端 P1 修复「仪表盘单点白屏」：三个请求任一失败不再导致整页错误，
  // 改用 allSettled 部分容错 —— 成功的部分照常渲染，失败的在顶部警告条提示
  const fetchAll = useCallback(async () => {
    const results = await Promise.allSettled([api.getStats(), api.getHealth(), api.getStatus()])
    const errs: string[] = []
    if (results[0].status === 'fulfilled') {
      const s = results[0].value
      setStats(s)
      // 网关端 P1 修复「趋势图画累计值」：blocks_total/passes_total 是单调累计计数器，
      // 直接画会一直递增失真，改为画相邻两次采样之间的增量（每周期新增量）
      setHistory(prev => {
        const last = prev[prev.length - 1]
        const dBlocks = last ? Math.max(0, s.blocks_total - last._bt) : 0
        const dPasses = last ? Math.max(0, s.passes_total - last._pt) : 0
        const next: DataPoint[] = [...prev, {
          time: new Date().toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
          blocks: dBlocks, passes: dPasses, latency: s.p50_latency_ms,
          _bt: s.blocks_total, _pt: s.passes_total,
        }]
        return next.length > 30 ? next.slice(-30) : next
      })
    } else {
      errs.push(`统计数据加载失败: ${String((results[0] as PromiseRejectedResult).reason)}`)
    }
    if (results[1].status === 'fulfilled') setHealth(results[1].value)
    else errs.push(`引擎健康: ${String((results[1] as PromiseRejectedResult).reason)}`)
    if (results[2].status === 'fulfilled') setStatus(results[2].value)
    else errs.push(`集群状态: ${String((results[2] as PromiseRejectedResult).reason)}`)
    setError(errs.join('；'))
  }, [])

  useEffect(() => { fetchAll(); const t = setInterval(fetchAll, 5000); return () => clearInterval(t) }, [fetchAll])

  const card = (label: string, value: string | number, unit: string, color: string) => (
    <div style={{ background: '#1e293b', borderRadius: 8, padding: '20px', border: '1px solid #334155' }}>
      <div style={{ fontSize: 13, color: '#94a3b8', marginBottom: 8 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700, color }}>{value}<span style={{ fontSize: 14, fontWeight: 400, color: '#64748b', marginLeft: 4 }}>{unit}</span></div>
    </div>
  )

  // 单点白屏修复配套：错误改为顶部警告条（部分数据仍可渲染），仅完全无数据时显示重试大块
  if (error && !stats && !health && !status) {
    return (
      <div style={{ padding: 24, color: '#f87171' }}>
        连接网关失败: {error}
        <button onClick={fetchAll} style={{ marginLeft: 12, padding: '4px 12px', borderRadius: 4, background: '#334155', border: 'none', color: '#e2e8f0', cursor: 'pointer' }}>重试</button>
      </div>
    )
  }

  // 首次加载无数据时显示引导提示
  const isFirstLoad = !stats || stats.requests_total === 0

  return (
    <div>
      {/* 部分加载失败警告条（数据仍可用的降级展示） */}
      {error && (
        <div style={{ marginBottom: 20, padding: '10px 16px', background: '#7f1d1d33', borderRadius: 8, border: '1px solid #7f1d1d', fontSize: 13, color: '#fca5a5', display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ flex: 1 }}>{error}</span>
          <button onClick={fetchAll} style={{ padding: '2px 10px', borderRadius: 4, background: '#334155', border: 'none', color: '#e2e8f0', cursor: 'pointer', fontSize: 12 }}>重试</button>
        </div>
      )}
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
        <button onClick={() => setReportOpen(true)} style={{ padding: '4px 14px', borderRadius: 6, background: '#334155', border: '1px solid #475569', color: '#e2e8f0', cursor: 'pointer', fontSize: 13 }}>生成报告</button>
      </div>

      {/* 指标卡片 */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
        {card('检测总数', stats?.requests_total ?? 0, '', '#38bdf8')}
        {card('拦截数', stats?.blocks_total ?? 0, '', '#f87171')}
        {card('拦截率', stats?.block_rate?.toFixed(1) ?? '0.0', '%', stats && stats.block_rate > 30 ? '#f87171' : '#4ade80')}
        {card('P95 延迟', stats?.p95_latency_ms?.toFixed(2) ?? '0.00', 'ms', '#a78bfa')}
      </div>

      {/* 趋势图 */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 24 }}>
        <Panel title="检测拦截趋势">
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

      {/* 报表导出对话框 */}
      {reportOpen && <ReportDialog onClose={() => setReportOpen(false)} />}
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

function ReportDialog({ onClose }: { onClose: () => void }) {
  const today = new Date().toISOString().slice(0, 10)
  const weekAgo = new Date(Date.now() - 6 * 86400000).toISOString().slice(0, 10)
  const [startDate, setStartDate] = useState(weekAgo)
  const [endDate, setEndDate] = useState(today)
  const [format, setFormat] = useState('csv')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<any>(null)
  const [err, setErr] = useState('')

  const quick = (days: number) => {
    const end = new Date()
    const start = new Date(end)
    start.setDate(start.getDate() - days)
    setStartDate(start.toISOString().slice(0, 10))
    setEndDate(end.toISOString().slice(0, 10))
  }

  const generate = async () => {
    setLoading(true); setErr('')
    try {
      const r = await api.exportReport({ start_date: startDate, end_date: endDate, format, sections: ['summary'] })
      setResult(r)
    } catch (e: any) { setErr(String(e?.message || e)) }
    finally { setLoading(false) }
  }

  const download = () => {
    // G-P0-1 修复：使用后端返回的真实报告内容生成文件（此前硬编码"报告已生成"伪造内容属于假报告）
    if (!result?.content) return
    const mimeMap: Record<string, string> = {
      csv: 'text/csv', json: 'application/json', html: 'text/html', md: 'text/markdown',
    }
    const blob = new Blob(['\ufeff' + result.content], { type: `${mimeMap[format] || 'text/plain'};charset=utf-8` })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = `xuandun_report.${format}`; a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 9999, display: 'flex', alignItems: 'center', justifyContent: 'center' }} onClick={onClose}>
      <div style={{ background: '#1e293b', border: '1px solid #475569', borderRadius: 12, padding: 24, maxWidth: 460, width: '90%' }} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <h2 style={{ fontSize: 16, fontWeight: 600, color: '#e2e8f0', margin: 0 }}>导出安全报告</h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: 18 }}>x</button>
        </div>

        {err && <div style={{ color: '#f87171', fontSize: 13, marginBottom: 12 }}>{err}</div>}

        {/* 快捷按钮 */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          {[{l:'今日',d:0},{l:'本周',d:6},{l:'本月',d:29}].map(({l,d}) => (
            <button key={l} onClick={() => quick(d)} style={{ padding: '4px 12px', borderRadius: 6, border: '1px solid #475569', background: '#334155', color: '#94a3b8', cursor: 'pointer', fontSize: 12 }}>{l}</button>
          ))}
        </div>

        {/* 日期 */}
        <div style={{ display: 'flex', gap: 12, marginBottom: 12 }}>
          <div style={{ flex: 1 }}>
            <label style={{ fontSize: 12, color: '#94a3b8' }}>开始日期</label>
            <input type="date" value={startDate} onChange={e => setStartDate(e.target.value)} style={{ width: '100%', padding: '6px', borderRadius: 6, background: '#0f172a', border: '1px solid #475569', color: '#e2e8f0' }} />
          </div>
          <div style={{ flex: 1 }}>
            <label style={{ fontSize: 12, color: '#94a3b8' }}>结束日期</label>
            <input type="date" value={endDate} onChange={e => setEndDate(e.target.value)} style={{ width: '100%', padding: '6px', borderRadius: 6, background: '#0f172a', border: '1px solid #475569', color: '#e2e8f0' }} />
          </div>
        </div>

        {/* 格式 */}
        <div style={{ marginBottom: 16 }}>
          <label style={{ fontSize: 12, color: '#94a3b8', display: 'block', marginBottom: 6 }}>导出格式</label>
          <div style={{ display: 'flex', gap: 8 }}>
            {['csv','json','html','md'].map(f => (
              <button key={f} onClick={() => setFormat(f)} style={{ padding: '6px 14px', borderRadius: 6, border: format === f ? '1px solid #38bdf8' : '1px solid #475569', background: format === f ? '#0c4a6e' : '#334155', color: format === f ? '#38bdf8' : '#94a3b8', cursor: 'pointer', fontSize: 12, textTransform: 'uppercase' }}>{f}</button>
            ))}
          </div>
        </div>

        {/* 生成结果 */}
        {result && (
          <div style={{ background: '#0f172a', borderRadius: 8, padding: 12, marginBottom: 12, fontSize: 13 }}>
            <div style={{ color: '#4ade80', marginBottom: 6 }}>报告已生成 ({(result.file_size / 1024).toFixed(1)} KB)</div>
            <div style={{ color: '#94a3b8' }}>检测总数: {result.summary?.total_requests ?? 0} | 拦截: {result.summary?.total_blocked ?? 0} | 拦截率: {result.summary?.block_rate ?? 0}%</div>
            <div style={{ color: '#64748b', marginTop: 4 }}>手动检测: {result.summary?.manual_requests ?? 0} 条 (不计入主指标)</div>
          </div>
        )}

        {/* 按钮 */}
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={{ padding: '8px 16px', borderRadius: 6, border: '1px solid #475569', background: 'transparent', color: '#94a3b8', cursor: 'pointer' }}>取消</button>
          {result && <button onClick={download} style={{ padding: '8px 16px', borderRadius: 6, border: 'none', background: '#059669', color: '#fff', cursor: 'pointer' }}>下载</button>}
          <button onClick={generate} disabled={loading} style={{ padding: '8px 16px', borderRadius: 6, border: 'none', background: loading ? '#475569' : '#2563eb', color: '#fff', cursor: loading ? 'not-allowed' : 'pointer' }}>{loading ? '生成中...' : '生成报告'}</button>
        </div>
      </div>
    </div>
  )
}

function formatUptime(s: number): string {
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60)
  return h > 0 ? `${h}h ${m}m` : `${m}m ${Math.floor(s % 60)}s`
}
