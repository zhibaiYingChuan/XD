import { useEffect, useState, useCallback } from 'react'
import { api } from '../services/api'

interface MetricsData {
  requests_total: number; blocks_total: number; passes_total: number
  errors_total: number; block_rate: number
  p50_latency_ms: number; p95_latency_ms: number; uptime_seconds: number
}

interface SnapshotItem {
  id: string; timestamp: string; reason: string; mode: string; sample_count: number
}

// 告警通道字段定义：每个通道的可配置字段（key/label/type/placeholder）
const NOTIFIER_CHANNELS: { name: string; label: string; fields: Array<{ key: string; label: string; type: string; placeholder?: string }> }[] = [
  {
    name: 'dingtalk', label: '钉钉 Webhook',
    fields: [
      { key: 'webhook_url', label: 'Webhook 地址', type: 'url', placeholder: 'https://oapi.dingtalk.com/robot/send?access_token=...' },
      { key: 'secret', label: '加签密钥', type: 'password', placeholder: 'SEC...' },
    ],
  },
  {
    name: 'feishu', label: '飞书 Bot',
    fields: [
      { key: 'webhook_url', label: 'Webhook 地址', type: 'url', placeholder: 'https://open.feishu.cn/open-apis/bot/v2/hook/...' },
      { key: 'secret', label: '签名密钥', type: 'password', placeholder: '可选' },
    ],
  },
  {
    name: 'email', label: '邮件 SMTP',
    fields: [
      { key: 'smtp_host', label: 'SMTP 主机', type: 'text', placeholder: 'smtp.example.com' },
      { key: 'smtp_port', label: '端口', type: 'number', placeholder: '465' },
      { key: 'smtp_user', label: '账号', type: 'text', placeholder: 'alert@example.com' },
      { key: 'smtp_password', label: '密码', type: 'password', placeholder: '授权码' },
      { key: 'from_email', label: '发件人', type: 'email', placeholder: 'alert@example.com' },
      { key: 'to_emails', label: '收件人（逗号分隔）', type: 'text', placeholder: 'ops@example.com' },
    ],
  },
  {
    name: 'webhook', label: 'HTTP Webhook',
    fields: [
      { key: 'url', label: '回调地址', type: 'url', placeholder: 'https://your-server/hook' },
      { key: 'method', label: '请求方法', type: 'text', placeholder: 'POST' },
      { key: 'headers', label: 'Headers（JSON）', type: 'text', placeholder: '{"Authorization":"Bearer ..."}' },
    ],
  },
  {
    name: 'syslog', label: 'Syslog',
    fields: [
      { key: 'host', label: '主机', type: 'text', placeholder: '127.0.0.1' },
      { key: 'port', label: '端口', type: 'number', placeholder: '514' },
      { key: 'protocol', label: '协议', type: 'text', placeholder: 'udp' },
    ],
  },
]

const inputStyle: React.CSSProperties = {
  width: '100%', background: '#0f172a', border: '1px solid #334155', borderRadius: 6,
  padding: '7px 10px', fontSize: 13, color: '#e2e8f0', outline: 'none', boxSizing: 'border-box',
}

export default function Settings() {
  const [metrics, setMetrics] = useState<MetricsData | null>(null)
  const [error, setError] = useState('')
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  // ── A. 输出护栏 / 敏感检测 ──
  const [outputGuardOn, setOutputGuardOn] = useState(true)
  const [sensitiveOn, setSensitiveOn] = useState(true)
  const [guardSaving, setGuardSaving] = useState(false)

  // ── B. 灰度部署 ──
  const [grayRatio, setGrayRatio] = useState(1.0)
  const [graySaving, setGraySaving] = useState(false)

  // ── C. 告警通道 ──
  const [notifiers, setNotifiers] = useState<Record<string, any>>({})
  const [notifierSaving, setNotifierSaving] = useState(false)
  const [testingChannel, setTestingChannel] = useState<string | null>(null)

  // ── D. 配置快照 ──
  const [snapshots, setSnapshots] = useState<SnapshotItem[]>([])
  const [snapshotReason, setSnapshotReason] = useState('')
  const [snapshotSaving, setSnapshotSaving] = useState(false)
  const [restoringId, setRestoringId] = useState<string | null>(null)

  const fetchMetrics = useCallback(async () => {
    try {
      const text = await api.getMetrics()
      const parse = (name: string) => {
        const m = text.match(new RegExp(`${name}\\s+([\\d.]+)`))
        return m ? parseFloat(m[1]) : 0
      }
      setMetrics({
        requests_total: parse('xuandun_requests_total'),
        blocks_total: parse('xuandun_blocks_total'),
        passes_total: parse('xuandun_passes_total'),
        errors_total: parse('xuandun_errors_total'),
        block_rate: parse('xuandun_block_rate'),
        p50_latency_ms: parse('xuandun_latency_p50_ms'),
        p95_latency_ms: parse('xuandun_latency_p95_ms'),
        uptime_seconds: parse('xuandun_uptime_seconds'),
      })
      setError('')
    } catch (e) { setError(String(e)) }
  }, [])

  const showMsg = (type: 'success' | 'error', text: string) => setMessage({ type, text })

  // 加载全部配置状态
  useEffect(() => {
    fetchMetrics()
    const load = async () => {
      // 并行加载，单项失败不阻塞其他（Promise.allSettled）
      const results = await Promise.allSettled([
        api.getGuardrails(),
        api.getGrayRatio(),
        api.getNotifiersConfig(),
        api.listSnapshots(),
      ])
      if (results[0].status === 'fulfilled') {
        setOutputGuardOn(results[0].value.output_guardrail)
        setSensitiveOn(results[0].value.sensitive_leak)
      } else {
        showMsg('error', `输出护栏状态加载失败: ${String(results[0].reason)}`)
      }
      if (results[1].status === 'fulfilled') {
        setGrayRatio(results[1].value.ratio)
      } else {
        showMsg('error', `灰度比例加载失败: ${String(results[1].reason)}`)
      }
      if (results[2].status === 'fulfilled') {
        setNotifiers(results[2].value.channels || {})
      }
      if (results[3].status === 'fulfilled') {
        setSnapshots(results[3].value.snapshots || [])
      }
    }
    load()
  }, [fetchMetrics])

  // A. 保存护栏开关
  const saveGuardrails = async (og?: boolean, sl?: boolean) => {
    if (guardSaving) return
    setGuardSaving(true)
    try {
      const r = await api.setGuardrails({
        ...(og !== undefined ? { output_guardrail: og } : {}),
        ...(sl !== undefined ? { sensitive_leak: sl } : {}),
      })
      setOutputGuardOn(r.output_guardrail)
      setSensitiveOn(r.sensitive_leak)
      showMsg('success', r.message)
    } catch (e) { showMsg('error', `保存护栏配置失败: ${e}`) }
    finally { setGuardSaving(false) }
  }

  // B. 保存灰度比例
  const saveGray = async () => {
    if (graySaving) return
    setGraySaving(true)
    try {
      const r = await api.setGrayRatio(grayRatio)
      setGrayRatio(r.ratio)
      showMsg('success', r.message)
    } catch (e) { showMsg('error', `保存灰度比例失败: ${e}`) }
    finally { setGraySaving(false) }
  }

  // C. 更新某个通道的字段/开关
  const updateNotifierField = (channel: string, field: string, value: any) => {
    setNotifiers(prev => ({ ...prev, [channel]: { ...(prev[channel] || {}), [field]: value } }))
  }
  const saveNotifiers = async () => {
    if (notifierSaving) return
    setNotifierSaving(true)
    try {
      const r = await api.saveNotifiersConfig(notifiers)
      showMsg('success', `告警通道已保存，当前启用 ${r.active_channels} 个通道`)
    } catch (e) { showMsg('error', `保存告警通道失败: ${e}`) }
    finally { setNotifierSaving(false) }
  }
  const testNotifier = async (channel: string) => {
    if (testingChannel) return
    setTestingChannel(channel)
    try {
      const r = await api.testNotifier(channel, notifiers[channel] || {})
      showMsg(r.status === 'ok' ? 'success' : 'error', r.status === 'ok' ? `${channel} 测试告警发送成功` : `${channel} 测试告警发送失败，请检查配置`)
    } catch (e) { showMsg('error', `测试告警失败: ${e}`) }
    finally { setTestingChannel(null) }
  }

  // D. 快照操作
  const createSnapshot = async () => {
    if (snapshotSaving) return
    setSnapshotSaving(true)
    try {
      const r = await api.createSnapshot(snapshotReason || 'manual')
      showMsg('success', `快照 ${r.id} 已创建`)
      setSnapshotReason('')
      const l = await api.listSnapshots()
      setSnapshots(l.snapshots || [])
    } catch (e) { showMsg('error', `创建快照失败: ${e}`) }
    finally { setSnapshotSaving(false) }
  }
  const restoreSnapshot = async (id: string) => {
    if (restoringId) return
    setRestoringId(id)
    try {
      const r = await api.restoreSnapshot(id)
      showMsg('success', r.message)
    } catch (e) { showMsg('error', `恢复快照失败: ${e}`) }
    finally { setRestoringId(null) }
  }

  const formatUptime = (s: number) => {
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60)
    return d > 0 ? `${d}d ${h}h` : `${h}h ${m}m`
  }

  return (
    <div>
      <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16 }}>高级配置</h2>

      {error && <div style={{ padding: 12, marginBottom: 16, background: '#7f1d1d33', borderRadius: 6, fontSize: 13, color: '#f87171' }}>{error}</div>}
      {message && (
        <div style={{ padding: 12, marginBottom: 16, background: message.type === 'success' ? '#16653433' : '#7f1d1d33', borderRadius: 6, fontSize: 13, color: message.type === 'success' ? '#4ade80' : '#f87171' }}>
          {message.text}
        </div>
      )}

      {/* Prometheus 指标面板 */}
      <section style={{ marginBottom: 24 }}>
        <h3 style={{ fontSize: 15, fontWeight: 600, color: '#94a3b8', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
          Prometheus 指标
          <button onClick={fetchMetrics} style={{ padding: '2px 8px', background: '#334155', border: 'none', color: '#38bdf8', borderRadius: 4, fontSize: 11, cursor: 'pointer' }}>刷新</button>
          <a href="/metrics" target="_blank" rel="noreferrer"
             style={{ padding: '2px 8px', background: '#334155', color: '#38bdf8', borderRadius: 4, fontSize: 11, textDecoration: 'none', cursor: 'pointer', border: 'none' }}>
            查看原始指标
          </a>
        </h3>
        {metrics && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              ['请求总数', metrics.requests_total, ''],
              ['拦截数', metrics.blocks_total, ''],
              ['错误数', metrics.errors_total, ''],
              ['拦截率', metrics.block_rate.toFixed(1), '%'],
              ['P50 延迟', metrics.p50_latency_ms.toFixed(2), 'ms'],
              ['P95 延迟', metrics.p95_latency_ms.toFixed(2), 'ms'],
              ['运行时长', formatUptime(metrics.uptime_seconds), ''],
              ['放行数', metrics.passes_total, ''],
            ].map(([label, value, unit]) => (
              <div key={label} style={{ background: '#1e293b', borderRadius: 8, padding: 16, border: '1px solid #334155' }}>
                <div style={{ fontSize: 11, color: '#64748b', marginBottom: 4 }}>{label}</div>
                <div style={{ fontSize: 20, fontWeight: 700, color: '#e2e8f0' }}>
                  {value}<span style={{ fontSize: 13, fontWeight: 400, color: '#64748b', marginLeft: 4 }}>{unit}</span>
                </div>
              </div>
            ))}
          </div>
        )}
        <div style={{ marginTop: 12, fontSize: 12, color: '#475569' }}>
          完整 Prometheus 指标请访问 <a href="/metrics" target="_blank" rel="noreferrer" style={{ color: '#38bdf8' }}>/metrics</a> 端点。Grafana Dashboard: <code>gateway/grafana_dashboard.json</code>
        </div>
      </section>

      {/* 输出护栏配置（A - 可交互开关） */}
      <section style={{ marginBottom: 24 }}>
        <h3 style={{ fontSize: 15, fontWeight: 600, color: '#94a3b8', marginBottom: 12 }}>输出护栏配置</h3>
        <div style={{ background: '#1e293b', borderRadius: 8, border: '1px solid #334155', padding: 20 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div>
                <div style={{ fontSize: 14, color: '#e2e8f0' }}>输出护栏（output_guardrail）</div>
                <div style={{ fontSize: 12, color: '#64748b', marginTop: 2 }}>检测模型输出中的敏感信息泄露，分三级处置（拦截/打码/告警）</div>
              </div>
              <label style={{ position: 'relative', display: 'inline-block', width: 44, height: 24, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={outputGuardOn}
                  onChange={(e) => { setOutputGuardOn(e.target.checked); saveGuardrails(e.target.checked, undefined) }}
                  disabled={guardSaving}
                  style={{ opacity: 0, width: 0, height: 0 }}
                />
                <span style={{
                  position: 'absolute', inset: 0, borderRadius: 12, background: outputGuardOn ? '#16a34a' : '#334155',
                  transition: 'background 0.2s',
                }} />
                <span style={{
                  position: 'absolute', top: 2, left: outputGuardOn ? 22 : 2, width: 20, height: 20, borderRadius: 10,
                  background: '#fff', transition: 'left 0.2s',
                }} />
              </label>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div>
                <div style={{ fontSize: 14, color: '#e2e8f0' }}>敏感信息检测（sensitive_leak）</div>
                <div style={{ fontSize: 12, color: '#64748b', marginTop: 2 }}>PII/密钥/JWT/身份证/银行卡 等 12 类敏感信息检测</div>
              </div>
              <label style={{ position: 'relative', display: 'inline-block', width: 44, height: 24, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={sensitiveOn}
                  onChange={(e) => { setSensitiveOn(e.target.checked); saveGuardrails(undefined, e.target.checked) }}
                  disabled={guardSaving}
                  style={{ opacity: 0, width: 0, height: 0 }}
                />
                <span style={{
                  position: 'absolute', inset: 0, borderRadius: 12, background: sensitiveOn ? '#16a34a' : '#334155',
                  transition: 'background 0.2s',
                }} />
                <span style={{
                  position: 'absolute', top: 2, left: sensitiveOn ? 22 : 2, width: 20, height: 20, borderRadius: 10,
                  background: '#fff', transition: 'left 0.2s',
                }} />
              </label>
            </div>
            <div style={{ fontSize: 12, color: '#475569' }}>
              开关即时生效，无需重启。状态对应 <code>gateway/config.yaml</code> → <code>security.output_guardrail</code> / <code>security.sensitive_leak</code>
            </div>
          </div>
        </div>
      </section>

      {/* 灰度部署（B - 可交互滑块） */}
      <section style={{ marginBottom: 24 }}>
        <h3 style={{ fontSize: 15, fontWeight: 600, color: '#94a3b8', marginBottom: 12 }}>灰度部署</h3>
        <div style={{ background: '#1e293b', borderRadius: 8, border: '1px solid #334155', padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 8 }}>
            <span style={{ fontSize: 14, color: '#e2e8f0' }}>拦截比例:</span>
            <input
              type="range" min={0} max={100} step={5}
              value={Math.round(grayRatio * 100)}
              onChange={(e) => setGrayRatio(Number(e.target.value) / 100)}
              style={{ flex: 1, accentColor: '#f59e0b' }}
            />
            <span style={{ padding: '4px 12px', background: '#334155', borderRadius: 4, fontSize: 14, color: '#f59e0b', fontWeight: 600, minWidth: 64, textAlign: 'center' }}>
              {Math.round(grayRatio * 100)}%
            </span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: '#64748b', marginBottom: 12 }}>
            <span>仅观察</span><span>全量拦截</span>
          </div>
          <div style={{ fontSize: 12, color: '#64748b', marginBottom: 12 }}>
            灰度部署按比例拦截攻击请求（例如 50% = 一半攻击被拦截，一半仅观察）。调整后点击「应用」即时生效。
          </div>
          <button
            onClick={saveGray}
            disabled={graySaving}
            style={{ padding: '8px 24px', background: '#16a34a', color: '#fff', border: 'none', borderRadius: 6, fontSize: 14, fontWeight: 500, cursor: graySaving ? 'not-allowed' : 'pointer', opacity: graySaving ? 0.6 : 1 }}>
            {graySaving ? '应用中...' : '应用灰度比例'}
          </button>
        </div>
      </section>

      {/* 告警通道配置（C - 可交互表单） */}
      <section style={{ marginBottom: 24 }}>
        <h3 style={{ fontSize: 15, fontWeight: 600, color: '#94a3b8', marginBottom: 12 }}>告警通道配置</h3>
        <div style={{ background: '#1e293b', borderRadius: 8, border: '1px solid #334155', padding: 20 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {NOTIFIER_CHANNELS.map(ch => {
              const cfg = notifiers[ch.name] || {}
              const enabled = !!cfg.enabled
              return (
                <div key={ch.name} style={{ border: '1px solid #334155', borderRadius: 8, padding: 14, background: '#16233a' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                    <span style={{ fontSize: 14, color: '#e2e8f0', fontWeight: 500 }}>{ch.label}</span>
                    <label style={{ position: 'relative', display: 'inline-block', width: 44, height: 24, cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={enabled}
                        onChange={(e) => updateNotifierField(ch.name, 'enabled', e.target.checked)}
                        style={{ opacity: 0, width: 0, height: 0 }}
                      />
                      <span style={{
                        position: 'absolute', inset: 0, borderRadius: 12, background: enabled ? '#16a34a' : '#334155',
                        transition: 'background 0.2s',
                      }} />
                      <span style={{
                        position: 'absolute', top: 2, left: enabled ? 22 : 2, width: 20, height: 20, borderRadius: 10,
                        background: '#fff', transition: 'left 0.2s',
                      }} />
                    </label>
                  </div>
                  {enabled && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                      {ch.fields.map(f => (
                        <div key={f.key}>
                          <label style={{ display: 'block', fontSize: 11, color: '#64748b', marginBottom: 4 }}>{f.label}</label>
                          <input
                            type={f.type} style={inputStyle}
                            placeholder={f.placeholder || ''}
                            value={cfg[f.key] || ''}
                            autoComplete={f.type === 'password' ? 'new-password' : 'off'}
                            onChange={(e) => updateNotifierField(ch.name, f.key, e.target.value)}
                          />
                        </div>
                      ))}
                      <div style={{ display: 'flex', gap: 10 }}>
                        <button
                          onClick={() => testNotifier(ch.name)}
                          disabled={testingChannel !== null}
                          style={{ padding: '6px 14px', background: '#334155', border: '1px solid #475569', borderRadius: 6, fontSize: 13, color: '#e2e8f0', cursor: testingChannel !== null ? 'not-allowed' : 'pointer' }}>
                          {testingChannel === ch.name ? '测试中...' : '测试告警'}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 16 }}>
            <button
              onClick={saveNotifiers}
              disabled={notifierSaving}
              style={{ padding: '8px 24px', background: '#16a34a', color: '#fff', border: 'none', borderRadius: 6, fontSize: 14, fontWeight: 500, cursor: notifierSaving ? 'not-allowed' : 'pointer', opacity: notifierSaving ? 0.6 : 1 }}>
              {notifierSaving ? '保存中...' : '保存告警通道'}
            </button>
            <span style={{ fontSize: 12, color: '#64748b' }}>启用后即时生效，支持去重、分级（info/warn/critical）、冷却期配置。</span>
          </div>
        </div>
      </section>

      {/* 配置快照管理（D - 可交互创建/恢复） */}
      <section style={{ marginBottom: 24 }}>
        <h3 style={{ fontSize: 15, fontWeight: 600, color: '#94a3b8', marginBottom: 12 }}>配置快照管理</h3>
        <div style={{ background: '#1e293b', borderRadius: 8, border: '1px solid #334155', padding: 20 }}>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 16 }}>
            <input
              type="text" style={{ ...inputStyle, flex: 1 }}
              placeholder="变更说明（可选，如：切换为 STRICT 前的备份）"
              value={snapshotReason}
              onChange={(e) => setSnapshotReason(e.target.value)}
            />
            <button
              onClick={createSnapshot}
              disabled={snapshotSaving}
              style={{ padding: '8px 20px', background: '#1d4ed8', color: '#fff', border: 'none', borderRadius: 6, fontSize: 13, fontWeight: 500, cursor: snapshotSaving ? 'not-allowed' : 'pointer', whiteSpace: 'nowrap', opacity: snapshotSaving ? 0.6 : 1 }}>
              {snapshotSaving ? '创建中...' : '创建快照'}
            </button>
          </div>
          <div style={{ fontSize: 12, color: '#64748b', marginBottom: 12 }}>
            创建快照备份当前引擎配置与学习状态，便于回滚。保留最近 5 个快照。
          </div>
          {snapshots.length === 0 ? (
            <div style={{ padding: 16, textAlign: 'center', color: '#64748b', fontSize: 13 }}>暂无快照。点击「创建快照」备份当前配置。</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ background: '#0f172a' }}>
                  {['ID', '时间', '说明', '模式', '样本数', '操作'].map(h => (
                    <th key={h} style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 600, color: '#94a3b8', borderBottom: '1px solid #334155' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {snapshots.map(s => (
                  <tr key={s.id} style={{ borderBottom: '1px solid #1e293b' }}>
                    <td style={{ padding: '8px 12px', fontFamily: 'monospace', fontSize: 12, color: '#38bdf8' }}>{s.id}</td>
                    <td style={{ padding: '8px 12px', color: '#64748b', whiteSpace: 'nowrap' }}>{s.timestamp}</td>
                    <td style={{ padding: '8px 12px' }}>{s.reason || '-'}</td>
                    <td style={{ padding: '8px 12px', color: '#94a3b8' }}>{s.mode || '-'}</td>
                    <td style={{ padding: '8px 12px', color: '#94a3b8' }}>{s.sample_count}</td>
                    <td style={{ padding: '8px 12px' }}>
                      <button
                        onClick={() => restoreSnapshot(s.id)}
                        disabled={restoringId !== null}
                        style={{ padding: '4px 12px', background: 'transparent', border: '1px solid #7f1d1d', borderRadius: 4, fontSize: 12, color: '#f87171', cursor: restoringId !== null ? 'not-allowed' : 'pointer' }}>
                        {restoringId === s.id ? '恢复中...' : '恢复'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>

      {/* MCP/Agent 工具调用检测 */}
      <section style={{ marginBottom: 24 }}>
        <h3 style={{ fontSize: 15, fontWeight: 600, color: '#94a3b8', marginBottom: 12 }}>MCP/Agent 工具调用检测</h3>
        <div style={{ background: '#1e293b', borderRadius: 8, border: '1px solid #334155', padding: 20 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 12 }}>
            {[
              ['CODE_EXEC', '代码执行', '#f87171', 'execute_command/eval/bash'],
              ['CREDENTIAL', '凭据访问', '#f59e0b', 'get_secret/read_env/config'],
              ['NETWORK', '网络请求', '#38bdf8', 'fetch/http_request/SSRF'],
              ['FILE_RW', '文件系统', '#a78bfa', 'fs_read/write/delete'],
            ].map(([key, label, color, tools]) => (
              <div key={key} style={{ background: '#0f172a', borderRadius: 6, padding: 12, border: `1px solid ${color}33` }}>
                <div style={{ width: 8, height: 8, borderRadius: 4, background: color, marginBottom: 6 }} />
                <div style={{ fontSize: 13, color: '#e2e8f0', fontWeight: 500 }}>{label}</div>
                <div style={{ fontSize: 11, color: '#94a3b8' }}>{key}</div>
                <div style={{ fontSize: 10, color: '#64748b', marginTop: 4 }}>{tools}</div>
              </div>
            ))}
          </div>
          <div style={{ fontSize: 12, color: '#64748b' }}>
            基于五行生克意图检测框架，22 个敏感工具注册表，三层风险（LOW/MEDIUM/HIGH）。
          </div>
        </div>
      </section>

      {/* Grafana 指引 */}
      <section>
        <h3 style={{ fontSize: 15, fontWeight: 600, color: '#94a3b8', marginBottom: 12 }}>Grafana 集成</h3>
        <div style={{ background: '#1e293b', borderRadius: 8, border: '1px solid #334155', padding: 20 }}>
          <div style={{ fontSize: 13, color: '#94a3b8' }}>
            完整 Grafana Dashboard 已提供：<code style={{ color: '#38bdf8' }}>gateway/grafana_dashboard.json</code>
          </div>
          <ol style={{ marginTop: 8, paddingLeft: 20, fontSize: 12, color: '#64748b', display: 'flex', flexDirection: 'column', gap: 4 }}>
            <li>在 Grafana 中配置 Prometheus 数据源指向本网关的 <a href="/metrics" target="_blank" rel="noreferrer" style={{ color: '#38bdf8' }}>/metrics</a> 端点</li>
            <li>导入 <code>grafana_dashboard.json</code></li>
            <li>Dashboard 包含 8 个面板：请求QPS、拦截率趋势、P50/P95/P99延迟、错误率、引擎运行状态、Redis/PostgreSQL连接状态</li>
          </ol>
        </div>
      </section>
    </div>
  )
}
