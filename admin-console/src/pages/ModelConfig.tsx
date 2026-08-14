import { useEffect, useState, useCallback, type ReactNode } from 'react'
import { api, ModelInfo, ModelItemConfig, RoutingConfig } from '../services/api'
import ConfirmModal from '../components/ConfirmModal'

// 轻量 YAML 语法高亮：注释灰色、键名青色、键值浅青色，提升配置示例可读性
function yamlHighlight(src: string): ReactNode[] {
  return src.split('\n').map((line, i) => {
    if (!line.trim()) return <div key={i}>&nbsp;</div>
    // 注释行
    if (line.trimStart().startsWith('#')) {
      return <div key={i} style={{ whiteSpace: 'pre', color: '#64748b' }}>{line}</div>
    }
    // 键: 值 结构（首个冒号前为键名）
    const m = line.match(/^(\s*)([^:]+)(:)(.*)$/)
    if (m) {
      return (
        <div key={i} style={{ whiteSpace: 'pre' }}>
          {m[1]}<span style={{ color: '#7dd3fc' }}>{m[2]}</span><span style={{ color: '#64748b' }}>:</span><span style={{ color: '#a5f3fc' }}>{m[3]}</span>
        </div>
      )
    }
    return <div key={i} style={{ whiteSpace: 'pre' }}>{line}</div>
  })
}

// 空行状态占位
function EmptyModelRow() {
  return (
    <div style={{ padding: 20, textAlign: 'center', color: '#64748b', fontSize: 13 }}>
      暂无已配置的模型。点击下方「+ 添加模型」新增一个模型路由，或到表格中编辑已有模型，然后点「保存配置」。
    </div>
  )
}

// 模型编辑表单：每行对应一个模型路由
function ModelEditor({ item, index, onChange, onRemove }: {
  item: ModelItemConfig
  index: number
  onChange: (index: number, field: keyof ModelItemConfig, value: string | number) => void
  onRemove: (index: number) => void
}) {
  const inputStyle: React.CSSProperties = {
    width: '100%', background: '#0f172a', border: '1px solid #334155', borderRadius: 6,
    padding: '7px 10px', fontSize: 13, color: '#e2e8f0', outline: 'none',
  }
  const labelStyle: React.CSSProperties = { display: 'block', fontSize: 11, color: '#64748b', marginBottom: 4 }
  return (
    <div style={{ border: '1px solid #334155', borderRadius: 8, padding: 14, background: '#16233a', position: 'relative' }}>
      <div style={{ position: 'absolute', top: 10, right: 12, fontSize: 12, color: '#64748b' }}>#{index + 1}</div>
      <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 1.2fr 1.8fr 0.7fr 1fr 0.6fr auto', gap: 10 }}>
        <div>
          <label style={labelStyle}>ID（必填，唯一）</label>
          <input style={inputStyle} placeholder="deepseek-v3" value={item.id}
            onChange={(e) => onChange(index, 'id', e.target.value)} />
        </div>
        <div>
          <label style={labelStyle}>名称</label>
          <input style={inputStyle} placeholder="深度求索 V3" value={item.name}
            onChange={(e) => onChange(index, 'name', e.target.value)} />
        </div>
        <div>
          <label style={labelStyle}>端点（http(s)://）</label>
          <input style={inputStyle} placeholder="http://internal.deepseek:8000/v1" value={item.endpoint}
            onChange={(e) => onChange(index, 'endpoint', e.target.value)} />
        </div>
        <div>
          <label style={labelStyle}>类型</label>
          <select style={inputStyle} value={item.type}
            onChange={(e) => onChange(index, 'type', e.target.value)}>
            <option value="private">private</option>
            <option value="public">public</option>
          </select>
        </div>
        <div>
          <label style={labelStyle}>权重</label>
          <input style={inputStyle} type="number" min={0} value={item.weight}
            onChange={(e) => onChange(index, 'weight', Number(e.target.value) || 0)} />
        </div>
        <div>
          <label style={labelStyle}>API Key</label>
          <input style={inputStyle} placeholder="留空则保持不变" value={item.api_key}
            onChange={(e) => onChange(index, 'api_key', e.target.value)} />
        </div>
        <div style={{ display: 'flex', alignItems: 'flex-end' }}>
          <button
            onClick={() => onRemove(index)}
            title="删除该模型"
            style={{ padding: '7px 10px', background: 'transparent', color: '#f87171', border: '1px solid #7f1d1d', borderRadius: 6, fontSize: 13, cursor: 'pointer', whiteSpace: 'nowrap' }}>
            删除
          </button>
        </div>
      </div>
    </div>
  )
}

export default function ModelConfig() {
  const [models, setModels] = useState<Record<string, ModelInfo>>({})
  const [stats, setStats] = useState<Record<string, unknown>>({})
  const [reloadStatus, setReloadStatus] = useState('')
  const [error, setError] = useState('')
  // 交互式表单编辑态
  const [editingModels, setEditingModels] = useState<ModelItemConfig[]>([])
  const [editingRouting, setEditingRouting] = useState<RoutingConfig>({ strategy: 'weighted', default: '' })
  const [saving, setSaving] = useState(false)
  const [saveStatus, setSaveStatus] = useState('')

  const fetch = useCallback(async () => {
    try {
      const data = await api.getModels()
      const { models: m, ...s } = data as Record<string, unknown> & { models: Record<string, ModelInfo> }
      setModels(m || {})
      setStats(s)
      // 初始化编辑表单（api_key 不回显，留空表示保持不变）
      setEditingModels(Object.entries(m || {}).map(([id, mi]) => ({
        id, name: mi.name || '', endpoint: mi.endpoint || '',
        type: mi.type || 'public', api_key: '', weight: mi.weight ?? 100,
      })))
      setEditingRouting({
        strategy: String((s as any).strategy || 'weighted'),
        default: String((s as any).default_model || ''),
      })
      setError('')
      setSaveStatus('')
    } catch (e) { setError(String(e)) }
  }, [])

  useEffect(() => { fetch() }, [fetch])

  const reload = async () => {
    try {
      setReloadStatus('加载中...')
      const r = await api.reloadConfig()
      setReloadStatus(`完成: ${r.previous_models} → ${r.current_models} 个模型`)
      setTimeout(fetch, 500)
    } catch (e) { setReloadStatus(`失败: ${e}`) }
  }

  const addModel = () => {
    setEditingModels(prev => [...prev, { id: '', name: '', endpoint: '', type: 'public', api_key: '', weight: 100 }])
  }

  const updateModel = (index: number, field: keyof ModelItemConfig, value: string | number) => {
    setEditingModels(prev => prev.map((it, i) => (i === index ? { ...it, [field]: value } : it)))
  }

  const removeModel = (index: number) => {
    const item = editingModels[index]
    // 网关端 P1 修复「模型删除无确认」：删除已生效模型（保存后真实下线）需二次确认；
    // 新添加尚未保存的行（id 不在已生效列表中）直接移除，不打断操作流
    if (item && models[item.id.trim()]) {
      setConfirmRemoveIndex(index)
      return
    }
    setEditingModels(prev => prev.filter((_, i) => i !== index))
  }
  const [confirmRemoveIndex, setConfirmRemoveIndex] = useState<number | null>(null)
  const doRemove = (index: number) => {
    setEditingModels(prev => prev.filter((_, i) => i !== index))
  }

  const save = async () => {
    if (saving) return
    // 前端兜底校验（与后端一致），失败给出明确提示
    const ids = editingModels.map(m => m.id.trim())
    if (ids.some(x => !x)) { setSaveStatus('错误: 每个模型都必须填写唯一的 ID'); return }
    if (new Set(ids).size !== ids.length) { setSaveStatus('错误: 模型 ID 不能重复'); return }
    for (const m of editingModels) {
      if (!/^https?:\/\//i.test(m.endpoint)) {
        setSaveStatus(`错误: 模型 ${m.id || '(未填 ID)'} 的端点必须以 http:// 或 https:// 开头`); return
      }
    }
    if (editingRouting.default && !ids.includes(editingRouting.default)) {
      setSaveStatus('错误: 默认模型不在已配置模型中，请先在下方模型列表添加'); return
    }
    setSaving(true)
    setSaveStatus('保存中...')
    try {
      const r = await api.saveModels({ models: editingModels, routing: editingRouting })
      setSaveStatus(`已保存并热加载生效: ${r.current_models} 个模型，默认=${r.routing.default || '无'}`)
      setTimeout(fetch, 400)
    } catch (e) { setSaveStatus(`保存失败: ${e}`) }
    finally { setSaving(false) }
  }

  const entries = Object.entries(models)

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <h2 style={{ fontSize: 18, fontWeight: 600 }}>模型配置</h2>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          {reloadStatus && <span style={{ fontSize: 13, color: '#94a3b8' }}>{reloadStatus}</span>}
          <button onClick={reload} style={{ padding: '8px 20px', background: '#1d4ed8', color: '#fff', border: 'none', borderRadius: 6, fontSize: 14, fontWeight: 500, cursor: 'pointer' }}>重新加载配置</button>
        </div>
      </div>

      {error && <div style={{ padding: 12, marginBottom: 16, background: '#7f1d1d33', borderRadius: 6, fontSize: 13, color: '#f87171' }}>{error}</div>}

      {/* 路由信息 */}
      <div style={{ display: 'flex', gap: 16, marginBottom: 20 }}>
        {[
          ['策略', String(stats.strategy || '-')],
          ['默认模型', String(stats.default_model || '无')],
          ['模型数', String(stats.model_count || 0)],
          ['热加载', String(stats.hot_reload || false)],
        ].map(([label, value]) => (
          <div key={label} style={{ flex: 1, background: '#1e293b', borderRadius: 8, padding: 16, border: '1px solid #334155' }}>
            <div style={{ fontSize: 12, color: '#64748b', marginBottom: 4 }}>{label}</div>
            <div style={{ fontSize: 16, fontWeight: 600 }}>{value}</div>
          </div>
        ))}
      </div>

      {/* 交互式编辑表单 */}
      <div style={{ background: '#1e293b', borderRadius: 8, border: '1px solid #334155', padding: 16, marginBottom: 16 }}>
        <div style={{ fontSize: 14, fontWeight: 600, color: '#e2e8f0', marginBottom: 4 }}>编辑模型配置</div>
        <div style={{ fontSize: 12, color: '#64748b', marginBottom: 16 }}>
          在下方表单中增删改模型，点「+ 添加模型」新增一行，配置完点「保存配置」即写入并热加载生效，无需手动编辑 YAML。
        </div>

        {/* 路由配置 */}
        <div style={{ display: 'flex', gap: 20, alignItems: 'flex-end', marginBottom: 16 }}>
          <div>
            <label style={{ display: 'block', fontSize: 11, color: '#64748b', marginBottom: 4 }}>路由策略</label>
            <select
              value={editingRouting.strategy}
              onChange={(e) => setEditingRouting({ ...editingRouting, strategy: e.target.value })}
              style={{ width: 180, background: '#0f172a', border: '1px solid #334155', borderRadius: 6, padding: '7px 10px', fontSize: 13, color: '#e2e8f0', outline: 'none' }}>
              <option value="weighted">weighted（加权）</option>
              <option value="round_robin">round_robin（轮询）</option>
              <option value="first_match">first_match（优先匹配）</option>
            </select>
          </div>
          <div>
            <label style={{ display: 'block', fontSize: 11, color: '#64748b', marginBottom: 4 }}>默认模型</label>
            <select
              value={editingRouting.default}
              onChange={(e) => setEditingRouting({ ...editingRouting, default: e.target.value })}
              style={{ width: 200, background: '#0f172a', border: '1px solid #334155', borderRadius: 6, padding: '7px 10px', fontSize: 13, color: '#e2e8f0', outline: 'none' }}>
              <option value="">（无）</option>
              {editingModels.map((m, i) => (
                <option key={`${m.id}-${i}`} value={m.id} disabled={!m.id.trim()}>{m.id || `(待填 ID 的模型 ${i + 1})`}</option>
              ))}
            </select>
          </div>
        </div>

        {/* 模型列表（可增删改） */}
        {editingModels.length === 0 ? (
          <EmptyModelRow />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {editingModels.map((item, i) => (
              <ModelEditor key={i} item={item} index={i} onChange={updateModel} onRemove={removeModel} />
            ))}
          </div>
        )}

        {/* 操作按钮 */}
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginTop: 16 }}>
          <button
            onClick={addModel}
            style={{ padding: '8px 18px', background: '#0ea5e9', color: '#fff', border: 'none', borderRadius: 6, fontSize: 14, fontWeight: 500, cursor: 'pointer' }}>
            + 添加模型
          </button>
          <button
            onClick={save}
            disabled={saving}
            style={{ padding: '8px 20px', background: '#16a34a', color: '#fff', border: 'none', borderRadius: 6, fontSize: 14, fontWeight: 500, cursor: saving ? 'not-allowed' : 'pointer', opacity: saving ? 0.6 : 1 }}>
            {saving ? '保存中...' : '保存配置'}
          </button>
          {saveStatus && <span style={{ fontSize: 13, color: saveStatus.startsWith('错误') || saveStatus.startsWith('保存失败') ? '#f87171' : '#4ade80' }}>{saveStatus}</span>}
        </div>
      </div>

      {/* 已生效模型（只读表格） */}
      <div style={{ background: '#1e293b', borderRadius: 8, border: '1px solid #334155', overflow: 'hidden' }}>
        <div style={{ padding: '14px 16px', fontSize: 14, fontWeight: 600, color: '#94a3b8', borderBottom: '1px solid #334155' }}>当前已生效模型</div>
        {entries.length === 0 && (
          <div style={{ padding: 32, textAlign: 'center', color: '#64748b', fontSize: 14 }}>
            暂无已配置的模型路由。请在上方表单添加模型并点击「保存配置」。
          </div>
        )}
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ background: '#0f172a' }}>
              {['ID', '名称', '端点', '类型', '权重'].map(h => (
                <th key={h} style={{ padding: '10px 12px', textAlign: 'left', fontWeight: 600, color: '#94a3b8', borderBottom: '1px solid #334155' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {entries.map(([id, m]) => (
              <tr key={id} style={{ borderBottom: '1px solid #1e293b' }}>
                <td style={{ padding: '10px 12px', fontFamily: 'monospace', color: '#38bdf8' }}>{id}</td>
                <td style={{ padding: '10px 12px' }}>{m.name}</td>
                <td style={{ padding: '10px 12px', fontFamily: 'monospace', fontSize: 12, color: '#94a3b8' }}>{m.endpoint}</td>
                <td style={{ padding: '10px 12px' }}>
                  <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, background: m.type === 'private' ? '#1e3a5f' : '#3b2f1e', color: m.type === 'private' ? '#38bdf8' : '#f59e0b' }}>{m.type}</span>
                </td>
                <td style={{ padding: '10px 12px' }}>{m.weight}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div style={{ marginTop: 24, padding: 20, background: '#1e293b', borderRadius: 8, border: '1px solid #334155', fontSize: 13, color: '#94a3b8' }}>
        <strong style={{ color: '#e2e8f0' }}>配置示例（等价于上方表单保存的内容，仅供对照）：</strong>
        <div style={{ marginTop: 12, padding: 16, background: '#0f172a', borderRadius: 8, border: '1px solid #334155', fontFamily: 'JetBrains Mono, Fira Code, monospace', fontSize: 13, lineHeight: 1.8, overflowX: 'auto' }}>
          {yamlHighlight(`# gateway/config.yaml
models:
  - id: deepseek-v3
    name: 深度求索 V3
    endpoint: http://internal.deepseek:8000/v1
    type: private
    api_key: \${DEEPSEEK_API_KEY}
  - id: gpt-4
    name: GPT-4
    endpoint: https://api.openai.com/v1
    type: public
    api_key: \${OPENAI_API_KEY}

routing:
  strategy: weighted
  default: deepseek-v3`)}
        </div>
        <div style={{ marginTop: 12 }}>
          你也可以点击上方「重新加载配置」或调用 <code>POST /api/config/reload</code> 手动刷新已生效配置，无需重启。
        </div>
      </div>

      {/* 模型删除二次确认（网关端 P1） */}
      <ConfirmModal
        open={confirmRemoveIndex !== null}
        message={(() => {
          const it = confirmRemoveIndex !== null ? editingModels[confirmRemoveIndex] : null
          return it ? `确定删除模型「${it.id}」（${it.name || '未命名'}）吗？\n\n点击「保存配置」后该模型路由将从网关下线，依赖它的调用将失败。未保存前可通过重新添加挽回。` : ''
        })()}
        confirmLabel="确认删除"
        onConfirm={() => { const i = confirmRemoveIndex; setConfirmRemoveIndex(null); if (i !== null) doRemove(i) }}
        onCancel={() => setConfirmRemoveIndex(null)}
      />
    </div>
  )
}
