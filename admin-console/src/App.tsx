import { Routes, Route, NavLink } from 'react-router-dom'
import { useState, useEffect, useCallback, useRef } from 'react'
import { api } from './services/api'
import Dashboard from './pages/Dashboard'
import AuditLogs from './pages/AuditLogs'
import ModelConfig from './pages/ModelConfig'
import Detect from './pages/Detect'
import Login from './pages/Login'
import Settings from './pages/Settings'
import AdminKeys from './pages/AdminKeys'
import ErrorBoundary from './components/ErrorBoundary'
import ConfirmModal from './components/ConfirmModal'

const AUTH_KEY_STORAGE = 'xuandun_api_key'

// Toast 通知（替代 alert 阻塞式弹窗）
interface Toast { id: number; message: string; type: 'info' | 'error' }
let toastId = 0

const nav = [
  { to: '/', label: '仪表盘' },
  { to: '/detect', label: '安全检测' },
  { to: '/audit', label: '审计日志' },
  { to: '/models', label: '模型配置' },
  { to: '/keys', label: 'API Key' },
  { to: '/settings', label: '高级配置' },
]

const MODE_LABELS: Record<string, string> = {
  protecting: '保护模式',
  observing: '观察模式',
  blocking: '封锁模式',
}

// 模式对应的视觉提示颜色
const modeColor: Record<string, string> = {
  protecting: '#4ade80',
  observing: '#f59e0b',
  blocking: '#f87171',
}

function MainApp({ onLogout }: { onLogout: () => void }) {
  // P0-A-2: window.confirm -> ConfirmModal, alert -> Toast
  // G-P1-1/2 扩展：支持必填输入模式（替代 window.prompt，取消时返回 null 而非静默空值继续）
  const [confirmModal, setConfirmModal] = useState<{open:boolean,message:string,withInput?:boolean,inputPlaceholder?:string}>({open:false,message:''})
  // 统一解析器约定：调用侧只会传 boolean / string / null 字面量（见下方 onConfirm/onCancel），
  // Promise resolve 参数类型逆变导致的 TS2322 在赋值处用断言归一
  const confirmResolveRef = useRef<((v: boolean | string | null) => void) | null>(null)
  const [toasts, setToasts] = useState<Toast[]>([])

  const showConfirm = async (message: string): Promise<boolean> => {
    return new Promise((resolve) => {
      confirmResolveRef.current = resolve as (v: boolean | string | null) => void
      setConfirmModal({open:true, message})
    })
  }

  /** 带必填输入的确认：确认返回输入值（非空），取消返回 null */
  const showConfirmWithInput = async (message: string, inputPlaceholder: string): Promise<string | null> => {
    return new Promise((resolve) => {
      confirmResolveRef.current = resolve as (v: boolean | string | null) => void
      setConfirmModal({open:true, message, withInput:true, inputPlaceholder})
    })
  }

  const addToast = (message: string, type: 'info'|'error' = 'error') => {
    const id = ++toastId
    setToasts(prev => [...prev, {id, message, type}])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 5000)
  }
  const [mode, setMode] = useState('protecting')
  const [modeVersion, setModeVersion] = useState(1)
  const [emergencyOn, setEmergencyOn] = useState(false)

  useEffect(() => {
    api.getMode().then(r => { setMode(r.mode); setModeVersion(r.version ?? 1) }).catch(() => {})
    api.getEmergency().then(r => setEmergencyOn(r.enabled)).catch(() => {})
  }, [])

  const handleModeSwitch = async (newMode: string) => {
    if (newMode !== 'protecting') {
      const label = MODE_LABELS[newMode] || newMode
      const message = newMode === 'observing'
        ? `确认切换到「${label}」？\n\n此模式下所有请求将被放行，仅记录不拦截。\n适用于安全审计、攻防演练观察阶段。\n\n请确认后继续。`
        : `确认切换到「${label}」？\n\n此模式下所有攻击将被无条件封锁。\n适用于遭受攻击期间的紧急防御。\n\n请确认后继续。`
      const ok = await showConfirm(message); if (!ok) return
    }
    try {
      const r = await api.switchMode(newMode, modeVersion)
      setMode(r.mode)
      setModeVersion(r.version ?? modeVersion + 1)
    } catch (e: any) {
      if (String(e).includes('409') || String(e).includes('冲突')) {
        try {
          const fresh = await api.getMode()
          setMode(fresh.mode)
          setModeVersion(fresh.version ?? 1)
        } catch {}
        addToast('模式切换失败：其他管理员刚刚修改了模式。页面已刷新为最新状态，请重试。')
      } else {
        addToast(`模式切换失败: ${e}`)
      }
    }
  }

  return (
    <div style={{ minHeight: '100vh', background: '#0f172a', color: '#e2e8f0' }}>
      <ConfirmModal
        open={confirmModal.open}
        message={confirmModal.message}
        withInput={confirmModal.withInput}
        inputPlaceholder={confirmModal.inputPlaceholder}
        onConfirm={(input) => { confirmResolveRef.current?.(confirmModal.withInput ? (input ?? null) : true); setConfirmModal({open:false,message:''}) }}
        onCancel={() => { confirmResolveRef.current?.(confirmModal.withInput ? null : false); setConfirmModal({open:false,message:''}) }}
      />
      {toasts.length > 0 && (
        <div style={{ position: 'fixed', bottom: 24, right: 24, zIndex: 9999, display: 'flex', flexDirection: 'column', gap: 8 }}>
          {toasts.map(t => (
            <div key={t.id} style={{
              padding: '10px 18px', borderRadius: 8, fontSize: 13, fontWeight: 500,
              background: t.type === 'error' ? '#7f1d1d' : '#1e3a5f',
              border: `1px solid ${t.type === 'error' ? '#f87171' : '#3b82f6'}`,
              color: '#e2e8f0', maxWidth: 400, wordBreak: 'break-word',
              boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
            }}>
              {t.message}
            </div>
          ))}
        </div>
      )}
      <header style={{ background: '#1e293b', borderBottom: '1px solid #334155', padding: '0 24px', display: 'flex', alignItems: 'center', height: 56 }}>
        <h1 style={{ fontSize: 18, fontWeight: 700, margin: 0, display: 'flex', alignItems: 'center', gap: 10 }}>
          <img src="/logo.png" alt="玄盾" style={{ width: 28, height: 28, objectFit: 'contain' }} />
          <span style={{ color: '#38bdf8' }}>玄盾</span> AI安全网关
          <span style={{ fontSize: 12, color: '#64748b', fontWeight: 400 }}>管理控制台 v{import.meta.env.VITE_APP_VERSION}</span>
        </h1>
        <nav style={{ marginLeft: 48, display: 'flex', gap: 8 }}>
          {nav.map(n => (
            <NavLink key={n.to} to={n.to} end={n.to === '/'}
              style={({ isActive }) => ({
                padding: '8px 16px', borderRadius: 6, fontSize: 14, fontWeight: 500,
                background: isActive ? '#334155' : 'transparent',
                color: isActive ? '#38bdf8' : '#94a3b8',
                textDecoration: 'none', transition: 'all .15s',
              })}>
              {n.label}
            </NavLink>
          ))}
        </nav>
        <button
          onClick={async () => {
            const newState = !emergencyOn
            if (newState) {
              // G-P1-1/2 修复：逃生原因为必填项；用户取消（返回 null）则整个操作放弃，
              // 不再像 window.prompt 那样取消后仍以空原因静默开启逃生通道
              const reason = await showConfirmWithInput(
                '确认启用紧急逃生通道？\n\n所有请求将绕过安全检测直接放行。\n此操作会产生审计记录，仅限紧急情况使用。\n\n必须填写逃生原因（将记录到审计日志）：',
                '例如：上游引擎故障，临时放行以保障业务连续性'
              )
              if (reason === null) return
              try {
                await api.toggleEmergency(true, reason)
                setEmergencyOn(true)
                addToast('逃生通道已启用（已记录原因），安全检测暂停', 'info')
              } catch (e) { addToast(`逃生通道操作失败: ${e}`) }
              return
            }
            const ok = await showConfirm('确认关闭紧急逃生通道？\n\n安全检测将恢复对所有请求的正常拦截。')
            if (!ok) return
            try {
              await api.toggleEmergency(false, '')
              setEmergencyOn(false)
              addToast('逃生通道已关闭，安全检测已恢复', 'info')
            } catch (e) { addToast(`逃生通道操作失败: ${e}`) }
          }}
          style={{
            marginLeft: 12, padding: '4px 14px', borderRadius: 4, fontSize: 12, fontWeight: 500,
            background: emergencyOn ? '#7f1d1d' : '#334155',
            color: emergencyOn ? '#fca5a5' : '#64748b',
            border: `1px solid ${emergencyOn ? '#f87171' : '#475569'}`,
            cursor: 'pointer', whiteSpace: 'nowrap',
          }}
        >
          {emergencyOn ? '逃生中' : '逃生通道'}
        </button>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ width: 10, height: 10, borderRadius: 5, background: modeColor[mode] || '#64748b' }} />
          <select value={mode} onChange={(e) => handleModeSwitch(e.target.value)}
            style={{ padding: '4px 8px', background: '#0f172a', color: '#e2e8f0', border: `1px solid ${modeColor[mode] || '#334155'}`, borderRadius: 4, fontSize: 12, cursor: 'pointer' }}>
            <option value="protecting">保护模式</option>
            <option value="observing">观察模式</option>
            <option value="blocking">封锁模式</option>
          </select>
          {/* 网关端 P1 修复「API Key 无法清除」：提供退出登录入口，清除会话中的管理密钥 */}
          <button onClick={onLogout} title="清除当前会话保存的管理密钥并返回登录页"
            style={{ padding: '4px 12px', background: '#334155', color: '#94a3b8', border: '1px solid #475569', borderRadius: 4, fontSize: 12, cursor: 'pointer', whiteSpace: 'nowrap' }}>
            退出登录
          </button>
        </div>
      </header>
      <main style={{ maxWidth: 1280, margin: '0 auto', padding: '24px' }}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/detect" element={<Detect />} />
          <Route path="/audit" element={<AuditLogs />} />
          <Route path="/models" element={<ModelConfig />} />
          <Route path="/keys" element={<AdminKeys />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
    </div>
  )
}

function AppInner() {
  const [apiKey, setApiKey] = useState<string | null>(() => sessionStorage.getItem(AUTH_KEY_STORAGE))
  const [checking, setChecking] = useState(true)

  const handleAuth = useCallback((key: string) => {
    sessionStorage.setItem(AUTH_KEY_STORAGE, key)
    api.setApiKey(key)
    setApiKey(key)
  }, [])

  // 网关端 P1「API Key 无法清除」：退出登录 = 清除 sessionStorage 与运行时密钥
  const handleLogout = useCallback(() => {
    sessionStorage.removeItem(AUTH_KEY_STORAGE)
    api.setApiKey(null)
    setApiKey(null)
  }, [])

  // 启动时验证已保存的 key
  useEffect(() => {
    const saved = sessionStorage.getItem(AUTH_KEY_STORAGE)
    if (!saved) { setChecking(false); return }
    api.setApiKey(saved)
    // 用 stats 端点验证 key 是否仍有效
    api.getStats().then(() => {
      setApiKey(saved)
      setChecking(false)
    }).catch(() => {
      // key 无效则清除
      sessionStorage.removeItem(AUTH_KEY_STORAGE)
      api.setApiKey(null)
      setApiKey(null)
      setChecking(false)
    })
  }, [])

  if (checking) {
    return <div style={{ minHeight: '100vh', background: '#0f172a', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#64748b', fontSize: 14 }}>验证登录状态...</div>
  }

  if (!apiKey) {
    return <Login onAuth={handleAuth} />
  }

  return <MainApp onLogout={handleLogout} />
}

// P0-A-1: ErrorBoundary 外层保护
export default function App() {
  return (
    <ErrorBoundary>
      <AppInner />
    </ErrorBoundary>
  )
}
