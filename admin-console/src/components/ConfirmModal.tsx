import { useEffect, useRef, useState } from 'react'

// G-P1-1/2 扩展：支持必填输入（替代 window.prompt —— 取消时不再静默以空值继续）
interface Props {
  open: boolean
  message: string
  onConfirm: (input?: string) => void
  onCancel: () => void
  /** 开启后显示必填输入框，确认时以输入值调用 onConfirm */
  withInput?: boolean
  inputPlaceholder?: string
  confirmLabel?: string
}

export default function ConfirmModal({ open, message, onConfirm, onCancel, withInput = false, inputPlaceholder = '', confirmLabel = '确认' }: Props) {
  const processingRef = useRef(false)
  const [processingUI, setProcessingUI] = useState(false)
  const safetyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const [inputVal, setInputVal] = useState('')
  const [inputErr, setInputErr] = useState(false)
  // 供 Enter 键复用最新的 handleConfirm（避免闭包过期）
  // Hooks 规则：必须声明在下方 `if (!open) return null` 早退之前，
  // 否则 open 翻转时 hooks 数量变化 → "Rendered more hooks" 运行时崩溃
  const handleConfirmRef = useRef<(() => void) | null>(null)

  useEffect(() => { return () => { if (safetyTimerRef.current) clearTimeout(safetyTimerRef.current) } }, [])
  // 打开时重置输入态
  useEffect(() => { if (open) { setInputVal(''); setInputErr(false) } }, [open])
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !processingRef.current) onCancel()
      if (e.key === 'Enter' && !processingRef.current) { e.preventDefault(); (document.getElementById('confirm-modal-input') as HTMLInputElement | null)?.focus?.(); handleConfirmRef.current?.() }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onCancel])

  if (!open) return null

  const handleConfirm = () => {
    if (processingRef.current) return
    // 必填校验：空输入不进入处理态，红框提示（而非静默放行）
    if (withInput && !inputVal.trim()) { setInputErr(true); return }
    processingRef.current = true
    setProcessingUI(true)
    safetyTimerRef.current = setTimeout(() => { processingRef.current = false; setProcessingUI(false) }, 30000)
    try { onConfirm(withInput ? inputVal.trim() : undefined) } catch { processingRef.current = false; setProcessingUI(false); if (safetyTimerRef.current) clearTimeout(safetyTimerRef.current) }
  }
  // 每次渲染同步最新 handleConfirm 到 ref（供 Enter 键监听调用，避免闭包过期）
  handleConfirmRef.current = handleConfirm

  const handleCancel = () => { if (processingRef.current) return; onCancel() }

  return (
    <div onClick={handleCancel} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 10000 }}>
      <div onClick={e => e.stopPropagation()} style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 12, padding: 28, maxWidth: 420, width: '90%' }}>
        <p style={{ color: '#e2e8f0', fontSize: 14, lineHeight: 1.7, margin: '0 0 24px', whiteSpace: 'pre-wrap' }}>{message}</p>
        {withInput && (
          <input
            id="confirm-modal-input"
            value={inputVal}
            disabled={processingUI}
            autoFocus
            placeholder={inputPlaceholder}
            onChange={(e) => { setInputVal(e.target.value); if (e.target.value.trim()) setInputErr(false) }}
            style={{
              width: '100%', padding: '8px 12px', borderRadius: 6, marginBottom: 20, fontSize: 13,
              background: '#0f172a', color: '#e2e8f0', outline: 'none',
              border: `1px solid ${inputErr ? '#f87171' : '#475569'}`, boxSizing: 'border-box',
            }}
          />
        )}
        {inputErr && <div style={{ color: '#f87171', fontSize: 12, margin: '-14px 0 16px' }}>此项为必填，请输入后确认（或点取消放弃操作）</div>}
        <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
          <button onClick={handleCancel} disabled={processingUI} style={{ padding: '8px 20px', background: 'transparent', color: '#94a3b8', border: '1px solid #475569', borderRadius: 6, fontSize: 13, cursor: processingUI ? 'not-allowed' : 'pointer', opacity: processingUI ? 0.4 : 1 }}>取消</button>
          <button onClick={handleConfirm} disabled={processingUI} style={{ padding: '8px 20px', background: processingUI ? '#1e3a5f' : '#1d4ed8', color: '#fff', border: 'none', borderRadius: 6, fontSize: 13, fontWeight: 600, cursor: processingUI ? 'not-allowed' : 'pointer' }}>{processingUI ? '处理中...' : confirmLabel}</button>
        </div>
      </div>
    </div>
  )
}
