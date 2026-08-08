import { useEffect, useRef, useState } from 'react'

interface Props { open: boolean; message: string; onConfirm: () => void; onCancel: () => void }

export default function ConfirmModal({ open, message, onConfirm, onCancel }: Props) {
  const processingRef = useRef(false)
  const [processingUI, setProcessingUI] = useState(false)
  const safetyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => { return () => { if (safetyTimerRef.current) clearTimeout(safetyTimerRef.current) } }, [])
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape' && !processingRef.current) onCancel() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onCancel])

  if (!open) return null

  const handleConfirm = () => {
    if (processingRef.current) return
    processingRef.current = true
    setProcessingUI(true)
    safetyTimerRef.current = setTimeout(() => { processingRef.current = false; setProcessingUI(false) }, 30000)
    try { onConfirm() } catch { processingRef.current = false; setProcessingUI(false); if (safetyTimerRef.current) clearTimeout(safetyTimerRef.current) }
  }
  const handleCancel = () => { if (processingRef.current) return; onCancel() }

  return (
    <div onClick={handleCancel} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 10000 }}>
      <div onClick={e => e.stopPropagation()} style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 12, padding: 28, maxWidth: 420, width: '90%' }}>
        <p style={{ color: '#e2e8f0', fontSize: 14, lineHeight: 1.7, margin: '0 0 24px', whiteSpace: 'pre-wrap' }}>{message}</p>
        <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
          <button onClick={handleCancel} disabled={processingUI} style={{ padding: '8px 20px', background: 'transparent', color: '#94a3b8', border: '1px solid #475569', borderRadius: 6, fontSize: 13, cursor: processingUI ? 'not-allowed' : 'pointer', opacity: processingUI ? 0.4 : 1 }}>取消</button>
          <button onClick={handleConfirm} disabled={processingUI} style={{ padding: '8px 20px', background: processingUI ? '#1e3a5f' : '#1d4ed8', color: '#fff', border: 'none', borderRadius: 6, fontSize: 13, fontWeight: 600, cursor: processingUI ? 'not-allowed' : 'pointer' }}>{processingUI ? '处理中...' : '确认'}</button>
        </div>
      </div>
    </div>
  )
}
