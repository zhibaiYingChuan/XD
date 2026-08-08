import { Component, ErrorInfo, ReactNode } from 'react'

interface Props { children: ReactNode }
interface State { hasError: boolean; error: Error | null }

export default class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('[XuanDun Admin] Uncaught error:', error, errorInfo)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ minHeight: '100vh', background: '#0f172a', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ maxWidth: 480, padding: 40, background: '#1e293b', border: '1px solid #334155', borderRadius: 12, textAlign: 'center' }}>
            <div style={{ fontSize: 48, marginBottom: 16 }}>!</div>
            <h2 style={{ fontSize: 20, fontWeight: 700, color: '#e2e8f0', margin: '0 0 8px' }}>控制台遇到异常</h2>
            <p style={{ fontSize: 14, color: '#94a3b8', lineHeight: 1.6, margin: '0 0 16px' }}>
              玄盾管理控制台运行中遇到未预期的错误。请尝试重新加载，如问题持续请联系技术支持。
            </p>
            {this.state.error && (
              <details style={{ textAlign: 'left', background: '#0f172a', borderRadius: 8, padding: 12, marginBottom: 16 }}>
                <summary style={{ cursor: 'pointer', color: '#64748b', fontSize: 12 }}>错误详情</summary>
                <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: '#f87171', fontSize: 11, lineHeight: 1.5, marginTop: 8, maxHeight: 200, overflow: 'auto' }}>
                  {this.state.error.message + '\n' + (this.state.error.stack || '')}
                </pre>
              </details>
            )}
            <button onClick={() => window.location.reload()} style={{ padding: '10px 32px', background: '#1d4ed8', color: '#fff', border: 'none', borderRadius: 8, fontSize: 14, fontWeight: 600, cursor: 'pointer' }}>
              重新加载
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
