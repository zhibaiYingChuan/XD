import { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';
import { isTauriBridgeAvailable } from '../services/tauriApi';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  // GAP-S5-10 修复：reload 后 Bridge 未就绪时显示等待提示
  reloading: boolean;
  bridgeReady: boolean;
}

export default class ErrorBoundary extends Component<Props, State> {
  // GAP-S5-10 修复：reload 后轮询 Bridge 就绪的 timer 引用
  private bridgePollTimer: ReturnType<typeof setInterval> | null = null;

  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null, reloading: false, bridgeReady: true };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, reloading: false, bridgeReady: true };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('[XuanDun] Uncaught error:', error, errorInfo);
  }

  componentWillUnmount() {
    if (this.bridgePollTimer) clearInterval(this.bridgePollTimer);
  }

  // GAP-S5-10 修复：reload 后轮询 Bridge 就绪，未就绪时显示初始化等待
  private checkBridgeReady = () => {
    if (isTauriBridgeAvailable()) {
      this.setState({ bridgeReady: true, reloading: false });
      if (this.bridgePollTimer) {
        clearInterval(this.bridgePollTimer);
        this.bridgePollTimer = null;
      }
    }
  };

  handleReload = () => {
    this.setState({ hasError: false, error: null, reloading: true, bridgeReady: false });
    window.location.reload();
    // GAP-S5-10 修复：reload 后轮询 Bridge 是否注入完成
    // Tauri 2.x WebView2 reload 后 __TAURI_INTERNALS__ 重新注入可能有延迟
    this.bridgePollTimer = setInterval(this.checkBridgeReady, 200);
    // 5 秒超时：若 Bridge 仍未就绪，提示用户手动重启应用
    setTimeout(() => {
      if (!isTauriBridgeAvailable()) {
        this.setState({
          bridgeReady: false,
          reloading: false,
          hasError: true,
          error: new Error('应用重新加载后 Tauri 桥接未就绪，请关闭应用后重新启动。'),
        });
        if (this.bridgePollTimer) {
          clearInterval(this.bridgePollTimer);
          this.bridgePollTimer = null;
        }
      }
    }, 5000);
  };

  render() {
    // GAP-S5-10 修复：reloading 中显示初始化等待
    if (this.state.reloading && !this.state.bridgeReady) {
      return (
        <div className="error-boundary">
          <div className="error-boundary-card">
            <RefreshCw size={48} strokeWidth={1.5} className="error-boundary-icon" style={{ animation: 'spin 1s linear infinite' }} />
            <h2 className="error-boundary-title">应用正在初始化</h2>
            <p className="error-boundary-desc">
              正在重新加载应用并初始化 Tauri 桥接，请稍候...
            </p>
          </div>
        </div>
      );
    }
    if (this.state.hasError) {
      return (
        <div className="error-boundary">
          <div className="error-boundary-card">
            <AlertTriangle size={48} strokeWidth={1.5} className="error-boundary-icon" />
            <h2 className="error-boundary-title">应用遇到异常</h2>
            <p className="error-boundary-desc">
              玄盾运行中遇到未预期的错误。请尝试重新加载应用，如问题持续请联系技术支持。
            </p>
            {this.state.error && (
              <details className="error-boundary-details">
                <summary>错误详情</summary>
                <pre>{this.state.error.message}</pre>
                {import.meta.env.DEV && <pre>{this.state.error.stack}</pre>}
              </details>
            )}
            <button className="btn btn-primary" onClick={this.handleReload}>
              <RefreshCw size={16} strokeWidth={1.5} /> 重新加载
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
