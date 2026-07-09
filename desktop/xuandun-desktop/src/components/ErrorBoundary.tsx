import { Component, ErrorInfo, ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export default class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('[XuanDun] Uncaught error:', error, errorInfo);
  }

  handleReload = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-boundary">
          <div className="error-boundary-card">
            <div className="error-boundary-icon">⚠️</div>
            <h2 className="error-boundary-title">应用遇到异常</h2>
            <p className="error-boundary-desc">
              玄盾运行中遇到未预期的错误。请尝试重新加载应用，如问题持续请联系技术支持。
            </p>
            {this.state.error && (
              <details className="error-boundary-details">
                <summary>错误详情</summary>
                <pre>{this.state.error.message}</pre>
                <pre>{this.state.error.stack}</pre>
              </details>
            )}
            <button className="btn btn-primary" onClick={this.handleReload}>
              🔄 重新加载
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
