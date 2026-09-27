/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   错误边界 — 消费级友好提示（不暴露技术细节）。
*/

import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';
import { ShieldAlert, RotateCcw } from 'lucide-react';
import { currentProxyPort } from '../services/api';

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('[玄盾个人版] 未捕获错误:', error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;

    return (
      <div className="error-screen">
        <ShieldAlert size={48} strokeWidth={1.5} color="var(--xd-danger)" />
        <div className="error-title">应用遇到问题</div>
        <div className="muted" style={{ maxWidth: 420 }}>
          玄盾个人版遇到了意外错误。你可以尝试重新加载，如果问题持续存在，
          请检查本地代理（127.0.0.1:{currentProxyPort()}）是否正常运行。
        </div>
        <details className="error-detail">
          <summary className="faint" style={{ cursor: 'pointer', fontSize: 12 }}>
            错误详情
          </summary>
          <div className="code-block mt-8">{this.state.error.message}</div>
        </details>
        <button className="btn mt-16" onClick={() => window.location.reload()}>
          <RotateCcw size={15} strokeWidth={1.5} />
          重新加载
        </button>
      </div>
    );
  }
}
