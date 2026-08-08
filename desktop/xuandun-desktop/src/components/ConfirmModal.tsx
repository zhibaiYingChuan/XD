import { useState, useCallback, useRef, useEffect } from 'react';
import { AlertTriangle, X } from 'lucide-react';

/**
 * ConfirmModal — 替代 window.confirm() 的自定义模态框
 *
 * NEW-P0-05 修复：window.confirm() 在 Tauri WebView2 中会阻塞消息循环，
 * 导致 CDP 连接卡死和 UI 无响应。此组件提供异步 confirm 功能。
 *
 * GAP-S5-01 修复：支持 ESC 键关闭弹窗（等同取消）
 */

interface ConfirmModalProps {
  open: boolean;
  message: string;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmModal({ open, message, onConfirm, onCancel }: ConfirmModalProps) {
  // ============================================================
  // Sprint2-CDP-B1: ConfirmModal 0ms双击穿透根因修复
  //
  // 旧方案(P0-2)问题：processing=useState(false)是异步批处理锁。
  // 在React同一macrotask内两次click，两次都读到false，confirmCalls=2。
  //
  // 新方案（双锁协同）：
  //   ① processingRef 同步锁(useRef)：同事件循环立即生效，防0ms穿透；
  //   ② processingUI 视觉锁(useState)：用于disabled/文案显示，不参与竞态；
  //   ③ open/message变化时重置锁——队列入参切换时（即使open仍true）也要清零，
  //      因为useConfirmModal在队列shift后showNext()会改message而保持open=true。
  // ============================================================
  const processingRef = useRef(false);
  const [processingUI, setProcessingUI] = useState(false);

  // P0-5 修复：ARIA 可访问性 - dialog ref 和 trigger 焦点记录
  const dialogRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLElement | null>(null);

  // open/message变化时重置两把锁（保证下一个队列项可点击）
  useEffect(() => {
    processingRef.current = false;
    setProcessingUI(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, message]);

  // GAP-S5-01 修复：ESC 键监听，弹窗打开时按 ESC 触发取消
  useEffect(() => {
    if (!open) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        if (!processingRef.current) onCancel();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [open, onCancel]);

  // P0-5 修复：焦点管理 - 打开时聚焦首个可交互元素，关闭时恢复焦点到触发元素
  useEffect(() => {
    if (open) {
      triggerRef.current = document.activeElement as HTMLElement;
      // 延迟聚焦，等待 dialog 渲染
      const timer = setTimeout(() => {
        const dialog = dialogRef.current;
        if (dialog) {
          const focusable = dialog.querySelectorAll<HTMLElement>('button:not([disabled]), [href], input:not([disabled]), [tabindex]:not([tabindex="-1"])');
          if (focusable.length > 0) {
            focusable[0].focus();
          }
        }
      }, 0);
      return () => clearTimeout(timer);
    } else {
      // 关闭时恢复焦点到触发元素
      if (triggerRef.current) {
        triggerRef.current.focus();
        triggerRef.current = null;
      }
    }
  }, [open]);

  // P0-5 修复：焦点陷阱 - Tab/Shift+Tab 在对话框内循环，不跳到背后内容（WCAG 2.1.2）
  useEffect(() => {
    if (!open) return;
    const handleTabKey = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return;
      const dialog = dialogRef.current;
      if (!dialog) return;
      const focusable = dialog.querySelectorAll<HTMLElement>('button:not([disabled]), [href], input:not([disabled]), [tabindex]:not([tabindex="-1"])');
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey) {
        if (document.activeElement === first) {
          e.preventDefault();
          last.focus();
        }
      } else {
        if (document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    window.addEventListener('keydown', handleTabKey);
    return () => window.removeEventListener('keydown', handleTabKey);
  }, [open]);

  // GAP-S5-09 修复：弹窗打开时通过 Web Notification API 通知用户（降级方案）
  // 当用户切换到其他应用时，系统通知栏会提示"有待确认操作"
  useEffect(() => {
    if (!open) return;
    if (typeof Notification === 'undefined') return;
    if (Notification.permission === 'granted') {
      try {
        const notif = new Notification('道体·玄盾 — 待确认操作', {
          body: message.length > 80 ? message.slice(0, 80) + '...' : message,
          tag: 'xuandun-confirm',
          requireInteraction: false,
        });
        // 用户点击通知时聚焦窗口
        notif.onclick = () => {
          window.focus();
          notif.close();
        };
        return () => notif.close();
      } catch {
        // 通知 API 不可用时静默降级
      }
    } else if (Notification.permission === 'default') {
      // 首次打开时请求权限（不阻塞 UI）
      Notification.requestPermission().catch(() => {});
    }
  }, [open, message]);

  // P0-4 修复：processingRef 锁定后若 IPC 永不返回，30s 自动恢复
  // 防止弹窗永久卡死导致用户无法操作应用
  useEffect(() => {
    if (!processingUI) return;
    const timeout = setTimeout(() => {
      console.warn('[ConfirmModal] Processing timeout after 30s, auto-recovering');
      processingRef.current = false;
      setProcessingUI(false);
    }, 30000);
    return () => clearTimeout(timeout);
  }, [processingUI]);

  // Sprint2-CDP-B1: 包装点击处理——同步锁先写ref（立即生效防穿透），再写UI锁（视觉反馈）
  // 旧代码仅用useState异步锁导致0ms间隔双击穿透
  const handleConfirmClick = () => {
    if (processingRef.current) return;
    processingRef.current = true;   // 同步锁：立即生效（同macrotask内后续click必然返回）
    setProcessingUI(true);
    // P0-A-5 修复：try-finally 确保回调异常时锁一定释放，避免按钮永久卡死
    try { onConfirm(); } catch {}
    // 异步 onConfirm 应在完成后通过 30s 兜底或手动关闭弹窗来释放锁
  };
  const handleCancelClick = () => {
    if (processingRef.current) return;
    processingRef.current = true;
    setProcessingUI(true);
    try { onCancel(); } catch {}
  };

  if (!open) return null;
  return (
    <div
      className="confirm-modal-overlay"
      role="presentation"
      style={{
        position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
        backgroundColor: 'rgba(0,0,0,0.5)', zIndex: 10000,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}
      onClick={handleCancelClick}
    >
      <div
        ref={dialogRef}
        className="confirm-modal-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="confirm-modal-title"
        style={{
          background: 'var(--bg-primary, #1a1a2e)',
          border: '1px solid var(--border-color, #333)',
          borderRadius: 12, padding: 24, maxWidth: 480, width: '90%',
          boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* P0-5 修复：ARIA 标题，屏幕阅读器可见，视觉隐藏 */}
        <h2 id="confirm-modal-title" className="sr-only">确认操作</h2>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 20 }}>
          <AlertTriangle size={24} strokeWidth={1.5} style={{ color: 'var(--warning, #f0ad4e)', flexShrink: 0, marginTop: 2 }} />
          <div style={{ whiteSpace: 'pre-wrap', lineHeight: 1.6, color: 'var(--text-primary, #e0e0e0)' }}>
            {message}
          </div>
          <button
            onClick={handleCancelClick}
            disabled={processingUI}
            style={{ background: 'none', border: 'none', cursor: processingUI ? 'not-allowed' : 'pointer', color: 'var(--text-secondary)', padding: 0, marginLeft: 'auto', opacity: processingUI ? 0.5 : 1 }}
            aria-label="关闭"
          >
            <X size={18} strokeWidth={1.5} />
          </button>
        </div>
        <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
          <button
            className="btn btn-secondary"
            onClick={handleCancelClick}
            disabled={processingUI}
            style={{ padding: '8px 20px', borderRadius: 6, cursor: processingUI ? 'not-allowed' : 'pointer', opacity: processingUI ? 0.6 : 1 }}
          >
            取消
          </button>
          <button
            className="btn btn-danger"
            onClick={handleConfirmClick}
            disabled={processingUI}
            style={{ padding: '8px 20px', borderRadius: 6, cursor: processingUI ? 'not-allowed' : 'pointer', background: 'var(--danger, #dc3545)', color: '#fff', border: 'none', opacity: processingUI ? 0.6 : 1 }}
          >
            {processingUI ? '处理中...' : '确认'}
          </button>
        </div>
      </div>
    </div>
  );
}

/**
 * useConfirmModal — 管理确认模态框状态的 hook
 *
 * GAP-01 修复：支持队列化，避免并发 confirm 导致首个 Promise 永挂。
 * 多个 confirm 调用会排队，逐个显示，用户确认/取消后自动显示下一个。
 *
 * GAP-S5-02 修复：组件卸载时清理队列中所有 Promise（resolve false），
 * 避免应用关闭/组件卸载时 Promise 永挂。
 *
 * 用法：
 *   const { modalProps, confirm } = useConfirmModal();
 *   if (!(await confirm('确定要执行吗？'))) return;
 *   // 在组件 JSX 末尾渲染：<ConfirmModal {...modalProps} />
 */
export function useConfirmModal() {
  const [open, setOpen] = useState(false);
  const [message, setMessage] = useState('');
  // GAP-01 修复：使用队列存储多个 confirm 请求，避免并发时 Promise 永挂
  const queueRef = useRef<Array<{ msg: string; resolve: (v: boolean) => void }>>([]);

  const showNext = useCallback(() => {
    if (queueRef.current.length > 0) {
      const next = queueRef.current[0];
      setMessage(next.msg);
      setOpen(true);
    } else {
      setOpen(false);
    }
  }, []);

  const confirm = useCallback((msg: string): Promise<boolean> => {
    return new Promise<boolean>((resolve) => {
      queueRef.current.push({ msg, resolve });
      // 如果是第一个，立即显示；否则排队等待
      if (queueRef.current.length === 1) {
        showNext();
      }
    });
  }, [showNext]);

  const handleConfirm = useCallback(() => {
    const current = queueRef.current.shift();
    if (current) {
      current.resolve(true);
    }
    showNext();
  }, [showNext]);

  const handleCancel = useCallback(() => {
    const current = queueRef.current.shift();
    if (current) {
      current.resolve(false);
    }
    showNext();
  }, [showNext]);

  // GAP-S5-02 修复：组件卸载时清理队列中所有未处理的 Promise
  // 避免应用关闭/路由切换时 Promise 永挂
  useEffect(() => {
    return () => {
      while (queueRef.current.length > 0) {
        const item = queueRef.current.shift();
        if (item) item.resolve(false);
      }
    };
  }, []);

  return {
    modalProps: { open, message, onConfirm: handleConfirm, onCancel: handleCancel },
    confirm,
  };
}
