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
  // GAP-S5-01 修复：ESC 键监听，弹窗打开时按 ESC 触发取消
  useEffect(() => {
    if (!open) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onCancel();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [open, onCancel]);

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

  if (!open) return null;
  return (
    <div
      className="confirm-modal-overlay"
      style={{
        position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
        backgroundColor: 'rgba(0,0,0,0.5)', zIndex: 10000,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}
      onClick={onCancel}
    >
      <div
        className="confirm-modal-dialog"
        style={{
          background: 'var(--bg-primary, #1a1a2e)',
          border: '1px solid var(--border-color, #333)',
          borderRadius: 12, padding: 24, maxWidth: 480, width: '90%',
          boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 20 }}>
          <AlertTriangle size={24} strokeWidth={1.5} style={{ color: 'var(--warning, #f0ad4e)', flexShrink: 0, marginTop: 2 }} />
          <div style={{ whiteSpace: 'pre-wrap', lineHeight: 1.6, color: 'var(--text-primary, #e0e0e0)' }}>
            {message}
          </div>
          <button
            onClick={onCancel}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)', padding: 0, marginLeft: 'auto' }}
            aria-label="关闭"
          >
            <X size={18} strokeWidth={1.5} />
          </button>
        </div>
        <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
          <button
            className="btn btn-secondary"
            onClick={onCancel}
            style={{ padding: '8px 20px', borderRadius: 6, cursor: 'pointer' }}
          >
            取消
          </button>
          <button
            className="btn btn-danger"
            onClick={onConfirm}
            style={{ padding: '8px 20px', borderRadius: 6, cursor: 'pointer', background: 'var(--danger, #dc3545)', color: '#fff', border: 'none' }}
          >
            确认
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
