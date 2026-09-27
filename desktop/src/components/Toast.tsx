/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   Toast 消息队列（消费级：不打扰原则，仅在必要时提示）。
*/

import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { CheckCircle2, XCircle, Info, X } from 'lucide-react';

// ══════════════════════════════════════════════════════════════
// 类型 + Context
// ══════════════════════════════════════════════════════════════

export type ToastType = 'success' | 'error' | 'info';

interface ToastItem {
  id: number;
  type: ToastType;
  text: string;
}

interface ToastApi {
  success: (text: string) => void;
  error: (text: string) => void;
  info: (text: string) => void;
}

const ToastContext = createContext<ToastApi | null>(null);

const DEFAULT_DURATION = 4000;

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error('useToast 必须在 ToastProvider 内使用');
  }
  return ctx;
}

// ══════════════════════════════════════════════════════════════
// Provider
// ══════════════════════════════════════════════════════════════

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const idRef = useRef(0);

  const remove = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const push = useCallback(
    (type: ToastType, text: string) => {
      const id = ++idRef.current;
      setToasts((prev) => {
        // 去重：同类型同文案不重复堆叠
        if (prev.some((t) => t.type === type && t.text === text)) return prev;
        return [...prev, { id, type, text }];
      });
      setTimeout(() => remove(id), DEFAULT_DURATION);
    },
    [remove],
  );

  const api = useMemo<ToastApi>(
    () => ({
      success: (t) => push('success', t),
      error: (t) => push('error', t),
      info: (t) => push('info', t),
    }),
    [push],
  );

  return (
    <ToastContext.Provider value={api}>
      {children}
      {toasts.length > 0 && (
        <div className="toast-stack" role="status" aria-live="polite">
          {toasts.map((t) => (
            <div key={t.id} className={`toast ${t.type}`}>
              <span className="toast-icon">
                {t.type === 'success' && <CheckCircle2 size={17} strokeWidth={1.5} />}
                {t.type === 'error' && <XCircle size={17} strokeWidth={1.5} />}
                {t.type === 'info' && <Info size={17} strokeWidth={1.5} />}
              </span>
              <span className="toast-text">{t.text}</span>
              <button
                className="toast-close"
                onClick={() => remove(t.id)}
                aria-label="关闭提示"
              >
                <X size={15} strokeWidth={1.5} />
              </button>
            </div>
          ))}
        </div>
      )}
    </ToastContext.Provider>
  );
}
