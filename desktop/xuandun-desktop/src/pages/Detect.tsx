import { useState, useRef, useCallback, useEffect } from 'react';
import { api, ProtectResponse, formatInvokeError, InvokeTimeoutError, formatTrustLevel } from '../services/tauriApi';
import { AlertTriangle, Zap, Info, CheckCircle, ShieldX } from 'lucide-react';

// G-13 修复：Toast 队列类型定义
interface ToastItem {
  id: number;
  message: string;
  type: 'error' | 'warning' | 'info';
}

// G-13 修复：Toast ID 自增计数器（模块级，保证唯一）
let toastIdCounter = 0;

// P1-13 修复：检测文本最大长度限制，防止超长文本导致 IPC 卡顿或后端超时
const MAX_DETECT_LENGTH = 10000;

export default function Detect() {
  const [text, setText] = useState('');
  const [mode, setMode] = useState('balanced');
  const [result, setResult] = useState<ProtectResponse | null>(null);
  const [loading, setLoading] = useState(false);
  // G-13 修复：使用 Toast 队列替代单个 error，多错误不覆盖
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  // G-11 修复：useRef 同步守卫，防止 React 状态更新异步性导致的重复点击
  const detectingRef = useRef(false);
  // Sprint2-CDP-B2-A1: React受控组件 + CDP直接改DOM.value兜底。
  // CDP测试工具、HCSE框架等通常直接写textarea.value绕过React setState，
  // 导致text state=""但真实DOM有内容 → handleDetect的!text.trim()直接return，
  // protect_calls=0 看似Bug。这里优先从DOM真实value取值，兜底React状态不同步场景。
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);

  // G-13 修复：添加 Toast 到队列（不覆盖现有 Toast）
  // P0-NEW-2 修复：Toast 去重——如果队列中已存在相同 message+type 的 Toast，不重复添加
  const addToast = useCallback((message: string, type: ToastItem['type'] = 'error') => {
    setToasts(prev => {
      // 去重检查：相同 message+type 的 Toast 已存在则不重复添加
      if (prev.some(t => t.message === message && t.type === type)) {
        return prev;
      }
      const id = ++toastIdCounter;
      // 5 秒后自动移除
      setTimeout(() => {
        setToasts(p => p.filter(t => t.id !== id));
      }, 5000);
      return [...prev, { id, message, type }];
    });
  }, []);

  // G-13 修复：手动关闭 Toast
  const removeToast = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  // NEW-P0-04 修复：检测进行中拦截页面关闭/刷新，防止 invoke Promise 丢弃
  useEffect(() => {
    if (!loading) return;
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, [loading]);

  // P1-NEW-2 修复：初始化时从后端读取当前防护模式，与 Settings 页面保持状态同步
  // 避免 Detect 显示"平衡"而 Settings 显示"低误报"的状态不一致问题
  useEffect(() => {
    api.getConfig('mode').then(m => {
      if (m) setMode(m);
    }).catch(() => {
      // 读取失败保持默认值 'balanced'
    });
  }, []);

  const handleDetect = useCallback(async () => {
    // 同步守卫：立即拒绝重复点击，不依赖 React 异步状态
    if (detectingRef.current) return;
    // Sprint2-CDP-B2-A1: DOM真实值优先（CDP直接写textarea.value时React state不同步）
    const domText = textareaRef.current?.value ?? '';
    const actualText = (domText.trim().length > 0) ? domText : text;
    if (!actualText.trim()) {
      addToast('请输入要检测的文本内容', 'info');
      return;
    }
    detectingRef.current = true;
    setLoading(true);
    try {
      const res = await api.protect(actualText, 'default', mode);
      setResult(res);
      // G-14 修复：根据 fallback 标志区分"引擎不可达"和"实际拦截"
      if (!res.allowed && res.fallback) {
        addToast('引擎不可达，已启动保护性阻断（fallback 模式）', 'warning');
      }
    } catch (e) {
      // L1-E 修复：区分超时错误与其他错误，提供精准修复路径指引
      if (e instanceof InvokeTimeoutError) {
        addToast('检测超时，请缩短文本或稍后重试（引擎可能过载）', 'warning');
      } else {
        addToast(formatInvokeError(e, '检测'), 'error');
      }
      setResult(null);
    } finally {
      setLoading(false);
      detectingRef.current = false;
    }
  }, [text, mode, addToast]);

  const modes = [
    { key: 'high_security', label: '高安全' },
    { key: 'balanced', label: '平衡' },
    { key: 'low_false_positive', label: '低误报' },
  ];

  return (
    <div className="page detect-page">
      {/* P0-4 修复：每页唯一 H1，符合 WCAG AA 规范 §3.3/§3.4 */}
      <div className="page-header">
        <h1 className="page-title">安全检测</h1>
      </div>
      {/* G-13 修复：Toast 队列渲染区域，多错误堆叠显示 */}
      {toasts.length > 0 && (
        <div className="toast-queue-container" style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 16 }}>
          {toasts.map(toast => (
            <div
              key={toast.id}
              className={`alert-banner ${
                toast.type === 'error' ? 'alert-danger' :
                toast.type === 'warning' ? 'alert-warning' : 'alert-info'
              }`}
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}
            >
              <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className="alert-icon">
                  {toast.type === 'error' ? <AlertTriangle size={18} strokeWidth={1.5} /> : toast.type === 'warning' ? <Zap size={18} strokeWidth={1.5} /> : <Info size={18} strokeWidth={1.5} />}
                </span>
                <span>{toast.message}</span>
              </span>
              <button
                onClick={() => removeToast(toast.id)}
                style={{
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  fontSize: 16,
                  padding: '0 4px',
                  color: 'inherit',
                  opacity: 0.7,
                }}
                aria-label="关闭提示"
              >
                ✕
              </button>
            </div>
          ))}
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h3>安全检测</h3>
        </div>
        <div className="card-body">
          <div className="form-group">
            <label className="form-label">检测模式</label>
            <div className="mode-selector" role="radiogroup" aria-label="检测模式">
              {modes.map((m) => {
                const isActive = mode === m.key;
                return (
                  <button
                    key={m.key}
                    role="radio"
                    aria-checked={isActive}
                    aria-label={`${m.label}模式`}
                    tabIndex={isActive ? 0 : -1}
                    className={`mode-btn ${isActive ? 'active' : ''}`}
                    onClick={() => setMode(m.key)}
                    onKeyDown={(e) => {
                      // P0-NEW-1 修复：支持键盘箭头键在模式间切换（WCAG 2.1 AA radiogroup 模式）
                      const idx = modes.findIndex(x => x.key === m.key);
                      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
                        e.preventDefault();
                        const nextIdx = (idx + 1) % modes.length;
                        const nextEl = e.currentTarget.parentElement?.children[nextIdx] as HTMLElement;
                        nextEl?.focus();
                        setMode(modes[nextIdx].key);
                      } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
                        e.preventDefault();
                        const prevIdx = (idx - 1 + modes.length) % modes.length;
                        const prevEl = e.currentTarget.parentElement?.children[prevIdx] as HTMLElement;
                        prevEl?.focus();
                        setMode(modes[prevIdx].key);
                      }
                    }}
                  >
                    {m.label}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">输入文本</label>
            <textarea
              ref={textareaRef}
              className="form-textarea"
              value={text}
              onChange={(e) => setText(e.target.value.slice(0, MAX_DETECT_LENGTH))}
              placeholder="输入要检测的文本内容..."
              rows={5}
              maxLength={MAX_DETECT_LENGTH}
            />
            {/* P1-13 修复：字符计数提示，接近上限时显示警告 */}
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px' }}>
              <span style={{ fontSize: '0.85em', color: 'var(--text-secondary)' }}>
                {text.length} / {MAX_DETECT_LENGTH}
              </span>
              {text.length > MAX_DETECT_LENGTH * 0.9 && (
                <span style={{ fontSize: '0.85em', color: 'var(--warning)' }}>
                  文本较长，可能影响检测速度
                </span>
              )}
            </div>
          </div>

          {/* P0修复 v2: 按钮disabled只绑loading状态
               1. 空文本点击有addToast('请输入...', 'info')守卫，不会崩溃也不会白屏
               2. CDP直写textarea.value不触发onChange→React state text=""但DOM有内容，
                  如果还绑!text.trim()则按钮永远灰无法点→actualText读取逻辑白做
               3. 正常用户onChange路径：有内容/无内容点都有合理反馈（无内容弹info toast）
               4. 加载中仍然disabled防止重复提交（detectingRef+loading双保险） */}
          <button
            className="btn btn-primary"
            onClick={handleDetect}
            disabled={loading}
          >
            {loading ? '检测中...' : '开始检测'}
          </button>

          {result && (
            <div className={`result-card ${result.allowed ? 'pass' : 'block'}`}>
              <div className="result-header">
                {/* G-14 修复：根据 fallback 标志显示不同图标和文案 */}
                <span className="result-icon">
                  {result.allowed ? <CheckCircle size={18} strokeWidth={1.5} /> : result.fallback ? <AlertTriangle size={18} strokeWidth={1.5} /> : <ShieldX size={18} strokeWidth={1.5} />}
                </span>
                <span className="result-text">
                  {result.allowed ? '通过' : result.fallback ? '引擎不可达（保护性阻断）' : '已拦截'}
                </span>
              </div>
              <div className="result-details">
                <span>信任等级: <span className={`trust-badge trust-${(result.trust_level || 'unknown').toLowerCase()}`}>{formatTrustLevel(result.trust_level)}</span></span>
                {result.reject_stage && <span>拦截阶段: {result.reject_stage}</span>}
                {result.domain_distance != null && (
                  <span>域距离: {result.domain_distance.toFixed(4)}</span>
                )}
                {result.timing_distance != null && (
                  <span>时序距离: {result.timing_distance.toFixed(4)}</span>
                )}
                {result.fallback && <span className="fallback-tag">回退模式</span>}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
