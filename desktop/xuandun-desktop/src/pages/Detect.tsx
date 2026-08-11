import { useState, useRef, useCallback, useEffect } from 'react';
import { api, ProtectResponse, OutputProtectResponse, formatInvokeError, InvokeTimeoutError, formatTrustLevel, MESSAGE_TIMEOUT_MS } from '../services/tauriApi';
import { AlertTriangle, Zap, Info, CheckCircle, ShieldX, Upload, Download, FileText, ShieldCheck, Eye, EyeOff } from 'lucide-react';

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

// 批量检测文件限制：单文件 ≤10MB，单批 ≤5000 条
const MAX_FILE_BYTES = 10 * 1024 * 1024;
const MAX_BATCH_ITEMS = 5000;
// 批量检测并发批次大小，避免过量并发导致 IPC 卡顿
const BATCH_CONCURRENCY = 5;

// 批量检测单条结果项
interface BatchItem {
  id: number;
  text: string;
  allowed: boolean | null; // null = 待检测/检测中
  // P1 修复：独立状态区分"待检测/通过/拦截/失败"，避免检测失败被错误渲染为"拦截"并计入拦截汇总
  status: 'pending' | 'passed' | 'blocked' | 'error';
  trust_level?: string;
  reject_stage?: string;
  error?: string;
}

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
  // 批量检测状态
  const [batchItems, setBatchItems] = useState<BatchItem[]>([]);
  const [batchLoading, setBatchLoading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  // 输入侧 / 输出侧护栏 检测标签切换
  const [detectTab, setDetectTab] = useState<'input' | 'output'>('input');
  // 输出侧护栏状态：模型输出文本 + 检测结果（含打码后的实际文本）
  const [outputText, setOutputText] = useState('');
  const [outputResult, setOutputResult] = useState<OutputProtectResponse | null>(null);
  const [outputLoading, setOutputLoading] = useState(false);
  const outputTextareaRef = useRef<HTMLTextAreaElement | null>(null);
  const outputCheckingRef = useRef(false);
  // 组件挂载守卫：批量检测循环内校验，用户中途切页时中止后续 setState 与网络请求
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

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
      }, MESSAGE_TIMEOUT_MS);
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

  // 输出侧护栏检测：对"模型输出"做三级处置（放行/拦截/打码/告警）
  // 关键：展示打码后的实际文本（output），让用户直观看到"片段级打码"效果
  const handleOutputCheck = useCallback(async () => {
    if (outputCheckingRef.current) return;
    const domText = outputTextareaRef.current?.value ?? '';
    const actualText = (domText.trim().length > 0) ? domText : outputText;
    if (!actualText.trim()) {
      addToast('请输入要检查的模型输出内容', 'info');
      return;
    }
    outputCheckingRef.current = true;
    setOutputLoading(true);
    try {
      const res = await api.checkOutput(actualText, 'output-check');
      setOutputResult(res);
    } catch (e) {
      if (e instanceof InvokeTimeoutError) {
        addToast('检查超时，请缩短文本或稍后重试（引擎可能过载）', 'warning');
      } else {
        addToast(formatInvokeError(e, '输出检查'), 'error');
      }
      setOutputResult(null);
    } finally {
      setOutputLoading(false);
      outputCheckingRef.current = false;
    }
  }, [outputText, addToast]);

  // 解析上传文件为文本列表（.txt / .csv / .jsonl）
  const parseFile = useCallback(async (file: File): Promise<string[]> => {
    const raw = await file.text();
    const name = file.name.toLowerCase();
    const lines = raw.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    if (name.endsWith('.jsonl')) {
      return lines.map((l) => {
        try {
          const obj = JSON.parse(l);
          // 兼容常见字段：content / prompt / text / 最后一条 messages.content
          const msg = obj.messages?.[obj.messages.length - 1]?.content;
          return String(obj.content ?? obj.prompt ?? obj.text ?? msg ?? l);
        } catch {
          // 非 JSON 行按原始文本处理
          return l;
        }
      });
    }
    // .txt / .csv 均按行切分
    return lines;
  }, []);

  // 选择文件后解析并载入批量列表
  const handleFileChange = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) {
      addToast('文件超过 10MB 限制，请拆分后重试', 'error');
      return;
    }
    try {
      const lines = await parseFile(file);
      if (lines.length === 0) {
        addToast('文件中没有可检测的文本', 'info');
        return;
      }
      if (lines.length > MAX_BATCH_ITEMS) {
        addToast(`单批最多 ${MAX_BATCH_ITEMS} 条，请拆分文件`, 'error');
        return;
      }
      const base = Date.now();
      setBatchItems(lines.map((t, idx) => ({
        id: base + idx,
        text: t.slice(0, MAX_DETECT_LENGTH),
        allowed: null,
        status: 'pending',
      })));
      addToast(`已载入 ${lines.length} 条文本，点击「开始批量检测」`, 'info');
    } catch (err) {
      addToast(`文件解析失败：${String(err)}`, 'error');
    }
  }, [parseFile, addToast]);

  // 批量检测：分批并发（每批5条），逐条更新结果
  const runBatchDetect = useCallback(async () => {
    if (batchLoading) return;
    const pending = batchItems.filter((i) => i.allowed === null);
    if (pending.length === 0) {
      addToast('请先上传文件添加待检测文本', 'info');
      return;
    }
    setBatchLoading(true);
    try {
      for (let i = 0; i < pending.length; i += BATCH_CONCURRENCY) {
        // 中途切页（组件卸载）时中止后续批次，避免对已卸载组件 setState
        if (!mountedRef.current) return;
        const chunk = pending.slice(i, i + BATCH_CONCURRENCY);
        await Promise.allSettled(chunk.map(async (item) => {
          try {
            const res = await api.protect(item.text, 'batch', mode);
            setBatchItems((prev) => prev.map((p) =>
              p.id === item.id
                ? {
                    ...p,
                    allowed: res.allowed,
                    status: res.allowed ? 'passed' : 'blocked',
                    trust_level: res.trust_level,
                    reject_stage: res.reject_stage ?? undefined,
                  }
                : p
            ));
          } catch (err) {
            // P1 修复：检测失败≠拦截。此前将失败置 allowed:false 并渲染为红色"拦截"、
            // 计入拦截汇总，属安全语义误导。现标记为独立的 error 状态，不混入拦截统计。
            setBatchItems((prev) => prev.map((p) =>
              p.id === item.id
                ? { ...p, allowed: false, status: 'error', error: formatInvokeError(err, '批量检测') }
                : p
            ));
          }
        }));
      }
    } finally {
      setBatchLoading(false);
    }
  }, [batchItems, batchLoading, mode, addToast]);

  // 导出批量检测报告为 CSV
  const exportReport = useCallback(() => {
    const headers = ['文本', '结果', '信任等级', '拦截阶段', '错误'];
    const rows = batchItems.map((i) => [
      i.text,
      i.status === 'pending' ? '待检测' : i.status === 'passed' ? '通过' : i.status === 'blocked' ? '拦截' : '失败',
      i.trust_level ?? '',
      i.reject_stage ?? '',
      i.error ?? '',
    ]);
    const escape = (v: string) => `"${String(v).replace(/"/g, '""')}"`;
    const csv = [headers, ...rows].map((r) => r.map(escape).join(',')).join('\r\n');
    const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = '玄盾批量检测报告.csv';
    a.click();
    URL.revokeObjectURL(url);
  }, [batchItems]);

  // 批量检测汇总统计
  const batchDone = batchItems.filter((i) => i.status !== 'pending');
  const batchPassed = batchDone.filter((i) => i.status === 'passed').length;
  const batchBlocked = batchDone.filter((i) => i.status === 'blocked').length;
  // P1 修复：检测失败独立统计，不混入拦截数，避免安全语义误导
  const batchFailed = batchDone.filter((i) => i.status === 'error').length;

  // ── 拦截理由"人话化"映射（严格对齐设计文档 §3.7）──
  const humanReason = (res: ProtectResponse): string => {
    if (res.allowed) {
      const lat = res.latency_ms != null ? `（延迟 ${Math.round(res.latency_ms)}ms）` : '';
      return `安全请求，已放行${lat}`;
    }
    if (res.fallback) return '引擎不可达，已启动保护性阻断';
    const stage = res.reject_stage || '';
    const category = res.attack_category || '';
    const dist = res.domain_distance;

    if (stage === 'outer_gate') {
      if (category === 'chinese_harmful_content') return '检测到危险内容组合（外门拦截）';
      if (category === 'strong_attack') return '检测到强攻击关键词（外门拦截）';
      if (category === 'roleplay_attack') return '检测到异常角色扮演（外门拦截）';
      return '检测到可疑内容（外门拦截）';
    }
    if (stage === 'inner_gate') {
      if (dist != null && dist < 0.3) return '检测到已知攻击模式（内门精判）';
      if (category && (category.includes('intent') || category.includes('jailbreak')))
        return '检测到越狱攻击意图（内门精判）';
      if ((res.trust_level || '').toLowerCase() === 'low') return '检测到异常行为模式（内门精判）';
      return '检测到异常请求（内门精判）';
    }
    if (stage === 'timing_checker') return '检测到时序异常（时序检测）';
    if (stage === 'output_guardrail') return '输出内容含违规信息（输出护栏）';
    return '安全拦截';
  };

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
          {/* 输入侧 / 输出侧护栏 双方向检测标签：同一检测能力，覆盖双向闭环 */}
          <div className="detect-tabs" role="tablist" aria-label="检测方向">
            <button
              role="tab"
              aria-selected={detectTab === 'input'}
              className={`detect-tab ${detectTab === 'input' ? 'active' : ''}`}
              onClick={() => setDetectTab('input')}
            >
              <ShieldCheck size={15} strokeWidth={1.5} style={{ marginRight: 6, verticalAlign: '-2px' }} />
              输入侧检测（用户 → 模型）
            </button>
            <button
              role="tab"
              aria-selected={detectTab === 'output'}
              className={`detect-tab ${detectTab === 'output' ? 'active' : ''}`}
              onClick={() => setDetectTab('output')}
            >
              <EyeOff size={15} strokeWidth={1.5} style={{ marginRight: 6, verticalAlign: '-2px' }} />
              输出护栏（模型 → 用户）
            </button>
          </div>

          {/* ── 输入侧检测（用户 → 模型） ── */}
          {detectTab === 'input' && (<>
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
                <span className="result-icon">
                  {result.allowed ? <CheckCircle size={18} strokeWidth={1.5} /> : result.fallback ? <AlertTriangle size={18} strokeWidth={1.5} /> : <ShieldX size={18} strokeWidth={1.5} />}
                </span>
                <span className="result-text">
                  {humanReason(result)}
                </span>
              </div>
              <div className="result-details" style={{ fontSize: '0.85em', opacity: 0.7 }}>
                <span>信任: {formatTrustLevel(result.trust_level)}</span>
                {result.reject_stage && <span>阶段: {result.reject_stage}</span>}
                {result.latency_ms != null && <span>耗时: {result.latency_ms.toFixed(1)}ms</span>}
                {result.fallback && <span className="fallback-tag">回退</span>}
              </div>
            </div>
          )}
          </>)}
          {/* ── 输出护栏（模型 → 用户）：检测模型输出是否夹带敏感/违规内容 ──
              三级处置：放行 / 拦截 / 打码（片段级）/ 告警。打码仅替换命中的
              敏感片段为 [REDACTED] 保留上下文——这里直接展示打码后的实际文本。 */}
          {detectTab === 'output' && (
            <div>
              <div className="output-guardrail-hint">
                输出护栏检测模型返回内容是否夹带敏感信息（手机号/邮箱/密钥/身份证号等）或违规内容。
                命中敏感片段时仅打码（替换为 [REDACTED]）并保留上下文；高危违规内容则整段拦截，不外送。
              </div>
              <div className="form-group">
                <label className="form-label">模型输出内容</label>
                <textarea
                  ref={outputTextareaRef}
                  className="form-textarea"
                  value={outputText}
                  onChange={(e) => setOutputText(e.target.value.slice(0, MAX_DETECT_LENGTH))}
                  placeholder="粘贴大模型返回的内容，例如：预约成功，我们将发送验证码到手机 13812345678..."
                  rows={5}
                  maxLength={MAX_DETECT_LENGTH}
                />
                <div style={{ fontSize: '0.85em', color: 'var(--text-secondary)', marginTop: '4px' }}>
                  {outputText.length} / {MAX_DETECT_LENGTH}
                </div>
              </div>
              <button
                className="btn btn-primary"
                onClick={handleOutputCheck}
                disabled={outputLoading}
              >
                {outputLoading ? '检查中...' : '检查输出'}
              </button>

              {outputResult && (
                <div className={`output-result-card ${outputResult.action}`}>
                  <div className="result-header">
                    <span className="result-icon">
                      {outputResult.action === 'pass'
                        ? <CheckCircle size={18} strokeWidth={1.5} />
                        : outputResult.action === 'alert'
                          ? <Info size={18} strokeWidth={1.5} />
                          : <ShieldX size={18} strokeWidth={1.5} />}
                    </span>
                    <span className="result-text">
                      {outputResult.action === 'pass' && '放行（未发现违规/敏感内容）'}
                      {outputResult.action === 'block' && '已拦截（高危违规内容，不对外输出）'}
                      {outputResult.action === 'redact' && '已打码（仅替换敏感片段，保留上下文）'}
                      {outputResult.action === 'alert' && '已告警（低风险，原样放行）'}
                    </span>
                    <span className={`output-risk-badge risk-${outputResult.risk_level || 'pass'}`}>
                      风险: {(outputResult.risk_level || 'pass').toUpperCase()}
                    </span>
                  </div>
                  <div className="result-details">
                    <span>处置动作: {outputResult.action}</span>
                    {outputResult.degraded && <span className="fallback-tag">降级放行</span>}
                    {outputResult.latency_ms != null && <span>耗时: {outputResult.latency_ms.toFixed(1)}ms</span>}
                    {outputResult.reason && <span>原因: {outputResult.reason}</span>}
                  </div>
                  {outputResult.action === 'redact' && outputResult.output && (
                    <div className="output-redacted-block">
                      <div className="output-redacted-label">
                        <Eye size={14} strokeWidth={1.5} style={{ marginRight: 6, verticalAlign: '-2px' }} />
                        打码后的输出（敏感片段已替换为 [REDACTED]）
                      </div>
                      <pre className="output-redacted-text">{outputResult.output}</pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* 批量检测：企业批量评测聊天记录/日志 */}
      <div className="card" style={{ marginTop: '16px' }}>
        <div className="card-header">
          <h3>批量检测</h3>
          <span className="card-subtitle">上传文件批量检测 · 支持 .txt / .csv / .jsonl</span>
        </div>
        <div className="card-body">
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
            <input
              ref={fileInputRef}
              type="file"
              accept=".txt,.csv,.jsonl"
              style={{ display: 'none' }}
              onChange={handleFileChange}
            />
            <button className="btn btn-secondary" onClick={() => fileInputRef.current?.click()} disabled={batchLoading}>
              <Upload size={16} strokeWidth={1.5} style={{ marginRight: '6px' }} />
              上传文件
            </button>
            <button className="btn btn-primary" onClick={runBatchDetect} disabled={batchLoading || batchItems.length === 0}>
              {batchLoading ? '检测中...' : '开始批量检测'}
            </button>
            {batchDone.length > 0 && (
              <button className="btn btn-secondary" onClick={exportReport}>
                <Download size={16} strokeWidth={1.5} style={{ marginRight: '6px' }} />
                导出报告
              </button>
            )}
            {batchItems.length > 0 && (
              <button className="btn btn-sm btn-secondary" onClick={() => setBatchItems([])} disabled={batchLoading}>
                清空
              </button>
            )}
          </div>

          {batchItems.length > 0 && (
            <div style={{ marginTop: '12px', fontSize: '0.85em', color: 'var(--text-secondary)' }}>
              共 {batchItems.length} 条 · 已检测 {batchDone.length} 条 · 通过 {batchPassed} 条 · 拦截 {batchBlocked} 条{batchFailed > 0 ? ` · 失败 ${batchFailed} 条` : ''}
            </div>
          )}

          {batchItems.length > 0 && (
            <div style={{ marginTop: '12px', maxHeight: '320px', overflow: 'auto', border: '1px solid var(--dt-border)', borderRadius: '8px' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85em' }}>
                <thead>
                  <tr style={{ background: 'var(--dt-bg-panel)', color: 'var(--text-secondary)' }}>
                    <th style={{ padding: '8px 12px', textAlign: 'left' }}>文本</th>
                    <th style={{ padding: '8px 12px', textAlign: 'left', width: '90px' }}>结果</th>
                    <th style={{ padding: '8px 12px', textAlign: 'left', width: '110px' }}>信任等级</th>
                    <th style={{ padding: '8px 12px', textAlign: 'left', width: '110px' }}>拦截阶段</th>
                  </tr>
                </thead>
                <tbody>
                  {batchItems.map((item) => (
                    <tr key={item.id} style={{ borderTop: '1px solid var(--dt-border)' }}>
                      <td style={{ padding: '8px 12px', maxWidth: '320px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        <FileText size={13} strokeWidth={1.5} style={{ marginRight: '6px', verticalAlign: '-2px', color: 'var(--text-secondary)' }} />
                        {item.text}
                      </td>
                      <td style={{ padding: '8px 12px' }}>
                        {item.status === 'pending' ? (
                          <span style={{ color: 'var(--text-secondary)' }}>待检测</span>
                        ) : item.status === 'passed' ? (
                          <span style={{ color: 'var(--success)' }}>通过</span>
                        ) : item.status === 'blocked' ? (
                          <span style={{ color: 'var(--danger)' }}>拦截</span>
                        ) : (
                          // P1 修复：检测失败用独立"失败"样式，不渲染为红色"拦截"，避免安全语义误导
                          <span style={{ color: 'var(--warning)' }}>失败</span>
                        )}
                      </td>
                      <td style={{ padding: '8px 12px' }}>{item.trust_level ? formatTrustLevel(item.trust_level) : '—'}</td>
                      <td style={{ padding: '8px 12px' }}>{item.reject_stage || (item.status === 'error' ? <span style={{ color: 'var(--warning)' }}>错误</span> : '—')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
