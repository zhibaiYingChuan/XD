import { useState, useEffect, useCallback, useRef } from 'react';
import { api, LearningStatus } from '../services/tauriApi';
// 设计系统规范：图标统一使用 lucide-react，strokeWidth=1.5，禁止 emoji
import {
  CheckCircle, AlertTriangle, Lightbulb, RefreshCw, Square,
  Smartphone, MessageSquare, Mail, Link, Monitor, type LucideIcon,
} from 'lucide-react';
import { ConfirmModal, useConfirmModal } from '../components/ConfirmModal';

// 通知渠道图标映射：将字符串名称映射为 lucide-react 图标组件
const NOTIFIER_ICON_MAP: Record<string, LucideIcon> = {
  smartphone: Smartphone,
  message: MessageSquare,
  mail: Mail,
  link: Link,
  monitor: Monitor,
};

interface NotifierField {
  key: string;
  label: string;
  type: string;
  placeholder?: string;
}

function NotifierChannel({
  channel,
  label,
  icon,
  config,
  fields,
  onFieldChange,
  onSave,
  onTest,
  testing,
}: {
  channel: string;
  label: string;
  icon: string;
  config: any;
  fields: NotifierField[];
  onFieldChange: (channel: string, field: string, value: any) => void;
  onSave: (channel: string, config: any) => void;
  onTest: (channel: string, config: any) => void;
  testing: boolean;
}) {
  const enabled = config.enabled || false;
  // 根据字符串名称从映射表取出图标组件，未匹配时回退到 Smartphone
  const IconComp = NOTIFIER_ICON_MAP[icon] || Smartphone;
  return (
    <div className={`notifier-channel ${enabled ? 'notifier-enabled' : ''}`}>
      <div className="notifier-header">
        <span className="notifier-icon"><IconComp size={16} strokeWidth={1.5} /></span>
        <span className="notifier-label">{label}</span>
        <label className="toggle toggle-sm">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => onFieldChange(channel, 'enabled', e.target.checked)}
          />
          <span className="toggle-slider"></span>
        </label>
      </div>
      {enabled && (
        <div className="notifier-fields">
          {fields.map((f) => (
            <div key={f.key} className="form-group form-group-inline">
              <label className="form-label form-label-sm">{f.label}</label>
              <input
                type={f.type}
                className="form-input"
                value={config[f.key] || ''}
                placeholder={f.placeholder || ''}
                onChange={(e) => onFieldChange(channel, f.key, e.target.value)}
                // P1-22 修复：密码字段禁用浏览器自动填充，避免填入无关密码
                autoComplete={f.type === 'password' ? 'new-password' : 'off'}
                name={`${channel}-${f.key}`}
              />
            </div>
          ))}
          <div className="notifier-actions">
            <button className="btn btn-sm btn-primary" onClick={() => onSave(channel, config)}>保存</button>
            <button className="btn btn-sm btn-secondary" onClick={() => onTest(channel, config)} disabled={testing}>
              {testing ? '测试中...' : '测试告警'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function Settings() {
  const [mode, setMode] = useState('balanced');
  const { modalProps: confirmModalProps, confirm } = useConfirmModal();
  const [autoStart, setAutoStart] = useState(false);
  const [interceptTraffic, setInterceptTraffic] = useState(true);
  const [warmupSafeText, setWarmupSafeText] = useState('');
  const [warmupAttackText, setWarmupAttackText] = useState('');
  const [warmupStatus, setWarmupStatus] = useState('');
  const [restarting, setRestarting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [auditReport, setAuditReport] = useState<string>('');
  const [hasKey, setHasKey] = useState(false);
  const [learning, setLearning] = useState<LearningStatus | null>(null);
  const [switchingMode, setSwitchingMode] = useState(false);
  const [notifierConfigs, setNotifierConfigs] = useState<Record<string, any>>({});
  const [testingChannel, setTestingChannel] = useState<string | null>(null);
  // P0修复：补全代理服务、紧急逃生、灰度部署、快照管理的状态
  const [proxyRunning, setProxyRunning] = useState(false);
  const [proxyPort, setProxyPort] = useState(18765);
  // P1-09 修复：端口输入框使用字符串 state，允许临时空值，blur 时校验
  const [proxyPortInput, setProxyPortInput] = useState('18765');
  const [proxyStarting, setProxyStarting] = useState(false);
  const [proxyStopping, setProxyStopping] = useState(false);
  const [emergencyBypass, setEmergencyBypass] = useState(false);
  const [grayRatio, setGrayRatio] = useState(1.0);
  // P1-10 修复：灰度比例滑块防抖，拖动过程仅更新本地 pending state
  const [grayRatioPending, setGrayRatioPending] = useState(1.0);
  const grayCommitTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // P1-11 修复：防护模式切换防并发
  const [modeSwitching, setModeSwitching] = useState(false);
  const [snapshots, setSnapshots] = useState<Array<[number, string, string]>>([]);
  const [snapshotLabel, setSnapshotLabel] = useState('');
  // P1修复：补全预热、审计验证、快照创建的加载状态
  const [warming, setWarming] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [creatingSnapshot, setCreatingSnapshot] = useState(false);
  // P1-21 修复：生成密钥按钮 loading 状态，防止用户重复点击
  const [generatingKey, setGeneratingKey] = useState(false);
  // GAP-03 修复：快照恢复 loading 状态，防止用户重复点击导致并发恢复覆盖配置
  const [restoringSnapshot, setRestoringSnapshot] = useState(false);

  const fetchLearning = useCallback(async () => {
    try {
      const l = await api.getLearningStatus();
      setLearning(l);
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    const loadConfig = async () => {
      try {
        const m = await api.getConfig('mode');
        if (m) setMode(m);
        const as = await api.getConfig('auto_start');
        if (as) setAutoStart(as === 'true');
        const it = await api.getConfig('intercept_traffic');
        if (it) setInterceptTraffic(it === 'true');
        const ws = await api.getConfig('warmup_safe_text');
        if (ws) setWarmupSafeText(ws);
        const wa = await api.getConfig('warmup_attack_text');
        if (wa) setWarmupAttackText(wa);
        const hk = await api.hasSecretKey();
        setHasKey(hk);
        const channels = ['dingtalk', 'feishu', 'email', 'webhook', 'syslog'];
        const configs: Record<string, any> = {};
        for (const ch of channels) {
          try {
            const cfg = await api.getNotifierConfig(ch);
            if (cfg) configs[ch] = cfg;
          } catch { /* ignore */ }
        }
        setNotifierConfigs(configs);
        // P0修复：加载代理服务、紧急逃生、灰度部署、快照管理状态
        try {
          const pr = await api.isProxyRunning();
          setProxyRunning(pr);
        } catch { /* ignore */ }
        try {
          const eb = await api.getEmergencyBypass();
          setEmergencyBypass(eb.enabled);
        } catch { /* ignore */ }
        try {
          const gr = await api.getGrayDeployRatio();
          setGrayRatio(gr.ratio);
        } catch { /* ignore */ }
        try {
          const snaps = await api.listSnapshots();
          setSnapshots(snaps);
        } catch { /* ignore */ }
      } catch {
        // ignore
      }
    };
    loadConfig();
    fetchLearning();
    const interval = setInterval(fetchLearning, 5000);
    return () => {
      clearInterval(interval);
      // GAP-S5-08 修复：组件卸载时清理灰度滑块的防抖 timer
      // 避免 setTimeout 对已卸载组件调用 setState（React 18 静默忽略但仍为隐患）
      if (grayCommitTimerRef.current) {
        clearTimeout(grayCommitTimerRef.current);
        grayCommitTimerRef.current = null;
      }
    };
  }, [fetchLearning]);

  const handleSwitchLearningMode = async (target: string) => {
    setSwitchingMode(true);
    try {
      await api.switchLearningMode(target);
      showMessage('success', `已切换到${target === 'protecting' ? '保护' : '观察'}模式`);
      await fetchLearning();
    } catch {
      showMessage('error', '模式切换失败，请确认引擎正常运行后重试');
    } finally {
      setSwitchingMode(false);
    }
  };

  const showMessage = (type: 'success' | 'error', text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 3000);
  };

  const handleModeChange = async (newMode: string) => {
    // P1-11 修复：防并发守卫，切换中拒绝新的点击
    if (modeSwitching) return;
    const oldMode = mode;
    setMode(newMode);
    setModeSwitching(true);
    // GAP-S5-04 修复：setMode + setConfig 事务化，任一失败回滚 UI 状态
    try {
      await api.setMode(newMode);
      try {
        await api.setConfig('mode', newMode);
        showMessage('success', '模式已更新');
      } catch (cfgErr) {
        // setConfig 失败：回滚 setMode（恢复引擎+UI 到 oldMode）
        try {
          await api.setMode(oldMode);
        } catch (rollbackErr) {
          // 回滚也失败：引擎与 DB 可能不一致，提示用户
          console.error('[XuanDun] 模式回滚失败:', rollbackErr);
        }
        setMode(oldMode);
        showMessage('error', `模式持久化失败，已回滚到 ${oldMode}`);
      }
    } catch {
      // setMode 失败：引擎未接受新模式，回滚 UI
      setMode(oldMode);
      showMessage('error', '模式更新失败');
    } finally {
      setModeSwitching(false);
    }
  };

  const handleAutoStartChange = async (val: boolean) => {
    const oldVal = autoStart;
    setAutoStart(val);
    try {
      await api.setConfig('auto_start', val ? 'true' : 'false');
      showMessage('success', '设置已保存');
    } catch {
      setAutoStart(oldVal);
      showMessage('error', '设置保存失败');
    }
  };

  const handleInterceptTrafficChange = async (val: boolean) => {
    const oldVal = interceptTraffic;
    setInterceptTraffic(val);
    try {
      await api.setConfig('intercept_traffic', val ? 'true' : 'false');
      showMessage('success', '设置已保存');
    } catch {
      setInterceptTraffic(oldVal);
      showMessage('error', '设置保存失败');
    }
  };

  const handleWarmup = async () => {
    const safeTexts = warmupSafeText.split('\n').filter(t => t.trim());
    const attackTexts = warmupAttackText.split('\n').filter(t => t.trim());
    if (!safeTexts.length && !attackTexts.length) {
      setWarmupStatus('请输入至少一条预热文本');
      return;
    }
    setWarming(true);
    setWarmupStatus('预热中...');
    try {
      const result = await api.warmup(safeTexts, attackTexts);
      await api.setConfig('warmup_safe_text', warmupSafeText);
      await api.setConfig('warmup_attack_text', warmupAttackText);
      setWarmupStatus(`预热成功: ${result.safe_count} 条良性, ${result.attack_count} 条攻击`);
    } catch (e: any) {
      setWarmupStatus(`预热失败: ${e}，请检查文本格式后重试`);
    } finally {
      setWarming(false);
    }
  };

  // NEW-P0-04 修复：引擎重启/停止进行中拦截页面关闭/刷新
  useEffect(() => {
    if (!restarting) return;
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, [restarting]);

  const handleRestart = async () => {
    // P1-16 修复：重启引擎前强制二次确认（与停止引擎一致，重启会中断所有检测）
    if (!(await confirm(
      '确定要重启引擎吗？\n\n' +
      '警告：重启期间（约 5-10 秒）所有 AI 请求将不受安全检测保护，' +
      '正在进行的检测会被中断。\n\n' +
      '建议在业务低峰期执行。'
    ))) {
      return;
    }
    setRestarting(true);
    // GAP-S5-12 修复：派发全局事件，StatusBar 显示"引擎重启中"全局提示
    window.dispatchEvent(new CustomEvent('xuandun:engine-restarting', { detail: { state: 'start' } }));
    try {
      await api.restartEngine();
      showMessage('success', '引擎已重启');
    } catch {
      showMessage('error', '引擎重启失败，请查看日志排查引擎状态');
    } finally {
      setRestarting(false);
      // GAP-S5-12 修复：重启完成（成功或失败）后派发全局事件解除全局提示
      window.dispatchEvent(new CustomEvent('xuandun:engine-restarting', { detail: { state: 'end' } }));
    }
  };

  const handleStop = async () => {
    // P0-03 修复：停止引擎前强制二次确认（会中断所有安全保护）
    if (!(await confirm('确定要停止引擎吗？\n\n警告：停止后所有 AI 请求将不再受安全检测保护，直到重新启动引擎。'))) {
      return;
    }
    setStopping(true);
    try {
      await api.stopEngine();
      showMessage('success', '引擎已停止');
    } catch {
      showMessage('error', '引擎停止失败，请查看日志排查引擎状态');
    } finally {
      setStopping(false);
    }
  };

  const handleVerifyAudit = async () => {
    setVerifying(true);
    try {
      const report = await api.verifyAudit();
      if (report.chain_intact) {
        setAuditReport(`审计链完整: ${report.verified_entries}/${report.total_entries} 条记录验证通过`);
      } else {
        const broken = report.broken_links.map(([id, reason]: [number, string]) => `ID=${id}: ${reason}`).join('; ');
        setAuditReport(`审计链异常: ${report.verified_entries}/${report.total_entries} 通过, 断裂: ${broken}`);
      }
    } catch (e: any) {
      setAuditReport(`验证失败: ${e}，请确认引擎正常运行后重试`);
    } finally {
      setVerifying(false);
    }
  };

  const handleGenerateKey = async () => {
    // P1-21 修复：防并发守卫，避免重复点击生成多个密钥
    if (generatingKey) return;
    setGeneratingKey(true);
    try {
      const key = crypto.randomUUID();
      await api.storeSecretKey(key);
      setHasKey(true);
      showMessage('success', '密钥已生成并存储到系统密钥库');
    } catch (e: any) {
      showMessage('error', `密钥存储失败: ${e}`);
    } finally {
      setGeneratingKey(false);
    }
  };

  const handleDeleteKey = async () => {
    // P0-03 修复：删除密钥前强制二次确认（密钥删除会导致历史日志无法解密）
    if (!(await confirm('确定要删除引擎密钥吗？\n\n警告：删除后历史加密日志将无法解密，且引擎需要重新配置密钥才能启动。\n此操作不可恢复！'))) {
      return;
    }
    try {
      await api.deleteSecretKey();
      setHasKey(false);
      showMessage('success', '密钥已从系统密钥库删除');
    } catch (e: any) {
      showMessage('error', `密钥删除失败: ${e}`);
    }
  };

  const handleSaveNotifier = async (channel: string, config: any) => {
    try {
      await api.saveNotifierConfig(channel, config);
      setNotifierConfigs(prev => ({ ...prev, [channel]: config }));
      showMessage('success', `${channel} 配置已保存`);
    } catch (e: any) {
      showMessage('error', `保存失败: ${e}`);
    }
  };

  const handleTestNotifier = async (channel: string, config: any) => {
    setTestingChannel(channel);
    try {
      const result = await api.testNotifier(channel, config);
      if (result?.status === 'ok') {
        // GAP-S5-11 修复：告警测试改为"已发送，请确认"，避免"发送成功"但对方未收到的误导
        showMessage('success', `${channel} 测试告警已发送，请确认对方是否收到`);
      } else {
        showMessage('error', `${channel} 测试告警发送失败`);
      }
    } catch (e: any) {
      showMessage('error', `测试失败: ${e}`);
    } finally {
      setTestingChannel(null);
    }
  };

  const handleNotifierFieldChange = (channel: string, field: string, value: any) => {
    setNotifierConfigs(prev => ({
      ...prev,
      [channel]: { ...(prev[channel] || {}), [field]: value },
    }));
  };

  // P0修复：代理服务启停处理
  // P1-09 修复：端口输入校验，允许临时空值，blur 时 clamp 到 [1024, 65535]
  const handlePortChange = (value: string) => {
    if (value === '') {
      setProxyPortInput('');
      return;
    }
    const num = parseInt(value);
    if (isNaN(num)) return;
    setProxyPortInput(String(num));
  };

  const handlePortBlur = () => {
    const num = parseInt(proxyPortInput);
    if (isNaN(num)) {
      setProxyPortInput('18765');
      setProxyPort(18765);
      return;
    }
    const clamped = Math.max(1024, Math.min(65535, num));
    setProxyPortInput(String(clamped));
    setProxyPort(clamped);
  };

  const handleStartProxy = async () => {
    setProxyStarting(true);
    try {
      await api.startProxy(proxyPort);
      setProxyRunning(true);
      showMessage('success', `代理已启动，监听 127.0.0.1:${proxyPort}`);
    } catch (e: any) {
      // GAP-S5-07 修复：代理启动失败时提供排查指引，特别针对端口占用场景
      const errMsg = String(e);
      if (errMsg.includes('port') || errMsg.includes('端口') || errMsg.includes('Address already in use') || errMsg.includes('EADDRINUSE')) {
        showMessage('error', `代理启动失败：端口 ${proxyPort} 可能被占用。\n\n排查建议：\n1. 检查端口占用：netstat -ano | findstr :${proxyPort}\n2. 尝试更换端口（1024-65535）\n3. 查看 engine.log 排查引擎状态`);
      } else {
        showMessage('error', `代理启动失败: ${e}`);
      }
    } finally {
      setProxyStarting(false);
    }
  };

  const handleStopProxy = async () => {
    setProxyStopping(true);
    try {
      await api.stopProxy();
      setProxyRunning(false);
      showMessage('success', '代理已停止');
    } catch (e: any) {
      showMessage('error', `代理停止失败: ${e}，请查看日志排查端口占用`);
    } finally {
      setProxyStopping(false);
    }
  };

  // P0修复：紧急逃生切换处理
  // P1-01 修复：启用紧急逃生时强制二次确认（停止引擎/删除密钥已有确认，紧急逃生风险更高）
  const handleEmergencyBypassChange = async (enabled: boolean) => {
    // 仅在"启用"时弹出二次确认；关闭逃生恢复正常防护无需确认
    if (enabled) {
      const confirmed = await confirm(
        '确定要启用紧急逃生吗？\n\n' +
        '警告：启用后所有 AI 请求将绕过阴阳门检测直接放行，无任何安全防护。\n' +
        '此操作会立即生效，建议仅在引擎故障或误报严重时临时使用。\n\n' +
        '点击"确定"启用紧急逃生，点击"取消"保持正常防护。'
      );
      if (!confirmed) {
        // 用户取消，toggle 视觉状态由 React 自动回滚（因未调用 setEmergencyBypass）
        return;
      }
    }
    const oldVal = emergencyBypass;
    setEmergencyBypass(enabled);
    try {
      await api.setEmergencyBypass(enabled);
      showMessage('success', enabled ? '紧急逃生已启用（所有请求放行）' : '紧急逃生已关闭，恢复防护');
    } catch {
      setEmergencyBypass(oldVal);
      showMessage('error', '紧急逃生切换失败，请确认引擎正常运行后重试');
    }
  };

  // P0修复：灰度部署比例调整
  // P1-10 修复：滑块拖动仅更新本地 pending state，500ms 防抖后才提交到后端
  const handleGrayRatioChange = (ratio: number) => {
    setGrayRatioPending(ratio);
    if (grayCommitTimerRef.current) clearTimeout(grayCommitTimerRef.current);
    grayCommitTimerRef.current = setTimeout(async () => {
      const oldVal = grayRatio;
      setGrayRatio(ratio);
      try {
        await api.setGrayDeployRatio(ratio);
        showMessage('success', `灰度比例已设为 ${(ratio * 100).toFixed(0)}%`);
      } catch {
        setGrayRatio(oldVal);
        setGrayRatioPending(oldVal);
        showMessage('error', '灰度比例设置失败，请确认引擎正常运行后重试');
      }
    }, 500);
  };

  // P0修复：快照管理
  const handleCreateSnapshot = async () => {
    if (!snapshotLabel.trim()) {
      showMessage('error', '请输入快照标签');
      return;
    }
    setCreatingSnapshot(true);
    try {
      await api.createSnapshot(snapshotLabel.trim());
      const snaps = await api.listSnapshots();
      setSnapshots(snaps);
      setSnapshotLabel('');
      showMessage('success', '快照已创建');
    } catch (e: any) {
      showMessage('error', `快照创建失败: ${e}，请确认引擎正常运行后重试`);
    } finally {
      setCreatingSnapshot(false);
    }
  };

  const handleRestoreSnapshot = async (snapshotId: number) => {
    // GAP-03 修复：防并发守卫，恢复中拒绝新的点击
    if (restoringSnapshot) return;
    if (!(await confirm('确定要恢复此快照吗？\n\n警告：当前配置将被快照内容覆盖。'))) {
      return;
    }
    setRestoringSnapshot(true);
    // GAP-S5-03 修复：添加 15s 超时，避免引擎挂起时按钮永久 disabled
    const restoreTimeout = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error('恢复超时（15s），请检查引擎状态后重试')), 15000);
    });
    try {
      await Promise.race([api.restoreSnapshot(snapshotId), restoreTimeout]);
      showMessage('success', '快照已恢复');
    } catch (e: any) {
      showMessage('error', `快照恢复失败: ${e}`);
    } finally {
      setRestoringSnapshot(false);
    }
  };

  const modes = [
    { key: 'high_security', label: '高安全', desc: '最严格的防护策略，可能产生较多误报' },
    { key: 'balanced', label: '平衡', desc: '兼顾安全与可用性的推荐策略' },
    { key: 'low_false_positive', label: '低误报', desc: '减少误报，适合对可用性要求高的场景' },
  ];

  return (
    <div className="page settings-page">
      {message && (
        <div className={`alert-banner ${message.type === 'success' ? 'alert-success' : 'alert-danger'}`}>
          <span className="alert-icon">
            {message.type === 'success'
              ? <CheckCircle size={18} strokeWidth={1.5} />
              : <AlertTriangle size={18} strokeWidth={1.5} />}
          </span>
          <span>{message.text}</span>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h3>防护模式</h3>
        </div>
        <div className="card-body">
          <div className="mode-cards">
            {modes.map((m) => (
              <div
                key={m.key}
                className={`mode-card ${mode === m.key ? 'mode-card-active' : ''}`}
                onClick={() => !modeSwitching && handleModeChange(m.key)}
                style={{ pointerEvents: modeSwitching ? 'none' : 'auto', opacity: modeSwitching ? 0.6 : 1 }}
              >
                <div className="mode-card-title">{m.label}</div>
                <div className="mode-card-desc">{m.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>活性防护模式</h3>
          <span className="card-subtitle">观察→学习→自动切换架构</span>
        </div>
        <div className="card-body">
          {learning ? (
            <>
              <div className="learning-mode-display">
                <span className={`mode-badge ${learning.mode === 'observing' ? 'mode-observing' : 'mode-protecting'}`}>
                  {learning.mode === 'observing'
                    ? <><span className="status-dot dot-observing"></span> 观察模式（学习中）</>
                    : <><span className="status-dot dot-protecting"></span> 保护模式</>}
                </span>
              </div>

              {learning.mode === 'observing' && (
                <div className="learning-progress-section">
                  <div className="learning-progress-label">
                    已学习：{learning.sample_count} / {learning.min_samples_for_switch} 条正常对话
                  </div>
                  <div className="learning-progress-bar-large">
                    <div className="learning-progress-fill-large" style={{ width: `${Math.round(learning.learning_progress * 100)}%` }}>
                      <span className="learning-progress-text">{Math.round(learning.learning_progress * 100)}%</span>
                    </div>
                  </div>
                  <div className="learning-prototypes-mini">
                    <span>安全原型: {learning.safe_prototypes}</span>
                    <span>攻击原型: {learning.attack_prototypes}</span>
                    <span>模拟拦截: {learning.would_block_count}</span>
                  </div>
                </div>
              )}

              <div className="mode-switch-buttons" style={{ marginTop: '16px' }}>
                <button
                  className={`btn ${learning.mode === 'observing' ? 'btn-warning' : 'btn-secondary'}`}
                  onClick={() => handleSwitchLearningMode('observing')}
                  disabled={switchingMode || learning.mode === 'observing'}
                >
                  <span className="status-dot dot-observing"></span> {switchingMode ? '切换中...' : '切换到观察模式'}
                </button>
                <button
                  className={`btn ${learning.mode === 'protecting' ? 'btn-primary' : 'btn-secondary'}`}
                  onClick={() => handleSwitchLearningMode('protecting')}
                  disabled={switchingMode || learning.mode === 'protecting'}
                >
                  <span className="status-dot dot-protecting"></span> {switchingMode ? '切换中...' : '切换到保护模式'}
                </button>
              </div>

              {learning.mode === 'observing' && learning.sample_count < learning.min_samples_for_switch && (
                <div className="mode-switch-warning">
                  样本不足（{learning.sample_count}/{learning.min_samples_for_switch}），提前切换到保护模式可能导致误报率升高
                </div>
              )}
            </>
          ) : (
            <div className="empty-state">加载学习中...</div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>通用设置</h3>
        </div>
        <div className="card-body">
          <div className="setting-item">
            <div className="setting-info">
              <div className="setting-label">开机自启动</div>
              <div className="setting-desc">系统启动时自动运行玄盾</div>
            </div>
            <label className="toggle">
              <input type="checkbox" checked={autoStart} onChange={(e) => handleAutoStartChange(e.target.checked)} />
              <span className="toggle-slider"></span>
            </label>
          </div>

          <div className="setting-item">
            <div className="setting-info">
              <div className="setting-label">流量拦截</div>
              <div className="setting-desc">启用实时流量拦截功能</div>
            </div>
            <label className="toggle">
              <input type="checkbox" checked={interceptTraffic} onChange={(e) => handleInterceptTrafficChange(e.target.checked)} />
              <span className="toggle-slider"></span>
            </label>
          </div>
        </div>
      </div>

      {/* P0修复：代理服务卡片 - 补全OnboardingWizard指引的代理启停功能 */}
      <div className="card">
        <div className="card-header">
          <h3>代理服务</h3>
          <span className="card-subtitle">HTTP 代理模式 · 拦截 AI 工具流量</span>
        </div>
        <div className="card-body">
          <div className="setting-item">
            <div className="setting-info">
              <div className="setting-label">代理状态</div>
              <div className="setting-desc">
                {proxyRunning
                  ? <><span className="status-dot dot-online"></span> 运行中 · 监听 127.0.0.1:{proxyPort}</>
                  : <><span className="status-dot dot-offline"></span> 已停止</>}
              </div>
            </div>
            <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
              {!proxyRunning ? (
                <>
                  <input
                    type="number"
                    className="form-input"
                    style={{ width: '80px' }}
                    value={proxyPortInput}
                    onChange={(e) => handlePortChange(e.target.value)}
                    onBlur={handlePortBlur}
                    min={1024}
                    max={65535}
                    disabled={proxyStarting}
                  />
                  <button className="btn btn-primary" onClick={handleStartProxy} disabled={proxyStarting}>
                    {proxyStarting ? '启动中...' : '启动代理'}
                  </button>
                </>
              ) : (
                <button className="btn btn-danger" onClick={handleStopProxy} disabled={proxyStopping}>
                  {proxyStopping ? '停止中...' : '停止代理'}
                </button>
              )}
            </div>
          </div>
          <div style={{ marginTop: '8px', fontSize: '0.85em', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Lightbulb size={16} strokeWidth={1.5} />
            <span>将 AI 工具的 HTTP 代理地址设为 127.0.0.1:{proxyPort} 即可接入玄盾防护</span>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>领域自适应</h3>
        </div>
        <div className="card-body">
          <div className="form-group">
            <label className="form-label">良性预热文本</label>
            <textarea
              className="form-textarea"
              value={warmupSafeText}
              onChange={(e) => setWarmupSafeText(e.target.value)}
              placeholder="输入领域相关的良性文本，每行一条..."
              rows={3}
            />
          </div>
          <div className="form-group">
            <label className="form-label">攻击预热文本</label>
            <textarea
              className="form-textarea"
              value={warmupAttackText}
              onChange={(e) => setWarmupAttackText(e.target.value)}
              placeholder="输入已知的攻击样本，每行一条..."
              rows={3}
            />
          </div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <button className="btn btn-primary" onClick={handleWarmup} disabled={warming}>{warming ? '预热中...' : '提交预热'}</button>
            {warmupStatus && <span style={{ fontSize: '0.85em', color: warmupStatus.startsWith('预热成功') ? 'var(--success)' : 'var(--danger)' }}>{warmupStatus}</span>}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>安全与审计</h3>
        </div>
        <div className="card-body">
          <div className="setting-item">
            <div className="setting-info">
              <div className="setting-label">审计日志完整性</div>
              <div className="setting-desc">验证日志哈希链是否完整未被篡改</div>
            </div>
            <button className="btn btn-primary" onClick={handleVerifyAudit} disabled={verifying}>{verifying ? '验证中...' : '验证'}</button>
          </div>
          {auditReport && <div style={{ marginTop: '8px', fontSize: '0.85em', padding: '8px', background: 'var(--bg-secondary)', borderRadius: '6px' }}>{auditReport}</div>}

          <div className="setting-item" style={{ marginTop: '12px' }}>
            <div className="setting-info">
              <div className="setting-label">密钥保护</div>
              <div className="setting-desc">将引擎密钥存储到操作系统密钥库{hasKey ? ' (已存储)' : ' (未设置)'}</div>
            </div>
            <div style={{ display: 'flex', gap: '6px' }}>
              {!hasKey && <button className="btn btn-primary" onClick={handleGenerateKey} disabled={generatingKey}>{generatingKey ? '生成中...' : '生成密钥'}</button>}
              {hasKey && <button className="btn btn-danger" onClick={handleDeleteKey}>删除密钥</button>}
            </div>
          </div>
        </div>
      </div>

      {/* P0修复：企业运维卡片 - 紧急逃生 + 灰度部署 */}
      <div className="card">
        <div className="card-header">
          <h3>企业运维</h3>
          <span className="card-subtitle">紧急逃生 · 灰度部署 · 故障容灾</span>
        </div>
        <div className="card-body">
          <div className="setting-item">
            <div className="setting-info">
              <div className="setting-label">紧急逃生通道</div>
              <div className="setting-desc">
                {emergencyBypass
                  ? '已启用 — 所有请求直接放行，不经过安全检测'
                  : '正常防护中 — 所有请求经过阴阳门检测'}
              </div>
            </div>
            <label className="toggle">
              <input
                type="checkbox"
                checked={emergencyBypass}
                onChange={(e) => handleEmergencyBypassChange(e.target.checked)}
              />
              <span className="toggle-slider"></span>
            </label>
          </div>

          <div className="setting-item" style={{ marginTop: '12px' }}>
            <div className="setting-info">
              <div className="setting-label">灰度部署比例</div>
              <div className="setting-desc">
                当前比例：{(grayRatio * 100).toFixed(0)}%
                {grayRatio < 1.0 && ' — 仅部分流量经过防护'}
              </div>
            </div>
            <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
              <input
                type="range"
                min={0}
                max={100}
                step={10}
                value={Math.round(grayRatioPending * 100)}
                onChange={(e) => handleGrayRatioChange(parseInt(e.target.value) / 100)}
                style={{ width: '120px' }}
              />
              <span style={{ fontSize: '0.85em', minWidth: '40px' }}>{Math.round(grayRatioPending * 100)}%</span>
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>告警通道</h3>
          <span className="card-subtitle">拦截事件自动推送到企业 IM / 邮件 / SIEM</span>
        </div>
        <div className="card-body">
          <NotifierChannel
            channel="dingtalk"
            label="钉钉机器人"
            icon="smartphone"
            config={notifierConfigs['dingtalk'] || {}}
            onFieldChange={handleNotifierFieldChange}
            onSave={handleSaveNotifier}
            onTest={handleTestNotifier}
            testing={testingChannel === 'dingtalk'}
            fields={[
              { key: 'webhook_url', label: 'Webhook URL', type: 'text', placeholder: 'https://oapi.dingtalk.com/robot/send?access_token=...' },
              { key: 'secret', label: '加签密钥（可选）', type: 'text', placeholder: 'SEC...' },
              { key: 'at_phones', label: '@手机号（逗号分隔）', type: 'text', placeholder: '13800138000,13900139000' },
            ]}
          />
          <NotifierChannel
            channel="feishu"
            label="飞书机器人"
            icon="message"
            config={notifierConfigs['feishu'] || {}}
            onFieldChange={handleNotifierFieldChange}
            onSave={handleSaveNotifier}
            onTest={handleTestNotifier}
            testing={testingChannel === 'feishu'}
            fields={[
              { key: 'webhook_url', label: 'Webhook URL', type: 'text', placeholder: 'https://open.feishu.cn/open-apis/bot/v2/hook/...' },
              { key: 'secret', label: '签名密钥（可选）', type: 'text', placeholder: '' },
            ]}
          />
          <NotifierChannel
            channel="email"
            label="邮件告警 (SMTP)"
            icon="mail"
            config={notifierConfigs['email'] || {}}
            onFieldChange={handleNotifierFieldChange}
            onSave={handleSaveNotifier}
            onTest={handleTestNotifier}
            testing={testingChannel === 'email'}
            fields={[
              { key: 'smtp_host', label: 'SMTP 服务器', type: 'text', placeholder: 'smtp.gmail.com' },
              { key: 'smtp_port', label: '端口', type: 'text', placeholder: '465' },
              { key: 'username', label: '用户名', type: 'text', placeholder: '' },
              { key: 'password', label: '密码', type: 'password', placeholder: '' },
              { key: 'from_addr', label: '发件人', type: 'text', placeholder: 'xuandun@company.com' },
              { key: 'to_addrs', label: '收件人（逗号分隔）', type: 'text', placeholder: 'admin@company.com' },
            ]}
          />
          <NotifierChannel
            channel="webhook"
            label="Webhook 通用告警"
            icon="link"
            config={notifierConfigs['webhook'] || {}}
            onFieldChange={handleNotifierFieldChange}
            onSave={handleSaveNotifier}
            onTest={handleTestNotifier}
            testing={testingChannel === 'webhook'}
            fields={[
              { key: 'webhook_url', label: 'Webhook URL', type: 'text', placeholder: 'https://your-siem.example.com/api/alert' },
            ]}
          />
          <NotifierChannel
            channel="syslog"
            label="Syslog (SIEM)"
            icon="monitor"
            config={notifierConfigs['syslog'] || {}}
            onFieldChange={handleNotifierFieldChange}
            onSave={handleSaveNotifier}
            onTest={handleTestNotifier}
            testing={testingChannel === 'syslog'}
            fields={[
              { key: 'host', label: '服务器地址', type: 'text', placeholder: '192.168.1.100' },
              { key: 'port', label: '端口', type: 'text', placeholder: '514' },
              { key: 'protocol', label: '协议 (udp/tcp)', type: 'text', placeholder: 'udp' },
              { key: 'facility', label: 'Facility', type: 'text', placeholder: 'local0' },
            ]}
          />
        </div>
      </div>

      {/* P0修复：数据快照卡片 - 配置快照管理 */}
      <div className="card">
        <div className="card-header">
          <h3>数据快照</h3>
          <span className="card-subtitle">配置备份 · 一键恢复</span>
        </div>
        <div className="card-body">
          <div className="form-group form-group-inline">
            <input
              type="text"
              className="form-input"
              value={snapshotLabel}
              onChange={(e) => setSnapshotLabel(e.target.value)}
              placeholder="输入快照标签（如：部署前基线）"
              style={{ flex: 1 }}
            />
            <button className="btn btn-primary" onClick={handleCreateSnapshot} disabled={creatingSnapshot}>{creatingSnapshot ? '创建中...' : '创建快照'}</button>
          </div>
          {snapshots.length > 0 ? (
            <div style={{ marginTop: '12px' }}>
              {snapshots.map(([id, label, timestamp]) => (
                <div key={id} className="setting-item" style={{ padding: '8px 0' }}>
                  <div className="setting-info">
                    <div className="setting-label">{label}</div>
                    <div className="setting-desc" style={{ fontSize: '0.8em' }}>
                      {timestamp}
                    </div>
                  </div>
                  <button
                    className="btn btn-sm btn-secondary"
                    onClick={() => handleRestoreSnapshot(id)}
                    disabled={restoringSnapshot}
                  >
                    {restoringSnapshot ? '恢复中...' : '恢复'}
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ marginTop: '8px', fontSize: '0.85em', color: 'var(--text-secondary)' }}>
              暂无快照记录
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>引擎管理</h3>
        </div>
        <div className="card-body">
          <div className="engine-actions">
            <button className="btn btn-warning" onClick={handleRestart} disabled={restarting}>
              {restarting ? '重启中...' : <><RefreshCw size={16} strokeWidth={1.5} /> 重启引擎</>}
            </button>
            <button className="btn btn-danger" onClick={handleStop} disabled={stopping}>
              {stopping ? '停止中...' : <><Square size={16} strokeWidth={1.5} /> 停止引擎</>}
            </button>
          </div>
        </div>
      </div>
      <ConfirmModal {...confirmModalProps} />
    </div>
  );
}
