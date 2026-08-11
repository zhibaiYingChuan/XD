import { useState, useEffect, useCallback, useRef } from 'react';
import { api, LearningStatus, formatInvokeError, MESSAGE_TIMEOUT_MS } from '../services/tauriApi';
import { enable, disable, isEnabled } from '@tauri-apps/plugin-autostart';
// 设计系统规范：图标统一使用 lucide-react，strokeWidth=1.5，禁止 emoji
import {
  CheckCircle, AlertTriangle, Lightbulb, RefreshCw, Square,
  Zap,
} from 'lucide-react';
import { ConfirmModal, useConfirmModal } from '../components/ConfirmModal';

export default function Settings() {
  const [mode, setMode] = useState('balanced');
  const { modalProps: confirmModalProps, confirm } = useConfirmModal();
  const [autoStart, setAutoStart] = useState(false);
  const [restarting, setRestarting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [auditReport, setAuditReport] = useState<string>('');
  const [hasKey, setHasKey] = useState(false);
  // Cycle1-L4-1 修复：hasKey同步锁useRef。防止setHasKey异步导致删除失败catch后按钮短暂显示"已删除"再恢复，
  // 条件渲染同时读hasKeyRef.current（同步）和state（异步），两者不一致时以ref为准，确保用户无感知竞争窗口
  const hasKeyRef = useRef<boolean>(false);
  const [learning, setLearning] = useState<LearningStatus | null>(null);
  // K2-企业安全：UI移除手动切换观察/保护按钮（安全产品不允许运维误触切回观察）
  // switchingMode/handleSwitchLearningMode 已全部移除，模式切换仅通过配置文件/启动参数
  // K3-企业精简版：专家模式开关。默认关闭隐藏所有敏感性配置（预热/密钥/快照/引擎重启）
  const [expertMode, setExpertMode] = useState(false);
  // P2: 模型自动发现 — 输入 GPU 服务器 IP，自动扫描常见模型端口
  const [modelIp, setModelIp] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState<Array<{ name: string; port: number; type: string }>>([]);
  const [scanError, setScanError] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);
  // P0修复：补全紧急逃生、灰度部署的状态
  const [emergencyBypass, setEmergencyBypass] = useState(false);
  const [grayRatio, setGrayRatio] = useState(1.0);
  // P1-10 修复：灰度比例滑块防抖，拖动过程仅更新本地 pending state
  const [grayRatioPending, setGrayRatioPending] = useState(1.0);
  const grayCommitTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // GAP-01 修复：逃生通道状态加载失败后的自动重试定时器（救命功能必须能自愈）
  const bypassAutoRetryTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  // P1-11 修复：防护模式切换防并发
  const [modeSwitching, setModeSwitching] = useState(false);
  // P1修复：补全审计验证的加载状态
  const [verifying, setVerifying] = useState(false);
  // P1-21 修复：生成密钥按钮 loading 状态，防止用户重复点击
  const [generatingKey, setGeneratingKey] = useState(false);
  // Sprint1-P0-3: 运维卡独立错误状态（Promise.allSettled + 独立报错，不再串行吞错）
  const [opsBypassLoadError, setOpsBypassLoadError] = useState<string | null>(null);
  const [opsGrayLoadError, setOpsGrayLoadError] = useState<string | null>(null);
  // GAP-P1-09 修复：Settings组件级 mountedRef，灰度滑块timer内setState前校验
  const settingsMountedRef = useRef(true);

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
      // GAP-P0-01 修复：主配置全部 Promise.allSettled 并行加载，单项失败不阻塞其他卡片
      const mainCfgResults = await Promise.allSettled([
        // [0] mode
        api.getConfig('mode'),
        // [1] hasSecretKey
        api.hasSecretKey(),
      ]);
      // [0] mode
      if (mainCfgResults[0].status === 'fulfilled' && mainCfgResults[0].value) {
        setMode(mainCfgResults[0].value);
      }
      // R9 修复：从 autostart 插件读取真实开机自启动状态，而非仅读取 DB
      try {
        const autoStartEnabled = await isEnabled();
        if (settingsMountedRef.current) setAutoStart(autoStartEnabled);
      } catch {
        // 插件不可用时降级读取 DB
        const dbAutoStart = await api.getConfig('auto_start');
        setAutoStart(dbAutoStart === 'true');
      }
      // [1] hasSecretKey
      if (mainCfgResults[1].status === 'fulfilled') {
        setHasKey(mainCfgResults[1].value);
      }

      // Sprint1-P0-3: 运维卡并行加载 + 独立错误（Promise.allSettled 互不阻塞）
      const opsResults = await Promise.allSettled([
        api.getEmergencyBypass(),
        api.getGrayDeployRatio(),
      ]);
      // [0] 紧急逃生
      if (opsResults[0].status === 'fulfilled') {
        setEmergencyBypass(opsResults[0].value.enabled);
        setOpsBypassLoadError(null);
      } else {
        // P1 修复：错误信息含原因+修复路径，不再干巴巴显示"获取失败"
        setOpsBypassLoadError(
          `紧急逃生状态获取失败：${formatInvokeError(opsResults[0].reason, '逃生状态')}。将自动重试，请确认引擎已启动（引擎管理→重启）。`
        );
        // GAP-01 修复：初始加载失败也启动每 5s 自动重试（内联，避免依赖顺序）
        if (!bypassAutoRetryTimerRef.current) {
          bypassAutoRetryTimerRef.current = setInterval(async () => {
            try {
              const r = await api.getEmergencyBypass();
              if (!settingsMountedRef.current) return;
              setEmergencyBypass(r.enabled);
              setOpsBypassLoadError(null);
              if (bypassAutoRetryTimerRef.current) {
                clearInterval(bypassAutoRetryTimerRef.current);
                bypassAutoRetryTimerRef.current = null;
              }
            } catch {
              // 继续等待下一次定时重试
            }
          }, 5000);
        }
      }
      // [1] 灰度比例
      if (opsResults[1].status === 'fulfilled') {
        setGrayRatio(opsResults[1].value.ratio);
        setGrayRatioPending(opsResults[1].value.ratio);
        setOpsGrayLoadError(null);
      } else {
        setOpsGrayLoadError(
          `灰度部署比例获取失败：${formatInvokeError(opsResults[1].reason, '灰度比例')}。请确认引擎已启动（引擎管理→重启），或点击重试。`
        );
      }
    };
    loadConfig();
    fetchLearning();
    const interval = setInterval(fetchLearning, 5000);
    return () => {
      // GAP-P1-09 修复：设置组件 mounted=false，所有异步回调检查此值
      settingsMountedRef.current = false;
      clearInterval(interval);
      // GAP-S5-08 修复：组件卸载时清理灰度滑块的防抖 timer
      if (grayCommitTimerRef.current) {
        clearTimeout(grayCommitTimerRef.current);
        grayCommitTimerRef.current = null;
      }
      // GAP-01 修复：组件卸载时清理逃生自动重试定时器，防止对已卸载组件 setState
      if (bypassAutoRetryTimerRef.current) {
        clearInterval(bypassAutoRetryTimerRef.current);
        bypassAutoRetryTimerRef.current = null;
      }
    };
  }, [fetchLearning]);

  const showMessage = useCallback((type: 'success' | 'error', text: string) => {
    setMessage({ type, text });
    setTimeout(() => {
      if (settingsMountedRef.current) setMessage(null);
    }, MESSAGE_TIMEOUT_MS);
    // settingsMountedRef 守卫确保组件卸载后不 setState
  }, []);

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
          showMessage('error', '模式回滚失败，引擎状态可能不一致。请手动检查防护模式并尝试重新切换。');
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

  // GAP-01 修复：停止逃生状态自动重试定时器
  const stopBypassAutoRetry = useCallback(() => {
    if (bypassAutoRetryTimerRef.current) {
      clearInterval(bypassAutoRetryTimerRef.current);
      bypassAutoRetryTimerRef.current = null;
    }
  }, []);

  // P1-NEW-1 修复：紧急逃生状态获取失败时提供重试按钮
  const retryEmergencyBypass = useCallback(async () => {
    setOpsBypassLoadError(null);
    try {
      const result = await api.getEmergencyBypass();
      if (!settingsMountedRef.current) return;
      setEmergencyBypass(result.enabled);
      stopBypassAutoRetry(); // 恢复成功，停止自动重试
    } catch (err) {
      if (!settingsMountedRef.current) return;
      setOpsBypassLoadError(
        `紧急逃生状态获取失败：${formatInvokeError(err, '逃生状态')}。将自动重试，请确认引擎已启动（引擎管理→重启）。`
      );
      // GAP-01 修复：失败后安排每 5s 自动重试，直到成功。
      if (!bypassAutoRetryTimerRef.current) {
        bypassAutoRetryTimerRef.current = setInterval(async () => {
          try {
            const r = await api.getEmergencyBypass();
            if (!settingsMountedRef.current) return;
            setEmergencyBypass(r.enabled);
            setOpsBypassLoadError(null);
            stopBypassAutoRetry();
          } catch {
            // 继续等待下一次定时重试
          }
        }, 5000);
      }
    }
  }, [stopBypassAutoRetry]);

  // P1-NEW-1 修复：灰度部署比例获取失败时提供重试按钮
  const retryGrayDeploy = useCallback(async () => {
    setOpsGrayLoadError(null);
    try {
      const result = await api.getGrayDeployRatio();
      if (!settingsMountedRef.current) return;
      setGrayRatio(result.ratio);
      setGrayRatioPending(result.ratio);
    } catch (err) {
      if (!settingsMountedRef.current) return;
      setOpsGrayLoadError(
        `灰度部署比例获取失败：${formatInvokeError(err, '灰度比例')}。请确认引擎已启动（引擎管理→重启），或再次重试。`
      );
    }
  }, []);

  const handleAutoStartChange = async (val: boolean) => {
    const oldVal = autoStart;
    setAutoStart(val);
    try {
      // R9 修复：调用 autostart 插件 enable/disable，而非仅写 DB
      if (val) {
        await enable();
      } else {
        await disable();
      }
      // 同步写入 DB 作为备份配置
      await api.setConfig('auto_start', val ? 'true' : 'false');
      showMessage('success', '设置已保存');
    } catch {
      setAutoStart(oldVal);
      showMessage('error', '设置保存失败');
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
      // GAP-P1-08 修复：删除成功后强制从引擎重新拉取真实hasKey状态
      try {
        const latestHasKey = await api.hasSecretKey();
        // Cycle1-L4-1：ref同步更新 + state异步更新，条件渲染以两者任一为true视为存在，避免竞争
        hasKeyRef.current = latestHasKey;
        setHasKey(latestHasKey);
      } catch {
        // 状态查询失败也没关系，保守设置为false避免用户重复点击
        hasKeyRef.current = false;
        setHasKey(false);
      }
      showMessage('success', '密钥已从系统密钥库删除');
    } catch (e: any) {
      showMessage('error', formatInvokeError(e, '密钥删除'));
      // GAP-P1-08 修复：删除失败后强制从引擎拉取真实状态，回滚hasKey
      try {
        const latestHasKey = await api.hasSecretKey();
        hasKeyRef.current = latestHasKey;
        setHasKey(latestHasKey);
      } catch {
        // 拉取失败保守回滚为 true（认为密钥仍存在），立即写ref防止按钮消失
        hasKeyRef.current = true;
        setHasKey(true);
      }
    }
  };

  // P0修复：紧急逃生切换处理
  // P1-01 修复：启用紧急逃生时强制二次确认（停止引擎/删除密钥已有确认，紧急逃生风险更高）
  const handleEmergencyBypassChange = async (enabled: boolean) => {
    // 仅在"启用"时弹出二次确认；关闭逃生恢复正常防护无需确认
    if (enabled) {
      const confirmed = await confirm(
        '开启紧急逃生通道将临时放行所有请求，是否继续？'
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
      // GAP-P1-09 修复：500ms后用户可能已经离开Settings页，校验mounted防止幽灵setState
      if (!settingsMountedRef.current) return;
      const oldVal = grayRatio;
      setGrayRatio(ratio);
      try {
        await api.setGrayDeployRatio(ratio);
        if (!settingsMountedRef.current) return;
        showMessage('success', `灰度比例已设为 ${(ratio * 100).toFixed(0)}%`);
      } catch {
        if (!settingsMountedRef.current) return;
        setGrayRatio(oldVal);
        setGrayRatioPending(oldVal);
        showMessage('error', '灰度比例设置失败，请确认引擎正常运行后重试');
      }
    }, 500);
  };

  // 防护模式：卡片仅展示模式名（标签），每个模式的详细说明由下方「当前模式」面板展示，
  // 切换模式时说明实时联动，避免把小字挤在卡片标签里看不清
  const modes = [
    {
      key: 'high_security',
      label: '高安全',
      detail: '最严格的防护策略：对所有疑似威胁（提示词注入、越狱、敏感信息泄露等）采用高强度拦截，是安全要求极高场景的首选。代价是可能产生较多误报，正常请求若被误判，需人工复核后放行。',
    },
    {
      key: 'balanced',
      label: '平衡',
      detail: '在拦截能力与正常请求可用性之间取得平衡：对高风险攻击严格拦截，对模糊边界请求适度放行，是系统推荐的默认策略，适用于大多数业务场景。',
    },
    {
      key: 'low_false_positive',
      label: '低误报',
      detail: '优先保障正常请求不被误伤：仅在置信度极高时才拦截，适合可用性优先、误报成本高的场景。代价是可能放行部分低置信度的风险请求，需配合日志人工抽查。',
    },
  ];

  return (
    <div className={`page settings-page${expertMode ? ' settings-expert-on' : ''}`}>
      {/* P0-4 修复：每页唯一 H1，符合 WCAG AA 规范 §3.3/§3.4 */}
      <div className="page-header">
        <h1 className="page-title">系统设置</h1>
      </div>
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

      {/* 专家模式全局开关：开启时专家卡片置顶、通用卡片变灰；关闭时仅显示通用功能。
          不再使用锚点导航条，而是通过 CSS order 将专家卡片置于页面顶部。 */}
      <div className="card">
        <div className="card-body" style={{ padding: '12px 20px' }}>
          <div className="setting-item" style={{ margin: 0 }}>
            <div className="setting-info">
              <div className="setting-label">专家模式</div>
              <div className="setting-desc">
                {expertMode
                  ? '已启用，专家卡片已置顶，通用卡片置灰弱化'
                  : '已关闭，隐藏敏感性配置（仅运维日常需要的配置可见）'}
              </div>
            </div>
            <label className="toggle">
              <input
                type="checkbox"
                checked={expertMode}
                onChange={(e) => setExpertMode(e.target.checked)}
              />
              <span className="toggle-slider"></span>
            </label>
          </div>
        </div>
      </div>

      {/* P2: 模型自动发现 — IP 输入框 + 一键扫描本地大模型服务 */}
      <div className="card general-card">
        <div className="card-header">
          <h3>模型连接</h3>
          <span className="card-subtitle">自动发现本地 GPU 服务器上的大模型服务</span>
        </div>
        <div className="card-body">
          <div className="form-group">
            <label className="form-label">GPU 服务器内网 IP</label>
            <div style={{ display: 'flex', gap: '8px' }}>
              <input
                type="text"
                className="form-input"
                placeholder="如 192.168.1.100"
                value={modelIp}
                onChange={(e) => setModelIp(e.target.value)}
              />
              <button
                className="btn btn-primary"
                onClick={async () => {
                  if (!modelIp.trim()) {
                    showMessage('error', '请输入 GPU 服务器的内网 IP 地址');
                    return;
                  }
                  setScanning(true);
                  setScanError(null);
                  setScanResults([]);
                  try {
                    const result = await api.scanModelServer(modelIp.trim());
                    if (result.success) {
                      setScanResults(result.models);
                      if (result.models.length === 0) {
                        setScanError('未检测到模型服务，请确认 IP 地址和端口是否正确');
                      }
                    } else {
                      setScanError(result.error || '扫描失败，请检查网络连接');
                    }
                  } catch (e: any) {
                    setScanError(`扫描失败：引擎可能不支持此功能，请升级到最新版本。${String(e?.message || e)}`);
                  } finally {
                    setScanning(false);
                  }
                }}
                disabled={scanning}
              >
                {scanning ? '扫描中...' : '自动检测'}
              </button>
            </div>
            <div className="setting-desc" style={{ marginTop: '6px' }}>
              自动扫描 11434（Ollama）、8000（vLLM）、8080（TGI）等常见端口
            </div>
          </div>

          {scanError && (
            <div className="alert-banner alert-danger" style={{ marginTop: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <AlertTriangle size={16} strokeWidth={1.5} />
              <span>{scanError}</span>
            </div>
          )}

          {scanResults.length > 0 && (
            <div style={{ marginTop: '12px' }}>
              <div style={{ fontSize: '13px', fontWeight: 600, marginBottom: '8px', color: 'var(--text-primary)' }}>
                发现 {scanResults.length} 个模型服务
              </div>
              {scanResults.map((model, idx) => (
                <div key={idx} className="setting-item" style={{ padding: '10px 0' }}>
                  <div className="setting-info">
                    <div className="setting-label">{model.name}</div>
                    <div className="setting-desc">{model.type} · 端口 {model.port}</div>
                  </div>
                  <button
                    className="btn btn-sm btn-primary"
                    onClick={async () => {
                      setConnecting(true);
                      try {
                        await api.connectModel(model.name, model.port, modelIp.trim());
                        showMessage('success', `已连接到 ${model.name}（${modelIp.trim()}:${model.port}）`);
                      } catch (e: any) {
                        showMessage('error', `连接失败：${String(e?.message || e)}`);
                      } finally {
                        setConnecting(false);
                      }
                    }}
                    disabled={connecting}
                  >
                    {connecting ? '连接中...' : '连接'}
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* 通用卡片区块：专家模式开启时整体置灰弱化（pointer-events 保持可交互） */}
      <div className="card general-card">
        <div className="card-header">
          <h3>防护模式</h3>
        </div>
        <div className="card-body">
          <div className="mode-cards" role="radiogroup" aria-label="防护模式">
            {modes.map((m) => {
              const isActive = mode === m.key;
              return (
                <div
                  key={m.key}
                  role="radio"
                  aria-checked={isActive}
                  aria-label={`${m.label}模式`}
                  tabIndex={modeSwitching ? -1 : (isActive ? 0 : -1)}
                  className={`mode-card ${isActive ? 'mode-card-active' : ''}`}
                  onClick={() => !modeSwitching && handleModeChange(m.key)}
                  onKeyDown={(e) => {
                    if (modeSwitching) return;
                    // P0-NEW-1 修复：支持键盘 Enter/Space 触发切换 + 箭头键在模式间循环（WCAG 2.1 AA radiogroup 模式）
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      handleModeChange(m.key);
                    } else if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
                      e.preventDefault();
                      const idx = modes.findIndex(x => x.key === m.key);
                      const nextIdx = (idx + 1) % modes.length;
                      const nextEl = e.currentTarget.parentElement?.children[nextIdx] as HTMLElement;
                      nextEl?.focus();
                      handleModeChange(modes[nextIdx].key);
                    } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
                      e.preventDefault();
                      const idx = modes.findIndex(x => x.key === m.key);
                      const prevIdx = (idx - 1 + modes.length) % modes.length;
                      const prevEl = e.currentTarget.parentElement?.children[prevIdx] as HTMLElement;
                      prevEl?.focus();
                      handleModeChange(modes[prevIdx].key);
                    }
                  }}
                  style={{ pointerEvents: modeSwitching ? 'none' : 'auto', opacity: modeSwitching ? 0.6 : 1 }}
                >
                  <div className="mode-card-title">{m.label}</div>
                </div>
              );
            })}
          </div>

          {/* 当前模式说明面板：展示选中模式的详细说明，切换模式时实时联动，替代挤在卡片里的文字 */}
          <div className="mode-detail-panel">
            <div className="mode-detail-title">
              <Zap size={14} strokeWidth={1.5} style={{ verticalAlign: '-2px', marginRight: '6px' }} />
              当前模式：{modes.find((m) => m.key === mode)?.label ?? '平衡'}
            </div>
            <div className="mode-detail-desc">
              {modes.find((m) => m.key === mode)?.detail ?? modes[1].detail}
            </div>
          </div>

          {/* 活性状态行：引擎自动的观察/保护状态 + 学习进度，与上方手动选择的防护模式共用一张模式卡 */}
          <div className="mode-active-row">
            <div className="mode-active-row-head">
              <span className="mode-active-row-label">活性状态</span>
              {learning ? (
                <span className={`mode-badge mode-active-sm ${learning.mode === 'observing' ? 'mode-observing' : 'mode-protecting'}`}>
                  {learning.mode === 'observing'
                    ? <><span className="status-dot dot-observing"></span> 观察（学习中）</>
                    : <><span className="status-dot dot-protecting"></span> 保护</>}
                </span>
              ) : (
                <span className="mode-badge mode-active-sm">加载中</span>
              )}
            </div>
            {learning && learning.mode === 'observing' && (
              <div className="mode-active-progress">
                <div className="learning-progress-label">
                  已学习：{learning.sample_count} / {learning.min_samples_for_switch} 条正常对话，达标后自动切换保护
                </div>
                <div className="learning-progress-bar-large mode-active-bar">
                  <div className="learning-progress-fill-large" style={{ width: `${Math.round(learning.learning_progress * 100)}%` }}>
                    <span className="learning-progress-text">{Math.round(learning.learning_progress * 100)}%</span>
                  </div>
                </div>
              </div>
            )}
            <div className="mode-active-note">
              <Lightbulb size={13} strokeWidth={1.5} style={{ verticalAlign: '-2px', marginRight: '6px' }} />
              活性状态由引擎根据学习进度自动切换，与上方防护模式相互独立：防护模式决定拦截严格度（手动选择），活性状态决定是否已启用拦截（自动）。
            </div>
          </div>
        </div>
      </div>

      <div className="card general-card">
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
        </div>
      </div>

      {/* K3-企业精简版：密钥保护属于高敏感操作，独立专家卡片并置顶 */}
      {expertMode && (
        <div className="card expert-card" id="expert-key">
          <div className="card-header">
            <h3>密钥保护</h3>
            <span className="card-subtitle">专家工具 · 签名防篡改</span>
          </div>
          <div className="card-body">
            <div className="setting-item" style={{ margin: 0 }}>
              <div className="setting-info">
                <div className="setting-label">引擎密钥</div>
                <div className="setting-desc">
                  引擎密钥用于签名防篡改，防止配置与日志被恶意篡改。密钥存入系统密钥库（Windows 凭据管理器 / macOS 钥匙串），由系统统一管理，不落明文盘；删除后引擎会重新生成新密钥，无需手动备份。
                  {hasKey ? ' (已存储)' : ' (未设置)'}
                </div>
              </div>
              <div style={{ display: 'flex', gap: '6px' }}>
                {/* Cycle1-L4-1：同时以ref同步值和state异步值做条件渲染，防止删除失败catch中异步setHasKey(true)未生效时按钮消失假状态
                    只要任一值为true就认为密钥存在，宁可显示删除按钮多一点也不暴露"假成功删除" */}
                {!(hasKey || hasKeyRef.current) && <button className="btn btn-primary" onClick={handleGenerateKey} disabled={generatingKey}>{generatingKey ? '生成中...' : '生成密钥'}</button>}
                {(hasKey || hasKeyRef.current) && <button className="btn btn-danger" onClick={handleDeleteKey}>删除密钥</button>}
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="card general-card">
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
        </div>
      </div>

      {/* P0修复：企业运维卡片 - 紧急逃生 + 灰度部署 */}
      <div className="card general-card">
        <div className="card-header">
          <h3>企业运维</h3>
          <span className="card-subtitle">紧急逃生 · 灰度部署 · 故障容灾</span>
        </div>
        <div className="card-body">
          {/* Sprint1-P0-3: 运维独立错误展示——每个子项在自己区域内显示错误，不影响其他项 */}
          <div className="setting-item">
            <div className="setting-info">
              <div className="setting-label">紧急逃生通道</div>
              <div className="setting-desc">
                {opsBypassLoadError ? (
                  <span style={{ color: 'var(--danger)' }}>{opsBypassLoadError}</span>
                ) : emergencyBypass ? (
                  '已启用 — 所有请求直接放行，不经过安全检测'
                ) : (
                  '正常防护中 — 所有请求经过阴阳门检测'
                )}
              </div>
            </div>
            {opsBypassLoadError ? (
              // P1-NEW-1 修复：失败时显示重试按钮，提供修复路径
              <button className="btn btn-sm btn-secondary" onClick={retryEmergencyBypass}>
                <RefreshCw size={14} strokeWidth={1.5} /> 重试
              </button>
            ) : (
              <label className="toggle">
                <input
                  type="checkbox"
                  checked={emergencyBypass}
                  onChange={(e) => handleEmergencyBypassChange(e.target.checked)}
                />
                <span className="toggle-slider"></span>
              </label>
            )}
          </div>

          <div className="setting-item" style={{ marginTop: '12px' }}>
            <div className="setting-info">
              <div className="setting-label">灰度部署比例</div>
              <div className="setting-desc">
                {opsGrayLoadError ? (
                  <span style={{ color: 'var(--danger)' }}>{opsGrayLoadError}</span>
                ) : (
                  <>
                    当前比例：{(grayRatio * 100).toFixed(0)}%
                    {grayRatio < 1.0 && ' — 仅部分流量经过防护'}
                  </>
                )}
              </div>
            </div>
            {opsGrayLoadError ? (
              // P1-NEW-1 修复：失败时显示重试按钮，提供修复路径
              <button className="btn btn-sm btn-secondary" onClick={retryGrayDeploy}>
                <RefreshCw size={14} strokeWidth={1.5} /> 重试
              </button>
            ) : (
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
                <span style={{ fontSize: '0.85em', minWidth: '40px' }}>
                  {`${Math.round(grayRatioPending * 100)}%`}
                </span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* K3-企业精简版：引擎管理重启/停止可能中断业务，默认隐藏 */}
      {expertMode && (
        <div className="card expert-card" id="expert-engine">
          <div className="card-header">
            <h3>引擎管理</h3>
            <span className="card-subtitle">专家工具 · 引擎重启/停止（会中断服务）</span>
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
      )}
      <ConfirmModal {...confirmModalProps} />
    </div>
  );
}
