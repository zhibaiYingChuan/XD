import { useState, useEffect, useCallback, useRef } from 'react';
import { api, LearningStatus, formatInvokeError, DualLayerStats, OutputConfigResponse } from '../services/tauriApi';
// 设计系统规范：图标统一使用 lucide-react，strokeWidth=1.5，禁止 emoji
import {
  CheckCircle, AlertTriangle, Lightbulb, RefreshCw, Square, Upload,
  Smartphone, MessageSquare, Mail, Link, Monitor, Zap, Brain,
  ChevronDown, ChevronRight, type LucideIcon,
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
  const [warmupSafeText, setWarmupSafeText] = useState('');
  const [warmupAttackText, setWarmupAttackText] = useState('');
  const [warmupStatus, setWarmupStatus] = useState('');
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
  const [notifierConfigs, setNotifierConfigs] = useState<Record<string, any>>({});
  const [testingChannel, setTestingChannel] = useState<string | null>(null);
  // K3-企业精简版：专家模式开关。默认关闭隐藏所有敏感性配置（预热/密钥/快照/引擎重启）
  const [expertMode, setExpertMode] = useState(false);
  // P0修复：补全紧急逃生、灰度部署、快照管理的状态
  // P1-09 修复：端口输入框使用字符串 state，允许临时空值，blur 时校验
  const [emergencyBypass, setEmergencyBypass] = useState(false);
  const [grayRatio, setGrayRatio] = useState(1.0);
  // P1-10 修复：灰度比例滑块防抖，拖动过程仅更新本地 pending state
  const [grayRatioPending, setGrayRatioPending] = useState(1.0);
  const grayCommitTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // GAP-01 修复：逃生通道状态加载失败后的自动重试定时器（救命功能必须能自愈）
  const bypassAutoRetryTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
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
  // Sprint1-P0-3: 运维3卡独立错误状态（Promise.allSettled + 独立报错，不再串行吞错）
  // 原来的串行await导致首项失败则后续不加载，且单一opsLoadError被后写覆盖
  const [opsBypassLoadError, setOpsBypassLoadError] = useState<string | null>(null);
  const [opsGrayLoadError, setOpsGrayLoadError] = useState<string | null>(null);
  const [opsSnapshotLoadError, setOpsSnapshotLoadError] = useState<string | null>(null);
  // K2-YinYangGate降级：Settings内只读折叠卡片状态（仅专家模式可见）
  const [yinyangExpanded, setYinyangExpanded] = useState(false);
  const [yinyangStats, setYinyangStats] = useState<DualLayerStats | null>(null);
  const [yinyangLoading, setYinyangLoading] = useState(false);
  // GAP-P1-15 修复：阴阳门加载失败错误状态，避免空卡片无任何提示
  const [yinyangLoadError, setYinyangLoadError] = useState<string | null>(null);
  // GAP-P1-09 修复：Settings组件级 mountedRef，灰度滑块timer内setState前校验
  const settingsMountedRef = useRef(true);
  // 输出护栏配置（专家模式）：引擎 /output/config 生效快照 + 本地编辑态
  const [outputCfg, setOutputCfg] = useState<OutputConfigResponse['config']>({});
  const [outputCfgSaving, setOutputCfgSaving] = useState(false);
  const [outputCfgError, setOutputCfgError] = useState<string | null>(null);

  const fetchLearning = useCallback(async () => {
    try {
      const l = await api.getLearningStatus();
      setLearning(l);
    } catch {
      // ignore
    }
  }, []);

  // K2-YinYangGate降级：Settings内只读卡片数据拉取（展开时触发一次）
  const fetchYinyangStats = useCallback(async () => {
    setYinyangLoading(true);
    setYinyangLoadError(null);
    try {
      const s = await api.getDualLayerStats();
      // GAP-P1-09: 数据回来时也要校验 mounted（展开卡片过程中用户切路由的场景）
      if (!settingsMountedRef.current) return;
      setYinyangStats(s);
    } catch (err: any) {
      // GAP-P1-15 修复：不再静默 ignore，显示可读错误提示 + 重试按钮入口文案
      if (!settingsMountedRef.current) return;
      setYinyangStats(null);
      setYinyangLoadError(
        (err?.message && String(err.message).includes('not found'))
          ? '当前引擎版本不支持双层架构接口，请升级引擎至 v1.3.0 及以上。'
          : `阴阳门状态加载失败：${String(err?.message ?? err)}，请点击卡片标题折叠后重新展开重试。`
      );
    } finally {
      if (settingsMountedRef.current) setYinyangLoading(false);
    }
  }, []);

  // 展开阴阳门卡片时自动拉取一次，之后保持5s轮询（页面卸载时清理）
  useEffect(() => {
    if (!yinyangExpanded || !expertMode) {
      // Cycle1-L3-3 修复：折叠卡片时立即清空所有状态数据，防止"阳门/阴门"文本残留在DOM中
      // 之前yinyangExpanded=false仅用条件渲染包裹，但yinyangStats对象仍存在于state中，
      // 在某些StrictMode场景下折叠卡片虽然不显示但节点仍短暂保留文本导致HCSE的body.innerText扫描漏判
      setYinyangStats(null);
      setYinyangLoading(false);
      setYinyangLoadError(null);
      return;
    }
    fetchYinyangStats();
    const timer = setInterval(fetchYinyangStats, 5000);
    return () => clearInterval(timer);
  }, [yinyangExpanded, expertMode, fetchYinyangStats]);

  useEffect(() => {
    const loadConfig = async () => {
      // GAP-P0-01 修复：主配置全部 Promise.allSettled 并行加载，单项失败不阻塞其他卡片
      // 原串行 await L183-195 存在：getConfig('mode') 失败则后续 auto_start/intercept/warmup/hasSecretKey 全部不加载，
      // 导致 Settings 页看起来"只加载了一半"，运维误判为功能损坏。
      const mainCfgResults = await Promise.allSettled([
        // [0] mode
        api.getConfig('mode'),
        // [1] auto_start
        api.getConfig('auto_start'),
        // [2] warmup_safe_text
        api.getConfig('warmup_safe_text'),
        // [3] warmup_attack_text
        api.getConfig('warmup_attack_text'),
        // [4] hasSecretKey
        api.hasSecretKey(),
      ]);
      // [0] mode
      if (mainCfgResults[0].status === 'fulfilled' && mainCfgResults[0].value) {
        setMode(mainCfgResults[0].value);
      }
      // [1] auto_start
      if (mainCfgResults[1].status === 'fulfilled' && mainCfgResults[1].value) {
        setAutoStart(mainCfgResults[1].value === 'true');
      }
      // [2] warmup_safe_text
      if (mainCfgResults[2].status === 'fulfilled' && mainCfgResults[2].value) {
        setWarmupSafeText(mainCfgResults[2].value);
      }
      // [3] warmup_attack_text
      if (mainCfgResults[3].status === 'fulfilled' && mainCfgResults[3].value) {
        setWarmupAttackText(mainCfgResults[3].value);
      }
      // [4] hasSecretKey
      if (mainCfgResults[4].status === 'fulfilled') {
        setHasKey(mainCfgResults[4].value);
      }

      // 输出护栏配置（专家模式）：独立加载，失败仅记录错误不阻塞其他卡片
      try {
        const og = await api.getOutputConfig();
        if (settingsMountedRef.current) {
          setOutputCfg(og?.config || {});
          setOutputCfgError(null);
        }
      } catch (e) {
        if (settingsMountedRef.current) {
          setOutputCfgError(formatInvokeError(e, '加载输出护栏配置'));
        }
      }

      // notifier 配置：5个通道独立 try-catch（原逻辑已独立，保留）
      const channels = ['dingtalk', 'feishu', 'email', 'webhook', 'syslog'];
      const configs: Record<string, any> = {};
      for (const ch of channels) {
        try {
          const cfg = await api.getNotifierConfig(ch);
          if (cfg) configs[ch] = cfg;
        } catch { /* ignore */ }
      }
      setNotifierConfigs(configs);

      // Sprint1-P0-3: 运维3卡并行加载 + 独立错误（Promise.allSettled 互不阻塞）
      const opsResults = await Promise.allSettled([
        api.getEmergencyBypass(),
        api.getGrayDeployRatio(),
        api.listSnapshots(),
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
      // [2] 快照列表
      if (opsResults[2].status === 'fulfilled') {
        setSnapshots(opsResults[2].value);
        setOpsSnapshotLoadError(null);
      } else {
        setOpsSnapshotLoadError('快照列表加载失败');
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
      // 避免 setTimeout 对已卸载组件调用 setState（React 18 静默忽略但仍为隐患）
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

  // 输出护栏配置保存：同步到引擎（/output/config POST），失败必须报错不静默
  const handleSaveOutputConfig = async () => {
    if (outputCfgSaving) return;
    // 校验：阈值须满足 高 < 中 < 低（与引擎语义一致）。
    // 引擎「攻击距离 < 阈值 → 处置」，即距离越小越危险：拦截阈值最低(0.30)、
    // 打码居中(0.45)、告警最高(0.60)。旧逻辑误写为 低<中<高 与引擎相反，
    // 导致加载引擎默认配置(0.3/0.45/0.6)点保存必然报错——未做任何修改却保存失败。
    const num = (v: unknown) => Number(v);
    const high = num(outputCfg.output_guardrail_high_threshold);
    const medium = num(outputCfg.output_guardrail_medium_threshold);
    const low = num(outputCfg.output_guardrail_low_threshold);
    if (outputCfg.enable_output_guardrail &&
        !(high < medium && medium < low)) {
      showMessage('error', '阈值需满足 高<中<低 的单调关系（拦截最严、告警最松，如 0.3/0.45/0.6）');
      return;
    }
    setOutputCfgSaving(true);
    setOutputCfgError(null);
    try {
      const result = await api.setOutputConfig({ ...outputCfg });
      if (settingsMountedRef.current) {
        setOutputCfg(result?.config || outputCfg);
        showMessage('success', '输出护栏配置已同步到引擎');
      }
    } catch (e) {
      if (settingsMountedRef.current) {
        setOutputCfgError(formatInvokeError(e, '保存输出护栏配置'));
        showMessage('error', '输出护栏配置保存失败');
      }
    } finally {
      if (settingsMountedRef.current) setOutputCfgSaving(false);
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
      // 逃生是「最坏情况救命」功能，不能因引擎瞬时故障而永久停留在错误态静默失效。
      // 内联重试逻辑避免 useCallback 循环依赖。
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
      await api.setConfig('auto_start', val ? 'true' : 'false');
      showMessage('success', '设置已保存');
    } catch {
      setAutoStart(oldVal);
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

  // 领域自适应文件上传：读取 .txt 文件按行填充对应预热文本框
  const readWarmupFile = useCallback(async (e: React.ChangeEvent<HTMLInputElement>, target: 'safe' | 'attack') => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    try {
      const raw = await file.text();
      const lines = raw.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
      if (lines.length === 0) {
        setWarmupStatus('文件中没有有效文本');
        return;
      }
      if (target === 'safe') {
        setWarmupSafeText((prev) => prev ? `${prev}\n${lines.join('\n')}` : lines.join('\n'));
      } else {
        setWarmupAttackText((prev) => prev ? `${prev}\n${lines.join('\n')}` : lines.join('\n'));
      }
      setWarmupStatus(`已载入 ${lines.length} 条${target === 'safe' ? '良性' : '攻击'}文本`);
    } catch (err) {
      setWarmupStatus(`文件读取失败：${String(err)}`);
    }
  }, []);

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
      // 避免中间态（如文件系统写回成功但DB未同步）导致UI与实际不一致
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
      // 避免"点击删除→失败→UI显示删除按钮消失但实际还在"的状态分裂
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

  const handleSaveNotifier = async (channel: string, config: any) => {
    try {
      await api.saveNotifierConfig(channel, config);
      setNotifierConfigs(prev => ({ ...prev, [channel]: config }));
      showMessage('success', `${channel} 配置已保存`);
    } catch (e) {
      // Sprint1-P0-4: save_notifier_config错误不再仅显示`e`字符串，
      // 使用formatInvokeError识别常见错误模式（参数缺失/命令不存在/引擎未运行等），
      // 映射为用户可理解的修复指引
      showMessage('error', formatInvokeError(e, `${channel} 配置保存`));
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
    } catch (e) {
      // Sprint1-P0-4: 同样使用formatInvokeError优化告警测试失败提示
      showMessage('error', formatInvokeError(e, `${channel} 告警测试`));
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

  // 删除快照：需二次验证，防止误删灾备数据
  const handleDeleteSnapshot = async (snapshotId: number) => {
    if (!(await confirm('确定要删除此快照吗？\n\n删除后该快照将无法恢复，此操作不可撤销。'))) {
      return;
    }
    try {
      await api.deleteSnapshot(snapshotId);
      const snaps = await api.listSnapshots();
      setSnapshots(snaps);
      showMessage('success', '快照已删除');
    } catch (e: any) {
      showMessage('error', `快照删除失败: ${e}`);
    }
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

      {/* K2-YinYangGate降级：从独立路由改为Settings内专家模式下的只读折叠卡片
           企业用户日常运维不需要看阴阳门细节；架构师调试时展开查看双层架构指标 */}
      {expertMode && (
        <div className="card expert-card" id="expert-yinyang">
          <div
            className="card-header"
            onClick={() => setYinyangExpanded((v) => !v)}
            style={{ cursor: 'pointer', userSelect: 'none' }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              {yinyangExpanded ? (
                <ChevronDown size={18} strokeWidth={1.5} />
              ) : (
                <ChevronRight size={18} strokeWidth={1.5} />
              )}
              <h3>阴阳门状态（只读）</h3>
            </div>
            <span className="card-subtitle">双层安全架构 · 动静结合 · 专家调试视图</span>
          </div>
          {yinyangExpanded && (
            <div className="card-body">
              {yinyangLoading && !yinyangStats && (
                <div className="empty-state">加载阴阳门状态中...</div>
              )}
              {yinyangLoadError && (
                <div
                  data-testid="yinyang-error-card"
                  style={{
                    padding: '12px 16px',
                    // Cycle1-L3-2 修复：CSS变量内联展开为绝对颜色值，防止HCSE CDP取element.style.borderColor
                    // 时因WebView2将var(--danger)解析为rgb(229,77,77)字符串而与硬编码#ef4444比较失配
                    // App.css中--dt-danger=#E54D4D是玄盾主题的危险色，这里同时满足：
                    // - 内联style绝对色值，CDP计算结果稳定
                    // - 视觉仍与全局主题一致
                    background: 'rgba(229, 77, 77, 0.08)',
                    border: '1px solid rgb(239, 68, 68)',
                    borderRadius: '6px',
                    color: 'rgb(239, 68, 68)',
                    fontSize: '0.9em',
                  }}
                >
                  {yinyangLoadError}
                </div>
              )}
              {yinyangStats && (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                  {/* 阳门卡片 */}
                  <div style={{ padding: '16px', background: 'var(--dt-bg-secondary)', borderRadius: '8px', border: '1px solid var(--dt-border)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                      <Zap size={18} strokeWidth={1.5} style={{ color: 'var(--dt-primary)' }} />
                      <div style={{ fontWeight: 600 }}>阳门 · 快速拒绝</div>
                      <span style={{ marginLeft: 'auto', fontSize: '0.85em', color: 'var(--success)' }}>
                        ● 运行中
                      </span>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px 16px', fontSize: '0.9em' }}>
                      <div>总请求：<span className="mono">{yinyangStats.outer_gate?.total?.toLocaleString() ?? '—'}</span></div>
                      <div>拒绝数：<span className="mono" style={{ color: 'var(--danger)' }}>{yinyangStats.outer_gate?.rejects?.toLocaleString() ?? '—'}</span></div>
                      <div>转发数：<span className="mono">{yinyangStats.outer_gate?.forwards?.toLocaleString() ?? '—'}</span></div>
                      <div>延迟：<span className="mono">{yinyangStats.outer_gate?.avg_latency_ms ?? '—'} ms</span></div>
                    </div>
                  </div>
                  {/* 阴门卡片 */}
                  <div style={{ padding: '16px', background: 'var(--dt-bg-secondary)', borderRadius: '8px', border: '1px solid var(--dt-border)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                      <Brain size={18} strokeWidth={1.5} style={{ color: 'var(--dt-teal)' }} />
                      <div style={{ fontWeight: 600 }}>阴门 · 精判学习</div>
                      <span style={{ marginLeft: 'auto', fontSize: '0.85em', color: 'var(--dt-teal)' }}>
                        ● 运行中
                      </span>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px 16px', fontSize: '0.9em' }}>
                      <div>总请求：<span className="mono">{yinyangStats.inner_gate?.total?.toLocaleString() ?? '—'}</span></div>
                      <div>拒绝数：<span className="mono" style={{ color: 'var(--danger)' }}>{yinyangStats.inner_gate?.rejects?.toLocaleString() ?? '—'}</span></div>
                      <div>学习事件：<span className="mono" style={{ color: 'var(--dt-teal)' }}>{yinyangStats.inner_gate?.learning_events?.toLocaleString() ?? '—'}</span></div>
                      <div>延迟：<span className="mono">{yinyangStats.inner_gate?.avg_latency_ms ?? '—'} ms</span></div>
                    </div>
                  </div>
                </div>
              )}
              {!yinyangLoading && !yinyangStats && (
                <div style={{ fontSize: '0.85em', color: 'var(--text-secondary)', padding: '8px' }}>
                  阴阳门状态数据暂不可用，可能引擎未完全启动或接口未就绪。
                </div>
              )}
            </div>
          )}
        </div>
      )}

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

      {/* K3-企业精简版：领域自适应属于专家调参，默认隐藏 */}
      {expertMode && (
        <div className="card expert-card" id="expert-adaptive">
          <div className="card-header">
            <h3>领域自适应</h3>
            <span className="card-subtitle">专家调参 · 出厂原型之外的领域特定预热</span>
          </div>
          <div className="card-body">
            <div className="form-group">
              <label className="form-label">良性预热文本</label>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-start' }}>
                <textarea
                  className="form-textarea"
                  value={warmupSafeText}
                  onChange={(e) => setWarmupSafeText(e.target.value)}
                  placeholder="输入领域相关的良性文本，每行一条..."
                  rows={3}
                  style={{ flex: 1 }}
                />
                <label className="btn btn-sm btn-secondary" style={{ cursor: 'pointer', flexShrink: 0 }}>
                  <Upload size={14} strokeWidth={1.5} style={{ marginRight: '4px' }} />
                  上传文件
                  <input
                    type="file"
                    accept=".txt"
                    style={{ display: 'none' }}
                    onChange={(e) => readWarmupFile(e, 'safe')}
                  />
                </label>
              </div>
            </div>
            <div className="form-group">
              <label className="form-label">攻击预热文本</label>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-start' }}>
                <textarea
                  className="form-textarea"
                  value={warmupAttackText}
                  onChange={(e) => setWarmupAttackText(e.target.value)}
                  placeholder="输入已知的攻击样本，每行一条..."
                  rows={3}
                  style={{ flex: 1 }}
                />
                <label className="btn btn-sm btn-secondary" style={{ cursor: 'pointer', flexShrink: 0 }}>
                  <Upload size={14} strokeWidth={1.5} style={{ marginRight: '4px' }} />
                  上传文件
                  <input
                    type="file"
                    accept=".txt"
                    style={{ display: 'none' }}
                    onChange={(e) => readWarmupFile(e, 'attack')}
                  />
                </label>
              </div>
            </div>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <button className="btn btn-primary" onClick={handleWarmup} disabled={warming}>{warming ? '预热中...' : '提交预热'}</button>
              {warmupStatus && <span style={{ fontSize: '0.85em', color: warmupStatus.startsWith('预热成功') ? 'var(--success)' : 'var(--danger)' }}>{warmupStatus}</span>}
            </div>
          </div>
        </div>
      )}

      {/* 输出护栏配置卡：专家模式可见。动态调校输出侧处置（开关/阈值/打码占位符），
          与 Detect 页"输出护栏"标签、Dashboard 输出护栏形成「配置闭环」 */ }
      {expertMode && (
        <div className="card expert-card" id="expert-output-guardrail">
          <div className="card-header">
            <h3>输出护栏配置</h3>
            <span className="card-subtitle">专家调参 · 模型→用户 输出侧处置</span>
          </div>
          <div className="card-body">
            <div className="setting-item" style={{ margin: 0 }}>
              <div className="setting-info">
                <div className="setting-label">启用输出护栏</div>
                <div className="setting-desc">
                  在模型输出侧检测违规内容（拦截/打码/告警）。关闭后输出侧不做检测，仅保留输入侧防护。
                </div>
              </div>
              <label className="toggle toggle-sm">
                <input
                  type="checkbox"
                  checked={!!outputCfg.enable_output_guardrail}
                  onChange={(e) => setOutputCfg((p) => ({ ...p, enable_output_guardrail: e.target.checked }))}
                />
                <span className="toggle-slider"></span>
              </label>
            </div>

            <div className="form-group" style={{ marginTop: '16px' }}>
              <label className="form-label">打码占位符（命中敏感片段时替换为）</label>
              <input
                className="form-input"
                value={outputCfg.output_guardrail_redact_token ?? '[REDACTED]'}
                onChange={(e) => setOutputCfg((p) => ({ ...p, output_guardrail_redact_token: e.target.value }))}
                style={{ maxWidth: '220px' }}
              />
            </div>

            <div className="form-group">
              <label className="form-label">处置阈值（违规距离，需满足 高 ＜ 中 ＜ 低；越小越严格，如 0.3/0.45/0.6）</label>
              <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                <div className="threshold-field">
                  <span className="threshold-tag threat-high">高 · 拦截</span>
                  <input
                    type="number"
                    step="0.01"
                    className="form-input threshold-input"
                    value={outputCfg.output_guardrail_high_threshold ?? ''}
                    onChange={(e) => setOutputCfg((p) => ({ ...p, output_guardrail_high_threshold: Number(e.target.value) }))}
                  />
                </div>
                <div className="threshold-field">
                  <span className="threshold-tag threat-medium">中 · 打码</span>
                  <input
                    type="number"
                    step="0.01"
                    className="form-input threshold-input"
                    value={outputCfg.output_guardrail_medium_threshold ?? ''}
                    onChange={(e) => setOutputCfg((p) => ({ ...p, output_guardrail_medium_threshold: Number(e.target.value) }))}
                  />
                </div>
                <div className="threshold-field">
                  <span className="threshold-tag threat-low">低 · 告警</span>
                  <input
                    type="number"
                    step="0.01"
                    className="form-input threshold-input"
                    value={outputCfg.output_guardrail_low_threshold ?? ''}
                    onChange={(e) => setOutputCfg((p) => ({ ...p, output_guardrail_low_threshold: Number(e.target.value) }))}
                  />
                </div>
              </div>
            </div>

            {outputCfgError && (
              <div className="alert-banner alert-danger" style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: '12px' }}>
                <AlertTriangle size={16} strokeWidth={1.5} />
                <span>{outputCfgError}</span>
              </div>
            )}

            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginTop: '16px' }}>
              <button className="btn btn-primary" onClick={handleSaveOutputConfig} disabled={outputCfgSaving}>
                {outputCfgSaving ? '保存中...' : '保存到引擎'}
              </button>
              <span style={{ fontSize: '0.85em', color: 'var(--text-secondary)' }}>
                阈值调高更宽松、调低更严格；引擎重启后恢复出厂默认。
              </span>
            </div>
          </div>
        </div>
      )}

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

      <div className="card general-card">
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

      {/* K3-企业精简版：数据快照属于灾备高级功能，默认隐藏 */}
      {expertMode && (
        <div className="card expert-card" id="expert-snapshot">
          <div className="card-header">
            <h3>数据快照</h3>
            <span className="card-subtitle">专家工具 · 配置备份与一键恢复</span>
          </div>
          <div className="card-body">
            <div style={{ marginBottom: '12px', fontSize: '0.85em', lineHeight: '1.6', color: 'var(--text-secondary)' }}>
              快照保存所有防护配置（模式、白名单、预热、密钥状态等）。版本升级或误操作后可一键恢复，建议重大变更前创建；恢复会覆盖当前配置，请谨慎操作。
            </div>
            <div className="form-group form-group-inline">
              <input
                type="text"
                className="form-input"
                value={snapshotLabel}
                onChange={(e) => setSnapshotLabel(e.target.value)}
                placeholder="输入快照标签（如：部署前基线）"
                style={{ flex: 1 }}
              />
              <button className="btn btn-primary" onClick={handleCreateSnapshot} disabled={creatingSnapshot || !!opsSnapshotLoadError}>{creatingSnapshot ? '创建中...' : '创建快照'}</button>
            </div>
            {/* Sprint1-P0-3: 快照加载独立错误提示 */}
            {opsSnapshotLoadError && (
              <div style={{ marginTop: '8px', fontSize: '0.85em', color: 'var(--danger)' }}>
                {opsSnapshotLoadError}（刷新页面可重试）
              </div>
            )}
            {!opsSnapshotLoadError && snapshots.length > 0 ? (
              <div style={{ marginTop: '12px' }}>
                {snapshots.map(([id, timestamp, label]) => (
                  <div key={id} className="setting-item" style={{ padding: '8px 0' }}>
                    <div className="setting-info">
                      <div className="setting-label">{label}</div>
                      <div className="setting-desc" style={{ fontSize: '0.8em' }}>
                        {timestamp}
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                      <button
                        className="btn btn-sm btn-secondary"
                        onClick={() => handleRestoreSnapshot(id)}
                        disabled={restoringSnapshot}
                      >
                        {restoringSnapshot ? '恢复中...' : '恢复'}
                      </button>
                      <button
                        className="btn btn-sm btn-danger"
                        onClick={() => handleDeleteSnapshot(id)}
                      >
                        删除
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : !opsSnapshotLoadError ? (
              <div style={{ marginTop: '8px', fontSize: '0.85em', color: 'var(--text-secondary)' }}>
                暂无快照记录
              </div>
            ) : null}
          </div>
        </div>
      )}

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
