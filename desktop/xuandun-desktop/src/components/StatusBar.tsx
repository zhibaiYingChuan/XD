import { useState, useEffect, useRef } from 'react';
import { api, LearningStatus } from '../services/tauriApi';
// 设计系统规范：图标统一使用 lucide-react，strokeWidth=1.5，禁止 emoji
import { AlertTriangle, ShieldOff, RefreshCw } from 'lucide-react';

export default function StatusBar() {
  const [status, setStatus] = useState<LearningStatus | null>(null);
  // P0-06 修复：引擎离线检测与全局提示
  const [engineOffline, setEngineOffline] = useState(false);
  // P0-09 修复：紧急逃生全局广播状态
  const [emergencyBypass, setEmergencyBypass] = useState(false);
  // GAP-S5-05 修复：记录最后成功连接时间，长时间离线时显示
  const [lastSuccessTime, setLastSuccessTime] = useState<Date | null>(null);
  // GAP-S5-12 修复：监听引擎重启全局事件，显示"引擎重启中"提示
  const [engineRestarting, setEngineRestarting] = useState(false);
  const failCountRef = useRef(0);

  useEffect(() => {
    // GAP-S5-12 修复：监听 Settings 页面派发的引擎重启事件
    const handleRestarting = (e: Event) => {
      const detail = (e as CustomEvent).detail;
      if (detail?.state === 'start') setEngineRestarting(true);
      else if (detail?.state === 'end') setEngineRestarting(false);
    };
    window.addEventListener('xuandun:engine-restarting', handleRestarting as EventListener);
    return () => window.removeEventListener('xuandun:engine-restarting', handleRestarting as EventListener);
  }, []);

  useEffect(() => {
    let timeoutId: ReturnType<typeof setTimeout>;
    let emergencyTimeoutId: ReturnType<typeof setTimeout>;
    let isMounted = true;

    const fetchStatus = async () => {
      try {
        const s = await api.getLearningStatus();
        if (!isMounted) return;
        setStatus(s);
        // 成功时清除离线状态，重置失败计数
        failCountRef.current = 0;
        setEngineOffline(false);
        // GAP-S5-05 修复：记录最后成功连接时间
        setLastSuccessTime(new Date());
        // 正常时 3 秒轮询
        timeoutId = setTimeout(fetchStatus, 3000);
      } catch (e) {
        if (!isMounted) return;
        // 连续失败 2 次才标记离线，避免单次超时误报
        failCountRef.current += 1;
        if (failCountRef.current >= 2) {
          setEngineOffline(true);
        }
        // B-05 修复：离线时指数退避，减少无效请求
        // 退避序列：3s → 6s → 12s → 24s → 48s → 60s（封顶）
        const backoff = Math.min(3000 * Math.pow(2, failCountRef.current - 1), 60000);
        timeoutId = setTimeout(fetchStatus, backoff);
      }
    };

    // P0-09 修复：独立轮询紧急逃生状态，确保全局 UI 同步
    // 紧急逃生是高风险状态，必须实时广播到所有页面
    const fetchEmergency = async () => {
      try {
        const eb = await api.getEmergencyBypass();
        if (!isMounted) return;
        setEmergencyBypass(eb.enabled);
        // 紧急逃生状态 5 秒轮询（比学习状态更频繁，确保及时感知切换）
        emergencyTimeoutId = setTimeout(fetchEmergency, 5000);
      } catch {
        if (!isMounted) return;
        // 引擎不可达时不影响紧急逃生提示（可能引擎正是被逃生停掉了）
        emergencyTimeoutId = setTimeout(fetchEmergency, 5000);
      }
    };

    fetchStatus();
    fetchEmergency();
    return () => {
      isMounted = false;
      clearTimeout(timeoutId);
      clearTimeout(emergencyTimeoutId);
    };
  }, []);

  // P0-09 修复：紧急逃生启用时显示最高优先级的全局警告条
  // 此警告必须高于"引擎离线"和"观察模式"，因为逃生模式下即便引擎在线也是无防护状态
  if (emergencyBypass) {
    return (
      <div className="status-bar status-bar-emergency" role="alert" aria-live="assertive">
        <div className="status-bar-left">
          <span className="status-bar-dot dot-emergency"></span>
          <span className="status-bar-mode" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
            <ShieldOff size={16} strokeWidth={1.5} /> 紧急逃生已启用 — 所有请求放行，无安全防护
          </span>
          <span className="status-bar-progress-text">
            所有 AI 请求绕过阴阳门检测直接放行。请前往「系统设置」关闭紧急逃生以恢复防护。
          </span>
        </div>
      </div>
    );
  }

  // GAP-S5-12 修复：引擎重启期间显示全局提示，避免用户在其他页面误以为引擎故障
  // 优先级低于紧急逃生，高于引擎离线（重启期间可能短暂触发离线检测，避免显示混乱）
  if (engineRestarting) {
    return (
      <div className="status-bar status-bar-restarting" role="status" aria-live="polite">
        <div className="status-bar-left">
          <span className="status-bar-dot dot-restarting" style={{ animation: 'pulse 1.5s ease-in-out infinite' }}></span>
          <span className="status-bar-mode" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
            <RefreshCw size={16} strokeWidth={1.5} style={{ animation: 'spin 1s linear infinite' }} /> 引擎重启中（约 5-10 秒）
          </span>
          <span className="status-bar-progress-text">
            引擎正在重启，期间所有 AI 请求将不受安全检测保护，请稍候...
          </span>
        </div>
      </div>
    );
  }

  // P0-06：引擎离线时显示醒目的全局警告条
  if (engineOffline) {
    // GAP-S5-05 修复：计算最后成功时间距今的间隔，超过 5 分钟显示"长时间离线"建议
    const offlineSeconds = lastSuccessTime ? Math.floor((Date.now() - lastSuccessTime.getTime()) / 1000) : 0;
    const offlineMinutes = Math.floor(offlineSeconds / 60);
    const lastSuccessText = lastSuccessTime
      ? `最后成功连接: ${lastSuccessTime.toLocaleTimeString('zh-CN')}`
      : '无成功连接记录';
    const longOfflineHint = offlineMinutes >= 5
      ? '（引擎长时间离线，建议前往「系统设置」重启引擎）'
      : '';
    return (
      <div className="status-bar status-bar-offline">
        <div className="status-bar-left">
          <span className="status-bar-dot dot-offline"></span>
          <span className="status-bar-mode" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
            <AlertTriangle size={16} strokeWidth={1.5} /> 引擎离线 — 安全检测已暂停
          </span>
          <span className="status-bar-progress-text">
            {lastSuccessText}{longOfflineHint} — 引擎未响应，AI 请求暂不受保护。请检查引擎状态或前往「系统设置」重启引擎。
          </span>
        </div>
      </div>
    );
  }

  if (!status) return null;

  const isObserving = status.mode === 'observing';
  const progress = Math.round(status.learning_progress * 100);
  const safeProto = status.safe_prototypes;
  const attackProto = status.attack_prototypes;

  return (
    <div className={`status-bar ${isObserving ? 'status-bar-observing' : 'status-bar-protecting'}`}>
      <div className="status-bar-left">
        <span className={`status-bar-dot ${isObserving ? 'dot-observing' : 'dot-protecting'}`}></span>
        <span className="status-bar-mode">
          {isObserving
            ? <><span className="status-dot dot-observing"></span> 观察模式（学习中）</>
            : <><span className="status-dot dot-protecting"></span> 保护模式</>}
        </span>
        {isObserving && (
          <>
            <span className="status-bar-progress-text">
              已学习 {status.sample_count} / {status.min_samples_for_switch} 条 ({progress}%)
            </span>
            <div className="status-bar-progress-bar">
              <div className="status-bar-progress-fill" style={{ width: `${progress}%` }}></div>
            </div>
          </>
        )}
      </div>
      <div className="status-bar-right">
        <span className="status-bar-stat">安全原型: {safeProto}</span>
        <span className="status-bar-stat">攻击原型: {attackProto}</span>
        {isObserving && status.would_block_count > 0 && (
          <span className="status-bar-stat status-bar-warn">
            模拟拦截: {status.would_block_count}
          </span>
        )}
      </div>
    </div>
  );
}
