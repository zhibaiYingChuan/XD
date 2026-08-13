import { useState, useEffect, useRef } from 'react';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { listen } from '@tauri-apps/api/event';
import { WifiOff, Database, ShieldOff } from 'lucide-react';
import Layout from './components/Layout';
import ErrorBoundary from './components/ErrorBoundary';
import UpdateBanner from './components/UpdateBanner';  // v1.3.4 P1-2: 自动更新横幅
import Dashboard from './pages/Dashboard';
import Detect from './pages/Detect';
import Logs from './pages/Logs';
import Settings from './pages/Settings';
import { api, isTauriBridgeAvailable } from './services/tauriApi';
import './App.css';

function AppContent() {
  // K1-企业精简版：移除首启引导Wizard逻辑（docker-compose部署没有点下一步的场景）
  // checking固定false=直接进入控制台，不再等待Wizard检查完成
  const prevLearningMode = useRef<string | null>(null);
  // Sprint1-P0-6: DB损坏横幅状态——Rust端insert_log/insert_audit失败时
  // 派发xuandun:db_corrupt事件，前端显示顶层红色横幅，不再散落报错
  const [dbCorruptError, setDbCorruptError] = useState<{ operation: string; error: string; hint: string } | null>(null);
  // Sprint1-P0-7: IPC析构散落报错修复——心跳失败横幅
  // 每10s调用noop_heartbeat，连续3次失败（30s窗口）判定桥接死亡，显示顶层红色横幅
  const [ipcDead, setIpcDead] = useState(false);
  const ipcFailStreak = useRef(0);
  const ipcBannerRef = useRef<{ operation?: string; error?: string; hint?: string } | null>(null);

  // R9 修复：引擎永久失效横幅——监听 Rust 端 engine-permanently-failed 事件
  const [enginePermanentlyFailed, setEnginePermanentlyFailed] = useState(false);

  // P2-01 修复：全局错误处理器，捕获未处理的异常和Promise拒绝
  useEffect(() => {
    const handleError = (event: ErrorEvent) => {
      console.error('[全局错误]', event.message, event.error);
      // 阻止默认的错误输出（避免控制台噪声）
      event.preventDefault();
    };
    const handleRejection = (event: PromiseRejectionEvent) => {
      console.error('[未处理Promise拒绝]', event.reason);
      event.preventDefault();
    };
    window.addEventListener('error', handleError);
    window.addEventListener('unhandledrejection', handleRejection);
    return () => {
      window.removeEventListener('error', handleError);
      window.removeEventListener('unhandledrejection', handleRejection);
    };
  }, []);

  // K1-移除Wizard后：直接启动学习模式自动切换轮询
  // 运维半夜被报警惊醒不会误触Wizard，直接看到控制台
  useEffect(() => {
    const checkModeSwitch = async () => {
      try {
        const status = await api.getLearningStatus();
        const currentMode = status.mode;
        if (prevLearningMode.current === 'observing' && currentMode === 'protecting') {
          await api.sendNotification(
            '道体·玄盾 - 学习完成',
            `已自动切换到保护模式（积累 ${status.sample_count} 条样本）。玄盾现在开始拦截攻击。`
          );
        }
        prevLearningMode.current = currentMode;
      } catch {
        // ignore - 心跳与横幅系统会独立报告引擎/IPC故障
      }
    };

    checkModeSwitch();
    const interval = setInterval(checkModeSwitch, 5000);
    return () => clearInterval(interval);
  }, []);

  // Sprint1-P0-6: SQLite损坏横幅——监听Rust端派发的xuandun:db_corrupt事件
  // 任何insert_log/insert_audit失败都会在这里集中显示，不再散落各处eprintln
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    (async () => {
      try {
        unlisten = await listen<{ operation: string; error: string; hint: string }>('xuandun:db_corrupt', (event) => {
          console.error('[全局DB损坏事件-Tauri原生事件]', event.payload);
          // GAP-P1-05 修复：每次收到事件都附加ts:Date.now()，强制React刷新对象引用
          // 避免同值setDbCorruptError(null→隐藏后，再收到同payload事件因Object.is比较不重新渲染横幅
          setDbCorruptError({
            operation: event.payload.operation || 'unknown',
            error: event.payload.error || '未知错误',
            hint: event.payload.hint || '请重启应用',
            ts: Date.now(),
          } as any);
        });
      } catch (e) {
        // Tauri事件系统不可用时降级为console.error
        console.warn('[App] 无法监听Tauri原生xuandun:db_corrupt事件（浏览器环境或事件系统不可用）:', e);
      }
    })();

    // Sprint2-CDP-B2-A4: 降级兼容——同时监听window自定义事件。
    // HCSE测试框架/Cypress/Playwright等通过window.dispatchEvent派发db_corrupt时走这里；
    // 真实生产环境仍走Tauri emit（上面的listen）。
    // 两者保证覆盖99%触发场景，避免横幅链路断链。
    const handleWindowDbCorrupt = (e: Event) => {
      const ce = e as CustomEvent;
      const payload = ce.detail || {};
      console.error('[全局DB损坏事件-window fallback]', payload);
      // GAP-P1-05 修复：同上，附加ts强制重渲染（对象引用每次都不同→React必刷新）
      setDbCorruptError({
        operation: payload.operation || 'unknown',
        error: payload.error || '未知错误',
        hint: payload.hint || '请重启应用',
        ts: Date.now(),
      } as any);
    };
    window.addEventListener('xuandun:db_corrupt', handleWindowDbCorrupt as EventListener);

    return () => {
      if (unlisten) unlisten();
      window.removeEventListener('xuandun:db_corrupt', handleWindowDbCorrupt as EventListener);
    };
  }, []);

  // Sprint1-P0-7: IPC析构散落报错修复——10s noop心跳
  // 检测逻辑：
  //   - 浏览器模式（无 __TAURI_INTERNALS__）→ 不显示错误，HTTP 回退在 tauriApi.ts 中处理
  //   - Tauri 桌面模式 → isTauriBridgeAvailable()==false 才显示桥接错误
  //   - 每10s调用 api.heartbeatNoop()，3s超时
  //   - 连续失败3次（30s窗口）才判定桥接死亡，显示顶层红色横幅
  //   - 成功1次即可清零连胜
  useEffect(() => {
    let cancelled = false;
    // 判断是否运行在 Tauri 容器中（桌面 app）而非普通浏览器
    const isTauriEnv = typeof window !== 'undefined' && !!(window as any).__TAURI_INTERNALS__;
    // 仅在 Tauri 桌面环境中做桥接检测；浏览器模式（Web Demo）走 HTTP 回退，不报错
    if (!isTauriEnv) {
      // Web Demo 模式：静默，不显示桥接错误横幅
      return;
    }
    // 桌面模式下桥接不可用 → 显示错误
    if (!isTauriBridgeAvailable()) {
      setIpcDead(true);
      ipcBannerRef.current = { error: 'Tauri桥接初始化失败：应用可能在浏览器环境中打开' };
    }
    const runHeartbeat = async () => {
      if (cancelled) return;
      try {
        const r = await api.heartbeatNoop();
        if (r.ok) {
          ipcFailStreak.current = 0;
          setIpcDead(false);
          ipcBannerRef.current = null;
          return;
        }
        throw new Error('heartbeat returned ok=false');
      } catch (e: any) {
        ipcFailStreak.current += 1;
        console.warn(`[IPC心跳] 失败 #${ipcFailStreak.current}:`, e?.message || String(e));
        // 连续3次失败=30s窗口，确认桥接已死，避免单次网络抖动误报
        if (ipcFailStreak.current >= 3) {
          setIpcDead(true);
          ipcBannerRef.current = {
            operation: 'noop_heartbeat',
            error: e?.message || String(e),
            hint: 'Tauri桥接无响应，所有调用将失败。请关闭窗口并重启应用。',
          };
        }
      }
    };
    // 启动后立即执行首次心跳，之后每10s
    const firstTimer = setTimeout(runHeartbeat, 1000);
    const interval = setInterval(runHeartbeat, 10000);
    return () => {
      cancelled = true;
      clearTimeout(firstTimer);
      clearInterval(interval);
    };
  }, []);

  // R9 修复：监听 engine-permanently-failed 事件，前端显示红色全局横幅
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    (async () => {
      try {
        unlisten = await listen('engine-permanently-failed', () => {
          console.error('[全局] 防护引擎已永久失效');
          setEnginePermanentlyFailed(true);
        });
      } catch (e) {
        console.warn('[App] 无法监听 engine-permanently-failed 事件:', e);
      }
    })();
    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  // Sprint1-P0-6/P0-7 + R9: 全局横幅渲染
  // 优先级：引擎永久失效 > DB损坏 > IPC桥接死亡
  const renderGlobalBanners = () => {
    const banners: JSX.Element[] = [];
    // R9 修复：引擎永久失效——最高优先级红色横幅，覆盖一切页面
    if (enginePermanentlyFailed) {
      banners.push(
        <div key="engine-fatal" style={{
          position: 'sticky', top: 0, zIndex: 10000,
          background: 'var(--dt-emergency-bg)', color: '#fff', padding: '12px 16px',
          borderBottom: '3px solid var(--dt-emergency-border)', fontSize: '13px', lineHeight: 1.5,
        }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
            <ShieldOff size={18} style={{ flexShrink: 0, marginTop: '2px' }} />
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 600, marginBottom: '4px' }}>
                ⚠ 防护引擎已永久失效，请重启应用
              </div>
              <div style={{ opacity: 0.9 }}>
                引擎连续多次重启失败，AI 安全检测已完全停止。所有请求将不受防护保护。
              </div>
            </div>
          </div>
        </div>
      );
    }
    if (dbCorruptError) {
      banners.push(
        <div key="db-corrupt" style={{
          position: 'sticky', top: 0, zIndex: 9999,
          background: 'var(--dt-emergency-bg)', color: '#fff', padding: '10px 16px',
          borderBottom: '2px solid var(--dt-emergency-border)', fontSize: '13px', lineHeight: 1.5,
        }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
            <Database size={18} style={{ flexShrink: 0, marginTop: '2px' }} />
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 600, marginBottom: '4px' }}>
                ⚠ 本地数据库损坏（{dbCorruptError.operation}）
              </div>
              <div style={{ opacity: 0.9 }}>{dbCorruptError.error}</div>
              <div style={{ opacity: 0.8, marginTop: '4px' }}>{dbCorruptError.hint}</div>
            </div>
            <button
              onClick={() => setDbCorruptError(null)}
              style={{ background: 'transparent', color: '#fff', border: '1px solid rgba(255,255,255,0.4)', padding: '2px 10px', borderRadius: 4, cursor: 'pointer', fontSize: '12px' }}
            >暂时隐藏</button>
          </div>
        </div>
      );
    }
    if (ipcDead) {
      banners.push(
        <div key="ipc-dead" style={{
          position: 'sticky', top: dbCorruptError ? '60px' : 0, zIndex: 9998,
          background: 'var(--dt-fatal-bg)', color: '#fff', padding: '10px 16px',
          borderBottom: '2px solid var(--dt-fatal-border)', fontSize: '13px', lineHeight: 1.5,
        }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
            <WifiOff size={18} style={{ flexShrink: 0, marginTop: '2px' }} />
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 600, marginBottom: '4px' }}>
                ⚠ 应用桥接连接断开
              </div>
              <div style={{ opacity: 0.9 }}>
                {ipcBannerRef.current?.error || '连续3次心跳失败，前端与后端的通信已中断。'}
              </div>
              <div style={{ opacity: 0.8, marginTop: '4px' }}>
                {ipcBannerRef.current?.hint || '请关闭窗口后重启应用。所有功能在此期间将不可用。'}
              </div>
            </div>
          </div>
        </div>
      );
    }
    return banners;
  };

  return (
    <>
      {/* Sprint1-P0-6/P0-7: 全局横幅优先于任何页面——DB损坏/IPC桥接死亡 顶层最高优先级显示 */}
      {renderGlobalBanners()}
      {/* v1.3.4 P1-2: 自动更新横幅 */}
      <UpdateBanner />
      <HashRouter>
        <Routes>
          <Route element={<Layout />}>
            {/* K3-企业精简导航：仅4项一级入口（实时监控/安全检测/拦截日志/系统设置）
                 Reports已降级为拦截日志的Top10摘要，YinYangGate已降级为Settings的只读折叠卡片 */}
            <Route path="/" element={<Dashboard />} />
            <Route path="/detect" element={<Detect />} />
            <Route path="/logs" element={<Logs />} />
            <Route path="/settings" element={<Settings />} />
            {/* Cycle1-交互P0 404白屏修复：所有未匹配路由（#/wizard/#/agents/#/reports/#/yinyang等历史旧URL）
                 统一重定向到仪表盘，不显示白屏。企业用户收藏旧URL不会看到空白页 */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </HashRouter>
    </>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <AppContent />
    </ErrorBoundary>
  );
}

export default App;
