import { useState, useEffect, useCallback } from 'react';
import { Download, X, RefreshCw } from 'lucide-react';
import { api } from '../services/tauriApi';

/**
 * UpdateBanner — 桌面端自动更新提示（右下角 Toast）
 *
 * v1.3.4 P1-2.3 新增。
 * 设计原则：更新属于"后台服务"，不打扰主流程。
 *  - 有更新：右下角小 Toast，温和告知，可一键更新或忽略
 *  - 下载中：小 Toast 显示进度
 *  - 安装中：小 Toast 提示即将重启
 *  - 检查失败：静默后台重试，不打扰用户（非关键路径）
 * 状态机：idle → available → downloading → installing → dismissed
 */

interface UpdateInfo {
  available: boolean;
  version?: string;
  body?: string;
  date?: string;
  current_version?: string;
}

type UpdatePhase = 'idle' | 'available' | 'downloading' | 'installing' | 'dismissed';

export default function UpdateBanner() {
  const [phase, setPhase] = useState<UpdatePhase>('idle');
  const [info, setInfo] = useState<UpdateInfo | null>(null);
  const [progress, setProgress] = useState(0);
  // D-P1-7: 下载/安装失败原因（用户可见），成功开始新一轮下载时清除
  const [error, setError] = useState<string | null>(null);

  // ── 启动后 3s 后台自动检查更新 ──
  useEffect(() => {
    const timer = setTimeout(() => {
      checkForUpdate();
    }, 3000);
    return () => clearTimeout(timer);
  }, []);

  // ── 监听 Rust 推送的下载进度事件 ──
  useEffect(() => {
    let unlisten: (() => void) | undefined;

    const setupListener = async () => {
      try {
        const { listen } = await import('@tauri-apps/api/event');
        unlisten = await listen<{ downloaded: number; total: number }>('update-progress', (event) => {
          if (event.payload.total > 0) {
            setProgress(Math.round((event.payload.downloaded / event.payload.total) * 100));
          }
        });
      } catch {
        // 事件监听不可用时静默降级
      }
    };
    setupListener();

    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  const checkForUpdate = useCallback(async () => {
    // 后台检查，仅在有更新时才显示 UI
    try {
      const result = await api.checkUpdate();
      if ((result as any).available) {
        setInfo(result as unknown as UpdateInfo);
        setPhase('available');
      }
      // 无更新或检查失败：完全静默，不打扰用户
    } catch (e: any) {
      console.warn('[UpdateBanner] 检查更新失败（静默后台）:', e?.message || e);
    }
  }, []);

  const handleDownload = useCallback(async () => {
    if (phase === 'downloading') return;
    setError(null);
    setPhase('downloading');
    setProgress(0);
    try {
      await api.downloadAndInstallUpdate();
      setPhase('installing');
    } catch (e: any) {
      // D-P1-7: 下载/安装失败必须告知用户（错误路径三要素：明确提示 + 状态恢复 + 可重试），
      // 此前仅静默回退到 available，用户对失败毫无感知
      setError(`更新失败：${e?.message || '网络或更新服务异常'}`);
      setPhase('available');
    }
  }, [phase]);

  const handleDismiss = useCallback(async () => {
    try {
      await api.dismissUpdate(info?.version);
    } catch {
      // 静默
    }
    setPhase('dismissed');
  }, [info]);

  // ── 无需要展示的状态时返回 null（不占任何布局）──
  if (phase === 'idle' || phase === 'dismissed') return null;

  // ── 右下角 Toast 样式 ──
  const toastStyle: React.CSSProperties = {
    position: 'fixed', right: 16, bottom: 16, zIndex: 9999,
    display: 'flex', alignItems: 'center', gap: 10,
    padding: '10px 16px', fontSize: 13,
    borderRadius: 8, boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
    color: '#fff', maxWidth: 360,
    animation: 'fadeInUp 0.25s ease-out',
  };

  const phaseStyle: Record<UpdatePhase, React.CSSProperties> = {
    idle: {},
    available: { background: 'var(--bg-secondary, #1e293b)' },
    downloading: { background: 'var(--bg-secondary, #1e293b)' },
    installing: { background: 'var(--bg-secondary, #1e293b)' },
    dismissed: {},
  };

  return (
    <div style={{ ...toastStyle, ...phaseStyle[phase] }}>
      {phase === 'available' && info && (
        <>
          <Download size={14} style={{ color: error ? '#f87171' : '#60a5fa', flexShrink: 0 }} />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
            <span>
              发现新版本 <strong>{info.version}</strong>
              {info.current_version && <>（当前 {info.current_version}）</>}
            </span>
            {error && (
              <span style={{ color: '#f87171', fontSize: 12 }}>
                {error}，可点击“更新”重试
              </span>
            )}
          </div>
          <button
            onClick={handleDownload}
            style={{
              background: '#3b82f6', border: 'none', borderRadius: 6,
              padding: '5px 12px', color: '#fff', cursor: 'pointer', fontSize: 12,
              flexShrink: 0,
            }}
          >
            更新
          </button>
          <button
            onClick={handleDismiss}
            title="本次忽略"
            style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.5)', cursor: 'pointer', padding: 2, flexShrink: 0 }}
          >
            <X size={14} />
          </button>
        </>
      )}

      {phase === 'downloading' && (
        <>
          <Download size={14} style={{ color: '#60a5fa', flexShrink: 0 }} />
          <span>正在下载更新... {progress}%</span>
          {progress > 0 && (
            <div style={{
              width: 80, height: 4, background: 'rgba(255,255,255,0.15)',
              borderRadius: 2, overflow: 'hidden', flexShrink: 0,
            }}>
              <div style={{
                width: `${progress}%`, height: '100%',
                background: '#60a5fa', borderRadius: 2,
                transition: 'width 0.2s ease',
              }} />
            </div>
          )}
        </>
      )}

      {phase === 'installing' && (
        <>
          <RefreshCw size={14} style={{ color: '#34d399', flexShrink: 0, animation: 'spin 1s linear infinite' }} />
          <span>更新完成，即将重启应用...</span>
        </>
      )}
    </div>
  );
}