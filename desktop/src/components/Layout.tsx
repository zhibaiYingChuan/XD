/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   侧边栏 + 状态栏布局骨架。
*/

import { useEffect, useRef, useState } from 'react';
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  FileText,
  Settings as SettingsIcon,
  HelpCircle,
  KeyRound,
} from 'lucide-react';
import { api, STATE_LABELS, currentProxyPort, syncProxyPort } from '../services/api';
import type { StateResponse, LicenseStatus } from '../services/api';
import { getAppVersion, isTauri, setTrayState, type TrayState } from '../lib/tauriShim';
import { useBootDeadline } from './EngineOffline';

// ══════════════════════════════════════════════════════════════
// 侧边导航（产品文档：4 个页面）
// ══════════════════════════════════════════════════════════════

const NAV_ITEMS = [
  { to: '/', label: '首页', icon: LayoutDashboard, end: true },
  { to: '/logs', label: '日志', icon: FileText, end: false },
  { to: '/settings', label: '设置', icon: SettingsIcon, end: false },
  { to: '/help', label: '帮助', icon: HelpCircle, end: false },
];

/**
 * 由引擎状态 + 今日统计推导托盘持续态。
 *
 * 优先级：paused > danger > suspect > safe。
 * danger 优先于 suspect —— 今日已阻断过就是今天最严重的事实，
 * 黄色不该覆盖红色。
 */
function deriveTrayState(
  s: StateResponse['state'],
  today: StateResponse['today'],
  reachable: boolean,
): { state: TrayState; detail: string } {
  if (!reachable || s === 'paused') {
    return { state: 'paused', detail: s === 'paused' ? '防护已暂停' : '本地代理未运行' };
  }
  if (!today) return { state: 'safe', detail: '正在建立基线' };

  if (today.danger_count > 0) {
    return { state: 'danger', detail: `今日已阻断 ${today.danger_count} 次` };
  }
  if (today.suspect_count > 0) {
    /* ★ 统计类信号不再把状态染成黄色「可疑」。
       它只说明「回答长度/结构与平时不同」，不指向任何安全问题 ——
       而状态栏是用户判断「我现在安不安全」的唯一依据。
       之前只要有统计命中就显示「可疑」，等于把正常的编程对话
       报成「可疑」，用户要么被无谓惊吓、要么学会忽略这个信号。
       现在它只作为右侧的计数出现（见下方 status-stat）。 */
    return { state: 'safe', detail: `今日 ${today.suspect_count} 条提示` };
  }
  return { state: 'safe', detail: `今日已检查 ${today.total_calls} 次` };
}

// ══════════════════════════════════════════════════════════════
// 状态栏（首页第一眼就知道"现在安全吗"）
// ══════════════════════════════════════════════════════════════

function StatusBar() {
  const [state, setState] = useState<StateResponse | null>(null);
  const [reachable, setReachable] = useState(true);
  // ★ 是否**曾经**连上过：区分「冷启动还没起来」与「用着用着挂了」。
  //   两者对用户的意义完全不同 —— 前者等两秒就好，后者是真故障。
  const [everUp, setEverUp] = useState(false);
  const failRef = useRef(0);
  // ★ P1-30：引擎没起来时，用户必须能**就地**恢复，而不是只被告知
  //   「请确认代理已启动（127.0.0.1:18765）」—— 那句话他没有办法执行。
  const [restarting, setRestarting] = useState(false);
  // 重建轮询用的计数器：重启成功后立刻重新拉一次，不必等退避到 30 秒。
  const [pollKey, setPollKey] = useState(0);
  // ★ P1-30：「还在启动」最多维持 20 秒 —— 之后必须给出可执行的动作。
  const bootTimedOut = useBootDeadline();

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;

    const poll = async () => {
      try {
        const s = await api.getState();
        if (cancelled) return;
        setState(s);
        setReachable(true);
        setEverUp(true);
        failRef.current = 0;          // ★ 成功后重置退避计数
        timer = setTimeout(poll, 2000);
      } catch {
        if (cancelled) return;
        setReachable(false);
        // 指数退避 2→4→8→…→30s 上限
        failRef.current = Math.min(failRef.current + 1, 4);
        timer = setTimeout(poll, Math.min(2000 * 2 ** failRef.current, 30000));
      }
    };

    poll();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [pollKey]);

  /** 就地重启引擎：成功即立刻重拉一次状态，失败把原因留在设置页。 */
  const handleRestartEngine = async () => {
    if (restarting) return;
    setRestarting(true);
    try {
      await api.restartEngine();
      failRef.current = 0;
      setPollKey((k) => k + 1);
    } catch {
      // 具体原因（端口被占用 / 配置损坏）由「设置 → 运行状态」呈现，
      // 状态栏这一层只说「仍然没起来」，不猜原因。
      failRef.current = 4;
    } finally {
      setRestarting(false);
    }
  };

  useEffect(() => {
    // ★ P1-10：先同步「实际运行中的端口」，再开始轮询。
    //   否则首次渲染时各页面文案会显示默认端口，
    //   而用户可能早已改过配置（未重启），导致提示错误地址。
    api
      .getActivePort()
      .then((p) => syncProxyPort(p))
      .catch(() => undefined);
  }, []);

  // 下发托盘持续态（两段式变色的「持续」段）
  // 只在状态实际变化时下发，避免每 2s 一次无意义的 IPC。
  const trayKey = reachable
    ? `${state?.state}|${state?.today?.danger_count}|${state?.today?.suspect_count}|${state?.today?.total_calls}`
    : 'unreachable';
  const lastTrayKey = useRef<string>('');
  useEffect(() => {
    if (trayKey === lastTrayKey.current) return;
    lastTrayKey.current = trayKey;
    const { state: ts, detail } = deriveTrayState(
      state?.state ?? 'learning',
      state?.today,
      reachable,
    );
    setTrayState(ts, detail);
  }, [trayKey, state, reachable]);

  if (!reachable) {
    // ★ 冷启动：引擎还在拉起时**不要**报「本地代理未运行」。
    //   每次打开应用先红一下，用户会以为防护坏了，甚至去重装。
    //   连续失败 3 次（约 14 秒）仍没起来，才当作真的没运行。
    //
    // ★ P1-30：但"还在启动"必须有**时间上限**。端口被别的程序占着时，
    //   请求会长时间挂着不回 —— 既没有成功也没有失败，失败计数一直是 0，
    //   界面就永远停在「首次启动需要几秒」。到点就必须说真话。
    if (!everUp && failRef.current < 3 && !bootTimedOut) {
      return (
        <div className="status-bar" role="status" aria-live="polite">
          <span className="status-dot learning" />
          <span className="status-label">正在启动本地代理…</span>
          <span className="status-meta">首次启动需要几秒</span>
        </div>
      );
    }
    return (
      <div className="status-bar" role="status" aria-live="polite">
        <span className="status-dot paused" />
        <span className="status-label" style={{ color: 'var(--xd-danger)' }}>
          本地代理未运行
        </span>
        <span className="status-meta">
          端口 127.0.0.1:{currentProxyPort()} 没有响应 ·
          可重启引擎，或看「设置 → 运行状态」里的原因
        </span>
        {isTauri() && (
          <button
            className="btn ghost sm"
            onClick={() => void handleRestartEngine()}
            disabled={restarting}
          >
            {restarting ? '正在重启…' : '重启引擎'}
          </button>
        )}
        <Link className="btn ghost sm" to="/settings#sec-engine">
          查看原因
        </Link>
      </div>
    );
  }

  // ★ 还没读到状态时不要说「学习中」—— 那是结论，不是加载态。
  const s = state?.state;
  const today = state?.today;

  return (
    <div className="status-bar">
      {/* ★ 只播报「状态」变化（2026-10-19）。
          此前整个状态栏是 role="status" aria-live="polite"，
          而它每 2 秒轮询一次、里面的「今日检查 N 次」等数字不断变化，
          读屏会被这些数字持续打断，真正要传达的状态反而听不清。
          改为一个读屏专用的 live 区域，只承载**状态文案**：
          它的文本仅在 state 真正切换时才变化，故只在状态变化时播报。 */}
      <span className="sr-only" aria-live="polite">
        {s ? STATE_LABELS[s] : '读取中'}
      </span>
      <span className={`status-dot ${s ?? 'learning'}`} />
      <span className="status-label">{s ? STATE_LABELS[s] : '读取中'}</span>
      {state?.message && <span className="status-meta">{state.message}</span>}

      {/* ★ 只读模式必须显式说出来。
          这时状态点仍可能是绿色、KPI 也在涨，但请求其实全部直通 ——
          不说就是谎报「正在保护你」。 */}
      {state?.read_only && (
        <span className="status-stat" style={{ color: 'var(--xd-suspect)' }}>
          未激活，当前为只读模式（不执行拦截）
        </span>
      )}

      <span className="status-bar-spacer" />

      {today && today.total_calls > 0 && (
        <>
          {/* ★ 数字必须能点进去（2026-10-20）。
              此前状态栏的「危险 26」「已打码 322 处」只是死文字：
              用户看到数字、想核对，唯一的路径是自己去日志页手动调四个下拉。
              这就是「数字对不上 / 点开啥都没有」的一半来源。
              现在每个数字都是一个带筛选条件的链接。 */}
          <Link
            to="/logs?days=1&marked=exclude"
            className="status-stat"
            style={{ textDecoration: 'none', color: 'inherit' }}
            title="查看今天参与统计的记录（不含已标记误报与转发中断）"
          >
            今日检查 <b className="mono">{today.total_calls}</b> 次
          </Link>
          {today.danger_count > 0 && (
            <Link
              to="/logs?days=1&action=block&marked=exclude"
              className="status-stat"
              style={{ textDecoration: 'none', color: 'var(--xd-danger)' }}
              title="查看今天被拦截的记录（已排除标记为误报的）"
            >
              危险 <b className="mono">{today.danger_count}</b>
            </Link>
          )}
          {today.suspect_count > 0 && (
            /* ★ 「可疑」改成「提示」。
               「可疑」暗示「出问题了」，而统计类信号（回答长度与平时不同）
               根本不指向任何问题 —— 用户看到它只会莫名紧张。
               改为中性的「提示」，与「危险」形成清晰的轻重区分。 */
            <Link
              to="/logs?days=1&action=alert&marked=exclude"
              className="status-stat"
              style={{ textDecoration: 'none', color: 'var(--xd-suspect)' }}
              title="查看今天的提示记录（已排除标记为误报的）"
            >
              提示 <b className="mono">{today.suspect_count}</b>
            </Link>
          )}
          {today.redaction_count > 0 && (
            <Link
              to="/logs?days=1&action=redact"
              className="status-stat"
              style={{ textDecoration: 'none', color: 'inherit' }}
              title="查看今天打过码的记录"
            >
              已打码 <b className="mono">{today.redaction_count}</b> 处
            </Link>
          )}
        </>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// 布局
// ══════════════════════════════════════════════════════════════

export default function Layout() {
  const location = useLocation();
  // ★ 初值为空而不是硬编码版本（2026-10-20）：
  //   取到真实版本前不显示，避免发布后首帧闪一下上个版本号。
  const [version, setVersion] = useState('');
  const [license, setLicense] = useState<LicenseStatus | null>(null);
  const mainRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    getAppVersion().then(setVersion).catch(() => undefined);
  }, []);

  // 激活状态：侧边栏「激活」入口上显示角标，
  // 让用户不用点进去就知道还没激活。
  // ★ 读不到时保持 null（不显示角标）而非当成「未激活」——
  //   引擎一抖动就到处报警是噪声，不是提示。
  useEffect(() => {
    let cancelled = false;
    const load = () => {
      api
        .getLicenseStatus()
        .then((s) => {
          if (!cancelled) setLicense(s);
        })
        .catch(() => undefined);
    };
    load();
    // ★ 激活成功后侧边栏的「未激活」角标必须立刻消失（2026-10-20）。
    //   此前只在路由切换时重读，用户在激活页看到「激活成功」，
    //   左侧却还挂着「未激活」—— 同一屏两个相反结论。
    const onLicenseChanged = () => load();
    window.addEventListener('xuandun:license-changed', onLicenseChanged);
    // 激活成功后会切页，回来时自然重新读取
    return () => {
      cancelled = true;
      window.removeEventListener('xuandun:license-changed', onLicenseChanged);
    };
  }, [location.pathname]);

  // 路由切换时滚动到顶部
  useEffect(() => {
    mainRef.current?.scrollTo({ top: 0 });
  }, [location.pathname]);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="sidebar-brand-icon">
            <Shield size={18} strokeWidth={1.5} />
          </div>
          <div className="sidebar-brand-text">
            <div className="sidebar-brand-title">道体·玄盾</div>
            <div className="sidebar-brand-sub">个人版</div>
          </div>
        </div>

        <nav className="sidebar-nav">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                // title：窄窗口折叠成图标栏后靠它提示每个图标是什么，导航仍然可辨识。
                title={item.label}
                className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
              >
                <Icon size={17} strokeWidth={1.5} />
                {/* 标签单独包一层：窄窗口（≤900px）折叠为图标栏时由 CSS 隐藏文字，
                    避免图标栏被挤爆。见 styles.css 的响应式断点。 */}
                <span className="nav-item-label">{item.label}</span>
              </NavLink>
            );
          })}
          <NavLink
            to="/activate"
            title="激活"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <KeyRound size={17} strokeWidth={1.5} />
            <span className="nav-item-label">激活</span>
            {license && !license.activated && (
              <span className="badge suspect" style={{ marginLeft: 'auto' }}>
                未激活
              </span>
            )}
          </NavLink>
        </nav>

        <div className="sidebar-footer">
          {version && <span>v{version}</span>}
          <span className="faint">本地运行</span>
        </div>
      </aside>

      <div className="main-area">
        <StatusBar />
        <main className="page-content" ref={mainRef}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
