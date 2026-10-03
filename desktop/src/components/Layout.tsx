/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   侧边栏 + 状态栏布局骨架。
*/

import { useEffect, useRef, useState } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
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
import { getAppVersion, setTrayState, type TrayState } from '../lib/tauriShim';

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
  const failRef = useRef(0);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;

    const poll = async () => {
      try {
        const s = await api.getState();
        if (cancelled) return;
        setState(s);
        setReachable(true);
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
  }, []);

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
    return (
      <div className="status-bar" role="status" aria-live="polite">
        <span className="status-dot paused" />
        <span className="status-label" style={{ color: 'var(--xd-danger)' }}>
          本地代理未运行
        </span>
        <span className="status-meta">
          请确认玄盾代理已启动（127.0.0.1:{currentProxyPort()}）
        </span>
      </div>
    );
  }

  const s = state?.state ?? 'learning';
  const today = state?.today;

  return (
    <div className="status-bar" role="status" aria-live="polite">
      <span className={`status-dot ${s}`} />
      <span className="status-label">{STATE_LABELS[s]}</span>
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
          <span className="status-stat">
            今日检查 <b className="mono">{today.total_calls}</b> 次
          </span>
          {today.danger_count > 0 && (
            <span className="status-stat" style={{ color: 'var(--xd-danger)' }}>
              危险 <b className="mono">{today.danger_count}</b>
            </span>
          )}
          {today.suspect_count > 0 && (
            /* ★ 「可疑」改成「提示」。
               「可疑」暗示「出问题了」，而统计类信号（回答长度与平时不同）
               根本不指向任何问题 —— 用户看到它只会莫名紧张。
               改为中性的「提示」，与「危险」形成清晰的轻重区分。 */
            <span className="status-stat" style={{ color: 'var(--xd-suspect)' }}>
              提示 <b className="mono">{today.suspect_count}</b>
            </span>
          )}
          {today.redaction_count > 0 && (
            <span className="status-stat">已打码 <b className="mono">{today.redaction_count}</b> 处</span>
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
  const [version, setVersion] = useState('0.1.3-alpha');
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
    // 激活成功后会切页，回来时自然重新读取
    return () => {
      cancelled = true;
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
                className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
              >
                <Icon size={17} strokeWidth={1.5} />
                {item.label}
              </NavLink>
            );
          })}
          <NavLink
            to="/activate"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <KeyRound size={17} strokeWidth={1.5} />
            激活
            {license && !license.activated && (
              <span className="badge suspect" style={{ marginLeft: 'auto' }}>
                未激活
              </span>
            )}
          </NavLink>
        </nav>

        <div className="sidebar-footer">
          <span>v{version}</span>
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
