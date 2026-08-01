import { useState, useEffect, useCallback } from 'react';
import { Routes, Route, NavLink, useLocation } from 'react-router-dom';
import { Shield, Zap, Activity, FlaskConical, Brain, Home, ChevronLeft, Menu, X } from 'lucide-react';
import HomePage from './pages/HomePage';
import DetectPage from './pages/DetectPage';
import YinYangPage from './pages/YinYangPage';
import SimulationPage from './pages/SimulationPage';
import LearningPage from './pages/LearningPage';
import { api } from './api';

const navItems = [
  { to: '/', icon: Home, label: '首页' },
  { to: '/detect', icon: Shield, label: '安全检测' },
  { to: '/yinyang', icon: Activity, label: '阴阳门演示' },
  { to: '/simulation', icon: FlaskConical, label: '模拟测试' },
  { to: '/learning', icon: Brain, label: '学习状态' },
];

// 应用版本号
const APP_VERSION = 'v1.3.0';

// 太极 Logo SVG 组件（道体·玄盾品牌标识）
function TaijiLogo({ size = 40 }: { size?: number }) {
  return (
    <div className="sidebar-logo-icon" style={{ width: size, height: size }}>
      <svg viewBox="0 0 100 100" width={size * 0.7} height={size * 0.7}>
        <defs>
          <linearGradient id="taijiGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#2B5FD7" />
            <stop offset="100%" stopColor="#00D4AA" />
          </linearGradient>
        </defs>
        <circle cx="50" cy="50" r="48" fill="none" stroke="url(#taijiGrad)" strokeWidth="2" />
        <path d="M50 2 A48 48 0 0 1 50 98 A24 24 0 0 0 50 50 A24 24 0 0 1 50 2" fill="url(#taijiGrad)" opacity="0.9" />
        <path d="M50 2 A48 48 0 0 0 50 98 A24 24 0 0 1 50 50 A24 24 0 0 0 50 2" fill="#0B0E14" opacity="0.9" />
        <circle cx="50" cy="26" r="6" fill="#0B0E14" />
        <circle cx="50" cy="74" r="6" fill="#00D4AA" />
      </svg>
    </div>
  );
}

export default function App() {
  const location = useLocation();
  // 侧边栏折叠状态（桌面端）
  const [collapsed, setCollapsed] = useState(false);
  // 移动端侧边栏开关
  const [mobileOpen, setMobileOpen] = useState(false);
  // 引擎在线状态
  const [online, setOnline] = useState<boolean | null>(null);
  // 当前学习模式（observe / protecting）
  const [mode, setMode] = useState<string>('');
  // 后端版本号（若获取失败则使用本地版本）
  const [serverVersion, setServerVersion] = useState(APP_VERSION);

  // 轮询引擎健康状态与学习模式
  useEffect(() => {
    let active = true;
    const poll = async () => {
      try {
        const health = await api.health();
        if (!active) return;
        setOnline(health.status === 'ok' || health.shield_ready);
        if (health.version) setServerVersion(health.version);
      } catch {
        if (active) setOnline(false);
      }
      try {
        const stats = await api.getStats();
        if (!active) return;
        setMode(stats.learning?.mode || '');
      } catch {
        // 静默忽略统计获取失败
      }
    };
    poll();
    const interval = setInterval(poll, 5000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);

  // 路由切换时关闭移动端菜单
  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname]);

  // 当前页面标题
  const currentTitle =
    navItems.find(n => (n.to === '/' ? location.pathname === '/' : location.pathname.startsWith(n.to)))?.label ||
    '道体·玄盾';

  // 切换折叠（桌面端）
  const toggleCollapsed = useCallback(() => setCollapsed(c => !c), []);
  // 切换移动端菜单
  const toggleMobile = useCallback(() => setMobileOpen(o => !o), []);

  // 模式展示文本
  const modeText = mode === 'protecting' ? '保护模式' : mode === 'observing' ? '观察模式' : mode || '待机';
  const modeClass = mode === 'protecting' ? 'protecting' : mode === 'observing' ? 'learning' : '';
  // 模式指示点颜色
  const modeDotColor = mode === 'protecting' ? 'var(--success)' : mode === 'observing' ? 'var(--warning)' : 'var(--text-tertiary)';

  return (
    <div className="app-layout">
      {/* 移动端遮罩 */}
      <div
        className={`sidebar-overlay ${mobileOpen ? 'visible' : ''}`}
        onClick={() => setMobileOpen(false)}
        aria-hidden="true"
      />

      {/* 侧边栏 */}
      <aside className={`sidebar ${collapsed ? 'collapsed' : ''} ${mobileOpen ? 'open' : ''}`}>
        <div className="sidebar-logo">
          <TaijiLogo size={40} />
          <div>
            <div className="sidebar-title">道体·玄盾</div>
            <div className="sidebar-subtitle">活性防护 LLM 防火墙</div>
          </div>
        </div>
        <nav className="sidebar-nav">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              data-label={item.label}
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            >
              <span className="nav-icon"><item.icon size={18} strokeWidth={1.5} /></span>
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          {APP_VERSION} · Web Demo
        </div>
        {/* 桌面端折叠按钮 */}
        <button
          className="sidebar-toggle"
          onClick={toggleCollapsed}
          aria-label={collapsed ? '展开侧边栏' : '收起侧边栏'}
          title={collapsed ? '展开' : '收起'}
        >
          <ChevronLeft size={14} strokeWidth={2} />
        </button>
      </aside>

      {/* 主内容区 */}
      <main className={`main-content ${collapsed ? 'collapsed' : ''}`}>
        {/* 顶部状态栏 */}
        <div className="topbar">
          <div className="topbar-left">
            {/* 移动端汉堡菜单按钮 */}
            <button
              className="topbar-toggle"
              onClick={toggleMobile}
              aria-label="切换菜单"
            >
              {mobileOpen ? <X size={18} strokeWidth={1.5} /> : <Menu size={18} strokeWidth={1.5} />}
            </button>
            <div className="topbar-title">{currentTitle}</div>
          </div>
          <div className="topbar-right">
            {/* 引擎在线状态 */}
            <span className={`topbar-status ${online === null ? '' : online ? 'online' : 'offline'}`}>
              <span className="dot" />
              {online === null ? '检测中' : online ? '引擎在线' : '引擎离线'}
            </span>
            {/* 当前模式 */}
            {mode && (
              <span className={`topbar-status ${modeClass}`}>
                <span className="dot" style={{ background: modeDotColor }} />
                {modeText}
              </span>
            )}
            {/* 版本号 */}
            <span className="topbar-version">{serverVersion}</span>
          </div>
        </div>

        {/* 路由出口 —— key 触发页面切换淡入 */}
        <div key={location.pathname} className="fade-in">
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/detect" element={<DetectPage />} />
            <Route path="/yinyang" element={<YinYangPage />} />
            <Route path="/simulation" element={<SimulationPage />} />
            <Route path="/learning" element={<LearningPage />} />
          </Routes>
        </div>
      </main>
    </div>
  );
}
