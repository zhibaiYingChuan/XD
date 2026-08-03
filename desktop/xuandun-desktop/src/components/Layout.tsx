import { NavLink, Outlet, useLocation } from 'react-router-dom';
import StatusBar from './StatusBar';
import { useState, useEffect } from 'react';
import { getVersion } from '@tauri-apps/api/app';
import { open as openUrl } from '@tauri-apps/plugin-shell';
import {
  LayoutDashboard,
  ShieldCheck,
  FileText,
  Settings,
  HelpCircle,
} from 'lucide-react';

// K3-企业精简版：导航从9项→4项（按"用户任务"而非"代码模块"组织）
// 1. 实时监控 = 仪表盘 + 日志入口
// 2. 安全检测 = 检测页面
// 3. 系统设置 = 黑白名单、防御等级、逃生通道
// 其他页面（阴阳门、报表、模拟、学习、Agent）全部移除导航入口或降级为Settings卡片
const navItems = [
  { to: '/', icon: <LayoutDashboard size={18} strokeWidth={1.5} />, label: '实时监控' },
  { to: '/detect', icon: <ShieldCheck size={18} strokeWidth={1.5} />, label: '安全检测' },
  { to: '/logs', icon: <FileText size={18} strokeWidth={1.5} />, label: '拦截日志' },
  { to: '/settings', icon: <Settings size={18} strokeWidth={1.5} />, label: '系统设置' },
];

export default function Layout() {
  const [version, setVersion] = useState('');
  // P1-18 修复：帮助中心点击反馈状态
  const [helpToast, setHelpToast] = useState<string | null>(null);
  // Sprint7 微交互：页面切换动画，使用 location.pathname 作为 key 触发重新挂载
  const location = useLocation();
  useEffect(() => {
    getVersion()
      .then(v => setVersion(`v${v}`))
      .catch(() => setVersion('v1.0.0'));
  }, []);

  // PB-01 修复：帮助中心点击打开用户指南文档
  const handleHelpClick = (e: { preventDefault: () => void }) => {
    e.preventDefault();
    openUrl('https://github.com/zhibaiYingChuan/XD/blob/main/docs/%E7%94%A8%E6%88%B7%E6%8C%87%E5%8D%97.md').catch(() => {
      // Tauri bridge 不可用时降级为 toast 提示
      setHelpToast('无法打开浏览器，请手动访问：github.com/zhibaiYingChuan/XD/blob/main/docs/用户指南.md');
      setTimeout(() => setHelpToast(null), 5000);
    });
  };

  return (
    <div className="app-layout">
      <aside
        className="sidebar"
        style={{
          width: 'var(--dt-sidebar-width)',
          backgroundColor: 'var(--dt-bg-panel)',
          borderRight: '1px solid var(--dt-border)',
        }}
      >
        <div className="sidebar-logo">
          <img src="/logo.jpg" alt="道体·玄盾 Logo" className="sidebar-logo-img" />
          <div className="sidebar-title-group">
            <span className="sidebar-title">道体·玄盾</span>
            <span className="sidebar-subtitle">模型防火墙控制台</span>
          </div>
        </div>
        <nav className="sidebar-nav">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                `nav-item ${isActive ? 'nav-item-active' : ''}`
              }
            >
              <span className="nav-icon">{item.icon}</span>
              <span className="nav-label">{item.label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          <a href="#" className="nav-item" onClick={handleHelpClick}>
            <span className="nav-icon">
              <HelpCircle size={18} strokeWidth={1.5} />
            </span>
            <span className="nav-label">帮助中心</span>
          </a>
          {version && <div className="sidebar-version">{version}</div>}
        </div>
      </aside>
      <main className="main-content">
        <StatusBar />
        {/* Sprint7 微交互：页面切换淡入动画 */}
        <div key={location.pathname} className="page-fade-in">
          <Outlet />
        </div>
      </main>
      {/* P1-18 修复：帮助中心点击 toast 提示，告知用户文档状态 */}
      {helpToast && (
        <div className="help-toast" style={{
          position: 'fixed', bottom: '16px', left: '50%', transform: 'translateX(-50%)',
          padding: '8px 16px', background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: '6px', boxShadow: '0 2px 8px rgba(0,0,0,0.15)', zIndex: 1000,
          fontSize: '0.9em', color: 'var(--text-primary)',
        }}>
          {helpToast}
        </div>
      )}
    </div>
  );
}
