import { NavLink, Outlet, useLocation } from 'react-router-dom';
import StatusBar from './StatusBar';
import { useState, useEffect } from 'react';
import { getVersion } from '@tauri-apps/api/app';
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
  // Sprint7 微交互：页面切换动画，使用 location.pathname 作为 key 触发重新挂载
  const location = useLocation();
  useEffect(() => {
    getVersion()
      .then(v => setVersion(`v${v}`))
      .catch(() => setVersion('v1.0.0'));
  }, []);

  // PB-01 修复：帮助中心改为内置用户手册页面（/help），不再跳转外部仓库文档

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
          <img src={import.meta.env.BASE_URL + 'logo.jpg'} alt="道体·玄盾 Logo" className="sidebar-logo-img" />
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
          <NavLink to="/help" className="nav-item">
            <span className="nav-icon">
              <HelpCircle size={18} strokeWidth={1.5} />
            </span>
            <span className="nav-label">帮助中心</span>
          </NavLink>
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
    </div>
  );
}
