import { NavLink, Outlet } from 'react-router-dom';

const navItems = [
  { to: '/', icon: '📊', label: '仪表盘' },
  { to: '/detect', icon: '🔍', label: '安全检测' },
  { to: '/agents', icon: '🤖', label: 'Agent' },
  { to: '/logs', icon: '📋', label: '日志' },
  { to: '/settings', icon: '⚙️', label: '设置' },
];

export default function Layout() {
  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <span className="shield-icon">🛡️</span>
          <span className="sidebar-title">玄盾</span>
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
          <span className="sidebar-version">v1.0.0</span>
        </div>
      </aside>
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}
