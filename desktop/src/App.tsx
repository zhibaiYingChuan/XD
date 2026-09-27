/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   应用入口 — 路由 + 首次启动向导分流。
*/

import { useCallback, useEffect, useState } from 'react';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import ErrorBoundary from './components/ErrorBoundary';
import { ToastProvider } from './components/Toast';
import Onboarding from './pages/Onboarding';
import Dashboard from './pages/Dashboard';
import Logs from './pages/Logs';
import Settings from './pages/Settings';
import Help from './pages/Help';
import Activate from './pages/Activate';
import { api } from './services/api';
import type { PersonalConfig } from './services/api';

// ══════════════════════════════════════════════════════════════
// 首次启动判定
// ══════════════════════════════════════════════════════════════

const ONBOARDING_KEY = 'xuandun-personal-onboarded';

function AppRoutes() {
  const [checking, setChecking] = useState(true);
  const [needOnboarding, setNeedOnboarding] = useState(false);

  const checkFirstRun = useCallback(async () => {
    // 已完成过向导 → 直接进主界面
    if (localStorage.getItem(ONBOARDING_KEY) === 'done') {
      setNeedOnboarding(false);
      setChecking(false);
      return;
    }
    // 未完成过向导：检查是否已配置中转站（配置完整则跳过向导）
    try {
      const cfg = (await api.getConfig()) as PersonalConfig;
      const configured = Boolean(cfg.relay?.base_url && cfg.relay?.api_key);
      setNeedOnboarding(!configured);
    } catch {
      // 代理未就绪 → 仍走向导（向导内含配置引导）
      setNeedOnboarding(true);
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    checkFirstRun();
  }, [checkFirstRun]);

  const finishOnboarding = useCallback(() => {
    localStorage.setItem(ONBOARDING_KEY, 'done');
    setNeedOnboarding(false);
  }, []);

  if (checking) {
    return (
      <div className="loading" style={{ height: '100vh' }}>
        <span className="spinner" />
        正在启动...
      </div>
    );
  }

  if (needOnboarding) {
    return <Onboarding onFinish={finishOnboarding} />;
  }

  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="logs" element={<Logs />} />
        <Route path="settings" element={<Settings />} />
        <Route path="activate" element={<Activate />} />
        <Route path="help" element={<Help />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <ToastProvider>
        <HashRouter>
          <AppRoutes />
        </HashRouter>
      </ToastProvider>
    </ErrorBoundary>
  );
}
