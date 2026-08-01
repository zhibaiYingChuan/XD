import { useState, useEffect, useCallback, useRef } from 'react';
import { HashRouter, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import ErrorBoundary from './components/ErrorBoundary';
import Dashboard from './pages/Dashboard';
import Detect from './pages/Detect';
import Agents from './pages/Agents';
import Logs from './pages/Logs';
import Settings from './pages/Settings';
import LearningStatusPage from './pages/LearningStatus';
import Simulation from './pages/Simulation';
import Reports from './pages/Reports';
import Wizard from './pages/Wizard';
import YinYangGate from './pages/YinYangGate';
import { api } from './services/tauriApi';
import './App.css';

function AppContent() {
  const [showWizard, setShowWizard] = useState(false);
  const [checking, setChecking] = useState(true);
  const prevLearningMode = useRef<string | null>(null);

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

  const checkWizard = useCallback(async () => {
    try {
      const completed = await api.getConfig('wizard_completed');
      if (completed !== 'true') {
        setShowWizard(true);
      }
    } catch {
      // ignore
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    checkWizard();
  }, [checkWizard]);

  useEffect(() => {
    if (showWizard || checking) return;

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
        // ignore
      }
    };

    checkModeSwitch();
    const interval = setInterval(checkModeSwitch, 5000);
    return () => clearInterval(interval);
  }, [showWizard, checking]);

  const handleWizardComplete = () => {
    setShowWizard(false);
  };

  if (checking) {
    return (
      <div className="loading-screen">
        <div className="loading-spinner"></div>
        <div className="loading-text">加载中...</div>
      </div>
    );
  }

  if (showWizard) {
    return <Wizard onComplete={handleWizardComplete} />;
  }

  return (
    <HashRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/detect" element={<Detect />} />
          <Route path="/agents" element={<Agents />} />
          <Route path="/logs" element={<Logs />} />
          <Route path="/learning" element={<LearningStatusPage />} />
          <Route path="/simulation" element={<Simulation />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/yinyang" element={<YinYangGate />} />
          <Route path="/settings" element={<Settings />} />
        </Route>
      </Routes>
    </HashRouter>
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
