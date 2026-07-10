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
import { api } from './services/tauriApi';
import './App.css';

function AppContent() {
  const [showWizard, setShowWizard] = useState(false);
  const [checking, setChecking] = useState(true);
  const prevLearningMode = useRef<string | null>(null);

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
