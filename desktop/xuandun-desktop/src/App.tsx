import { useState, useEffect, useCallback } from 'react';
import { HashRouter, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Detect from './pages/Detect';
import Agents from './pages/Agents';
import Logs from './pages/Logs';
import Settings from './pages/Settings';
import Wizard from './pages/Wizard';
import { api } from './services/tauriApi';
import './App.css';

function AppContent() {
  const [showWizard, setShowWizard] = useState(false);
  const [checking, setChecking] = useState(true);

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
          <Route path="/settings" element={<Settings />} />
        </Route>
      </Routes>
    </HashRouter>
  );
}

function App() {
  return <AppContent />;
}

export default App;
