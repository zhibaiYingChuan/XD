import { useState, useEffect, useRef } from 'react';
import { api } from '../services/tauriApi';

interface WizardProps {
  onComplete: () => void;
}

export default function Wizard({ onComplete }: WizardProps) {
  const [step, setStep] = useState(0);
  const [mode, setMode] = useState('balanced');
  const onCompleteRef = useRef(onComplete);
  onCompleteRef.current = onComplete;

  useEffect(() => {
    const checkWizard = async () => {
      try {
        const completed = await api.getConfig('wizard_completed');
        if (completed === 'true') {
          onCompleteRef.current();
        }
      } catch {
        // ignore, show wizard
      }
    };
    checkWizard();
  }, []);

  const handleFinish = async () => {
    try {
      await api.setMode(mode);
      await api.setConfig('mode', mode);
      await api.setConfig('wizard_completed', 'true');
    } catch {
      // ignore
    }
    onCompleteRef.current();
  };

  const steps = [
    <div className="wizard-step" key="welcome">
      <div className="wizard-icon">🛡️</div>
      <h2>欢迎使用道体·玄盾</h2>
      <p>您的智能安全防护系统。接下来将引导您完成初始配置。</p>
      <button className="btn btn-primary btn-lg" onClick={() => setStep(1)}>
        开始配置
      </button>
    </div>,

    <div className="wizard-step" key="mode">
      <h2>选择防护模式</h2>
      <p>根据您的使用场景选择合适的防护策略</p>
      <div className="wizard-mode-cards">
        <div
          className={`mode-card ${mode === 'high_security' ? 'mode-card-active' : ''}`}
          onClick={() => setMode('high_security')}
        >
          <div className="mode-card-title">🔒 高安全</div>
          <div className="mode-card-desc">最严格的防护策略，适合对安全性要求极高的场景</div>
        </div>
        <div
          className={`mode-card ${mode === 'balanced' ? 'mode-card-active' : ''}`}
          onClick={() => setMode('balanced')}
        >
          <div className="mode-card-title">⚖️ 平衡</div>
          <div className="mode-card-desc">兼顾安全与可用性，推荐大多数用户使用</div>
        </div>
        <div
          className={`mode-card ${mode === 'low_false_positive' ? 'mode-card-active' : ''}`}
          onClick={() => setMode('low_false_positive')}
        >
          <div className="mode-card-title">🎯 低误报</div>
          <div className="mode-card-desc">减少误报率，适合对可用性要求高的场景</div>
        </div>
      </div>
      <div className="wizard-actions">
        <button className="btn btn-secondary" onClick={() => setStep(0)}>上一步</button>
        <button className="btn btn-primary" onClick={() => setStep(2)}>下一步</button>
      </div>
    </div>,

    <div className="wizard-step" key="done">
      <div className="wizard-icon">✨</div>
      <h2>配置完成</h2>
      <p>玄盾已准备就绪，开始守护您的安全。</p>
      <button className="btn btn-primary btn-lg" onClick={handleFinish}>
        进入玄盾
      </button>
    </div>,
  ];

  return (
    <div className="wizard-overlay">
      <div className="wizard-container">
        <div className="wizard-progress">
          {steps.map((_, i) => (
            <div
              key={i}
              className={`wizard-progress-dot ${i === step ? 'dot-active' : i < step ? 'dot-done' : ''}`}
            />
          ))}
        </div>
        {steps[step]}
      </div>
    </div>
  );
}
