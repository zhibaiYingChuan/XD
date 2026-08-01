import { useState, useEffect, useRef } from 'react';
import { api } from '../services/tauriApi';
import { Shield, Lock, Scale, Target, Sparkles } from 'lucide-react';

interface WizardProps {
  onComplete: () => void;
}

export default function Wizard({ onComplete }: WizardProps) {
  const [step, setStep] = useState(0);
  const [mode, setMode] = useState('balanced');
  // P1-17 修复：提交时 loading 状态，防止用户重复点击
  const [finishing, setFinishing] = useState(false);
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
    // P1-17 修复：防并发守卫，避免重复点击触发多次配置写入
    if (finishing) return;
    setFinishing(true);
    try {
      await api.setMode(mode);
      await api.setConfig('mode', mode);
      await api.setConfig('wizard_completed', 'true');
    } catch {
      // ignore — 即使配置失败也允许进入应用，避免用户卡死在向导
    } finally {
      setFinishing(false);
    }
    onCompleteRef.current();
  };

  const steps = [
    <div className="wizard-step" key="welcome">
      <div className="wizard-icon"><Shield size={32} strokeWidth={1.5} /></div>
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
          <div className="mode-card-title"><Lock size={18} strokeWidth={1.5} /> 高安全</div>
          <div className="mode-card-desc">最严格的防护策略，适合对安全性要求极高的场景</div>
        </div>
        <div
          className={`mode-card ${mode === 'balanced' ? 'mode-card-active' : ''}`}
          onClick={() => setMode('balanced')}
        >
          <div className="mode-card-title"><Scale size={18} strokeWidth={1.5} /> 平衡</div>
          <div className="mode-card-desc">兼顾安全与可用性，推荐大多数用户使用</div>
        </div>
        <div
          className={`mode-card ${mode === 'low_false_positive' ? 'mode-card-active' : ''}`}
          onClick={() => setMode('low_false_positive')}
        >
          <div className="mode-card-title"><Target size={18} strokeWidth={1.5} /> 低误报</div>
          <div className="mode-card-desc">减少误报率，适合对可用性要求高的场景</div>
        </div>
      </div>
      <div className="wizard-actions">
        <button className="btn btn-secondary" onClick={() => setStep(0)}>上一步</button>
        <button className="btn btn-primary" onClick={() => setStep(2)}>下一步</button>
      </div>
    </div>,

    <div className="wizard-step" key="done">
      <div className="wizard-icon"><Sparkles size={32} strokeWidth={1.5} /></div>
      <h2>配置完成</h2>
      <p>玄盾已准备就绪，开始守护您的安全。</p>
      <button className="btn btn-primary btn-lg" onClick={handleFinish} disabled={finishing}>
        {finishing ? '配置中...' : '进入玄盾'}
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
