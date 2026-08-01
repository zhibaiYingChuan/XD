import { Zap, Brain, RefreshCw } from 'lucide-react';
import type { GateStats } from '../api';

/** 太极数据流图：可视化阳门->阴门->反馈闭环的双向数据流 */
interface Props {
  activeStep: number;
  outerStats?: GateStats;
  innerStats?: GateStats;
}

export default function TaijiFlowDiagram({ activeStep, outerStats, innerStats }: Props) {
  const attackActive = activeStep >= 1;
  const outerActive = activeStep >= 2;
  const forwardActive = activeStep === 3 || activeStep >= 6;
  const innerActive = activeStep >= 4;
  const feedbackActive = activeStep === 5 || activeStep >= 6;
  const allDone = activeStep >= 6;

  return (
    <div className="card" style={{ padding: '32px 24px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px', flexWrap: 'wrap', minHeight: '200px' }}>
        <Node label="攻击请求" icon="X" color="var(--danger)" active={attackActive} pulsing={activeStep === 1} sub={outerStats ? `共 ${outerStats.total} 条` : undefined} />
        <Arrow active={attackActive} />
        <Gate icon={<Zap size={24} strokeWidth={1.5} />} label="阳门" sublabel="快速拒绝" color="var(--primary)" active={outerActive} pulsing={activeStep === 2} stats={outerStats ? { '拒绝': outerStats.rejects, '转发': outerStats.forwards, '延迟': `${outerStats.avg_latency_ms}ms` } : undefined} />
        <Arrow active={forwardActive} color="var(--warning)" label="转发" />
        <Taiji spinning={allDone} />
        <Arrow active={feedbackActive} color="var(--success)" label="反馈" reverse />
        <Gate icon={<Brain size={24} strokeWidth={1.5} />} label="阴门" sublabel="精判学习" color="var(--teal)" active={innerActive} pulsing={activeStep === 4} stats={innerStats ? { '拒绝': innerStats.rejects, '学习': innerStats.learning_events || 0, '延迟': `${innerStats.avg_latency_ms}ms` } : undefined} />
        <Arrow active={innerActive} />
        <Node label="安全放行" icon="Y" color="var(--success)" active={allDone} />
      </div>
      {feedbackActive && (
        <div style={{ marginTop: '24px', padding: '12px 16px', background: 'rgba(0, 212, 170, 0.08)', borderRadius: 'var(--radius-lg)', border: '1px solid rgba(0, 212, 170, 0.2)', display: 'flex', alignItems: 'center', gap: '8px', animation: 'fadeIn 0.4s ease-out' }}>
          <RefreshCw size={14} strokeWidth={1.5} style={{ color: 'var(--teal)', animation: 'spin 2s linear infinite' }} />
          <span style={{ fontSize: '12px', color: 'var(--teal)' }}>反馈闭环已激活：阴门学习到的新模式正在更新阳门规则库</span>
        </div>
      )}
      <style>{`@keyframes flowDash { 0% { left: 0; opacity: 0; } 20% { opacity: 1; } 80% { opacity: 1; } 100% { left: calc(100% - 8px); opacity: 0; } }`}</style>
    </div>
  );
}

function Node({ label, icon, color, active, pulsing, sub }: { label: string; icon: string; color: string; active: boolean; pulsing?: boolean; sub?: string }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '4px', opacity: active ? 1 : 0.3, transition: 'opacity 0.4s ease' }}>
      <div style={{ width: '64px', height: '64px', borderRadius: '50%', background: active ? color : 'var(--bg-panel)', display: 'flex', alignItems: 'center', justifyContent: 'center', border: `2px solid ${active ? color : 'var(--border)'}`, boxShadow: pulsing ? `0 0 24px ${color}40` : 'none', transition: 'all 0.4s ease', fontSize: '22px', color: active ? '#fff' : 'var(--text-tertiary)' }}>{icon}</div>
      <span style={{ fontSize: '11px', color: active ? 'var(--text-primary)' : 'var(--text-tertiary)', fontWeight: 600 }}>{label}</span>
      {sub && <span style={{ fontSize: '10px', color: 'var(--text-tertiary)' }}>{sub}</span>}
    </div>
  );
}

function Gate({ icon, label, sublabel, color, active, pulsing, stats }: { icon: React.ReactNode; label: string; sublabel: string; color: string; active: boolean; pulsing: boolean; stats?: Record<string, number | string> }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '4px', opacity: active ? 1 : 0.3, transition: 'opacity 0.4s ease' }}>
      <div style={{ width: '64px', height: '64px', borderRadius: '50%', background: active ? color : 'var(--bg-panel)', display: 'flex', alignItems: 'center', justifyContent: 'center', border: `2px solid ${active ? color : 'var(--border)'}`, boxShadow: pulsing ? `0 0 24px ${color}40` : 'none', transition: 'all 0.4s ease', color: active ? '#fff' : 'var(--text-tertiary)' }}>{icon}</div>
      <span style={{ fontSize: '11px', color: active ? 'var(--text-primary)' : 'var(--text-tertiary)', fontWeight: 600 }}>{label}</span>
      <span style={{ fontSize: '10px', color: 'var(--text-tertiary)' }}>{sublabel}</span>
      {stats && active && (
        <div style={{ display: 'flex', gap: '6px', fontSize: '10px', color: 'var(--text-tertiary)' }}>
          {Object.entries(stats).map(([k, v]) => (<span key={k}>{k}: <strong style={{ color: 'var(--text-secondary)' }}>{v}</strong></span>))}
        </div>
      )}
    </div>
  );
}

function Arrow({ active, color = 'var(--primary)', label, reverse = false }: { active: boolean; color?: string; label?: string; reverse?: boolean }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '2px', opacity: active ? 1 : 0.2, transition: 'opacity 0.4s ease', minWidth: '48px' }}>
      {label && <span style={{ fontSize: '10px', color: active ? color : 'var(--text-tertiary)', fontWeight: 600 }}>{label}</span>}
      <div style={{ position: 'relative', width: '48px', height: '20px' }}>
        <div style={{ position: 'absolute', top: '50%', left: 0, right: 0, height: '2px', background: active ? color : 'var(--border)', transform: 'translateY(-50%)', transition: 'background 0.4s ease' }} />
        {active && <div style={{ position: 'absolute', top: '50%', width: '6px', height: '6px', borderRadius: '50%', background: color, boxShadow: `0 0 6px ${color}`, animation: `flowDash 1.5s linear infinite`, transform: 'translateY(-50%)', ...(reverse ? { animationDirection: 'reverse' } : {}) }} />}
        <div style={{ position: 'absolute', top: '50%', [reverse ? 'left' : 'right']: 0, transform: `translateY(-50%) rotate(${reverse ? 180 : 0}deg)`, width: 0, height: 0, borderLeft: `5px solid ${active ? color : 'var(--border)'}`, borderTop: '3px solid transparent', borderBottom: '3px solid transparent', transition: 'border-left-color 0.4s ease' }} />
      </div>
    </div>
  );
}

function Taiji({ spinning }: { spinning: boolean }) {
  return (
    <div style={{ width: '72px', height: '72px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <svg viewBox="0 0 100 100" width="72" height="72" style={{ animation: spinning ? 'spin 8s linear infinite' : 'none', opacity: spinning ? 1 : 0.5, transition: 'opacity 0.4s ease' }}>
        <defs><linearGradient id="taijiGrad" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stopColor="var(--primary)" /><stop offset="100%" stopColor="var(--teal)" /></linearGradient></defs>
        <path d="M50 0 A50 50 0 0 1 50 100 A25 25 0 0 0 50 50 A25 25 0 0 1 50 0" fill="var(--bg-card)" />
        <path d="M50 0 A50 50 0 0 0 50 100 A25 25 0 0 1 50 50 A25 25 0 0 0 50 0" fill="url(#taijiGrad)" />
        <circle cx="50" cy="25" r="6" fill="var(--bg-card)" />
        <circle cx="50" cy="75" r="6" fill="var(--primary)" />
      </svg>
    </div>
  );
}
