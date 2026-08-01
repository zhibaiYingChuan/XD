import { useState, useEffect, useRef } from 'react';
import { api, ShowcaseResult, BatchResult, DemoAttacks, DualLayerStats, LearningStatus } from '../api';
import { Play, RefreshCw, Target, Loader2, CheckCircle, XCircle, Activity } from 'lucide-react';
import TaijiFlowDiagram from '../components/TaijiFlowDiagram';
import CompareMode from '../components/CompareMode';
import LearningEvolution from '../components/LearningEvolution';

export default function YinYangPage() {
  const [showcase, setShowcase] = useState<ShowcaseResult | null>(null);
  const [batchResult, setBatchResult] = useState<BatchResult | null>(null);
  const [demoAttacks, setDemoAttacks] = useState<DemoAttacks | null>(null);
  const [stats, setStats] = useState<DualLayerStats | null>(null);
  const [learning, setLearning] = useState<LearningStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeStep, setActiveStep] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const timersRef = useRef<ReturnType<typeof setTimeout>[]>([]);
  const loadingRef = useRef(false);
  const abortRef = useRef<AbortController | null>(null);

  const clearAllTimers = () => {
    timersRef.current.forEach(t => clearTimeout(t));
    timersRef.current = [];
  };

  useEffect(() => {
    let cancelled = false;
    api.getDemoAttacks().then(data => { if (!cancelled) setDemoAttacks(data); }).catch(() => {});
    api.getStats().then(s => { if (!cancelled) { setStats(s.dual_layer); setLearning(s.learning); } }).catch(() => {});
    return () => {
      cancelled = true;
      clearAllTimers();
      abortRef.current?.abort();
    };
  }, []);

  // 真实API驱动演示：每步基于真实API响应推进
  const handleShowcase = async () => {
    if (loadingRef.current) return;
    loadingRef.current = true;
    setLoading(true);
    setError(null);
    setActiveStep(0);
    setBatchResult(null);
    try {
      // 步骤1：注入攻击
      setActiveStep(1);
      await new Promise(r => { const t = setTimeout(r, 400); timersRef.current.push(t); });

      // 步骤2：阳门拦截（调用真实API，阳门开始工作）
      setActiveStep(2);
      await new Promise(r => { const t = setTimeout(r, 400); timersRef.current.push(t); });

      // 步骤3：转发阴门（阳门放行的请求转发阴门）
      setActiveStep(3);
      await new Promise(r => { const t = setTimeout(r, 400); timersRef.current.push(t); });

      // 步骤4：阴门学习（阴门深度判定+学习）
      setActiveStep(4);
      // 真实API调用：运行完整演示，支持组件卸载时取消
      abortRef.current = new AbortController();
      const data = await api.showcase({ signal: abortRef.current.signal });
      setShowcase(data);
      setStats(data.dual_layer);
      setLearning(data.learning);

      // 步骤5：反馈闭环（阴门学习结果反馈阳门）
      setActiveStep(5);
      await new Promise(r => { const t = setTimeout(r, 600); timersRef.current.push(t); });

      // 步骤6：完成
      setActiveStep(6);
    } catch (e: any) {
      setError(e.message || '演示失败');
      setActiveStep(0);
      setShowcase(null);
    } finally {
      loadingRef.current = false;
      setLoading(false);
    }
  };

  // 批量演示某类攻击
  const handleBatch = async (attackType: string) => {
    if (loadingRef.current) return;
    loadingRef.current = true;
    setLoading(true);
    setError(null);
    setActiveStep(2);
    setShowcase(null);
    try {
      const data = await api.batchDemo(attackType);
      setBatchResult(data);
      setStats(data.dual_layer);
      setActiveStep(6);
    } catch (e: any) {
      setError(e.message || '批量测试失败');
      setActiveStep(0);
    } finally {
      loadingRef.current = false;
      setLoading(false);
    }
  };

  const outerStats = stats?.outer_gate;
  const innerStats = stats?.inner_gate;

  return (
    <div className="fade-in">
      <div style={{ marginBottom: '24px' }}>
        <h1 style={{ fontSize: '24px', fontWeight: 700, marginBottom: '8px' }}>阴阳门演示</h1>
        <p style={{ color: 'var(--text-secondary)' }}>一键体验双层阴阳架构的完整工作流程</p>
      </div>

      {/* SVG 数据流图 */}
      <TaijiFlowDiagram
        activeStep={activeStep}
        outerStats={outerStats}
        innerStats={innerStats}
      />

      {/* 演示控制 */}
      <div className="card" style={{ textAlign: 'center', padding: '24px' }}>
        {error && (
          <div style={{ padding: '8px 12px', background: 'rgba(229, 77, 77, 0.08)', borderRadius: 'var(--radius-md)', color: 'var(--danger)', fontSize: '12px', marginBottom: '12px' }}>
            {error}
          </div>
        )}
        <button className="btn btn-primary" onClick={handleShowcase} disabled={loading} style={{ fontSize: '14px', padding: '12px 32px' }}>
          {loading ? <Loader2 size={16} strokeWidth={1.5} className="taiji-spin" /> : <Play size={16} strokeWidth={1.5} />}
          {loading ? '演示中...' : '一键演示完整流程'}
        </button>
      </div>

      {/* 学习进化可视化（演示完成后显示） */}
      {activeStep >= 4 && learning && (
        <LearningEvolution
          learningEvents={innerStats?.learning_events || 0}
          attackPrototypes={learning.attack_prototypes}
          safePrototypes={learning.safe_prototypes}
          builtinAttacks={learning.builtin_attacks_loaded}
          active={activeStep >= 4}
        />
      )}

      {/* A/B 对比模式 */}
      <CompareMode />

      {/* 分类型攻击演示 */}
      {demoAttacks && (
        <div className="card">
          <div className="card-header">
            <div>
              <div className="card-title">分类型攻击演示</div>
              <div className="card-subtitle">选择攻击类型，批量测试拦截效果</div>
            </div>
            <Target size={18} strokeWidth={1.5} style={{ color: 'var(--text-tertiary)' }} />
          </div>
          <div className="grid grid-3">
            {demoAttacks.attack_types.map(at => (
              <button key={at.id} className="btn btn-secondary" onClick={() => handleBatch(at.id)} disabled={loading}
                style={{ flexDirection: 'column', padding: '16px', gap: '4px', alignItems: 'stretch' }}>
                <span style={{ fontWeight: 600, fontSize: '13px' }}>{at.label}</span>
                <span style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>{at.count} 个样本</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* 演示结果 */}
      {showcase && (
        <div className="fade-in">
          <div className="grid grid-2" style={{ marginBottom: '16px' }}>
            <div className="card" style={{ borderColor: 'var(--danger)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <XCircle size={24} strokeWidth={1.5} style={{ color: 'var(--danger)' }} />
                <div>
                  <div style={{ fontWeight: 600 }}>攻击样本拦截</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>共 {showcase.attacks.total} 个攻击样本</div>
                </div>
              </div>
              <div style={{ fontSize: '32px', fontWeight: 700, color: 'var(--danger)' }}>
                {(showcase.attacks.block_rate * 100).toFixed(1)}<span className="metric-unit">%</span>
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '4px' }}>
                拦截 {showcase.attacks.blocked} / {showcase.attacks.total}
              </div>
            </div>
            <div className="card" style={{ borderColor: 'var(--success)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <CheckCircle size={24} strokeWidth={1.5} style={{ color: 'var(--success)' }} />
                <div>
                  <div style={{ fontWeight: 600 }}>正常样本放行</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>共 {showcase.safe.total} 个正常样本</div>
                </div>
              </div>
              <div style={{ fontSize: '32px', fontWeight: 700, color: 'var(--success)' }}>
                {(showcase.safe.pass_rate * 100).toFixed(1)}<span className="metric-unit">%</span>
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '4px' }}>
                放行 {showcase.safe.passed} / {showcase.safe.total}
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <div className="card-title">攻击拦截详情</div>
              <span className="badge badge-danger">{showcase.attacks.blocked} 已拦截</span>
            </div>
            <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
              {showcase.attacks.results.map((r, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
                  {!r.allowed ? (
                    <XCircle size={14} strokeWidth={1.5} style={{ color: 'var(--danger)', flexShrink: 0 }} />
                  ) : (
                    <CheckCircle size={14} strokeWidth={1.5} style={{ color: 'var(--warning)', flexShrink: 0 }} />
                  )}
                  <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', flexShrink: 0, width: '80px' }}>{r.type}</span>
                  <span style={{ fontSize: '12px', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.text}</span>
                  {!r.allowed && <code style={{ fontSize: '10px', color: 'var(--danger)' }}>{r.reason}</code>}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 批量演示结果 */}
      {batchResult && !showcase && (
        <div className="card fade-in">
          <div className="card-header">
            <div className="card-title">{demoAttacks?.attack_types.find(a => a.id === batchResult.attack_type)?.label || batchResult.attack_type} 拦截结果</div>
            <span className="badge badge-danger">拦截率 {(batchResult.blocked / Math.max(1, batchResult.total) * 100).toFixed(1)}%</span>
          </div>
          <div className="grid grid-3" style={{ marginBottom: '16px' }}>
            <div className="metric-card">
              <div className="metric-label">总样本</div>
              <div className="metric-value">{batchResult.total}</div>
            </div>
            <div className="metric-card">
              <div className="metric-label">已拦截</div>
              <div className="metric-value danger">{batchResult.blocked}</div>
            </div>
            <div className="metric-card">
              <div className="metric-label">已放行</div>
              <div className="metric-value success">{batchResult.passed}</div>
            </div>
          </div>
          {batchResult.results.map((r, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              {!r.allowed ? (
                <XCircle size={14} strokeWidth={1.5} style={{ color: 'var(--danger)', flexShrink: 0 }} />
              ) : (
                <CheckCircle size={14} strokeWidth={1.5} style={{ color: 'var(--warning)', flexShrink: 0 }} />
              )}
              <span style={{ fontSize: '12px', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.text}</span>
              {!r.allowed && <code style={{ fontSize: '10px', color: 'var(--danger)' }}>{r.reason}</code>}
            </div>
          ))}
        </div>
      )}

      {/* 双层架构实时数据 */}
      {stats && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">双层架构实时数据</div>
            <Activity size={18} strokeWidth={1.5} style={{ color: 'var(--teal)' }} />
          </div>
          <div className="grid grid-2">
            <div style={{ padding: '16px', background: 'var(--bg-panel)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                <RefreshCw size={16} strokeWidth={1.5} style={{ color: 'var(--primary)' }} />
                <span style={{ fontWeight: 600 }}>阳门</span>
              </div>
              <div className="grid grid-2" style={{ gap: '8px', fontSize: '12px' }}>
                <div>总请求: <strong>{stats.outer_gate.total}</strong></div>
                <div>拒绝: <strong style={{ color: 'var(--danger)' }}>{stats.outer_gate.rejects}</strong></div>
                <div>转发: <strong style={{ color: 'var(--warning)' }}>{stats.outer_gate.forwards}</strong></div>
                <div>学习攻击: <strong>{stats.outer_gate.learned_attack_count || 0}</strong></div>
              </div>
            </div>
            <div style={{ padding: '16px', background: 'var(--bg-panel)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                <Activity size={16} strokeWidth={1.5} style={{ color: 'var(--teal)' }} />
                <span style={{ fontWeight: 600 }}>阴门</span>
              </div>
              <div className="grid grid-2" style={{ gap: '8px', fontSize: '12px' }}>
                <div>总请求: <strong>{stats.inner_gate.total}</strong></div>
                <div>拒绝: <strong style={{ color: 'var(--danger)' }}>{stats.inner_gate.rejects}</strong></div>
                <div>学习事件: <strong style={{ color: 'var(--teal)' }}>{stats.inner_gate.learning_events || 0}</strong></div>
                <div>平均延迟: <strong>{stats.inner_gate.avg_latency_ms}ms</strong></div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}