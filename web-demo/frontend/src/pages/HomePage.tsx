import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api, DualLayerStats, LearningStatus } from '../api';
import { Shield, Zap, Brain, Activity, ArrowRight, Play, CheckCircle, XCircle } from 'lucide-react';

export default function HomePage() {
  const [stats, setStats] = useState<DualLayerStats | null>(null);
  const [learning, setLearning] = useState<LearningStatus | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getStats().then(data => {
      setStats(data.dual_layer);
      setLearning(data.learning);
      setLoading(false);
    }).catch(() => setLoading(false));
    const interval = setInterval(() => {
      api.getStats().then(data => {
        setStats(data.dual_layer);
        setLearning(data.learning);
      }).catch(() => {});
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  const outer = stats?.outer_gate;
  const inner = stats?.inner_gate;

  return (
    <div className="fade-in">
      {/* 英雄区 */}
      <div className="hero">
        <div className="hero-taiji taiji-spin">
          <svg viewBox="0 0 100 100" width="100%" height="100%">
            <defs>
              <linearGradient id="heroGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#2B5FD7" />
                <stop offset="100%" stopColor="#00D4AA" />
              </linearGradient>
            </defs>
            <circle cx="50" cy="50" r="48" fill="none" stroke="url(#heroGrad)" strokeWidth="2" />
            <path d="M50 2 A48 48 0 0 1 50 98 A24 24 0 0 0 50 50 A24 24 0 0 1 50 2" fill="url(#heroGrad)" opacity="0.9" />
            <path d="M50 2 A48 48 0 0 0 50 98 A24 24 0 0 1 50 50 A24 24 0 0 0 50 2" fill="#0B0E14" opacity="0.9" />
            <circle cx="50" cy="26" r="6" fill="#0B0E14" />
            <circle cx="50" cy="74" r="6" fill="#00D4AA" />
          </svg>
        </div>
        <h1 className="hero-title">道体·玄盾</h1>
        <p className="hero-subtitle">
          活性防护 LLM 防火墙 — 基于拒绝门理论 + 洛书映射器 + 动态阴阳壳架构，
          为 AI 应用提供数据驱动的动态安全防护
        </p>
        <div style={{ display: 'flex', gap: '12px', justifyContent: 'center', flexWrap: 'wrap' }}>
          <Link to="/yinyang" className="btn btn-primary">
            <Play size={16} strokeWidth={1.5} /> 一键演示双层架构
          </Link>
          <Link to="/detect" className="btn btn-secondary">
            <Shield size={16} strokeWidth={1.5} /> 立即体验检测
          </Link>
        </div>
      </div>

      {/* 核心数据 */}
      <div className="grid grid-4" style={{ marginBottom: '24px' }}>
        <div className="metric-card">
          <div className="metric-label">总请求数</div>
          <div className="metric-value">{outer ? outer.total.toLocaleString() : '—'}</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">拦截数</div>
          <div className="metric-value danger">{outer ? outer.rejects.toLocaleString() : '—'}</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">阳门拦截率</div>
          <div className="metric-value warning">
            {outer ? (outer.reject_rate * 100).toFixed(1) : '—'}<span className="metric-unit">%</span>
          </div>
        </div>
        <div className="metric-card">
          <div className="metric-label">学习进度</div>
          <div className="metric-value success">
            {learning ? (learning.learning_progress * 100).toFixed(1) : '—'}<span className="metric-unit">%</span>
          </div>
        </div>
      </div>

      {/* 核心特性 */}
      <div className="grid grid-3" style={{ marginBottom: '24px' }}>
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
            <div style={{ width: '40px', height: '40px', borderRadius: '8px', background: 'rgba(43, 95, 215, 0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Zap size={20} strokeWidth={1.5} style={{ color: 'var(--primary)' }} />
            </div>
            <h3 style={{ fontSize: '15px', fontWeight: 600 }}>阳门 · 快速拒绝</h3>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            毫秒级响应，基于规则和已学习模式快速筛选已知攻击。外显于表，动而生阳，以快制快。
          </p>
        </div>
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
            <div style={{ width: '40px', height: '40px', borderRadius: '8px', background: 'rgba(0, 212, 170, 0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Brain size={20} strokeWidth={1.5} style={{ color: 'var(--teal)' }} />
            </div>
            <h3 style={{ fontSize: '15px', fontWeight: 600 }}>阴门 · 精判学习</h3>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            基于AI原型的深度判定，精确识别未知攻击，持续学习进化。内敛于里，静而生阴，以精取胜。
          </p>
        </div>
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
            <div style={{ width: '40px', height: '40px', borderRadius: '8px', background: 'var(--gradient-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Activity size={20} strokeWidth={1.5} style={{ color: '#fff' }} />
            </div>
            <h3 style={{ fontSize: '15px', fontWeight: 600 }}>阴阳闭环</h3>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            阳门拦截数据喂给阴门学习，阴门发现新模式更新阳门规则，形成正循环。阴阳相济，防御日臻完善。
          </p>
        </div>
      </div>

      {/* 核心技术亮点 */}
      <div className="card" style={{ marginBottom: '24px', background: 'var(--bg-panel)' }}>
        <div className="card-header">
          <div>
            <div className="card-title">核心技术亮点</div>
            <div className="card-subtitle">三大原创技术构筑护城河</div>
          </div>
        </div>
        <div className="grid grid-3">
          <div style={{ padding: '20px', background: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border)', transition: 'transform 0.2s ease, box-shadow 0.2s ease', cursor: 'default' }}
            onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-4px)'; e.currentTarget.style.boxShadow = 'var(--shadow-lg)'; }}
            onMouseLeave={e => { e.currentTarget.style.transform = ''; e.currentTarget.style.boxShadow = ''; }}>
            <div style={{ width: '48px', height: '48px', borderRadius: 'var(--radius-lg)', background: 'rgba(43, 95, 215, 0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '12px' }}>
              <Shield size={24} strokeWidth={1.5} style={{ color: 'var(--primary)' }} />
            </div>
            <h3 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '8px' }}>拒绝门理论</h3>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '8px' }}>
              基于信任等级的动态拒绝决策模型，将输入分为拒绝/转发/放行三级，实现毫秒级安全筛选。
            </p>
            <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '10px', padding: '2px 8px', background: 'rgba(43, 95, 215, 0.08)', borderRadius: 'var(--radius-full)', color: 'var(--primary)' }}>信任等级</span>
              <span style={{ fontSize: '10px', padding: '2px 8px', background: 'rgba(43, 95, 215, 0.08)', borderRadius: 'var(--radius-full)', color: 'var(--primary)' }}>动态阈值</span>
              <span style={{ fontSize: '10px', padding: '2px 8px', background: 'rgba(43, 95, 215, 0.08)', borderRadius: 'var(--radius-full)', color: 'var(--primary)' }}>毫秒响应</span>
            </div>
          </div>
          <div style={{ padding: '20px', background: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border)', transition: 'transform 0.2s ease, box-shadow 0.2s ease', cursor: 'default' }}
            onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-4px)'; e.currentTarget.style.boxShadow = 'var(--shadow-lg)'; }}
            onMouseLeave={e => { e.currentTarget.style.transform = ''; e.currentTarget.style.boxShadow = ''; }}>
            <div style={{ width: '48px', height: '48px', borderRadius: 'var(--radius-lg)', background: 'rgba(0, 212, 170, 0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '12px' }}>
              <Activity size={24} strokeWidth={1.5} style={{ color: 'var(--teal)' }} />
            </div>
            <h3 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '8px' }}>洛书映射器</h3>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '8px' }}>
              融合古代洛书数理与现代向量空间映射，将文本语义转换为多维特征向量，捕捉隐蔽攻击意图。
            </p>
            <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '10px', padding: '2px 8px', background: 'rgba(0, 212, 170, 0.08)', borderRadius: 'var(--radius-full)', color: 'var(--teal)' }}>向量映射</span>
              <span style={{ fontSize: '10px', padding: '2px 8px', background: 'rgba(0, 212, 170, 0.08)', borderRadius: 'var(--radius-full)', color: 'var(--teal)' }}>语义分析</span>
              <span style={{ fontSize: '10px', padding: '2px 8px', background: 'rgba(0, 212, 170, 0.08)', borderRadius: 'var(--radius-full)', color: 'var(--teal)' }}>多维特征</span>
            </div>
          </div>
          <div style={{ padding: '20px', background: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border)', transition: 'transform 0.2s ease, box-shadow 0.2s ease', cursor: 'default' }}
            onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-4px)'; e.currentTarget.style.boxShadow = 'var(--shadow-lg)'; }}
            onMouseLeave={e => { e.currentTarget.style.transform = ''; e.currentTarget.style.boxShadow = ''; }}>
            <div style={{ width: '48px', height: '48px', borderRadius: 'var(--radius-lg)', background: 'var(--gradient-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '12px' }}>
              <Brain size={24} strokeWidth={1.5} style={{ color: '#fff' }} />
            </div>
            <h3 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '8px' }}>动态阴阳壳架构</h3>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '8px' }}>
              双层防护壳：阳门快速拦截已知攻击，阴门深度学习未知威胁，阴阳互根形成自适应防御闭环。
            </p>
            <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '10px', padding: '2px 8px', background: 'rgba(245, 166, 35, 0.08)', borderRadius: 'var(--radius-full)', color: 'var(--warning)' }}>双层架构</span>
              <span style={{ fontSize: '10px', padding: '2px 8px', background: 'rgba(245, 166, 35, 0.08)', borderRadius: 'var(--radius-full)', color: 'var(--warning)' }}>在线学习</span>
              <span style={{ fontSize: '10px', padding: '2px 8px', background: 'rgba(245, 166, 35, 0.08)', borderRadius: 'var(--radius-full)', color: 'var(--warning)' }}>反馈闭环</span>
            </div>
          </div>
        </div>
      </div>

      {/* 双层架构实时状态 */}
      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">双层架构实时状态</div>
            <div className="card-subtitle">阳门与阴门协同工作数据</div>
          </div>
          {stats?.enabled && <span className="badge badge-success">● 运行中</span>}
        </div>
        {loading ? (
          <div className="grid grid-2">
            <div style={{ padding: '16px', background: 'var(--bg-panel)', borderRadius: '8px', border: '1px solid var(--border)' }}>
              <div className="skeleton" style={{ height: '20px', width: '60%', marginBottom: '12px' }}></div>
              <div className="grid grid-2" style={{ gap: '8px' }}>
                <div className="skeleton" style={{ height: '40px' }}></div>
                <div className="skeleton" style={{ height: '40px' }}></div>
                <div className="skeleton" style={{ height: '40px' }}></div>
                <div className="skeleton" style={{ height: '40px' }}></div>
              </div>
            </div>
            <div style={{ padding: '16px', background: 'var(--bg-panel)', borderRadius: '8px', border: '1px solid var(--border)' }}>
              <div className="skeleton" style={{ height: '20px', width: '60%', marginBottom: '12px' }}></div>
              <div className="grid grid-2" style={{ gap: '8px' }}>
                <div className="skeleton" style={{ height: '40px' }}></div>
                <div className="skeleton" style={{ height: '40px' }}></div>
                <div className="skeleton" style={{ height: '40px' }}></div>
                <div className="skeleton" style={{ height: '40px' }}></div>
              </div>
            </div>
          </div>
        ) : outer && inner ? (
          <div className="grid grid-2">
            {/* 阳门 */}
            <div style={{ padding: '16px', background: 'var(--bg-panel)', borderRadius: '8px', border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                <Zap size={16} strokeWidth={1.5} style={{ color: 'var(--primary)' }} />
                <span style={{ fontWeight: 600, fontSize: '14px' }}>阳门（外门）</span>
              </div>
              <div className="grid grid-2" style={{ gap: '8px' }}>
                <div><span style={{ color: 'var(--text-tertiary)', fontSize: '11px' }}>总请求</span><br /><strong>{outer.total}</strong></div>
                <div><span style={{ color: 'var(--text-tertiary)', fontSize: '11px' }}>拒绝</span><br /><strong style={{ color: 'var(--danger)' }}>{outer.rejects}</strong></div>
                <div><span style={{ color: 'var(--text-tertiary)', fontSize: '11px' }}>转发阴门</span><br /><strong style={{ color: 'var(--warning)' }}>{outer.forwards}</strong></div>
                <div><span style={{ color: 'var(--text-tertiary)', fontSize: '11px' }}>平均延迟</span><br /><strong>{outer.avg_latency_ms}ms</strong></div>
              </div>
            </div>
            {/* 阴门 */}
            <div style={{ padding: '16px', background: 'var(--bg-panel)', borderRadius: '8px', border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                <Brain size={16} strokeWidth={1.5} style={{ color: 'var(--teal)' }} />
                <span style={{ fontWeight: 600, fontSize: '14px' }}>阴门（内门）</span>
              </div>
              <div className="grid grid-2" style={{ gap: '8px' }}>
                <div><span style={{ color: 'var(--text-tertiary)', fontSize: '11px' }}>总请求</span><br /><strong>{inner.total}</strong></div>
                <div><span style={{ color: 'var(--text-tertiary)', fontSize: '11px' }}>拒绝</span><br /><strong style={{ color: 'var(--danger)' }}>{inner.rejects}</strong></div>
                <div><span style={{ color: 'var(--text-tertiary)', fontSize: '11px' }}>学习事件</span><br /><strong style={{ color: 'var(--teal)' }}>{inner.learning_events}</strong></div>
                <div><span style={{ color: 'var(--text-tertiary)', fontSize: '11px' }}>平均延迟</span><br /><strong>{inner.avg_latency_ms}ms</strong></div>
              </div>
            </div>
          </div>
        ) : (
          <div className="empty-state">暂无数据</div>
        )}
      </div>

      {/* CTA */}
      <div className="card" style={{ textAlign: 'center', background: 'var(--gradient-yin-yang)', marginTop: '24px' }}>
        <h2 style={{ fontSize: '20px', fontWeight: 700, marginBottom: '8px' }}>体验双层阴阳架构</h2>
        <p style={{ color: 'var(--text-secondary)', marginBottom: '16px' }}>
          一键注入攻击样本，观察阳门快速拦截 → 阴门深度判定 → 反馈闭环的完整过程
        </p>
        <Link to="/yinyang" className="btn btn-primary">
          <Play size={16} strokeWidth={1.5} /> 开始演示 <ArrowRight size={14} strokeWidth={1.5} />
        </Link>
      </div>
    </div>
  );
}