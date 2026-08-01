import { useState, useEffect, useCallback } from 'react';
import { api, ShowcaseResult, DemoAttacks, BatchResult } from '../api';
import {
  FlaskConical, Play, CheckCircle, XCircle, Loader2,
  Swords, ShieldCheck, ChevronRight, Zap, AlertTriangle,
} from 'lucide-react';
import {
  PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts';

// 聚合的批量测试结果
interface BatchAgg {
  byType: { type: string; total: number; blocked: number; blockRate: number }[];
  allResults: { text: string; allowed: boolean; reason: string; type: string; isAttack: boolean }[];
  totalAttacks: number;
  totalBlocked: number;
  safeTotal: number;
  safePassed: number;
}

// 攻击类型图标映射（根据类型名匹配）
function getAttackIcon(_type: string) {
  // 统一用 Swords 图标，避免类型不匹配
  return Swords;
}

export default function SimulationPage() {
  const [demoData, setDemoData] = useState<DemoAttacks | null>(null);
  const [selectedTypes, setSelectedTypes] = useState<Set<string>>(new Set());
  const [showcase, setShowcase] = useState<ShowcaseResult | null>(null);
  const [batchAgg, setBatchAgg] = useState<BatchAgg | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // 批量测试进度
  const [progress, setProgress] = useState<{ current: number; total: number } | null>(null);
  // 展开的详情行索引
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  // 加载攻击类型清单
  useEffect(() => {
    api.getDemoAttacks().then(data => {
      setDemoData(data);
      // 默认全选
      setSelectedTypes(new Set(data.attack_types.map(a => a.id)));
    }).catch(() => {
      // 静默处理，仍可使用一键完整测试
    });
  }, []);

  // 切换攻击类型选中
  const toggleType = (id: string) => {
    setSelectedTypes(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // 一键完整测试（保留原有 API 调用逻辑）
  const runShowcase = useCallback(async () => {
    setLoading(true);
    setError(null);
    setProgress(null);
    setBatchAgg(null);
    try {
      const data = await api.showcase();
      setShowcase(data);
    } catch (e: any) {
      setError(e.message || '测试失败，请检查引擎是否在线');
      setShowcase(null);
    } finally {
      setLoading(false);
    }
  }, []);

  // 按选中类型批量测试
  const runBatch = useCallback(async () => {
    if (selectedTypes.size === 0 || !demoData) return;
    setLoading(true);
    setError(null);
    setShowcase(null);
    setBatchAgg(null);
    const types = Array.from(selectedTypes);
    setProgress({ current: 0, total: types.length });
    const byType: BatchAgg['byType'] = [];
    const allResults: BatchAgg['allResults'] = [];
    let totalAttacks = 0;
    let totalBlocked = 0;
    try {
      for (let i = 0; i < types.length; i++) {
        const typeId = types[i];
        const res: BatchResult = await api.batchDemo(typeId);
        byType.push({
          type: res.attack_type,
          total: res.total,
          blocked: res.blocked,
          blockRate: res.total > 0 ? res.blocked / res.total : 0,
        });
        res.results.forEach(r => {
          allResults.push({ ...r, type: res.attack_type, isAttack: true });
        });
        totalAttacks += res.total;
        totalBlocked += res.blocked;
        setProgress({ current: i + 1, total: types.length });
      }
      // 安全样本测试
      let safeTotal = 0;
      let safePassed = 0;
      try {
        const safeRes = await api.safeDemo();
        safeTotal = safeRes.total;
        safePassed = safeRes.passed;
        safeRes.results.forEach((r: any) => {
          allResults.push({ text: r.text, allowed: r.allowed, reason: r.reason, type: '安全样本', isAttack: false });
        });
      } catch {
        // 安全样本失败不阻断
      }
      setBatchAgg({ byType, allResults, totalAttacks, totalBlocked, safeTotal, safePassed });
    } catch (e: any) {
      setError(e.message || '批量测试失败');
    } finally {
      setLoading(false);
      setProgress(null);
    }
  }, [selectedTypes, demoData]);

  // 切换详情展开
  const toggleExpand = (idx: number) => {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  // 统一结果数据来源
  const hasResult = !!(showcase || batchAgg);
  const attacksBlocked = showcase ? showcase.attacks.blocked : batchAgg?.totalBlocked ?? 0;
  const attacksTotal = showcase ? showcase.attacks.total : batchAgg?.totalAttacks ?? 0;
  const blockRate = showcase ? showcase.attacks.block_rate : (batchAgg && batchAgg.totalAttacks > 0 ? batchAgg.totalBlocked / batchAgg.totalAttacks : 0);
  const safePassed = showcase ? showcase.safe.passed : batchAgg?.safePassed ?? 0;
  const safeTotal = showcase ? showcase.safe.total : batchAgg?.safeTotal ?? 0;
  const passRate = showcase ? showcase.safe.pass_rate : (batchAgg && batchAgg.safeTotal > 0 ? batchAgg.safePassed / batchAgg.safeTotal : 0);

  // 饼图数据
  const pieData = [
    { name: '攻击已拦截', value: attacksBlocked, color: '#00D4AA' },
    { name: '攻击漏拦截', value: Math.max(attacksTotal - attacksBlocked, 0), color: '#F5A623' },
    { name: '正常放行', value: safePassed, color: '#2B5FD7' },
    { name: '正常误拦截', value: Math.max(safeTotal - safePassed, 0), color: '#E54D4D' },
  ].filter(d => d.value > 0);

  // 柱状图数据（按攻击类型）
  const barData = batchAgg
    ? batchAgg.byType.map(t => ({ name: t.type, 拦截率: +(t.blockRate * 100).toFixed(1), 拦截数: t.blocked, 总数: t.total }))
    : [];

  // 详情列表
  const detailResults = showcase
    ? [
        ...showcase.attacks.results.map(r => ({ ...r, isAttack: true })),
        ...showcase.safe.results.map(r => ({ ...r, isAttack: false })),
      ]
    : batchAgg
      ? batchAgg.allResults
      : [];

  return (
    <div className="fade-in">
      {/* 页面标题 */}
      <div style={{ marginBottom: '24px' }}>
        <h1 style={{ fontSize: '24px', fontWeight: 700, marginBottom: '8px' }}>模拟测试</h1>
        <p style={{ color: 'var(--text-secondary)' }}>运行完整攻击+安全样本对比测试，查看拦截率报告</p>
      </div>

      {/* 攻击类型卡片选择器 */}
      {demoData && (
        <div className="card stagger-item" style={{ marginBottom: '16px' }}>
          <div className="flex-between" style={{ marginBottom: '12px' }}>
            <div>
              <div className="card-title">攻击类型选择</div>
              <div className="card-subtitle">支持多选 · 已选 {selectedTypes.size} / {demoData.attack_types.length} 类</div>
            </div>
            <div className="flex gap-8">
              <button
                className="btn btn-secondary"
                style={{ fontSize: '12px', padding: '6px 12px' }}
                onClick={() => setSelectedTypes(new Set(demoData.attack_types.map(a => a.id)))}
              >
                全选
              </button>
              <button
                className="btn btn-secondary"
                style={{ fontSize: '12px', padding: '6px 12px' }}
                onClick={() => setSelectedTypes(new Set())}
              >
                清空
              </button>
            </div>
          </div>
          <div className="attack-grid">
            {demoData.attack_types.map(a => {
              const Icon = getAttackIcon(a.id);
              const selected = selectedTypes.has(a.id);
              return (
                <div
                  key={a.id}
                  className={`attack-card ${selected ? 'selected' : ''}`}
                  onClick={() => toggleType(a.id)}
                >
                  <div className="attack-card-header">
                    <div className="attack-card-icon"><Icon size={18} strokeWidth={1.5} /></div>
                    <div className="attack-card-check">
                      {selected && <CheckCircle size={12} strokeWidth={3} />}
                    </div>
                  </div>
                  <div className="attack-card-name">{a.label}</div>
                  <div className="attack-card-count">{a.count} 个样本</div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 进度条 */}
      {loading && progress && (
        <div className="card stagger-item" style={{ marginBottom: '16px' }}>
          <div className="progress-label">
            <span>正在批量测试...</span>
            <span className="count">{progress.current} / {progress.total}</span>
          </div>
          <div className="progress">
            <div
              className="progress-fill"
              style={{ width: `${progress.total > 0 ? (progress.current / progress.total) * 100 : 0}%` }}
            />
          </div>
        </div>
      )}

      {/* 运行按钮区 */}
      <div className="card stagger-item" style={{ textAlign: 'center' }}>
        <FlaskConical size={40} strokeWidth={1.5} style={{ color: 'var(--primary)', marginBottom: '12px' }} />
        <p style={{ color: 'var(--text-secondary)', marginBottom: '16px', fontSize: '13px' }}>
          {demoData
            ? `一键运行 ${demoData.total_attacks + (demoData.safe_samples?.length || 0)} 个样本的完整测试，或按选中类型定向测试`
            : '一键运行完整攻击 + 安全样本对比测试'}
        </p>
        <div className="flex gap-12" style={{ justifyContent: 'center', flexWrap: 'wrap' }}>
          <button className="btn btn-primary" onClick={runShowcase} disabled={loading}>
            {loading && !progress ? <Loader2 size={16} strokeWidth={1.5} className="taiji-spin" /> : <Play size={16} strokeWidth={1.5} />}
            一键完整测试
          </button>
          <button
            className="btn btn-secondary"
            onClick={runBatch}
            disabled={loading || selectedTypes.size === 0}
            title={selectedTypes.size === 0 ? '请至少选择一种攻击类型' : ''}
          >
            <Zap size={16} strokeWidth={1.5} /> 测试选中类型（{selectedTypes.size}）
          </button>
        </div>
      </div>

      {/* 错误提示 */}
      {error && (
        <div className="card result-pulse" style={{ borderColor: 'var(--danger)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--danger)' }}>
            <AlertTriangle size={16} strokeWidth={1.5} />
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* 空状态引导 */}
      {!hasResult && !loading && !error && (
        <div className="card empty-illustration">
          <div className="empty-illustration-icon">
            <FlaskConical size={32} strokeWidth={1.5} />
          </div>
          <div className="empty-illustration-title">尚未运行测试</div>
          <div className="empty-illustration-desc">
            选择上方攻击类型并点击「测试选中类型」，或直接点击「一键完整测试」，查看双壳架构对各类攻击的拦截表现与对正常请求的放行能力。
          </div>
        </div>
      )}

      {/* 结果区 */}
      {hasResult && (
        <div className="fade-in">
          {/* 对比卡片：攻击拦截率 vs 正常放行率 */}
          <div className="compare-grid" style={{ marginBottom: '16px' }}>
            <div className="compare-card attack">
              <div className="compare-card-title">
                <Swords size={16} strokeWidth={1.5} style={{ color: 'var(--danger)' }} />
                攻击拦截率
              </div>
              <div className="compare-card-value" style={{ color: 'var(--danger)' }}>
                {(blockRate * 100).toFixed(1)}<span className="metric-unit">%</span>
              </div>
              <div className="compare-card-desc">
                {attacksBlocked} / {attacksTotal} 已拦截 · 数值越高防护越强
              </div>
            </div>
            <div className="compare-card safe">
              <div className="compare-card-title">
                <ShieldCheck size={16} strokeWidth={1.5} style={{ color: 'var(--success)' }} />
                正常放行率
              </div>
              <div className="compare-card-value" style={{ color: 'var(--success)' }}>
                {(passRate * 100).toFixed(1)}<span className="metric-unit">%</span>
              </div>
              <div className="compare-card-desc">
                {safePassed} / {safeTotal} 已放行 · 数值越高误伤越少
              </div>
            </div>
          </div>

          {/* 图表区：饼图 + 柱状图 */}
          <div className="grid grid-2" style={{ marginBottom: '16px' }}>
            <div className="card">
              <div className="card-title" style={{ marginBottom: '16px' }}>测试结果分布</div>
              <ResponsiveContainer width="100%" height={280}>
                <PieChart>
                  <Pie
                    data={pieData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={90}
                    innerRadius={45}
                    paddingAngle={2}
                    label={({ name, value }) => `${name}: ${value}`}
                    labelLine={false}
                    isAnimationActive
                    animationDuration={800}
                  >
                    {pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border-strong)', borderRadius: '8px', fontSize: '12px' }}
                  />
                  <Legend wrapperStyle={{ fontSize: '11px' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: '16px' }}>
                {batchAgg ? '各攻击类型拦截率' : '测试概览'}
              </div>
              {barData.length > 0 ? (
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart data={barData} margin={{ top: 8, right: 8, bottom: 24, left: -8 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                    <XAxis dataKey="name" tick={{ fill: 'var(--text-tertiary)', fontSize: 11 }} interval={0} angle={-20} textAnchor="end" />
                    <YAxis tick={{ fill: 'var(--text-tertiary)', fontSize: 11 }} />
                    <Tooltip
                      contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border-strong)', borderRadius: '8px', fontSize: '12px' }}
                      cursor={{ fill: 'rgba(255,255,255,0.04)' }}
                    />
                    <Legend wrapperStyle={{ fontSize: '11px' }} />
                    <Bar dataKey="拦截率" fill="#2B5FD7" radius={[4, 4, 0, 0]} isAnimationActive animationDuration={800} />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div style={{ height: 280, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: '12px' }}>
                  <div style={{ fontSize: '32px', fontWeight: 700, color: 'var(--primary)' }}>
                    {attacksTotal + safeTotal}<span className="metric-unit">样本</span>
                  </div>
                  <div className="text-sm text-tertiary">
                    攻击 {attacksTotal} · 正常 {safeTotal}
                  </div>
                  <div className="text-xs text-tertiary">选择攻击类型并定向测试可查看分类型柱状图</div>
                </div>
              )}
            </div>
          </div>

          {/* 可展开详情列表 */}
          <div className="card">
            <div className="flex-between" style={{ marginBottom: '12px' }}>
              <div className="card-title">详细结果（{detailResults.length} 条）</div>
              <button
                className="text-xs text-tertiary"
                style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '4px 8px' }}
                onClick={() => setExpanded(prev => prev.size === detailResults.length ? new Set() : new Set(detailResults.map((_, i) => i)))}
              >
                {expanded.size === detailResults.length ? '全部收起' : '全部展开'}
              </button>
            </div>
            <div style={{ maxHeight: '420px', overflowY: 'auto' }}>
              {detailResults.map((r, i) => {
                const isOpen = expanded.has(i);
                return (
                  <div key={i} className={`detail-row ${isOpen ? 'expanded' : ''}`}>
                    <div className="detail-row-header" onClick={() => toggleExpand(i)}>
                      <ChevronRight size={14} strokeWidth={2} className="detail-row-toggle" />
                      {r.allowed ? (
                        <CheckCircle size={14} strokeWidth={2} style={{ color: r.isAttack ? 'var(--warning)' : 'var(--success)', flexShrink: 0 }} />
                      ) : (
                        <XCircle size={14} strokeWidth={2} style={{ color: 'var(--danger)', flexShrink: 0 }} />
                      )}
                      <span className={`detail-tag ${r.isAttack ? 'attack' : 'safe'}`}>
                        {r.isAttack ? '攻击' : '正常'}
                      </span>
                      <span style={{ fontSize: '12px', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-secondary)' }}>
                        {r.text}
                      </span>
                      {!r.allowed && (
                        <span className={`detail-tag blocked`}>已拦截</span>
                      )}
                      {r.allowed && r.isAttack && (
                        <span className={`detail-tag`} style={{ background: 'rgba(245,166,35,0.12)', color: 'var(--warning)' }}>漏拦截</span>
                      )}
                      {r.allowed && !r.isAttack && (
                        <span className={`detail-tag passed`}>已放行</span>
                      )}
                    </div>
                    {isOpen && (
                      <div className="detail-row-body">
                        <div style={{ marginBottom: '6px' }}>
                          <span className="text-tertiary">类型：</span>
                          <span style={{ color: 'var(--text-primary)' }}>{(r as any).type || (r.isAttack ? '攻击样本' : '安全样本')}</span>
                        </div>
                        <div style={{ marginBottom: '6px' }}>
                          <span className="text-tertiary">判定：</span>
                          <span style={{ color: r.allowed ? 'var(--success)' : 'var(--danger)' }}>
                            {r.allowed ? '放行' : '拦截'}
                          </span>
                        </div>
                        <div style={{ marginBottom: '6px' }}>
                          <span className="text-tertiary">原文：</span>
                          <span style={{ color: 'var(--text-primary)' }}>{r.text}</span>
                        </div>
                        {r.reason && (
                          <div>
                            <span className="text-tertiary">原因：</span>
                            <code style={{ color: 'var(--warning)' }}>{r.reason}</code>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
