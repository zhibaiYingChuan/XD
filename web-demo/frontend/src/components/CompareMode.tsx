import { useState } from 'react';
import { api, CompareResult } from '../api';
import { GitCompare, Loader2, TrendingUp, AlertTriangle } from 'lucide-react';

/** A/B对比模式：单层防护 vs 双层防护拦截率对比 */
export default function CompareMode() {
  const [result, setResult] = useState<CompareResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleCompare = async (attackType: string = 'all') => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.compare(attackType);
      setResult(data);
    } catch (e: any) {
      setResult(null);
      setError(e.message || '对比测试失败');
    } finally {
      setLoading(false);
    }
  };

  const improvementPercent = result
    ? (result.improvement.rate_improvement * 100).toFixed(1)
    : '0';

  return (
    <div className="card fade-in">
      <div className="card-header">
        <div>
          <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <GitCompare size={18} strokeWidth={1.5} style={{ color: 'var(--primary)' }} />
            A/B 对比演示
          </div>
          <div className="card-subtitle">同一批攻击样本，对比单层与双层防护的拦截效果</div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', flexWrap: 'wrap' }}>
        <button className="btn btn-primary" onClick={() => handleCompare('all')} disabled={loading}>
          {loading ? <Loader2 size={14} strokeWidth={1.5} className="taiji-spin" /> : <GitCompare size={14} strokeWidth={1.5} />}
          {loading ? '对比测试中...' : '全类型攻击对比'}
        </button>
      </div>

      {error && (
        <div style={{ padding: '12px', background: 'rgba(229, 77, 77, 0.08)', borderRadius: 'var(--radius-md)', color: 'var(--danger)', fontSize: '12px', marginBottom: '16px' }}>
          {error}
        </div>
      )}

      {result && !loading && (
        <div className="fade-in">
          {/* 对比卡片 */}
          <div className="grid grid-2" style={{ marginBottom: '16px' }}>
            {/* 单层防护 */}
            <div style={{ padding: '20px', background: 'var(--bg-panel)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                <AlertTriangle size={18} strokeWidth={1.5} style={{ color: 'var(--warning)' }} />
                <span style={{ fontWeight: 600, fontSize: '14px' }}>单层防护（仅阳门）</span>
              </div>
              <div style={{ fontSize: '36px', fontWeight: 700, color: 'var(--warning)', marginBottom: '4px' }}>
                {(result.single_layer.block_rate * 100).toFixed(1)}<span style={{ fontSize: '14px', color: 'var(--text-tertiary)' }}>%</span>
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>
                拦截 {result.single_layer.blocked} / {result.batch_total} 条
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-tertiary)', marginTop: '8px' }}>
                {result.single_layer.description}
              </div>
            </div>

            {/* 双层防护 */}
            <div style={{ padding: '20px', background: 'rgba(0, 212, 170, 0.05)', borderRadius: 'var(--radius-lg)', border: '1px solid rgba(0, 212, 170, 0.2)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                <TrendingUp size={18} strokeWidth={1.5} style={{ color: 'var(--success)' }} />
                <span style={{ fontWeight: 600, fontSize: '14px' }}>双层防护（阳门+阴门）</span>
              </div>
              <div style={{ fontSize: '36px', fontWeight: 700, color: 'var(--success)', marginBottom: '4px' }}>
                {(result.dual_layer.block_rate * 100).toFixed(1)}<span style={{ fontSize: '14px', color: 'var(--text-tertiary)' }}>%</span>
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>
                拦截 {result.dual_layer.blocked} / {result.batch_total} 条
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-tertiary)', marginTop: '8px' }}>
                {result.dual_layer.description}
              </div>
            </div>
          </div>

          {/* 提升指标 */}
          <div style={{ padding: '16px', background: 'rgba(43, 95, 215, 0.08)', borderRadius: 'var(--radius-lg)', border: '1px solid rgba(43, 95, 215, 0.2)', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '12px' }}>
            <TrendingUp size={24} strokeWidth={1.5} style={{ color: 'var(--primary)' }} />
            <div>
              <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--primary)' }}>
                双层架构额外拦截了 {result.improvement.extra_blocked} 条攻击
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>
                拦截率提升 +{improvementPercent}%，有效阻止了未知攻击模式突破阳门防线
              </div>
            </div>
          </div>

          {/* 拦截率对比柱状图 */}
          <div style={{ marginBottom: '16px' }}>
            <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginBottom: '8px' }}>拦截率对比</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <BarRow label="单层防护" value={result.single_layer.block_rate} color="var(--warning)" />
              <BarRow label="双层防护" value={result.dual_layer.block_rate} color="var(--success)" />
            </div>
          </div>

          {/* 详细结果 */}
          <div style={{ maxHeight: '200px', overflowY: 'auto' }}>
            {result.results.map((r, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', width: '80px', flexShrink: 0 }}>{r.type}</span>
                <span style={{ fontSize: '12px', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.text}</span>
                {r.allowed ? (
                  <span style={{ fontSize: '10px', color: 'var(--warning)', flexShrink: 0 }}>放行</span>
                ) : (
                  <span style={{ fontSize: '10px', color: 'var(--danger)', flexShrink: 0 }}>拦截</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function BarRow({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
      <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', width: '60px', flexShrink: 0 }}>{label}</span>
      <div style={{ flex: 1, height: '20px', background: 'var(--bg-panel)', borderRadius: 'var(--radius-sm)', overflow: 'hidden' }}>
        <div style={{ width: `${value * 100}%`, height: '100%', background: color, borderRadius: 'var(--radius-sm)', transition: 'width 0.6s ease' }} />
      </div>
      <span style={{ fontSize: '12px', fontWeight: 600, color, width: '48px', textAlign: 'right' }}>{(value * 100).toFixed(1)}%</span>
    </div>
  );
}