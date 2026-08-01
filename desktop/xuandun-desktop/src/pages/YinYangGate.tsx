import { useState, useEffect } from 'react';
import { api, DualLayerStats } from '../services/tauriApi';
import {
  Zap,
  Brain,
  Activity,
  Target,
  ShieldCheck,
  RefreshCw,
  ArrowRight,
  ArrowLeft,
} from 'lucide-react';

export default function YinYangGate() {
  const [stats, setStats] = useState<DualLayerStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const fetchStats = async () => {
      try {
        const data = await api.getDualLayerStats();
        if (!cancelled) {
          setStats(data);
          setError(null);
        }
      } catch (err) {
        if (!cancelled && !stats) {
          setError(err instanceof Error ? err.message : '无法获取阴阳门状态数据');
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  if (loading) {
    return (
      <div className="yinyang-page">
        <div className="yinyang-loading">加载中...</div>
      </div>
    );
  }

  const outer = stats?.outer_gate;
  const inner = stats?.inner_gate;

  // P0修复：基于实际统计数据生成反馈闭环摘要，而非硬编码空数组
  // 反馈闭环描述阳门拦截数据喂给阴门学习、阴门更新阳门规则的双向过程
  const feedbackLoop: Array<{ timestamp: string; source: string; type: string; count: number; description: string }> = [];
  if (outer && inner && stats?.enabled) {
    const now = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    // 阳门 → 阴门：阳门拦截的请求转发给阴门进行深度判定和学习
    if (outer.forwards > 0) {
      feedbackLoop.push({
        timestamp: now,
        source: 'outer',
        type: '阳门转发 → 阴门精判',
        count: outer.forwards,
        description: `阳门放行 ${outer.forwards} 条请求至阴门进行深度判定与学习`,
      });
    }
    // 阴门 → 阳门：阴门学习到的新攻击模式更新阳门规则
    if (inner.learning_events > 0) {
      feedbackLoop.push({
        timestamp: now,
        source: 'inner',
        type: '阴门学习 → 阳门更新',
        count: inner.learning_events,
        description: `阴门产生 ${inner.learning_events} 个学习事件，新模式将反馈至阳门规则库`,
      });
    }
    // 阳门已学习的攻击/安全原型
    if (outer.learned_attack_count > 0 || outer.learned_safe_count > 0) {
      feedbackLoop.push({
        timestamp: now,
        source: 'outer',
        type: '阳门规则库更新',
        count: outer.learned_attack_count + outer.learned_safe_count,
        description: `阳门规则库已学习 ${outer.learned_attack_count} 条攻击模式、${outer.learned_safe_count} 条安全模式`,
      });
    }
  }

  return (
    <div className="yinyang-page">
      {/* 页面标题区域 */}
      <div className="dt-mb-8">
        <div className="dt-title-decoration">
          <h2 className="yinyang-page-title">阴阳门状态</h2>
        </div>
        <p className="yinyang-page-subtitle">双层安全架构 · 动静结合</p>
        <div className="yinyang-divider-row">
          <div
            className="yinyang-divider-line"
            style={{ background: 'linear-gradient(to right, transparent, var(--dt-primary-100))' }}
          ></div>
          <span className="yinyang-divider-text">☯ 阴阳相济 · 道法自然 ☯</span>
          <div
            className="yinyang-divider-line"
            style={{ background: 'linear-gradient(to left, transparent, var(--dt-primary-100))' }}
          ></div>
        </div>
      </div>

      {/* 阴阳门对比卡片区域 */}
      <div className="yinyang-cards-grid">
        {/* 外门（阳门）卡片 */}
        <div className="yinyang-gate-card">
          <div className="yinyang-gate-card-header">
            <div>
              <div className="yinyang-gate-card-title-row">
                <Zap size={20} strokeWidth={1.5} style={{ color: 'var(--dt-primary)' }} />
                <h3 className="yinyang-gate-card-title">阳门 · 快速拒绝</h3>
              </div>
              <p className="yinyang-gate-card-subtitle">外显 · 快速 · 拦截</p>
            </div>
            <div className="yinyang-status-badge success">
              <span className="yinyang-status-dot success"></span>
              <span>运行中</span>
            </div>
          </div>

          <div className="yinyang-metrics-grid">
            <div className="yinyang-metric-card">
              <div className="yinyang-metric-label">总请求数</div>
              <div className="yinyang-metric-value">
                {outer ? outer.total.toLocaleString() : '—'}
              </div>
            </div>
            <div className="yinyang-metric-card">
              <div className="yinyang-metric-label">拒绝数</div>
              <div className="yinyang-metric-value danger">
                {outer ? outer.rejects.toLocaleString() : '—'}
              </div>
            </div>
            <div className="yinyang-metric-card">
              <div className="yinyang-metric-label">转发数</div>
              <div className="yinyang-metric-value">
                {outer ? outer.forwards.toLocaleString() : '—'}
              </div>
            </div>
            <div className="yinyang-metric-card">
              <div className="yinyang-metric-label">平均延迟</div>
              <div className="yinyang-metric-value">
                {outer ? outer.avg_latency_ms : '—'}
                <span className="yinyang-metric-unit">ms</span>
              </div>
            </div>
          </div>

          <div className="yinyang-gate-footer">
            <span>第一层防御</span>
            <div
              className="dt-taiji-mini"
              style={{
                background:
                  'linear-gradient(to right, var(--dt-bg-card) 50%, var(--dt-primary) 50%)',
              }}
            ></div>
          </div>
        </div>

        {/* 中间太极分割线 */}
        <div className="yinyang-taiji-center">
          <div className="yinyang-taiji-vertical-text">阴阳相济</div>
          <div className="yinyang-taiji-svg taiji-pulse">
            <svg viewBox="0 0 100 100" width="100%" height="100%">
              <defs>
                <linearGradient id="yangGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop
                    offset="0%"
                    style={{ stopColor: 'var(--dt-primary)', stopOpacity: 1 }}
                  />
                  <stop
                    offset="100%"
                    style={{ stopColor: 'var(--dt-teal)', stopOpacity: 1 }}
                  />
                </linearGradient>
              </defs>
              <path
                d="M50 0 A50 50 0 0 1 50 100 A25 25 0 0 0 50 50 A25 25 0 0 1 50 0"
                fill="var(--dt-bg-card)"
              />
              <path
                d="M50 0 A50 50 0 0 0 50 100 A25 25 0 0 1 50 50 A25 25 0 0 0 50 0"
                fill="url(#yangGrad)"
              />
              <circle cx="50" cy="25" r="6" fill="var(--dt-bg-card)" />
              <circle cx="50" cy="75" r="6" fill="var(--dt-primary)" />
            </svg>
          </div>
          <div className="yinyang-taiji-vertical-text">动静结合</div>
        </div>

        {/* 内门（阴门）卡片 */}
        <div className="yinyang-gate-card">
          <div className="yinyang-gate-card-header">
            <div>
              <div className="yinyang-gate-card-title-row">
                <Brain size={20} strokeWidth={1.5} style={{ color: 'var(--dt-teal)' }} />
                <h3 className="yinyang-gate-card-title">阴门 · 精判学习</h3>
              </div>
              <p className="yinyang-gate-card-subtitle">内敛 · 深度 · 进化</p>
            </div>
            <div className="yinyang-status-badge teal">
              <span className="yinyang-status-dot teal"></span>
              <span>运行中</span>
            </div>
          </div>

          <div className="yinyang-metrics-grid">
            <div className="yinyang-metric-card">
              <div className="yinyang-metric-label">总请求数</div>
              <div className="yinyang-metric-value">
                {inner ? inner.total.toLocaleString() : '—'}
              </div>
            </div>
            <div className="yinyang-metric-card">
              <div className="yinyang-metric-label">拒绝数</div>
              <div className="yinyang-metric-value danger">
                {inner ? inner.rejects.toLocaleString() : '—'}
              </div>
            </div>
            <div className="yinyang-metric-card">
              <div className="yinyang-metric-label">学习事件数</div>
              <div className="yinyang-metric-value teal">
                {inner ? inner.learning_events.toLocaleString() : '—'}
              </div>
            </div>
            <div className="yinyang-metric-card">
              <div className="yinyang-metric-label">平均延迟</div>
              <div className="yinyang-metric-value">
                {inner ? inner.avg_latency_ms : '—'}
                <span className="yinyang-metric-unit">ms</span>
              </div>
            </div>
          </div>

          <div className="yinyang-gate-footer">
            <span>第二层防御</span>
            <div
              className="dt-taiji-mini"
              style={{
                background:
                  'linear-gradient(to right, var(--dt-bg-card) 50%, var(--dt-teal) 50%)',
              }}
            ></div>
          </div>
        </div>
      </div>

      {/* 阴阳反馈闭环时间线 */}
      <div className="yinyang-feedback-card">
        <div className="yinyang-feedback-header">
          <div className="yinyang-feedback-header-row">
            <Activity size={20} strokeWidth={1.5} style={{ color: 'var(--dt-primary)' }} />
            <h3 className="yinyang-feedback-title">阴阳反馈闭环</h3>
            <span className="yinyang-feedback-tag">实时</span>
          </div>
          <p className="yinyang-feedback-subtitle">双向学习 · 动态平衡</p>
        </div>
        <div className="yinyang-feedback-body">
          {feedbackLoop.length === 0 ? (
            <div className="yinyang-empty-state">
              {error ? `数据获取失败：${error}` : '暂无反馈数据'}
            </div>
          ) : (
            <div className="dt-relative">
              <div className="yinyang-timeline-line"></div>
              {feedbackLoop.map((item, index) => {
                const isOuter = item.source === 'outer';
                const sourceClass = isOuter ? 'primary' : 'teal';
                const sourceLabel = isOuter ? '阳门' : '阴门';
                const ArrowIcon = isOuter ? ArrowRight : ArrowLeft;
                const arrowColor = isOuter
                  ? 'var(--dt-primary)'
                  : 'var(--dt-teal)';
                return (
                  <div key={index} className="yinyang-timeline-item">
                    <div className="yinyang-timeline-time">
                      <div className={`yinyang-timeline-source ${sourceClass}`}>
                        {sourceLabel}
                      </div>
                      <div className="yinyang-timeline-timestamp">{item.timestamp}</div>
                    </div>
                    <div className="yinyang-timeline-dot-wrapper">
                      <div className={`yinyang-timeline-dot ${sourceClass}`}></div>
                    </div>
                    <div className="yinyang-timeline-content">
                      <div className="yinyang-timeline-content-header">
                        <ArrowIcon
                          size={16}
                          strokeWidth={1.5}
                          style={{ color: arrowColor }}
                        />
                        <span className="yinyang-timeline-content-title">{item.type}</span>
                        <span
                          className={`yinyang-timeline-count-badge ${sourceClass}`}
                        >
                          {item.count}条
                        </span>
                      </div>
                      <p className="yinyang-timeline-content-desc">{item.description}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* 双层架构原理说明 */}
      <div className="yinyang-principle-card">
        <div className="yinyang-principle-header">
          <div className="yinyang-principle-header-row">
            <Target size={20} strokeWidth={1.5} style={{ color: 'var(--dt-primary)' }} />
            <h3 className="yinyang-principle-title">双层架构原理</h3>
          </div>
          <p className="yinyang-principle-subtitle">动静互根 · 阴阳互化</p>
        </div>
        <div className="yinyang-principle-grid">
          <div className="yinyang-principle-item">
            <div className="yinyang-principle-item-header">
              <div className="yinyang-principle-icon-box primary">
                <ShieldCheck size={16} strokeWidth={1.5} />
              </div>
              <span className="yinyang-principle-item-title">阳门 · 第一层</span>
            </div>
            <p className="yinyang-principle-item-desc">
              基于规则的快速拒绝引擎，毫秒级响应，拦截已知攻击模式。外显于表，动而生阳，以快制快。
            </p>
          </div>
          <div className="yinyang-principle-item">
            <div className="yinyang-principle-item-header">
              <div className="yinyang-principle-icon-box teal">
                <Brain size={16} strokeWidth={1.5} />
              </div>
              <span className="yinyang-principle-item-title">阴门 · 第二层</span>
            </div>
            <p className="yinyang-principle-item-desc">
              基于AI原型的深度判定引擎，精确识别未知攻击，持续学习进化。内敛于里，静而生阴，以精取胜。
            </p>
          </div>
          <div className="yinyang-principle-item">
            <div className="yinyang-principle-item-header">
              <div className="yinyang-principle-icon-box gradient">
                <RefreshCw size={16} strokeWidth={1.5} />
              </div>
              <span className="yinyang-principle-item-title">阴阳闭环</span>
            </div>
            <p className="yinyang-principle-item-desc">
              阳门拦截数据喂给阴门学习，阴门发现新模式更新阳门规则，形成正循环。阴阳相济，防御日臻完善。
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
