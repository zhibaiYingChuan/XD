import { useState, useEffect, useRef, useCallback } from 'react';
import { api, LearningStatus, DualLayerStats } from '../api';
import { Brain, GraduationCap, Zap, Activity, Eye, Shield, Loader2, CheckCircle } from 'lucide-react';
import {
  RadialBarChart, RadialBar, ResponsiveContainer, PolarAngleAxis,
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
} from 'recharts';

// 学习事件时间线条目
interface LearnEvent {
  id: number;
  text: string;
  time: string;
  type: 'success' | 'warning' | 'danger';
}

// 学习曲线历史数据点
interface HistoryPoint {
  idx: number;
  requests: number;
  blocks: number;
  learns: number;
}

// 数字增长动画组件
function CountUp({ value, duration = 800 }: { value: number; duration?: number }) {
  const [display, setDisplay] = useState(0);
  const fromRef = useRef(0);
  useEffect(() => {
    const from = fromRef.current;
    const to = value;
    if (from === to) return;
    let raf = 0;
    const start = performance.now();
    const animate = (now: number) => {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3); // easeOutCubic
      setDisplay(Math.round(from + (to - from) * eased));
      if (progress < 1) raf = requestAnimationFrame(animate);
      else fromRef.current = to;
    };
    raf = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(raf);
  }, [value, duration]);
  return <span className="count-up">{display.toLocaleString()}</span>;
}

export default function LearningPage() {
  const [learning, setLearning] = useState<LearningStatus | null>(null);
  const [stats, setStats] = useState<DualLayerStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState<string | null>(null);
  // 学习事件列表
  const [events, setEvents] = useState<LearnEvent[]>([]);
  // 学习曲线历史数据点
  const [history, setHistory] = useState<HistoryPoint[]>([]);
  // 上次学习事件计数（用于增量检测）
  const lastLearnCountRef = useRef<number | null>(null);
  // 事件自增 id
  const evtIdRef = useRef(0);
  // 历史点序号
  const histIdxRef = useRef(0);

  // 拉取数据
  useEffect(() => {
    const fetchData = async () => {
      try {
        const data = await api.getStats();
        setLearning(data.learning);
        setStats(data.dual_layer);

        // 学习事件增量检测
        const curLearn = data.dual_layer?.inner_gate?.learning_events ?? 0;
        if (lastLearnCountRef.current !== null && curLearn > lastLearnCountRef.current) {
          const delta = curLearn - lastLearnCountRef.current;
          const now = new Date();
          const time = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;
          evtIdRef.current += 1;
          const newEvt: LearnEvent = {
            id: evtIdRef.current,
            text: `阴门捕获 ${delta} 个新学习事件`,
            time,
            type: 'success',
          };
          setEvents(prev => [newEvt, ...prev].slice(0, 12));
        }
        lastLearnCountRef.current = curLearn;

        // 追加学习曲线数据点
        histIdxRef.current += 1;
        setHistory(prev => [
          ...prev,
          {
            idx: histIdxRef.current,
            requests: data.dual_layer?.outer_gate?.total ?? 0,
            blocks: data.dual_layer?.outer_gate?.rejects ?? 0,
            learns: curLearn,
          },
        ].slice(-20));
      } catch {
        // 静默忽略
      } finally {
        setLoading(false);
      }
    };
    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  // 自动消失 toast
  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 2600);
    return () => clearTimeout(t);
  }, [toast]);

  // 模式切换（演示，无后端 API 时仅给出提示）
  const handleModeSwitch = useCallback((target: string) => {
    if (!learning) return;
    if (learning.mode === target) return;
    // 当前无切换 API，展示确认提示
    setToast(`已请求切换到「${target === 'protecting' ? '保护模式' : '观察模式'}」（演示：需后端切换接口支持）`);
  }, [learning]);

  const progressData = learning ? [{ name: '学习进度', value: learning.learning_progress * 100, fill: '#2B5FD7' }] : [];
  // 阶段标识
  const stage = learning?.mode === 'protecting' ? 'protect' : 'observe';
  const stageLabel = learning?.mode === 'protecting' ? '保护期' : '观察期';
  // 学习曲线数据
  const curveData = history.map(h => ({
    name: `T${h.idx}`,
    请求数: h.requests,
    拦截数: h.blocks,
    学习数: h.learns,
  }));

  return (
    <div className="fade-in">
      {/* 页面标题 */}
      <div style={{ marginBottom: '24px' }}>
        <h1 style={{ fontSize: '24px', fontWeight: 700, marginBottom: '8px' }}>学习状态</h1>
        <p style={{ color: 'var(--text-secondary)' }}>活性防护架构的在线学习进度与原型库规模</p>
      </div>

      {loading ? (
        <div className="card skeleton-card">
          <div className="flex gap-12" style={{ alignItems: 'center', marginBottom: '16px' }}>
            <div className="skeleton" style={{ width: '48px', height: '48px', borderRadius: '12px' }} />
            <div style={{ flex: 1 }}>
              <div className="skeleton skeleton-line" style={{ width: '30%', height: '16px' }} />
              <div className="skeleton skeleton-line" style={{ width: '50%', height: '12px', marginTop: '6px' }} />
            </div>
          </div>
          <div className="grid grid-2">
            <div className="skeleton" style={{ height: '200px' }} />
            <div className="skeleton" style={{ height: '200px' }} />
          </div>
        </div>
      ) : learning ? (
        <div className="fade-in">
          {/* 学习模式 + 模式切换 */}
          <div className="card stagger-item" style={{ marginBottom: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{
                  width: '48px', height: '48px', borderRadius: '12px',
                  background: learning.mode === 'protecting' ? 'rgba(0, 212, 170, 0.12)' : 'rgba(245, 166, 35, 0.12)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  {learning.mode === 'protecting' ? (
                    <Shield size={24} strokeWidth={1.5} style={{ color: 'var(--success)' }} />
                  ) : (
                    <Eye size={24} strokeWidth={1.5} style={{ color: 'var(--warning)' }} />
                  )}
                </div>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '18px', fontWeight: 600 }}>
                      {learning.mode === 'protecting' ? '保护模式' : '观察模式'}
                    </span>
                    <span className={`stage-badge ${stage}`}>
                      {learning.mode === 'protecting' ? <Shield size={11} strokeWidth={2} /> : <Eye size={11} strokeWidth={2} />}
                      {stageLabel}
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>
                    {learning.mode === 'protecting' ? '正在主动拦截攻击请求' : '正在学习正常语言模式'}
                  </div>
                </div>
              </div>
              {/* 模式切换 */}
              <div className="mode-switch">
                <button
                  className={`mode-switch-btn ${learning.mode === 'observing' ? 'active observe' : ''}`}
                  onClick={() => handleModeSwitch('observing')}
                >
                  <Eye size={13} strokeWidth={2} /> 观察
                </button>
                <button
                  className={`mode-switch-btn ${learning.mode === 'protecting' ? 'active protect' : ''}`}
                  onClick={() => handleModeSwitch('protecting')}
                >
                  <Shield size={13} strokeWidth={2} /> 保护
                </button>
              </div>
            </div>
          </div>

          {/* 学习进度 + 原型库规模 */}
          <div className="grid grid-2" style={{ marginBottom: '16px' }}>
            <div className="card stagger-item" style={{ animationDelay: '0.05s' }}>
              <div className="card-header">
                <div className="card-title">学习进度</div>
                <span className={`stage-badge ${stage}`}>{stageLabel}</span>
              </div>
              <ResponsiveContainer width="100%" height={200}>
                <RadialBarChart cx="50%" cy="50%" innerRadius="60%" outerRadius="100%" data={progressData} startAngle={90} endAngle={-270}>
                  <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
                  <RadialBar background dataKey="value" cornerRadius={10} isAnimationActive animationDuration={900} />
                </RadialBarChart>
              </ResponsiveContainer>
              <div style={{ textAlign: 'center', marginTop: '-40px' }}>
                <div style={{ fontSize: '24px', fontWeight: 700 }}>
                  <CountUp value={Math.round(learning.learning_progress * 1000) / 10} />%
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>
                  <CountUp value={learning.sample_count} /> / {learning.min_samples_for_switch} 样本
                </div>
              </div>
            </div>
            <div className="card stagger-item" style={{ animationDelay: '0.1s' }}>
              <div className="card-title" style={{ marginBottom: '12px' }}>原型库规模</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingTop: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ width: '40px', height: '40px', borderRadius: '8px', background: 'rgba(0, 212, 170, 0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <Brain size={18} strokeWidth={1.5} style={{ color: 'var(--teal)' }} />
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>安全原型</div>
                    <div style={{ fontSize: '20px', fontWeight: 700, color: 'var(--success)' }}>
                      <CountUp value={learning.safe_prototypes} />
                    </div>
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ width: '40px', height: '40px', borderRadius: '8px', background: 'rgba(229, 77, 77, 0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <Zap size={18} strokeWidth={1.5} style={{ color: 'var(--danger)' }} />
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>攻击原型</div>
                    <div style={{ fontSize: '20px', fontWeight: 700, color: 'var(--danger)' }}>
                      <CountUp value={learning.attack_prototypes} />
                    </div>
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ width: '40px', height: '40px', borderRadius: '8px', background: 'rgba(43, 95, 215, 0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <GraduationCap size={18} strokeWidth={1.5} style={{ color: 'var(--primary)' }} />
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>内置攻击样本</div>
                    <div style={{ fontSize: '20px', fontWeight: 700 }}>
                      <CountUp value={learning.builtin_attacks_loaded} />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* 学习曲线图 */}
          <div className="card stagger-item" style={{ marginBottom: '16px', animationDelay: '0.15s' }}>
            <div className="card-header">
              <div>
                <div className="card-title">学习曲线</div>
                <div className="card-subtitle">请求数 / 拦截数 / 学习数 随时间变化</div>
              </div>
              <span className="badge badge-info">最近 {curveData.length} 个采样点</span>
            </div>
            {curveData.length > 1 ? (
              <ResponsiveContainer width="100%" height={260}>
                <LineChart data={curveData} margin={{ top: 8, right: 12, bottom: 4, left: -8 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                  <XAxis dataKey="name" tick={{ fill: 'var(--text-tertiary)', fontSize: 11 }} />
                  <YAxis tick={{ fill: 'var(--text-tertiary)', fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border-strong)', borderRadius: '8px', fontSize: '12px' }}
                    cursor={{ stroke: 'rgba(255,255,255,0.1)' }}
                  />
                  <Legend wrapperStyle={{ fontSize: '11px' }} />
                  <Line type="monotone" dataKey="请求数" stroke="#2B5FD7" strokeWidth={2} dot={false} isAnimationActive animationDuration={600} />
                  <Line type="monotone" dataKey="拦截数" stroke="#E54D4D" strokeWidth={2} dot={false} isAnimationActive animationDuration={600} />
                  <Line type="monotone" dataKey="学习数" stroke="#00D4AA" strokeWidth={2} dot={false} isAnimationActive animationDuration={600} />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="empty-state" style={{ padding: '32px' }}>
                <Activity size={32} strokeWidth={1.5} style={{ color: 'var(--text-tertiary)', marginBottom: '8px' }} />
                <div className="text-sm text-tertiary">数据采样中，请稍候...</div>
              </div>
            )}
          </div>

          {/* 学习事件时间线 + 双层架构累计数据 */}
          <div className="grid grid-2">
            <div className="card stagger-item" style={{ animationDelay: '0.2s' }}>
              <div className="card-title" style={{ marginBottom: '12px' }}>学习事件时间线</div>
              {events.length > 0 ? (
                <div className="timeline">
                  {events.map(evt => (
                    <div key={evt.id} className={`timeline-item ${evt.type}`}>
                      <div className="timeline-item-content">
                        <span className="timeline-item-text">
                          <CheckCircle size={11} strokeWidth={2} style={{ display: 'inline', marginRight: '4px', verticalAlign: 'middle' }} />
                          {evt.text}
                        </span>
                        <span className="timeline-item-time">{evt.time}</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="timeline-empty">
                  <Eye size={24} strokeWidth={1.5} style={{ marginBottom: '8px' }} />
                  暂无新学习事件，等待阴门捕获...
                </div>
              )}
            </div>
            {stats && (
              <div className="card stagger-item" style={{ animationDelay: '0.25s' }}>
                <div className="card-title" style={{ marginBottom: '12px' }}>双层架构累计数据</div>
                <div className="grid grid-2" style={{ gap: '12px' }}>
                  <div className="metric-card">
                    <div className="metric-label">阳门总请求</div>
                    <div className="metric-value"><CountUp value={stats.outer_gate.total} /></div>
                  </div>
                  <div className="metric-card">
                    <div className="metric-label">阳门拦截</div>
                    <div className="metric-value danger"><CountUp value={stats.outer_gate.rejects} /></div>
                  </div>
                  <div className="metric-card">
                    <div className="metric-label">阴门总请求</div>
                    <div className="metric-value"><CountUp value={stats.inner_gate.total} /></div>
                  </div>
                  <div className="metric-card">
                    <div className="metric-label">阴门学习</div>
                    <div className="metric-value success"><CountUp value={stats.inner_gate.learning_events || 0} /></div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="card empty-illustration">
          <div className="empty-illustration-icon">
            <Brain size={32} strokeWidth={1.5} />
          </div>
          <div className="empty-illustration-title">暂无学习数据</div>
          <div className="empty-illustration-desc">请确认引擎已启动并完成初始化，稍后将自动加载学习状态。</div>
        </div>
      )}

      {/* Toast 提示 */}
      {toast && (
        <div className="toast warning">
          <Activity size={15} strokeWidth={1.5} style={{ color: 'var(--warning)' }} />
          <span>{toast}</span>
        </div>
      )}

      {/* 加载指示（轮询中） */}
      {!loading && learning && (
        <div style={{ position: 'fixed', bottom: 16, right: 24, display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-tertiary)', background: 'var(--bg-card)', padding: '6px 12px', borderRadius: 'var(--radius-full)', border: '1px solid var(--border)' }}>
          <Loader2 size={11} strokeWidth={2} className="taiji-spin" /> 实时刷新中
        </div>
      )}
    </div>
  );
}
