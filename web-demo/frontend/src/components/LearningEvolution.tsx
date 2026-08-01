import { useEffect, useRef, useState } from 'react';
import { Brain, Database, Zap } from 'lucide-react';

/** 学习进化动画：原型库数字增长 + 攻击模式飘入 */
interface Props {
  learningEvents: number;
  attackPrototypes: number;
  safePrototypes: number;
  builtinAttacks: number;
  active: boolean;
}

export default function LearningEvolution({ learningEvents, attackPrototypes, safePrototypes, builtinAttacks, active }: Props) {
  const [displayAttacks, setDisplayAttacks] = useState(0);
  const [displaySafe, setDisplaySafe] = useState(0);
  const [floatingCards, setFloatingCards] = useState<Array<{ id: number; type: string; left: number }>>([]);
  const cardIdRef = useRef(0);
  const timeoutsRef = useRef<Set<ReturnType<typeof setTimeout>>>(new Set());

  // 数字增长动画
  useEffect(() => {
    if (!active) return;
    const duration = 1200;
    const steps = 30;
    const interval = duration / steps;
    const attackStep = attackPrototypes / steps;
    const safeStep = safePrototypes / steps;
    let current = 0;
    const timer = setInterval(() => {
      current++;
      if (current >= steps) {
        setDisplayAttacks(attackPrototypes);
        setDisplaySafe(safePrototypes);
        clearInterval(timer);
      } else {
        setDisplayAttacks(Math.floor(attackStep * current));
        setDisplaySafe(Math.floor(safeStep * current));
      }
    }, interval);
    return () => clearInterval(timer);
  }, [active, attackPrototypes, safePrototypes]);

  // 攻击模式卡片飘入动画
  useEffect(() => {
    if (!active || learningEvents === 0) return;
    const types = ['提示注入', '越狱', '编码混淆', '数据泄露', '工具滥用', '社会工程'];
    let cardCount = 0;
    const timer = setInterval(() => {
      if (cardCount >= Math.min(learningEvents, 20)) {
        clearInterval(timer);
        return;
      }
      cardCount++;
      const id = cardIdRef.current++;
      const type = types[id % types.length];
      const left = Math.random() * 60 + 20;
      setFloatingCards(prev => [...prev, { id, type, left }]);
      const tid = setTimeout(() => {
        setFloatingCards(prev => prev.filter(c => c.id !== id));
        timeoutsRef.current.delete(tid);
      }, 2500);
      timeoutsRef.current.add(tid);
    }, 800);
    return () => {
      clearInterval(timer);
      timeoutsRef.current.forEach(t => clearTimeout(t));
      timeoutsRef.current.clear();
    };
  }, [active, learningEvents]);

  if (!active) return null;

  return (
    <div className="card fade-in" style={{ position: 'relative', overflow: 'hidden' }}>
      <div className="card-header">
        <div>
          <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Brain size={18} strokeWidth={1.5} style={{ color: 'var(--teal)' }} />
            学习进化可视化
          </div>
          <div className="card-subtitle">阴门原型库实时进化 · 攻击模式自动归档</div>
        </div>
      </div>

      {/* 飘入的攻击模式卡片 */}
      {floatingCards.map(card => (
        <div key={card.id} style={{
          position: 'absolute',
          left: `${card.left}%`,
          top: '60px',
          padding: '6px 12px',
          background: 'rgba(229, 77, 77, 0.15)',
          border: '1px solid rgba(229, 77, 77, 0.3)',
          borderRadius: 'var(--radius-full)',
          fontSize: '11px',
          color: 'var(--danger)',
          animation: 'floatDown 2.5s ease-in-out forwards',
          pointerEvents: 'none',
          zIndex: 10,
        }}>
          <Zap size={10} strokeWidth={1.5} style={{ display: 'inline', marginRight: '4px' }} />
          {card.type}
        </div>
      ))}

      {/* 原型库数字展示 */}
      <div className="grid grid-3">
        <div className="metric-card" style={{ textAlign: 'center' }}>
          <Database size={20} strokeWidth={1.5} style={{ color: 'var(--danger)', marginBottom: '8px' }} />
          <div className="metric-label">攻击原型</div>
          <div className="metric-value danger" style={{ fontSize: '32px' }}>
            {displayAttacks}
          </div>
          <div style={{ fontSize: '10px', color: 'var(--text-tertiary)', marginTop: '4px' }}>
            内置 {builtinAttacks} + 学习 {attackPrototypes - builtinAttacks > 0 ? attackPrototypes - builtinAttacks : 0}
          </div>
        </div>
        <div className="metric-card" style={{ textAlign: 'center' }}>
          <Database size={20} strokeWidth={1.5} style={{ color: 'var(--success)', marginBottom: '8px' }} />
          <div className="metric-label">安全原型</div>
          <div className="metric-value success" style={{ fontSize: '32px' }}>
            {displaySafe}
          </div>
          <div style={{ fontSize: '10px', color: 'var(--text-tertiary)', marginTop: '4px' }}>
            正常请求模式库
          </div>
        </div>
        <div className="metric-card" style={{ textAlign: 'center' }}>
          <Brain size={20} strokeWidth={1.5} style={{ color: 'var(--teal)', marginBottom: '8px' }} />
          <div className="metric-label">学习事件</div>
          <div className="metric-value" style={{ fontSize: '32px', color: 'var(--teal)' }}>
            {learningEvents}
          </div>
          <div style={{ fontSize: '10px', color: 'var(--text-tertiary)', marginTop: '4px' }}>
            累计深度判定次数
          </div>
        </div>
      </div>

      {/* 进化进度条 */}
      <div style={{ marginTop: '16px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-tertiary)', marginBottom: '4px' }}>
          <span>原型库进化进度</span>
          <span>{attackPrototypes + safePrototypes} / {attackPrototypes + safePrototypes + 100}</span>
        </div>
        <div style={{ height: '6px', background: 'var(--bg-panel)', borderRadius: 'var(--radius-full)', overflow: 'hidden' }}>
          <div style={{
            width: `${Math.min(100, ((attackPrototypes + safePrototypes) / (attackPrototypes + safePrototypes + 100)) * 100)}%`,
            height: '100%',
            background: 'linear-gradient(90deg, var(--primary), var(--teal))',
            borderRadius: 'var(--radius-full)',
            transition: 'width 1.2s ease',
          }} />
        </div>
      </div>

      <style>{`
        @keyframes floatDown {
          0% { transform: translateY(-20px) scale(0.8); opacity: 0; }
          20% { transform: translateY(0) scale(1); opacity: 1; }
          80% { transform: translateY(180px) scale(1); opacity: 0.8; }
          100% { transform: translateY(240px) scale(0.9); opacity: 0; }
        }
      `}</style>
    </div>
  );
}