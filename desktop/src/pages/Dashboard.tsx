/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   首页 — 设计原则：用户打开应用，3 秒内知道"现在安全吗"。

   信息层级：
     ① 英雄区：大字状态 + 今日概览
     ② KPI 三卡：安全 / 可疑 / 危险
     ③ 近期安全记录：最近 5 条非安全事件
     ④ 当前中转站：信誉评分
     ⑤ 快速操作：暂停防护 / 打开日志 / 分享诊断
*/

import { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Clock,
  PauseCircle,
  FileText,
  Share2,
  Copy,
  CheckCircle2,
  AlertTriangle,
  Info,
  ChevronDown,
  RefreshCw,
} from 'lucide-react';
import {
  api,
  STATE_LABELS,
  currentProxyPort,
  formatTime,
  actionBadgeClass,
  findingExplanation,
  primaryFindingCategory,
  displayDomain,
  type StateResponse,
  type LogEntry,
  type RelayReputation,
} from '../services/api';
import { useToast } from '../components/Toast';
import { copyToClipboard } from '../lib/tauriShim';

/**
 * 首页卡片的标题文案：优先说人话，说不出来才用引擎的原话。
 *
 * ★ 为什么不能直接显示 summary（2026-10-04）
 *   summary 存的是检测器的 detail（如「[企业版护栏] 输出内容命中
 *   高危违规模式，已拦截」）。日志页已经把它翻译成人话，
 *   首页却直接把引擎原话摆出来 —— 同一个事件两套说法，
 *   而用户在首页看到的那套是他看不懂的。
 */
function entryHeadline(entry: LogEntry): string {
  const ex = findingExplanation(primaryFindingCategory(entry.detail_json));
  return ex ? ex.title : entry.summary;
}

// ══════════════════════════════════════════════════════════════
// 英雄区图标（按状态）
// ══════════════════════════════════════════════════════════════

const STATE_ICON: Record<string, typeof ShieldCheck> = {
  protecting: ShieldCheck,
  learning: Clock,
  suspect: AlertTriangle,
  danger: ShieldX,
  paused: PauseCircle,
};

const RELAY_LEVEL_TEXT: Record<string, string> = {
  safe: '信誉良好',
  normal: '正常',
  risky: '存在风险',
  malicious: '高危中转站',
};

/**
 * 信誉评分扣分明细。
 *
 * ★★★ 权重必须与后端 `_compute_score` 严格一致：
 *   这里是给用户看的「为什么是这个分」，一旦后端调权重而前端没跟上，
 *   界面就会给出一套自相矛盾的解释，比不给解释更糟。
 *
 * ★★ v0.1.0 起算法已改（详见后端 tracker._compute_score）：
 *   1. 只有**中转站责任**的风险参与扣分；
 *   2. 按**占比**扣分，不按绝对次数 —— 分数不再触底恒为 0；
 *   3. 定性证据（水印 / 域名模式）一次即扣，不被比例稀释。
 */
const SCORE_WEIGHTS = {
  watermark: 30,
  suspiciousPattern: 15,
  behaviorMax: 55,
} as const;

// ══════════════════════════════════════════════════════════════
// 页面
// ══════════════════════════════════════════════════════════════

export default function Dashboard() {
  const toast = useToast();
  const [state, setState] = useState<StateResponse | null>(null);
  const [recent, setRecent] = useState<LogEntry[]>([]);
  const [relays, setRelays] = useState<RelayReputation[]>([]);
  // ★ Phase 7：信誉详情默认收起。首页要在 3 秒内回答「现在安全吗」，
  //   评分明细是用户主动追问时才需要的信息，常开会把首屏挤成表格。
  const [showRepDetail, setShowRepDetail] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // ★ 手动刷新状态 + 上次成功刷新时刻。
  //   轮询失败时 mountedRef 会置空，手动刷新必须能独立重试，
  //   否则「连接断了 → 按钮也点不动 → 只能重启应用」。
  const [refreshing, setRefreshing] = useState(false);
  const [lastLoadedAt, setLastLoadedAt] = useState<number | null>(null);
  const failRef = useRef(0);
  const mountedRef = useRef(true);

  // ★ P2-11 修复所需：当前配置的中转站域名。
  //   /api/relays 按信誉分升序返回（最差在前），直接取 [0]
  //   会把「信誉最差的中转站」当成「当前中转站」展示，语义完全相反。
  //
  // ★★ 必须区分「没配」与「还没查完」。
  //   getDiagnostics 是一次性请求（不进轮询），它返回前 currentDomain
  //   是空串。此前空串一律渲染成「尚未配置中转站」——
  //   于是每次打开首页都有几秒显示「没配」，
  //   而用户明明配好了。**加载中就说「没配」是谎报**，
  //   它会让用户以为配置丢了，去反复重填甚至以为软件坏了。
  //   null = 还在查；'' = 查过了，确实没配。
  const [currentDomain, setCurrentDomain] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    api
      .getDiagnostics()
      .then((d) => {
        // ★ 后端没给 relay_domain（字段缺失）不等于「没配」。
        //   `?? ''` 会把「后端没说」悄悄变成「用户没配」——
        //   这是最隐蔽的一种谎报：数据缺失被当成了否定结论。
        if (!cancelled) {
          const v = d?.relay_domain;
          setCurrentDomain(typeof v === 'string' ? v : null);
        }
      })
      .catch(() => {
        // ★ 读取失败 ≠ 没配。
        //   设成 '' 会让界面说「尚未配置中转站」——
        //   而真实原因是查不到，用户去反复重填配置，
        //   问题却在读取侧，越重填越没用。
        //   保持 null（未知）→ 界面显示「正在读取」，
        //   至少不说谎。
        if (!cancelled) setCurrentDomain(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // ── 数据加载（保留上次成功数据，避免闪空）──
  const load = useCallback(async () => {
    try {
      const [s, logs, r] = await Promise.all([
        api.getState(),
        api.getLogs({ limit: 5, action: 'block' }).catch(() => null),
        api.getRelays().catch(() => null),
      ]);
      if (!mountedRef.current) return;
      setState(s);
      setLoadError(null);
      failRef.current = 0;
      // ★ 记录刷新时刻。轮询与手动刷新都走这里，
      //   所以它反映的是「界面上的数字有多新」——
      //   这正是用户判断「数据对不对得上」需要的唯一时间锚点。
      //   注意 formatTime 吃的是**秒**，Date.now() 是毫秒，
      //   直接传会把时间显示成 5 万多年前的时刻。
      setLastLoadedAt(Date.now() / 1000);
      if (logs) {
        // 首页只展示非"安全"事件：阻断 + 告警
        const all = await api
          .getLogs({ limit: 8 })
          .then((x) => x.entries.filter((e) => e.action !== 'pass'))
          .catch(() => logs.entries);
        if (mountedRef.current) setRecent(all.slice(0, 5));
      }
      if (r && mountedRef.current) setRelays(r.relays);
    } catch (e) {
      if (!mountedRef.current) return;
      setLoadError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  // ── 轮询（成功 3s，失败指数退避至 30s）──
  useEffect(() => {
    mountedRef.current = true;
    let timer: ReturnType<typeof setTimeout>;

    const schedule = async () => {
      await load();
      if (!mountedRef.current) return;
      const delay =
        loadError === null ? 3000 : Math.min(3000 * 2 ** (failRef.current + 1), 30000);
      if (loadError !== null) failRef.current = Math.min(failRef.current + 1, 3);
      timer = setTimeout(schedule, delay);
    };

    schedule();
    return () => {
      mountedRef.current = false;
      clearTimeout(timer);
    };
  }, [load, loadError]);

  // ── 手动刷新 ──
  // ★ 必须走独立的状态机，不复用 busy：
  //   busy 是「暂停/恢复/分享诊断」的操作锁，
  //   混用会让刷新按钮在别的操作进行中变灰，
  //   用户点不动又不知道原因。
  const handleRefresh = async () => {
    if (refreshing) return;
    setRefreshing(true);
    try {
      await load();
    } finally {
      if (mountedRef.current) setRefreshing(false);
    }
  };

  // ── 操作：暂停防护（P1-6：5 / 30 / 永久 三档）──
  const handlePause = async (durationMin: number) => {
    if (busy) return;
    setBusy(true);
    try {
      await api.pause(durationMin);
      toast.info(
        durationMin > 0 ? `防护已暂停 ${durationMin} 分钟` : '防护已永久暂停，直到手动恢复',
      );
      await load();
    } catch (e) {
      toast.error(`暂停失败：${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  const handleResume = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await api.resume();
      toast.success('防护已恢复');
      await load();
    } catch (e) {
      toast.error(`恢复失败：${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  // ── 操作：分享诊断报告（脱敏后复制）──
  const handleShareDiagnostics = async () => {
    if (busy) return;
    setBusy(true);
    try {
      const d = await api.getDiagnostics();
      const report = [
        '道体·玄盾 个人版 — 诊断报告',
        `版本: ${d.version}`,
        // ★ P2-4 修复：原硬编码 127.0.0.1:18765，
        //   用户改过端口后报告会给出错误的排查指引
        `代理端口: ${d.server?.host ?? '127.0.0.1'}:${d.server?.port ?? '-'}`,
        `中转站: ${displayDomain(d.relay_domain) || '(未配置)'}`,
        `安全级别: ${d.verifier?.level ?? '-'}`,
        `企业版护栏: ${d.verifier?.guardrail_available ? '已加载' : '未加载'}`,
        `日志总数: ${d.storage?.total_logs ?? 0}`,
        `已知中转站: ${d.reputation?.total_relays ?? 0}`,
        '',
        '（本报告不含任何对话内容与 API 密钥）',
      ].join('\n');
      const ok = await copyToClipboard(report);
      if (ok) toast.success('诊断报告已复制到剪贴板');
      else toast.error('复制失败，请手动截图');
    } catch (e) {
      toast.error(`生成诊断报告失败：${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  // ══════════════════════════════════════════════════════════
  // 渲染
  // ══════════════════════════════════════════════════════════

  if (loadError && !state) {
    return (
      <div>
        <div className="page-header">
          <h1 className="page-title">首页</h1>
        </div>
        <div className="alert danger">
          <ShieldAlert size={17} strokeWidth={1.5} className="alert-icon" />
          <div>
            <b>无法连接本地代理</b>
            <div className="mt-8">{loadError}</div>
            <div className="mt-8 faint">
              请确认玄盾代理已启动（默认 127.0.0.1:{currentProxyPort()}）。
              若尚未配置中转站，请前往「设置」页面完成配置。
            </div>
          </div>
        </div>
        <button className="btn" onClick={() => load()}>
          重试
        </button>
      </div>
    );
  }

  const s = state?.state ?? 'learning';
  const StateIcon = STATE_ICON[s] ?? ShieldCheck;
  const today = state?.today;
  // ★ P2-11 修复：按域名匹配当前配置的中转站；匹配不到时退而取
  //   信誉最高者（relays 按分数升序 → 最后一个），而不是最差的那个。
  //
  // ★★ 但那个兜底**只在「确实没配」时才允许**。
  //   currentDomain 非空却匹配不上，只有一个含义：配置了、还没发过
  //   对话，信誉库里还没有它。此时回退去取 relays[last] 会把
  //   **另一个中转站**当成「当前中转站」展示 —— 同样的谎报，
  //   只是发生在多中转站场景下。宁可空着也不能指错对象。
  //   currentDomain 为 null（还在查）同理：不知道是哪个，
  //   更不能随便挑一个顶替。
  const matchedRelay = currentDomain
    ? relays.find((r) => r.domain === currentDomain)
    : undefined;
  // ★ 2026-10-04：删掉了「未配置时取 relays[last] 顶替」那条回退。
  //   它会在「配置已被清空、但信誉库还留着历史记录」时，
  //   把一家**已经不再使用**的中转站显示成「当前中转站」——
  //   用户会以为配置没删干净，或以为软件认错了服务商。
  //   这与上面那条注释说的是同一件事：宁可空着也不能指错对象。
  //   匹配不到时自然落到下面的「尚未配置 / 已配置但无记录」两个分支，
  //   那两个分支本来就能把话说清楚。
  const primaryRelay = matchedRelay;
  // ★ 「配了但还没有调用记录」是独立于有无信誉记录的状态，
  //   把它与「压根没配」分成两种文案 —— 后者会让已配置的用户
  //   以为自己的配置丢了，进而重复配置或以为软件坏了。
  //   null（还在查）不能当成「没配」：那是加载态，不是结论。
  const relayConfigured = !!currentDomain;
  const relayProbeDone = currentDomain !== null;
  // ★ P2-11 配套：首日 last_seen - first_seen 不足 1 天，
  //   原 `Math.max(1, ...)` 会向用户谎报「已使用 1 天」
  const usedDays = primaryRelay
    ? Math.floor((primaryRelay.last_seen - primaryRelay.first_seen) / 86400)
    : 0;
  const usedLabel =
    usedDays >= 1
      ? `已使用 ${usedDays} 天`
      : primaryRelay
        ? '今天开始使用'
        : '';

  // ── 评分扣分明细 ──
  // ★★★ 只列**实际命中**的扣分项。
  //   两处关键改动（v0.1.0）：
  //   ① 「中转站侧危险/可疑」用的是 relay_* 计数，
  //      不再把用户自己贴密钥造成的拦截算到中转站头上 ——
  //      旧版界面显示「19 次危险 −380」，实测那 19 条全是
  //      「响应长度突变」：用户问了个长问题，
  //      中转站被扣 380 分。而真正的中转站风险是 0。
  //   ② 行为扣分按占比、有上限，不会再出现 −616 这种数字 ——
  //      分数一旦触底就恒为 0，之后所有新增风险都看不出来。
  const relayRisk = (primaryRelay?.relay_danger_count ?? 0)
    + (primaryRelay?.relay_suspect_count ?? 0);
  const selfRisk = (primaryRelay?.self_danger_count ?? 0)
    + (primaryRelay?.self_suspect_count ?? 0);
  // 与后端 _compute_score 的比例公式**逐字对应**：
  //   relayRisk   = relay_danger + relay_suspect
  //   normal      = total_calls − relayRisk − selfRisk
  //   denominator = relayRisk + normal        ← 排除用户自身造成的调用
  //   ratio       = (relay_danger×2 + relay_suspect) / denominator
  //   penalty     = min(behaviorMax, ratio × behaviorMax × 4)
  //
  // ★ 分母排除 selfRisk 不是可选项，实测踩过：
  //   用 total_calls 当分母时，用户多贴几次密钥就能把中转站分数抬高
  //   （实测 60 → 96）—— 分数被用户的操作洗白了。
  // ★ 系数 4 与分母口径都必须与后端一致，改一边就要改两边 ——
  //   不一致的后果是界面解释的扣分与实际分数对不上，
  //   而这正是「评分明细没有意义」的另一种表现。
  const denominator = primaryRelay
    ? Math.max(
        0,
        relayRisk
          + (primaryRelay.total_calls - relayRisk - selfRisk),
      )
    : 0;
  const rawRatio = denominator > 0
    ? ((primaryRelay?.relay_danger_count ?? 0) * 2
        + (primaryRelay?.relay_suspect_count ?? 0)) / denominator
    : 0;
  const behaviorPenalty = Math.min(
    SCORE_WEIGHTS.behaviorMax,
    rawRatio * SCORE_WEIGHTS.behaviorMax * 4,
  );
  const repDeductions = primaryRelay
    ? [
        {
          key: 'malicious',
          label: '命中已知恶意中转站库',
          detail: '信誉直接归零',
          points: primaryRelay.known_malicious ? primaryRelay.score : 0,
          hit: primaryRelay.known_malicious,
        },
        {
          key: 'watermark',
          label: '检测到数据保留迹象',
          detail: `响应中出现中转站自述留存 · ${SCORE_WEIGHTS.watermark} 分`,
          points: primaryRelay.watermark_detected ? SCORE_WEIGHTS.watermark : 0,
          hit: primaryRelay.watermark_detected,
        },
        {
          key: 'pattern',
          label: '域名高风险模式',
          detail: `免费顶级域名等滥用高发特征 · ${SCORE_WEIGHTS.suspiciousPattern} 分`,
          points: primaryRelay.notes.some((n) => n.startsWith('高风险模式'))
            ? SCORE_WEIGHTS.suspiciousPattern
            : 0,
          hit: primaryRelay.notes.some((n) => n.startsWith('高风险模式')),
        },
        {
          key: 'behavior',
          label: '中转站侧可疑响应占比',
          detail:
            `危险 ${primaryRelay.relay_danger_count ?? 0} 次`
            + `（权重 2）+ 可疑 ${primaryRelay.relay_suspect_count ?? 0} 次`
            + `，共 ${primaryRelay.total_calls} 次调用`
            + ` → 扣 ${behaviorPenalty.toFixed(1)} 分（上限 ${SCORE_WEIGHTS.behaviorMax}）`,
          points: Number(behaviorPenalty.toFixed(1)),
          hit: relayRisk > 0,
        },
      ].filter((d) => d.hit)
    : [];

  return (
    <div>
      {/* ① 英雄区 */}
      <div className="card hero">
        <div className={`hero-state ${s}`}>{STATE_LABELS[s]}</div>
        <div className="hero-message">{state?.message ?? '正在获取状态...'}</div>

        {/* ★ 手动刷新 + 上次更新时间。
            只有 3 秒轮询时，用户既不知道数字有多新，也无法在
            数值可疑时立刻拉一次 —— 只能干等或重启应用。
            「数据对不上」的第一嫌疑往往是时间差，
            把刷新时刻摆出来，判断才有依据。 */}
        <div
          className="faint"
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 10,
            fontSize: 11,
            marginBottom: 12,
          }}
        >
          <span className="mono">
            {lastLoadedAt ? `更新于 ${formatTime(lastLoadedAt)}` : '尚未更新'}
          </span>
          <button
            className="btn ghost sm"
            onClick={() => void handleRefresh()}
            disabled={refreshing}
            aria-label="刷新数据"
          >
            <RefreshCw
              size={13}
              strokeWidth={1.5}
              className={refreshing ? 'spin-icon' : undefined}
            />
            {refreshing ? '刷新中' : '刷新'}
          </button>
        </div>

        {today && (
          <div className="kpi-row" style={{ maxWidth: 460, margin: '0 auto' }}>
            <div className="kpi">
              <div className="kpi-value safe">{today.safe_count}</div>
              <div className="kpi-label">安全</div>
            </div>
            <div className="kpi">
              <div className="kpi-value suspect">{today.suspect_count}</div>
              {/* ★ 「可疑」→「提示」。
                  「可疑」暗示「出问题了」，但这一栏现在装的是
                  「回答长度/结构与平时不同」这类统计信号 ——
                  它不指向任何问题。用户看到「可疑 42」只会莫名紧张，
                  反而看不到真正该看的「危险」。 */}
              <div className="kpi-label">提示</div>
            </div>
            <div className="kpi">
              <div className="kpi-value danger">{today.danger_count}</div>
              <div className="kpi-label">危险</div>
            </div>
          </div>
        )}
      </div>

      {/* ② 近期安全记录 */}
      <div className="card">
        <div className="card-title">
          <span>近期安全记录</span>
          <Link to="/logs" className="btn ghost sm">
            查看全部
            <span style={{ transform: 'translateX(1px)' }}>→</span>
          </Link>
        </div>

        {recent.length === 0 ? (
          <div className="empty">
            <div className="empty-icon">
              <CheckCircle2 size={34} strokeWidth={1.5} />
            </div>
            <div className="empty-text">
              {today && today.total_calls > 0
                ? '今天没有发现危险响应，你的 AI 对话很安全'
                : '还没有检测记录 — 使用 AI 工具发起一次对话试试'}
            </div>
          </div>
        ) : (
          <div className="list">
            {recent.map((entry) => (
              <div key={entry.id} className="list-item">
                <span className={`list-icon ${actionBadgeClass(entry)}`}>
                  {entry.action === 'block' ? (
                    <ShieldX size={14} strokeWidth={1.5} />
                  ) : entry.severity === 'medium' ? (
                    <AlertTriangle size={14} strokeWidth={1.5} />
                  ) : (
                    <Info size={14} strokeWidth={1.5} />
                  )}
                </span>
                <span className="list-time">{formatTime(entry.timestamp)}</span>
                <span className="list-text" title={entryHeadline(entry)}>
                  {entryHeadline(entry)}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ③ 当前中转站 */}
      <div className="card">
        <div className="card-title">当前中转站</div>
        {primaryRelay ? (
          <>
            <div className="flex items-center justify-between gap-12">
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 15, fontWeight: 500 }}>{displayDomain(primaryRelay.domain)}</div>
                <div className="faint" style={{ fontSize: 12, marginTop: 2 }}>
                  {usedLabel}
                  {usedLabel && ' · '}
                  {primaryRelay.total_calls} 次调用
                  {/* ★ 只把「中转站侧」的风险算到中转站头上。
                      旧版这里显示的是 danger_count（总量），
                      实测 19 次里全部是「响应长度突变」——
                      用户问了个长问题，中转站被写成「19 次危险」。
                      那会让用户白白弃用一个没问题的服务商。 */}
                  {(primaryRelay.relay_danger_count ?? 0) > 0 && (
                    <>
                      {' · '}
                      <span style={{ color: 'var(--xd-danger)' }}>
                        {(primaryRelay.relay_danger_count ?? 0) + (primaryRelay.relay_suspect_count ?? 0)} 次可疑响应
                      </span>
                    </>
                  )}
                  {(primaryRelay.self_danger_count ?? 0) > 0 && (
                    <>
                      {' · '}
                      <span title="这些请求在发往中转站之前就被拦下了，中转站从未收到">
                        你有 {primaryRelay.self_danger_count} 次操作被拦截
                      </span>
                    </>
                  )}
                  {primaryRelay.watermark_detected && (
                    <>
                      {' · '}
                      <span style={{ color: 'var(--xd-suspect)' }}>检测到数据保留迹象</span>
                    </>
                  )}
                </div>
              </div>
              <div style={{ textAlign: 'right', flexShrink: 0 }}>
                <div className={`rep-score ${primaryRelay.level}`}>
                  {primaryRelay.score}
                  <span style={{ fontSize: 13, fontWeight: 400 }}>/100</span>
                </div>
                <div className="faint" style={{ fontSize: 11 }}>
                  {RELAY_LEVEL_TEXT[primaryRelay.level]}
                </div>
              </div>
            </div>

          {/* Phase 7：评分明细展开 */}
          <div className="mt-16">
            <button
              className="btn ghost sm"
              onClick={() => setShowRepDetail((v) => !v)}
              aria-expanded={showRepDetail}
            >
              <ChevronDown
                size={14}
                strokeWidth={1.5}
                style={{
                  transform: showRepDetail ? 'rotate(180deg)' : 'none',
                  transition: 'transform .15s ease',
                }}
              />
              {showRepDetail ? '收起评分明细' : '为什么是这个分数？'}
            </button>

            {showRepDetail && (
              <div className="rep-detail mt-12">
                {relayRisk === 0 && repDeductions.length === 0 ? (
                  <div className="faint" style={{ fontSize: 12, lineHeight: 1.7 }}>
                    本次使用未触发任何扣分项 —
                    没有中转站侧的危险或可疑响应、没有检测到数据保留迹象，域名也不在风险特征库中。
                    {selfRisk > 0 && (
                      <>
                        <br />
                        另有 {selfRisk} 次拦截来自你自己的操作（如在对话里粘贴了密钥），
                        按设计不计入中转站信誉 ——
                        请求在发往中转站之前就被拦下了，中转站从未收到过这些内容。
                      </>
                    )}
                  </div>
                ) : (
                  <>
                    <div className="table" style={{ marginBottom: 12 }}>
                      <div className="rep-row rep-row-head">
                        <span>扣分项</span>
                        <span className="faint">依据</span>
                        <span style={{ textAlign: 'right' }}>扣分</span>
                      </div>
                      {repDeductions.map((d) => (
                        <div key={d.key} className="rep-row">
                          <span>{d.label}</span>
                          <span className="faint">{d.detail}</span>
                          <span style={{ textAlign: 'right', color: 'var(--xd-danger)' }}>
                            −{d.points}
                          </span>
                        </div>
                      ))}
                      <div className="rep-row rep-row-total">
                        <span>当前信誉分</span>
                        <span className="faint">满分 100</span>
                        <span style={{ textAlign: 'right' }}>{primaryRelay.score}</span>
                      </div>
                    </div>

                    {primaryRelay.notes.length > 0 && (
                      <div className="faint" style={{ fontSize: 12, lineHeight: 1.7 }}>
                        证据：
                        {primaryRelay.notes.map((n) => (
                          <div key={n}>· {n}</div>
                        ))}
                      </div>
                    )}

                    <div className="faint" style={{ fontSize: 12, lineHeight: 1.7, marginTop: 8 }}>
                      平均响应延迟{' '}
                      <span className="mono">
                        {primaryRelay.latency_samples > 0
                          ? `${Math.round(primaryRelay.avg_latency_ms)} ms`
                          : '暂无样本'}
                      </span>
                      （{primaryRelay.latency_samples} 次采样）
                    </div>
                  </>
                )}
              </div>
            )}
          </div>
          </>
        ) : (
          <div className="empty" style={{ padding: '24px 20px' }}>
            <div className="empty-icon">
              <Info size={30} strokeWidth={1.5} />
            </div>
            {!relayProbeDone ? (
              /* 还在查 —— 不给结论。
                 早先这里直接落到「尚未配置中转站」，
                 于是每次打开首页都有几秒在谎报用户没配。 */
              <div className="empty-text faint">正在读取中转站配置…</div>
            ) : relayConfigured ? (
              /* ★ 已配置但信誉库里还没有它 —— 通常是刚填完还没发过对话。
                 这里**必须**显示域名：用户刚在设置页填完地址回来，
                 看到「尚未配置中转站」会以为保存失败了，去反复重填、
                 甚至以为软件坏了。域名摆出来才能证明「收到了，正在用」。 */
              <div className="empty-text">
                <div style={{ fontSize: 15, fontWeight: 500, color: 'var(--xd-text)' }}>
                  {displayDomain(currentDomain)}
                </div>
                <div className="faint" style={{ fontSize: 12, marginTop: 4 }}>
                  已配置 · 尚未产生调用记录
                </div>
                <div className="faint" style={{ fontSize: 12, marginTop: 8 }}>
                  用 AI 工具发起一次对话后，这里会显示它的信誉评分与调用统计。
                </div>
              </div>
            ) : (
              <div className="empty-text">
                尚未配置中转站
                <div className="mt-8">
                  <Link to="/settings" className="btn sm">
                    前往设置
                  </Link>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ④ 快速操作 */}
      <div className="card">
        <div className="card-title">快速操作</div>
        <div className="btn-row">
          {s === 'paused' ? (
            <button className="btn" onClick={handleResume} disabled={busy}>
              <ShieldCheck size={15} strokeWidth={1.5} />
              恢复防护
            </button>
          ) : (
            <>
              <button className="btn secondary" onClick={() => handlePause(5)} disabled={busy}>
                <PauseCircle size={15} strokeWidth={1.5} />
                暂停 5 分钟
              </button>
              <button className="btn secondary" onClick={() => handlePause(30)} disabled={busy}>
                <PauseCircle size={15} strokeWidth={1.5} />
                暂停 30 分钟
              </button>
              <button className="btn secondary" onClick={() => handlePause(0)} disabled={busy}>
                <PauseCircle size={15} strokeWidth={1.5} />
                永久暂停
              </button>
            </>
          )}
          <Link to="/logs" className="btn secondary">
            <FileText size={15} strokeWidth={1.5} />
            打开日志
          </Link>
          <button className="btn secondary" onClick={handleShareDiagnostics} disabled={busy}>
            <Share2 size={15} strokeWidth={1.5} />
            分享诊断报告
          </button>
        </div>
        {s === 'paused' && (
          <div className="alert suspect mt-16" style={{ marginBottom: 0 }}>
            <PauseCircle size={17} strokeWidth={1.5} className="alert-icon" />
            <div>
              防护已暂停，你的 AI 对话当前<b>不受任何检测保护</b>。
              中转站可以自由篡改返回内容、截留你的数据。
            </div>
          </div>
        )}
      </div>

      {/* 状态图标引用（避免未使用告警，同时用于语义化留档） */}
      <span hidden aria-hidden>
        <StateIcon size={1} />
        <Copy size={1} />
      </span>
    </div>
  );
}
