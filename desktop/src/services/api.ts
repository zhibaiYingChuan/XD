/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   个人版 API 客户端。

   两种运行模式：
   1. Tauri 环境 → 优先走 Rust IPC（避免跨域 + 免鉴权）
   2. 浏览器环境（npm run dev）→ 直连本地代理 HTTP

   无论哪种模式，对外暴露统一的方法签名，页面层无需感知差异。
*/

import { invoke, isTauri } from '../lib/tauriShim';

// ══════════════════════════════════════════════════════════════
// 类型定义
// ══════════════════════════════════════════════════════════════

export type GuardState = 'protecting' | 'learning' | 'suspect' | 'danger' | 'paused';
export type LogAction = 'pass' | 'redact' | 'block' | 'alert';
export type LogType = 'request_sanitize' | 'response_verify' | 'proxy_error' | 'relay';
export type Severity = 'low' | 'medium' | 'high';
export type SecurityLevel = 'lenient' | 'balanced' | 'strict';

export interface TodayStats {
  total_calls: number;
  danger_count: number;
  suspect_count: number;
  safe_count: number;
  redaction_count: number;
}

export interface StateResponse {
  state: GuardState;
  message: string;
  security_level?: SecurityLevel;
  upstream?: string;
  today?: TodayStats;
  paused_remaining_s?: number;
  /**
   * 只读模式（未激活 / 已过期）。
   *
   * ★ 这时 state 仍可能是 protecting、KPI 也会照常统计 ——
   *   但请求实际全部直通。界面必须显式提示，
   *   否则用户会以为防护在正常工作。
   */
  read_only?: boolean;
}

export interface DailyStat {
  date: string;
  total_calls: number;
  danger_count: number;
  suspect_count: number;
  safe_count: number;
}

export interface StatsResponse {
  today: TodayStats;
  recent: DailyStat[];
}

export interface LogEntry {
  id: number;
  timestamp: number;
  log_type: LogType;
  relay_domain: string;
  action: LogAction;
  severity: Severity;
  model: string;
  finding_count: number;
  summary: string;
  detail_json: string;
  text_preview: string;
  marked_safe: boolean;
}

export interface LogsResponse {
  entries: LogEntry[];
  total: number;
}

/** 日志筛选条件（列表查询与按条件删除共用同一套）。 */
export interface LogFilterParams {
  log_type?: string;
  action?: string;
  search?: string;
  days?: number;
  marked_safe?: boolean;
}

/**
 * 日志概览统计（2026-10-03）。
 *
 * ★ 界面上「共 N 条」只是分页器需要的一个数字，回答不了
 *   用户真正会问的「我这些日志都是些什么」。
 */
export interface LogBreakdown {
  total: number;
  marked_safe: number;
  oldest_ts: number;
  newest_ts: number;
  by_type: Record<string, number>;
  by_action: Record<string, number>;
  top_domains: Array<{ domain: string; count: number }>;
}

export interface RedactionRecord {
  id: number;
  session_id: string;
  redaction_idx: number;
  category: string;
  original: string;
  redacted: string;
  start_pos: number;
  end_pos: number;
  created_at: number;
}

export interface LogDetail {
  entry: LogEntry;
  redactions: RedactionRecord[];
}

/**
 * ★ v0.1.0：已配置的中转站（配置视角，非信誉视角）。
 *
 * 与 RelayReputation 的区别：那个是「我用过哪些、它们表现如何」，
 * 这个是「我配了哪些、现在用哪家」。刚填完还没发过对话时
 * 信誉表是空的，两者混在一起会让用户以为配置没生效。
 */
export interface ConfiguredRelay {
  id: string;
  name: string;
  base_url: string;
  /** 规范化后的接入地址（实际请求用到的就是这个）。 */
  normalized_base: string;
  /** 掩码后的 Key，**永不下发明文**。 */
  api_key_masked: string;
  active: boolean;
}

export interface ConfiguredRelaysResponse {
  relays: ConfiguredRelay[];
  active_id: string;
}

export interface RelayReputation {
  domain: string;
  score: number;
  first_seen: number;
  last_seen: number;
  total_calls: number;
  danger_count: number;
  suspect_count: number;
  avg_latency_ms: number;
  latency_samples: number;
  known_malicious: boolean;
  watermark_detected: boolean;
  notes: string[];
  level: 'safe' | 'normal' | 'risky' | 'malicious';
  /** 延迟突变次数。评分扣分项之一，用于向用户解释分数来源。 */
  latency_anomalies?: number;
  /**
   * ★ v0.1.0：中转站责任的可疑次数（参与评分）。
   *
   * 只有确实指向中转站本身的检测项才计在这里
   * （恶意 tool_call、隐藏指令、隐写、语义违规、敏感泄露）。
   * 「响应长度突变」不算 —— 那取决于你问了什么。
   */
  relay_danger_count?: number;
  relay_suspect_count?: number;
  /**
   * ★ v0.1.0：用户自身造成的风险次数（**不**参与评分）。
   *
   * 例如在对话里粘贴了密钥被请求侧拦截 ——
   * 那是你的操作问题，不是中转站的问题：
   * 请求在发往中转站之前就被拦下了，它从未收到过这些内容。
   */
  self_danger_count?: number;
  self_suspect_count?: number;
}

/**
 * 中转站静态风险预检结果（Phase 7）。
 *
 * 与 RelayReputation 的区别：这是**尚未产生调用记录**时的静态判断，
 * 只含域名指纹库与域名模式两类结论，不含延迟突变与水印
 * （那两项依赖历史调用数据）。`isPrecheck` 用于防止前端
 * 把预检分数当成实测信誉展示。
 */
export interface RelayPrecheck {
  domain: string;
  score: number;
  known_malicious: boolean;
  watermark_detected: boolean;
  notes: string[];
  risk_flags: Array<'known_malicious' | 'suspicious_pattern'>;
  level: 'safe' | 'normal' | 'risky' | 'malicious';
  is_precheck: boolean;
}

/**
 * 中转站真实连通性测试结果。
 *
 * ★ 与 RelayPrecheck 的区别：precheck 是**不发请求**的静态信誉判断，
 *   这是**真发了一次请求**的实测结果。用户「配好了但用不了」时，
 *   需要的正是后者 —— 它能把地址错、Key 错、站点不可达三者分开。
 */
export interface RelayTestResult {
  ok: boolean;
  /** ok / auth / address / unreachable / timeout / http */
  kind: 'ok' | 'auth' | 'address' | 'unreachable' | 'timeout' | 'http';
  /** 玄盾规范化之后实际使用的接入地址 —— 用户要核对的就是它 */
  address: string;
  /** 玄盾真正会打到的完整路径 */
  request_url: string;
  status: number | null;
  model_count: number | null;
  elapsed_ms: number;
  message: string;
  /** 上游响应片段（截断），便于用户与官方排查 */
  raw: string;
}

export interface RelaysResponse {
  relays: RelayReputation[];
  summary: {
    total_relays: number;
    malicious: number;
    risky: number;
    watermarked: number;
  };
}

export interface RelayConfig {
  name: string;
  base_url: string;
  api_key: string;
  enabled: boolean;
}

export interface GuardConfig {
  security_level: SecurityLevel;
  enable_response_verify: boolean;
  enable_request_sanitize: boolean;
  enable_reputation: boolean;
  enable_pattern_check: boolean;
  enabled_categories: Record<string, boolean>;
  custom_keywords: string[];
}

export interface ServerConfig {
  host: string;
  port: number;
  log_level: string;
  request_timeout_s: number;
}

export interface PersonalConfig {
  relay: RelayConfig;
  guard: GuardConfig;
  server: ServerConfig;
}

export interface Diagnostics {
  version: string;
  verifier: { level: string; guardrail_available: boolean };
  storage: { db_path: string; db_size_bytes: number; total_logs: number };
  reputation: Record<string, number>;
  server?: { host: string; port: number };
  relay_configured: boolean;
  relay_domain: string;
}

/**
 * 激活状态。
 *
 * ★ 字段名是 **camelCase**，不是 snake_case。
 *   Rust 侧 `LicenseStatus` 标了 `#[serde(rename_all = "camelCase")]`
 *   （src-tauri/src/license.rs），序列化后就是 camelCase。
 *   写成 snake_case 时 TypeScript 不会报错（那只是本地 interface），
 *   但运行时字段全是 undefined —— 界面会把机器码渲染成空白，
 *   而用户恰恰靠它去申请激活码。踩过一次，别再改回去。
 *
 * ★ `verifierAvailable=false` 与 `activated=false` 是两件不同的事：
 *   前者表示「引擎没能执行校验」（缺公钥 / 引擎未启动），
 *   结论不可信；后者表示「确实没通过」。UI 必须分开显示 ——
 *   把「验不了」说成「码无效」会让用户反复换码却永远激活不了。
 */
export interface LicenseStatus {
  activated: boolean;
  expiresAt: number | null;
  tier: string | null;
  subject: string | null;
  jti: string | null;
  /** 未激活原因（已激活时为 null） */
  reason: string | null;
  /** 本机机器码哈希 —— 用户报障时要报给签发方的东西 */
  machineCode: string;
  remainingDays: number;
  /** 引擎是否成功执行了校验（false = 结论不可信） */
  verifierAvailable: boolean;
}

/** 换绑请求串（用户发给售后即可完成换机绑定） */
export interface RebindRequest {
  request: string;
  machine_code_hash: string;
}

// ══════════════════════════════════════════════════════════════
// HTTP 层
// ══════════════════════════════════════════════════════════════

/** 本地代理默认端口（与后端 config.DEFAULT_PORT 一致） */
export const DEFAULT_PROXY_PORT = 18765;

/** 当前生效的代理端口。
 *
 *  ★ P1-10：端口是用户可配置项（设置页可改，用于解决端口冲突）。
 *  这里保留一份「已知端口」供浏览器开发模式与提示文案使用；
 *  Tauri 模式下所有请求走 Rust IPC，由 Rust 侧自行读配置，不依赖此值。
 *  每次从配置拉取后调用 syncProxyPort() 同步。
 */
let _proxyPort = DEFAULT_PROXY_PORT;

/** 手动覆盖代理地址（浏览器开发模式指向远程引擎时用）。
 *  一旦手动设置，proxyBase() 优先用它，syncProxyPort 不再影响。 */
let _baseOverride: string | null = null;

/** 同步代理端口（配置变更时调用） */
export function syncProxyPort(port: number | undefined): void {
  if (port && port >= 1024 && port <= 65535) {
    _proxyPort = port;
  }
}

/** 当前生效的代理端口（供各页面显示正确的地址） */
export function currentProxyPort(): number {
  return _proxyPort;
}

// 注意：显式标注为 Record 而非 as const 字面量类型，
// 否则 TS 会把 FAST 收窄成字面量 5000，导致默认值参数类型不兼容。
const TIMEOUT: Record<'FAST' | 'NORMAL' | 'PROBE', number> = {
  FAST: 5_000,      // 状态查询、配置读写
  NORMAL: 15_000,   // 列表查询、模式切换
  // ★ 真实网络探测：引擎侧最坏情况（/models 失败后再打业务端点）约 36s。
  //   必须比引擎侧宽，否则是前端先超时、用户拿到超时错误而非探测结论。
  PROBE: 50_000,
};

class ApiTimeoutError extends Error {
  constructor(public path: string, public timeoutMs: number) {
    super(`${path} 请求超时（${timeoutMs / 1000}s）`);
    this.name = 'ApiTimeoutError';
  }
}

export function setProxyBase(base: string | null): void {
  _baseOverride = base;
}

function proxyBase(): string {
  return _baseOverride ?? `http://127.0.0.1:${_proxyPort}`;
}

/** 依赖 Rust 侧的能力在浏览器模式下不可用。 */
function requireTauriFor(what: string): void {
  if (!isTauri()) {
    throw new Error(`${what} 需要桌面版（机器码只能在本机采集）`);
  }
}

async function httpGet<T>(path: string, timeoutMs = TIMEOUT.NORMAL): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${proxyBase()}${path}`, {
      signal: controller.signal,
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`GET ${path} → HTTP ${res.status}`);
    }
    return (await res.json()) as T;
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') {
      throw new ApiTimeoutError(path, timeoutMs);
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

async function httpSend<T>(
  method: 'POST' | 'PUT' | 'DELETE',
  path: string,
  body?: unknown,
  timeoutMs = TIMEOUT.NORMAL,
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${proxyBase()}${path}`, {
      method,
      signal: controller.signal,
      headers: { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!res.ok) {
      // 尽量提取后端 detail
      let detail = `HTTP ${res.status}`;
      try {
        const data = await res.json();
        if (data?.detail) {
          detail = typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail);
        }
      } catch {
        /* 忽略解析失败 */
      }
      throw new Error(detail);
    }
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') {
      throw new ApiTimeoutError(path, timeoutMs);
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

// ══════════════════════════════════════════════════════════════
// 统一调用层：Tauri 优先，浏览器回退 HTTP
// ══════════════════════════════════════════════════════════════

async function call<T>(
  tauriCmd: string,
  httpMethod: 'GET' | 'POST' | 'PUT' | 'DELETE',
  httpPath: string,
  body?: unknown,
  timeoutMs = TIMEOUT.NORMAL,
  /** Tauri 专用：需传给 Rust 命令的顶层参数（如 id） */
  tauriArgs?: Record<string, unknown>,
): Promise<T> {
  if (isTauri()) {
    // ★ P0-2/P0-3 修复：Tauri 命令需要顶层参数（如 id），
    //   不能只塞进 payload，否则 Rust 侧反序列化失败
    return invoke<T>(tauriCmd, { ...(tauriArgs ?? {}), payload: body ?? {} });
  }
  switch (httpMethod) {
    case 'GET':
      return httpGet<T>(httpPath, timeoutMs);
    default:
      return httpSend<T>(httpMethod, httpPath, body, timeoutMs);
  }
}

// ══════════════════════════════════════════════════════════════
// 对外 API
// ══════════════════════════════════════════════════════════════

export const api = {
  // ── 状态与统计 ──
  getState: () => call<StateResponse>('get_state', 'GET', '/api/state', undefined, TIMEOUT.FAST),
  getStats: (days = 7) =>
    call<StatsResponse>('get_stats', 'GET', `/api/stats?days=${days}`, undefined, TIMEOUT.NORMAL),
  getDiagnostics: () =>
    call<Diagnostics>('get_diagnostics', 'GET', '/api/diagnostics', undefined, TIMEOUT.NORMAL),

  // ── 日志 ──
  getLogs: (params: {
    limit?: number;
    offset?: number;
    log_type?: string;
    action?: string;
    search?: string;
    /** 时间范围筛选（天）。后端支持但此前未接线 */
    days?: number;
    /** 只看 / 只不看 被标记为误报的（2026-10-03） */
    marked_safe?: boolean;
  } = {}) => {
    const q = new URLSearchParams();
    if (params.limit) q.set('limit', String(params.limit));
    if (params.offset) q.set('offset', String(params.offset));
    if (params.log_type) q.set('log_type', params.log_type);
    if (params.action) q.set('action', params.action);
    if (params.search) q.set('search', params.search);
    if (params.days) q.set('days', String(params.days));
    // ★ 布尔必须显式判 undefined：写成 if (params.marked_safe) 会漏掉 false，
    //   而 false 正是「只看未标记误报的」这一档 —— 漏掉它该筛选静默失效。
    if (params.marked_safe !== undefined) {
      q.set('marked_safe', String(params.marked_safe));
    }
    const qs = q.toString();
    // ★ P0-3 修复：Tauri 模式下 Rust 侧从 payload 读取筛选参数，
    //   原实现只把参数拼进 HTTP query string 导致桌面端筛选/搜索/分页全失效
    return call<LogsResponse>(
      'get_logs',
      'GET',
      `/api/logs${qs ? `?${qs}` : ''}`,
      params,
    );
  },
  getLogDetail: (id: number) =>
    // ★ P0-2 修复：id 必须作为顶层参数传给 Rust 命令
    call<LogDetail>('get_log_detail', 'GET', `/api/logs/${id}`, undefined, TIMEOUT.NORMAL, {
      id,
    }),
  deleteLog: (id: number) =>
    call<void>('delete_log', 'DELETE', `/api/logs/${id}`, undefined, TIMEOUT.NORMAL, { id }),
  markLogSafe: (id: number) =>
    call<{ ok: boolean; log_id: number }>(
      'mark_log_safe',
      'POST',
      `/api/logs/${id}/mark-safe`,
      undefined,
      TIMEOUT.NORMAL,
      { id },
    ),
  /**
   * 撤销误报标记。
   *
   * ★ 与 markLogSafe 必须成对存在：
   *   标记现在会真的改动当日统计（危险/可疑），
   *   若只能标不能撤，一次手滑就永久改写了统计，
   *   而界面上没有任何入口能改回来。
   */
  unmarkLogSafe: (id: number) =>
    call<{ ok: boolean; log_id: number }>(
      'unmark_log_safe',
      'POST',
      `/api/logs/${id}/unmark-safe`,
      undefined,
      TIMEOUT.NORMAL,
      { id },
    ),
  exportLogs: (format: 'csv' | 'json' = 'csv') =>
    call<{ ok: boolean; filename: string; content: string }>(
      'export_logs',
      'POST',
      '/api/logs/export',
      { format },
    ),
  clearLogs: (beforeDays = 0) =>
    call<{ ok: boolean; deleted: number }>('clear_logs', 'POST', '/api/logs/clear', {
      before_days: beforeDays,
    }),

  /**
   * ★ 日志概览统计（2026-10-03）。
   * 此前日志页一个数字都没有，用户想知道「我这些日志都是什么」
   * 「有没有一直记着同一个中转站」只能自己翻。
   */
  getLogStats: () =>
    call<LogBreakdown>('get_logs_stats', 'GET', '/api/logs/stats'),

  /**
   * ★ 按当前筛选条件删除（两步确认，2026-10-03）。
   *
   * 为什么要两步：删除不可恢复，而「当前筛选条件」是个隐式概念 ——
   * 用户点了筛选就以为范围是那几十条，实际上可能是全部。
   * 第一步只回报 matched（将要删多少条），让用户看清范围再决定。
   *
   * 此前只有「清空全部」一条路：想清理筛选结果就只能全清，
   * 于是要么留着垃圾、要么把有用记录一起删掉。
   */
  countFilteredLogs: (params: LogFilterParams = {}) =>
    call<{ ok: boolean; matched: number }>(
      'count_filtered_logs',
      'POST',
      '/api/logs/delete-filtered',
      params,
    ),
  deleteFilteredLogs: (params: LogFilterParams = {}) =>
    call<{ ok: boolean; deleted: number }>(
      'delete_filtered_logs',
      'POST',
      '/api/logs/delete-filtered/confirm',
      params,
    ),

  // ── 中转站信誉 ──
  getRelays: () => call<RelaysResponse>('get_relays', 'GET', '/api/relays'),

  /**
   * ★ v0.1.0：已配置的中转站列表（多中转站）。
   *
   * 路径刻意是 /api/relays/configured 而不是 /api/relays：
   * 后者已被「信誉列表」占用，FastAPI 遇到重复路径不报错，
   * 而是让先注册的那个生效 —— 同名的新路由会变成死代码。
   */
  getConfiguredRelays: () =>
    call<ConfiguredRelaysResponse>(
      'get_configured_relays', 'GET', '/api/relays/configured'),
  /** 切换当前启用的中转站（显式切换，不做自动故障转移）。 */
  switchRelay: (id: string) =>
    call<{ ok: boolean; active_id: string }>(
      'switch_relay', 'POST', '/api/relays/active',
      undefined, TIMEOUT.NORMAL, { id }),
  /**
   * 新增一家中转站到列表（**不**设为启用项）。
   *
   * ★ 为什么必须有它：没有新增路径时，用户改「当前中转站」的地址
   *   就等于把原来那家覆盖掉 —— 多中转站在界面上看得见、
   *   在数据上永远只有一家，而用户毫无察觉。
   */
  addRelay: (relay: { name: string; base_url: string; api_key: string }) =>
    call<{ ok: boolean; id: string; total: number }>(
      'add_relay', 'POST', '/api/relays/configured', relay,
      undefined,
      // ★★★ 键名必须是 **camelCase**：Tauri v2 默认把命令实参
      //   转成 camelCase 再交给 Rust 反序列化。
      //   传 `{ base_url: ... }` 而 Rust 声明 `base_url: String` 时，
      //   它找的是 `baseUrl` —— 找不到就报
      //   「missing required key baseUrl」，
      //   而界面上只显示一行「添加失败：invalid args …」，
      //   用户既看不出原因，也丢掉了自己刚填的地址。
      //   实测踩过：这条 Toast 是唯一线索。
      {
        name: relay.name,
        baseUrl: relay.base_url,
        apiKey: relay.api_key,
      }),
  /** 移除列表里的一家（不能移除当前启用项）。 */
  removeRelay: (id: string) =>
    call<{ ok: boolean; total: number }>(
      'remove_relay', 'POST', '/api/relays/configured/remove',
      undefined, TIMEOUT.NORMAL, { id }),
  /**
   * 中转站静态风险预检（Phase 7）。
   *
   * ★ 必须独立于 getRelays：信誉记录只在真正转发过一次请求后建立。
   *   用户刚填完地址还没发过对话时列表里查无此人，
   *   若据此显示「无风险」等于蒙蔽用户。
   */
  precheckRelay: (baseUrl: string) =>
    call<RelayPrecheck>('precheck_relay', 'POST', '/api/relay/precheck', { base_url: baseUrl }),

  /**
   * 真实连通性测试（发一次真请求，实测地址与 Key 能不能用）。
   *
   * ★ apiKey 只在用户重新输入过时才传；空串的语义是「沿用已保存的」。
   *   界面上回显的是掩码，把掩码回传会让引擎拿着 ``xxxx****yyyy``
   *   去请求，测出来必然是「Key 被拒绝」。
   */
  testRelay: (baseUrl: string, apiKey?: string) =>
    call<RelayTestResult>(
      'test_relay',
      'POST',
      '/api/relay/test',
      { base_url: baseUrl, api_key: apiKey ?? '' },
      TIMEOUT.PROBE,
    ),
  clearReputation: () =>
    call<{ ok: boolean; cleared: number }>('clear_reputation', 'POST', '/api/reputation/clear'),

  // ── 配置 ──
  getConfig: async () => {
    const c = await call<PersonalConfig>('get_config', 'GET', '/api/config', undefined, TIMEOUT.FAST);
    // ★ P1-10：拿到配置即同步端口，供后续浏览器模式请求与各页文案使用
    syncProxyPort(c?.server?.port);
    return c;
  },
  /**
   * 读取本进程实际使用的代理端口。
   *
   * ★ P1-10：与配置里的端口可能不同 —— 用户改端口后未重启时，
   * 配置已落盘但引擎仍监听旧端口。界面必须显示「实际跑着的」那个，
   * 否则用户照着改 AI 工具配置会填到失效地址。
   * 浏览器模式无 Tauri IPC，回退用配置端口。
   */
  getActivePort: async () => {
    if (isTauri()) {
      try {
        const mod = await import('@tauri-apps/api/core');
        return (await mod.invoke<number>('get_active_port')) ?? DEFAULT_PROXY_PORT;
      } catch {
        /* 回退用配置端口 */
      }
    }
    return _proxyPort;
  },
  updateConfig: (patch: Partial<PersonalConfig>) =>
    call<{ ok: boolean; config: PersonalConfig }>('update_config', 'PUT', '/api/config', patch),

  // ── 防护控制 ──
  pause: (durationMin: number) =>
    call<{ ok: boolean; paused_minutes: number; resume_at: number }>(
      'pause_protection',
      'POST',
      '/api/pause',
      { duration_min: durationMin },
    ),
  resume: () => call<{ ok: boolean }>('resume_protection', 'POST', '/api/resume'),

  // ── 激活 ──
  //
  // ★ 机器码必须由 Rust 侧采集（sysinfo），Python/浏览器都算不出来。
  //   浏览器开发模式下没有 Tauri IPC，因此这三项直接抛错而不是
  //   返回一个假的「未激活」—— 假的未激活会让人以为码坏了。
  getLicenseStatus: async (): Promise<LicenseStatus> => {
    requireTauriFor('getLicenseStatus');
    return invoke<LicenseStatus>('get_license_status');
  },
  activate: async (code: string): Promise<LicenseStatus> => {
    requireTauriFor('activate');
    return invoke<LicenseStatus>('activate_license', { code });
  },
  clearLicense: async (): Promise<LicenseStatus> => {
    requireTauriFor('clearLicense');
    return invoke<LicenseStatus>('clear_license');
  },
  /**
   * 生成换绑请求串。
   *
   * 换机后原码在新机上必然验不过（一码一机绑的是旧机器）。
   * 把「原码 + 新机器码」打包成一个可复制的串发给售后，
   * 签发方验签后只改机器码重签即可，不需要用户再牵扯旧机器。
   */
  buildRebindRequest: async (code: string): Promise<RebindRequest> => {
    requireTauriFor('buildRebindRequest');
    return invoke<RebindRequest>('build_rebind_request', { code });
  },
};

// ══════════════════════════════════════════════════════════════
// 格式化工具
// ══════════════════════════════════════════════════════════════

export const STATE_LABELS: Record<GuardState, string> = {
  protecting: '防护中',
  learning: '学习中',
  suspect: '可疑',
  danger: '危险',
  paused: '已暂停',
};

export const ACTION_LABELS: Record<LogAction, string> = {
  pass: '安全',
  redact: '已打码',
  block: '已拦截',
  alert: '已告警',
};

export const LOG_TYPE_LABELS: Record<LogType, string> = {
  request_sanitize: '请求脱敏',
  response_verify: '响应验证',
  proxy_error: '代理错误',
  relay: '正常转发',
};

export const CATEGORY_LABELS: Record<string, string> = {
  api_key: 'API 密钥',
  aws_key: 'AWS 凭证',
  private_key: '私钥',
  jwt: 'JWT 令牌',
  idcard: '身份证',
  bankcard: '银行卡',
  phone: '手机号',
  email: '邮箱',
  custom: '自定义关键词',
};

export const SEVERITY_LABELS: Record<Severity, string> = {
  low: '低',
  medium: '中',
  high: '高',
};

/**
 * 把检测类别翻译成「用户能不能据此判断」的说话方式。
 *
 * ★ 为什么不能直接把 detail 原文给用户（2026-10-03）
 * ────────────────────────────────────────────────────────────
 * 引擎给出的 detail 是给排障看的，含 σ 倍数、字符偏移、哈希：
 *   「响应长度突然变长：本次 23851 字符，偏离历史均值 1742 达 124.0σ」
 *   「第 3 处 · API 密钥 · 位于 用户提问 · 第 41673-41693 字符」
 * 普通用户看不懂 σ 是什么，也看不到第 41673 个字符在哪 ——
 * 于是日志对他只有「玄盾说有问题，但不知道是什么问题」这一信息量，
 * 于是「误报」几乎成了默认结论。
 *
 * 这里给出「是什么问题 + 这意味着什么 + 你该怎么做」三段。
 */
export const FINDING_LABELS: Record<string, { title: string; meaning: string }> = {
  length_anomaly: {
    title: '这次回答的长度和平时不太一样',
    meaning: '仅作记录，不影响使用。回答变长变短通常只是你换了话题。',
  },
  structure_anomaly: {
    title: '这次回答的内容类型和平时不太一样',
    meaning: '仅作记录，不影响使用。比如你让AI 写代码，它就会从聊天变成代码。',
  },
  structure_drift: {
    title: '这次回答的结构和之前声明的不一致',
    meaning: '中转站可能改了回答的组织方式，内容本身不一定有问题。',
  },
  undeclared_tool: {
    title: '中转站调用了你没有授权的功能',
    meaning: '你只告诉了 AI 哪些工具可用，它却用了别的 —— 这属于铁证，请检查中转站。',
  },
  model_downgrade: {
    title: '中转站把你的模型换成了别的',
    meaning: '你付费买的模型和实际回答你的模型不一致，这是明确的偷换。',
  },
  tool_call_dangerous: {
    title: 'AI 想执行一个危险操作',
    meaning: '例如删除文件、执行破坏性命令。建议确认后再允许。',
  },
  system_prompt_inject: {
    title: '中转站可能在偷偷改写 AI 的行为',
    meaning: '检测到系统提示词被篡改迹象，属于严重问题，建议换中转站。',
  },
  sensitive_leak: {
    title: '回答里出现了敏感信息',
    // ★ 2026-10-04 改：原文案是「本不该外发给你的敏感信息…
    //   可能来自其他用户或被缓存污染，建议换中转站」——
    //   但这条日志实际多来自护栏的「命中敏感模式，已打码」，
    //   即玄盾**已经处理过**的内容（常常是用户自己发出去的密钥）。
    //   把「已打码」说成「泄露他人数据、建议换站」，
    //   会让人白白弃用一个没问题的中转站。
    meaning: '可能是你自己发出去的内容（比如密钥、手机号），也可能是中转站带回来的。玄盾已按规则处理过。若确认不是你的内容，再检查中转站。',
  },
  hidden_instruction: {
    title: '回答里藏了不给你看的指令',
    meaning: '模型试图绕过你的设置做额外的事，属于严重问题。',
  },
  request_blocked: {
    title: '你的提问里有不能外发的内容',
    meaning: '玄盾拦下了这次请求。删掉相关内容后重试即可。',
  },
  content_policy: {
    title: '这段回答触发了内容合规词表',
    meaning: '只是回答里出现了敏感词，与中转站是否篡改无关，不会影响你使用。',
  },
};

/** 把引擎的 detail 换成用户能读懂的说明；无对应类别时返回 null。 */
export function findingExplanation(
  category: string | undefined,
): { title: string; meaning: string } | null {
  if (!category) return null;
  return FINDING_LABELS[category] ?? null;
}

/**
 * 只作记录、不指控中转站的类别。
 * 与后端 verifier.OBSERVATION_ONLY_SIGNALS 对齐 —— 两边漂移会让
 * 首页把「仅记录」的项显示成头条，那是另一种谎报。
 */
export const OBSERVATION_ONLY_CATEGORIES = new Set([
  'length_anomaly',
  'structure_anomaly',
  'content_policy',
]);

/**
 * 从日志的 detail_json 里挑出「最值得摆在首页头条」的一条类别。
 *
 * ★ 为什么要挑而不是取第一条：
 *   一条响应常同时命中多个检测项，而 detail_json 的顺序由检测器
 *   内部顺序决定，与「哪个重要」无关。若直接取 [0]，
 *   一次「长度突变 + 中转站调用未授权工具」会被显示成
 *   「这次回答的长度和平时不太一样」—— 把最严重的问题藏起来了。
 *   所以优先挑**指向中转站责任**的那条，观测类只在没有别的项时兜底。
 */
export function primaryFindingCategory(
  detailJson: string | undefined,
): string | undefined {
  try {
    const arr = JSON.parse(detailJson || '[]');
    if (!Array.isArray(arr)) return undefined;
    const cats = arr
      .map((x) => String((x as { category?: string })?.category || ''))
      .filter(Boolean);
    if (cats.length === 0) return undefined;
    return cats.find((c) => !OBSERVATION_ONLY_CATEGORIES.has(c)) ?? cats[0];
  } catch {
    return undefined;
  }
}

/**
 * 把信誉键（`主机#Key指纹`）还原成用户看得懂的域名。
 *
 * ★ 为什么要剥掉指纹（2026-10-04）
 *   同一地址配多个账号时，信誉键带 Key 指纹以便分开统计 ——
 *   但指纹是内部实现细节，直接显示会变成
 *   `api.example.com#a1b2c3d4`，用户既看不懂也认不出是哪家。
 *   注意：**匹配**（判断「是不是当前这家」）必须用完整的键，
 *   只有**展示**才剥掉。
 */
export function displayDomain(key: string | undefined | null): string {
  if (!key) return '';
  return key.split('#', 1)[0];
}

export function formatTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString('zh-CN', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function formatDateTime(ts: number): string {
  return new Date(ts * 1000).toLocaleString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d} 天 ${h} 小时`;
  if (h > 0) return `${h} 小时 ${m} 分`;
  return `${m} 分钟`;
}

/** 依据 action + severity 得出徽章样式类 */
export function actionBadgeClass(entry: { action: LogAction; severity: Severity }): string {
  if (entry.action === 'block') return 'danger';
  if (entry.action === 'alert' || entry.severity === 'medium') return 'suspect';
  if (entry.action === 'redact') return 'info';
  return 'safe';
}
