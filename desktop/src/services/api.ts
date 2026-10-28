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
  /** 本条日志记录了几处打码（明细可能已被隐私清除，计数仍在） */
  redaction_count?: number;
  /** 中转站实际返回的模型（响应侧日志才有） */
  response_model?: string;
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
  /** 排除某一类日志（首页 KPI 不含「转发中断」，点数字进来时用它对齐条数） */
  exclude_log_type?: string;
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
 * 单条日志的可对外证据包（2026-10-23）。
 *
 * 回答的是「这枚凭证从哪来」，而不是「玄盾拦了什么」：
 * 同一个指纹在台账里首次出现的方向，决定了它是
 * 用户这边带进来的，还是中转站返回的。
 */
export interface EvidenceHit {
  category: string;
  severity: string;
  detail: string;
  evidence: string;
  /** SHA-256 指纹；对方可用同一串原文复核 */
  fingerprint: string;
  first_seen: {
    direction: 'request' | 'response';
    direction_label: string;
    role: string;
    time: string;
  } | null;
}

export interface EvidenceBundle {
  schema: string;
  generated_at: string;
  engine_version: string;
  scope: string;
  log: {
    id: number;
    time: string;
    log_type: string;
    action: string;
    severity: string;
    relay_domain: string;
    model: string;
    summary: string;
  };
  verdict: { code: string; label: string; note: string };
  hits: EvidenceHit[];
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
  /**
   * 这家的专属入口端口。0 = 没有单独分配（只有主端口）。
   *
   * ★ 2026-10-22：AI 工具按「服务地址」区分供应商，
   *   同一地址只让填一次。两家中转站模型 ID 一样时，
   *   只有地址不同才能在工具里并存。
   */
  port: number;
  /** 专属入口地址（可直接填进 AI 工具）；未分配时为空串。 */
  proxy_url: string;
  /** 这个端口此刻是否真的在监听（被占用/未启动时为 false）。 */
  listening: boolean;
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
  /** ★ 2026-10-22：这家的专属入口端口；0 = 不单独分配（可选，老配置没有） */
  port?: number;
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

export interface StorageConfig {
  /** 日志保留天数。0 = 永久保留 */
  log_retention_days: number;
}

export interface PersonalConfig {
  relay: RelayConfig;
  guard: GuardConfig;
  server: ServerConfig;
  /** ★ 2026-10-20：旧配置可能没有这一节，读取时按 0（永久）降级 */
  storage?: StorageConfig;
}

export interface Diagnostics {
  version: string;
  verifier: { level: string; guardrail_available: boolean };
  storage: { db_path: string; db_size_bytes: number; total_logs: number };
  reputation: Record<string, number>;
  /** port 为**实际监听端口**；configured_port 是配置文件里的值（可能尚未生效） */
  server?: { host: string; port: number; configured_port?: number };
  relay_configured: boolean;
  relay_domain: string;
}

/**
 * 引擎（本地守护进程）的运行状态。
 *
 * ★ 字段名是 **snake_case**，与上面的 LicenseStatus 正好相反 ——
 *   Rust 侧 `EngineStatus`（src-tauri/src/lib.rs）**没有**标
 *   `#[serde(rename_all = "camelCase")]`，序列化后原样输出下划线命名。
 *   若写成 camelCase，TypeScript 不会报错（那只是本地 interface），
 *   但运行时字段全是 undefined —— 而 `startup_error` 恰恰是
 *   「引擎为什么起不来」的唯一线索，显示成空白等于把排障入口焊死。
 */
export interface EngineStatus {
  /** 引擎进程是否在运行 */
  running: boolean;
  /** 健康检查是否通过（running 但 healthy=false = 起了还没就绪） */
  healthy: boolean;
  /** 最近一次启动失败的原因（正常时为 null） */
  startup_error: string | null;
  /** 启动时间（Unix 秒；未启动为 null） */
  started_at: number | null;
  /** 最近一次健康检查时间（Unix 秒） */
  last_check: number | null;
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

// ══════════════════════════════════════════════════════════════
// 管理令牌（★ P0-5）
// ══════════════════════════════════════════════════════════════

/**
 * 为什么前端需要管令牌：
 *
 * 引擎启动时由桌面端注入 XUANDUN_ADMIN_TOKEN，之后所有 /api/* 请求
 * 都必须带 X-Admin-Token（防本机任意进程读日志/改中转站）。
 * Tauri 模式下由 Rust 侧 proxy_call 统一注入，前端不必关心；
 * 但**浏览器回退通道**（httpGet / httpSend）以前完全不发这个头 ——
 * 于是「桌面端在跑、用浏览器打开 1420」这个最常见的调试姿势，
 * 全站 401、首启直接卡在向导，而错误文案还把锅推给端口。
 */
let _adminToken: string | null = null;

/** 设置管理令牌（桌面端启动时注入；纯浏览器模式下保持为空）。 */
export function setAdminToken(token: string | null): void {
  const t = (token ?? '').trim();
  _adminToken = t ? t : null;
}

/**
 * 启动时拉取管理令牌。
 *
 * 只有 Tauri 拿得到（IPC 不经过 HTTP，天然不会被 401 挡住）；
 * 纯浏览器预览拿不到 —— 那条通道要求用户以「不设令牌」的方式手动启动引擎。
 * 拿不到时保持为空，由 401 的专门文案兜底，不阻断界面启动。
 */
export async function initAdminToken(): Promise<void> {
  if (!isTauri()) return;
  try {
    setAdminToken(await invoke<string>('get_admin_token'));
  } catch {
    /* 忽略：缺令牌只会影响浏览器回退通道 */
  }
}

function baseHeaders(): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json' };
  if (_adminToken) h['X-Admin-Token'] = _adminToken;
  return h;
}

/**
 * 401 的统一解释。
 *
 * ★ 不能沿用「请检查端口」那套文案：401 与端口无关，
 *   把人引向端口只会让他反复重启引擎而永远解决不了。
 */
function unauthorizedMessage(path: string): string {
  return (
    `${path} → 401：管理接口仅限玄盾桌面端访问。` +
    '若你在浏览器里预览，请先关闭正在运行的桌面端，' +
    '或以不设置 XUANDUN_ADMIN_TOKEN 的方式手动启动引擎。'
  );
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

/**
 * 从后端错误体里取出「人话」（★ P1-11）。
 *
 * 后端存在三种错误形态：
 *   · `{"detail": "..."}`     —— FastAPI 业务异常（最常见）
 *   · `{"detail": [{...}]}`   —— 422 参数校验错误（数组，含 msg 字段）
 *   · `{"error": {"message": "..."}}` —— 代理透传的上游错误
 *
 * 原实现只认 `detail` 且只处理字符串，其余一律退化成「HTTP 500」——
 * 用户拿到的是一句状态码，等于没有错误信息，也没法判断该改哪里。
 */
function extractErrorMessage(data: unknown, fallback: string): string {
  const pick = (v: unknown): string | null => {
    if (typeof v === 'string') return v.trim() ? v : null;
    if (Array.isArray(v)) {
      const parts = v.map(pick).filter((x): x is string => Boolean(x));
      return parts.length ? parts.join('；') : null;
    }
    if (v && typeof v === 'object') {
      const obj = v as Record<string, unknown>;
      // ★★ 2026-10-29（P0-4）：`errors` 是引擎一批 400 出口的形态
      //   （`{"detail": {"errors": ["中转站地址不能为空", ...]}}`）。
      //   原来只认 msg/message/detail，于是这类校验错误一律退化成
      //   「HTTP 400 Bad Request」，用户不知道该改哪一项。
      for (const key of ['msg', 'message', 'detail', 'errors']) {
        if (key in obj) {
          const got = pick(obj[key]);
          if (got) return got;
        }
      }
    }
    return null;
  };
  if (data && typeof data === 'object') {
    const obj = data as Record<string, unknown>;
    for (const key of ['detail', 'error', 'message']) {
      if (key in obj) {
        const got = pick(obj[key]);
        if (got) return got;
      }
    }
  }
  return fallback;
}

async function httpGet<T>(path: string, timeoutMs = TIMEOUT.NORMAL): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${proxyBase()}${path}`, {
      signal: controller.signal,
      headers: baseHeaders(),
    });
    if (!res.ok) {
      if (res.status === 401) throw new Error(unauthorizedMessage(path));
      let detail = `GET ${path} → HTTP ${res.status}`;
      try {
        detail = extractErrorMessage(await res.json(), detail);
      } catch {
        /* 忽略解析失败 */
      }
      throw new Error(detail);
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
      headers: baseHeaders(),
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!res.ok) {
      // ★ P0-5：401 有确定含义（缺管理令牌），不能被并进「HTTP 401」里
      if (res.status === 401) throw new Error(unauthorizedMessage(path));
      // 尽量提取后端给出的原因（三种形态都认，见 extractErrorMessage）
      let detail = `HTTP ${res.status}`;
      try {
        detail = extractErrorMessage(await res.json(), detail);
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

/**
 * 把日志筛选条件编码成 query string（★ P0-6）。
 *
 * ★ 为什么必须显式编码：后端这两个端点的筛选参数是 **query 参数**
 *   （`log_type: Optional[str] = None`），而浏览器通道原来把整个
 *   params 当 body 发过去 —— 后端一个字段都读不到，全部按 None 处理。
 *   后果不是「删不掉」，而是**删得比用户以为的多**：
 *   确认框写「筛选结果 12 条」，实际清空整库。
 *
 *   Tauri 通道由 Rust 的 filter_query() 拼同样的 query 串，
 *   两条通道从此同一口径。
 */
function toFilterQuery(params: LogFilterParams): string {
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    q.append(key, String(value));
  }
  const s = q.toString();
  return s ? `?${s}` : '';
}

// ══════════════════════════════════════════════════════════════
// 对外 API
// ══════════════════════════════════════════════════════════════

export const api = {
  // ── 状态与统计 ──
  getState: () => call<StateResponse>('get_state', 'GET', '/api/state', undefined, TIMEOUT.FAST),
  getStats: (days = 7) =>
    // ★ M1 修复（2026-10-04）：days 必须放进 payload 供 Rust 命令读取。
    //   原实现只把 days 拼进 HTTP query string，而 Tauri 模式走的是
    //   invoke('get_stats', { payload }) —— Rust 侧收不到 days，
    //   只能硬编码 7 天，桌面端改天数没有任何效果。
    call<StatsResponse>('get_stats', 'GET', `/api/stats?days=${days}`, { days }, TIMEOUT.NORMAL),
  getDiagnostics: () =>
    call<Diagnostics>('get_diagnostics', 'GET', '/api/diagnostics', undefined, TIMEOUT.NORMAL),

  // ── 引擎运行状态（Rust 侧命令，非代理 HTTP 接口）──
  //
  // ★ 这两个命令由 Rust 侧直接维护「本机引擎进程」的状态与重启，
  //   并不存在对应的 Python HTTP 端点。所以这里不能用通用的 call()——
  //   它会退化成对 /api/engine/... 发请求，那个路由根本不存在。
  /**
   * 读取引擎运行状态。
   *
   * ★ 浏览器预览模式没有 Tauri IPC，也就没有本地引擎进程可查：
   *   返回 null 让调用方按「不可用」降级展示，
   *   而不是抛错把设置页整个打崩（参考同文件 getActivePort 的降级写法）。
   */
  getEngineStatus: async (): Promise<EngineStatus | null> => {
    if (!isTauri()) return null;
    return invoke<EngineStatus>('get_engine_status');
  },
  /**
   * 重启引擎（Rust 侧「先停后起」，全程持锁保证原子性）。
   *
   * ★ 只有桌面版能做：浏览器预览模式没有该命令，
   *   抛一个可识别的错误让界面给出明确提示，而不是静默无反应。
   */
  restartEngine: async (): Promise<void> => {
    if (!isTauri()) {
      throw new Error('重启引擎仅在桌面版可用');
    }
    await invoke<void>('restart_engine');
  },

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
  /**
   * 单条日志的可对外证据包。
   *
   * ★ 与详情分开：详情给你自己看（含内部类别名），
   *   证据包拿去问中转站 —— 只有可核对字段，没有凭证原文。
   */
  getLogEvidence: (id: number) =>
    call<EvidenceBundle>(
      'get_log_evidence', 'GET', `/api/logs/${id}/evidence`,
      undefined, TIMEOUT.NORMAL, { id }),
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
  // ★ 2026-10-19：导出必须带上当前筛选条件。
  //   原实现只传 format，后端又忽略筛选参数 —— 用户按筛选导出
  //   拿到的却是全量数据。现把筛选条件一并下传（后端已接线）。
  exportLogs: (format: 'csv' | 'json' = 'csv', filters: LogFilterParams = {}) =>
    call<{ ok: boolean; filename: string; content: string }>(
      'export_logs',
      'POST',
      '/api/logs/export',
      { format, ...filters },
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
      `/api/logs/delete-filtered${toFilterQuery(params)}`,
      params,
    ),
  deleteFilteredLogs: (params: LogFilterParams = {}) =>
    call<{ ok: boolean; deleted: number }>(
      'delete_filtered_logs',
      'POST',
      `/api/logs/delete-filtered/confirm${toFilterQuery(params)}`,
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
  addRelay: (relay: { name: string; base_url: string; api_key: string; port?: number }) =>
    call<{ ok: boolean; id: string; total: number; port: number; proxy_url: string }>(
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
        port: relay.port ?? 0,
      }),
  /**
   * 给某一家分配 / 修改 / 取消专属入口端口（0 = 取消）。
   *
   * ★ 与保存配置分开：配置接口里 others 的 Key 是掩码副本，
   *   整体回传会把别家的真实 Key 覆盖掉。改端口就只改端口。
   */
  setRelayPort: (id: string, port: number) =>
    call<{ ok: boolean; id: string; port: number; proxy_url: string }>(
      'set_relay_port', 'POST', '/api/relays/configured/port',
      // ★ body 必须是对象：浏览器预览模式下 call() 直接发这个 body，
      //   传 undefined 会发一个没有请求体的 POST，
      //   后端 Body(...) 校验直接 422 —— 界面上只看到「端口没设上」。
      { id, port }, TIMEOUT.NORMAL, { id, port }),
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
    const c = await call<
      PersonalConfig & { port_errors?: Record<string, string> }
    >('get_config', 'GET', '/api/config', undefined, TIMEOUT.FAST);
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
    call<{
      ok: boolean;
      config: PersonalConfig;
      /** 专属端口没能全部监听时的原因（{端口: 原因}）；正常时为空 */
      port_errors?: Record<string, string>;
    }>('update_config', 'PUT', '/api/config', patch),

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
  // ★ 2026-10-20：「可疑」统一改为「提示」。
  //   首页 KPI 与状态栏早已改用「提示」（统计类信号不指向问题），
  //   但这里和后端 /api/state 的 message 仍是「可疑响应」——
  //   同一个数字，两处两个说法，用户以为在说两件事。
  suspect: '提示',
  danger: '危险',
  paused: '已暂停',
};

export const ACTION_LABELS: Record<LogAction, string> = {
  pass: '安全',
  redact: '已打码',
  block: '已拦截',
  alert: '已告警',
};

/**
 * 「结果」这一列真正显示的文字。
 *
 * ★ 2026-10-22：连不上中转站（proxy_error）已从「已拦截」改成 alert，
 *   但直接显示「已告警」仍会让人以为检测到了风险。
 *   按日志类型再收一层：链路失败说「未送达」，既不冒充拦截，
 *   也不让人去猜「是不是我的内容有问题」。
 */
export function entryActionLabel(entry: {
  log_type?: string;
  action: LogAction;
}): string {
  if (entry.log_type === 'proxy_error') {
    return entry.action === 'alert' ? '未送达' : (ACTION_LABELS[entry.action] ?? entry.action);
  }
  return ACTION_LABELS[entry.action] ?? entry.action;
}

export const LOG_TYPE_LABELS: Record<LogType, string> = {
  request_sanitize: '请求脱敏',
  response_verify: '响应验证',
  // ★ 原名「代理错误」是站在实现视角的描述，用户读到只会想「谁错了、错哪了」。
  //   proxy_error 记录的其实是「本地代理到中转站这一段没走通」，
  //   改说「转发中断」直指现象，用户才知道发生了什么。
  proxy_error: '转发中断',
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
    title: '返回的模型与请求的不一致',
    // ★ 2026-10-20 改：原文案是「中转站把你的模型换成了别的 /
    //   这是明确的偷换」。
    //   但 2026-10-20 04:58 实测：同一模型的日期快照
    //   （deepseek-v4.1-flash → deepseek-v4.1-flash-1017）
    //   就被这句「明确的偷换」定了性，而它只是构建号不同。
    //   「名字不一致」是事实，「偷换」是推断 ——
    //   界面不能替用户下结论，否则一次误报就会让人白白弃用中转站。
    meaning: '你请求的模型和实际返回的模型不一样。可能是换成了更便宜的模型、被路由改写，也可能只是同一模型的日期快照。展开下方「查看技术细节」可以看到这两个模型名。',
  },
  tool_call_dangerous: {
    title: 'AI 准备做一个有风险的操作',
    // ★ 2026-10-22 改：原文案「AI 想执行一个危险操作 / 例如删除文件、
    //   执行破坏性命令」默认了「一定是执行命令」，但实测最常见的命中是
    //   「Write 工具的内容里提到 .env」——既不是删除，也不是命令。
    //   用一句放之四海皆准的话开头，再由 explainFinding 按命中内容细分。
    meaning: '例如读写密钥文件、执行破坏性命令、连接可疑地址。先看清它到底要做什么，再决定放不放行。',
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
    // ★ 2026-10-22：个人版把「企业版护栏要求打码」的命中归到这一类，
    //   所以这句要同时说清「谁判的」和「会不会影响用」。
    title: '内容检查提了一句，不影响使用',
    meaning:
      '玄盾内置的通用内容检查（与企业版共用同一套规则）觉得这段里有敏感内容。它偏保守，技术文档里的密钥示例、变量名都可能被点到。只作记录，不会拦你。',
  },
  dangerous_content: {
    // ★ 2026-10-04 新增：与「结构化 tool_call 危险参数」分开。
    //   正文/代码块里出现 rm -rf、eval( 是编程助手的正常输出，
    //   仅作记录；真正需要警惕的是「它作为工具调用被执行」的形态。
    title: '回答的正文或代码里出现了危险命令',
    meaning: '仅作记录，不会阻断。让 AI 写含 rm -rf、eval( 的脚本是正常需求；只有当它作为可执行的工具调用出现时才会被拦截。',
  },
  credential_from_response: {
    // ★ 2026-10-23：这一类是为「留证据」而存在的，不是拦截理由。
    //   模型可能在示例代码里自己编一枚 JWT，所以措辞必须留余地。
    title: '中转站返回了一枚你没发过的凭证',
    meaning: '这枚令牌不在你这次发出去的内容里。它可能是模型自己编的示例，也可能来自中转站返回的内容 —— 先核对，再决定要不要找对方说明。',
  },
};

/** 把引擎的 detail 换成用户能读懂的说明；无对应类别时返回 null。 */
export function findingExplanation(
  category: string | undefined,
): { title: string; meaning: string } | null {
  if (!category) return null;
  return FINDING_LABELS[category] ?? null;
}

/** 一条检测结果的「人话解释」 */
export interface FindingExplanation {
  /** 到底发生了什么（一句话） */
  title: string;
  /** 有什么风险、为什么会被拦 */
  meaning: string;
  /** 建议怎么做（尤其在被拦时） */
  action?: string;
  /** 命中的那一小段原文，供界面高亮 */
  hit?: string;
}

/** 从引擎 detail 里拆出「工具名 / 动作 / 命中物」。
 *
 *  引擎的三种句子（见 verifier.py 的 _check_tool_calls）：
 *    Tool Call "Write" 参数包含{危险命令}：{命中}
 *    Tool Call "Write" 试图{敏感文件}：{命中}
 *    Tool Call "Write" 请求{可疑地址}：{命中}
 */
const TOOL_DETAIL_RE = /^Tool Call "([^"]+)"\s*(?:参数包含|试图|请求)(.+?)[：:]([\s\S]+)$/;

/** 判断是不是「写入类」工具。
 *
 *  ★ 为什么必须区分（2026-10-22 实测误报）：
 *    AI 用 Write 写一份审计文档，正文里提到「.env.example 里没登记的变量」，
 *    引擎对所有 tool call 参数一律跑「敏感文件路径」规则，于是这条被写成
 *    「Tool Call "Write" 试图读取环境变量文件」并当成高危拦下。
 *    可它根本没读 .env —— 是把带 .env 字样的内容**写出去**。
 *    两者风险完全不同：读是「可能被带走」，写是「可能正在带走」。
 */
function isWriteTool(name: string): boolean {
  const n = (name || '').toLowerCase();
  return /write|edit|patch|create_file|replace|insert/.test(n);
}

/**
 * 按「命中内容」给用户一段能读懂的解释。
 *
 * ★ 与 findingExplanation 的分工：
 *   那个只看类别（category），同一句「AI 准备做一个有风险的操作」
 *   会套在删除命令、读密钥、写文档三种完全不同的情况上 ——
 *   用户无法据此判断该不该放行。
 *   这里额外读引擎给的 detail，把「工具 + 动作 + 命中物」翻成人话。
 */
export function explainFinding(f: {
  category?: string;
  detail?: string;
}): FindingExplanation | null {
  const category = f?.category;
  if (!category) return null;

  if (category === 'tool_call_dangerous') {
    const parsed = TOOL_DETAIL_RE.exec(f.detail ?? '');
    if (parsed) {
      const tool = parsed[1];
      const label = parsed[2].trim();
      const hit = parsed[3].trim().replace(/\s+/g, ' ').slice(0, 60);
      const writeTool = isWriteTool(tool);

      // ① 环境变量文件
      if (label.includes('环境变量')) {
        if (writeTool) {
          return {
            title: `AI 正在写文件，内容里提到了 ${hit}`,
            meaning:
              '它不是在读你的 .env，而是准备把带这个字样的内容写进文件。玄盾按最坏情况处理：万一里面夹着真实密钥，就会跟着这次写入离开你的电脑。',
            action:
              '如果只是变量名、示例文件（如 .env.example）或文档说明，确认里面没有真实密钥后，点「标记为误报」即可；以后这类内容用占位符代替真实值，就不会再被拦。',
            hit,
          };
        }
        return {
          title: `AI 要读你的环境变量文件（${hit}）`,
          meaning:
            '.env 里通常放着密钥和账号。读它本身不算攻击，但内容一旦被发到别处，密钥就跟着泄露了。',
          action: '确认这是你自己要它做的；不想让它碰，就在对话里直接说明不要读取 .env。',
          hit,
        };
      }

      // ② 凭据类文件
      if (/私钥|凭证|账户|配置|登录|授权/.test(label)) {
        return {
          title: `AI 想碰你的登录凭据（${hit}）`,
          meaning: `这类文件里是能直接登录你账号的东西（${label}）。一旦被带出去，对方可以冒充你操作。`,
          action: '不是你主动要求的话，建议这次拒绝执行，并检查该中转站。',
          hit,
        };
      }

      // ③ 危险命令
      return {
        title: 'AI 准备执行一条会破坏东西的命令',
        meaning: `命中：${label}。这类命令一旦跑起来，文件或数据可能就回不来了。`,
        action: '确认这是你要它做的；如果只是文档或示例里出现这句话，点「标记为误报」即可。',
        hit: hit || undefined,
      };
    }
  }

  const base = FINDING_LABELS[category];
  if (category === 'sensitive_leak') {
    // ★ 2026-10-22 更正：这类命中来自**玄盾自己复用的企业版输出护栏**，
    //   不是中转站那边的东西。上一版文案写成「中转站那边判的」，
    //   属于把自家组件的结论甩给别人 —— 用户一眼就看出来了。
    //   现在如实说明来源，并解释它为什么容易误判技术文档。
    if ((f.detail ?? '').startsWith('[企业版护栏]')) {
      return {
        title: '玄盾的内容检查觉得这段像敏感信息',
        meaning:
          '这条来自玄盾内置的通用内容检查（与企业版共用同一套规则）。它偏保守：技术文档里的密钥示例、变量名、字段名都可能被判成敏感内容。',
        action:
          '内容已按规则打码，没有拦你。确认不是真实密钥就当噪音忽略，或点「标记为误报」。',
      };
    }
  }

  if (category === 'undeclared_tool') {
    const detail = f.detail ?? '';
    const withDeclared = /未声明的工具[：:](.+?)（你只声明了\s*(\d+)\s*个工具[：:](.+?)）/.exec(detail);
    if (withDeclared) {
      const used = withDeclared[1].trim();
      return {
        title: `回答里用了你没声明过的工具：${used}`,
        meaning: `这次你只声明了 ${withDeclared[2]} 个工具（${withDeclared[3].trim()}），返回的却是上面那个名字。中转站凭空造调用是一种可能；但客户端改了工具名、网关加前缀，也会得到同样的结果。`,
        action:
          '展开技术细节对一下两个名字：只是写法不同（如 read_file 与 readFile）就点「标记为误报」；名字完全不认识，再检查中转站。',
        hit: used,
      };
    }
    const bare = /响应却返回了工具调用[：:](.+)$/.exec(detail);
    if (bare) {
      return {
        title: `你没开工具，回答里却冒出了工具调用：${bare[1].trim()}`,
        meaning:
          '这轮请求里没有任何工具可用，返回内容却带着工具调用。可能是中转站塞进来的，也可能是客户端把工具列表漏发了。',
        action: '先确认你的客户端这一轮确实没开工具；确认没开，再检查中转站。',
        hit: bare[1].trim(),
      };
    }
  }

  return base ? { ...base } : null;
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
  // ★ 2026-10-04 新增，与后端 verifier.OBSERVATION_ONLY_SIGNALS 对齐
  'dangerous_content',
  // ★ 2026-10-23：响应里出现「请求从未发送过的凭证」。
  //   它的用途是留证据给用户去核实，不是拦截理由。
  'credential_from_response',
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

/**
 * 把底层错误信息翻译成「怎么了 + 怎么办」，原始信息留作技术细节备查。
 *
 * ★ 为什么不能直接把原始信息摆给用户（2026-10-19）
 *   底层抛出的形如 `GET /api/state → HTTP 500`、`Failed to fetch`，
 *   那是开发者视角的字符串。用户既读不懂 GET，也不知道下一步该做什么 ——
 *   而这恰恰是「连不上」时唯一需要告诉他的两件事。
 *   原始信息不是没价值，它该收进折叠的「技术细节」里，
 *   给愿意核对或要拿去报障的人看。
 */
export function humanizeLoadError(raw: string | null | undefined): {
  /** 给用户看的一句话：说清楚发生了什么、该怎么办 */
  message: string;
  /** 折叠起来的技术细节（原始错误串） */
  detail: string;
} {
  const text = (raw ?? '').trim();
  const howTo = '点「重试」；若持续失败请重启玄盾。';
  const status = /HTTP (\d{3})/.exec(text);
  if (status) {
    return {
      message: `无法连接到玄盾本地服务（错误 ${status[1]}）。${howTo}`,
      detail: text,
    };
  }
  // 超时（ApiTimeoutError 的文案含「超时」）与网络不可达分开说，
  // 两者的排查方向不同：前者是服务没响应，后者是根本没连上。
  if (text.includes('超时')) {
    return { message: `连接玄盾本地服务超时。${howTo}`, detail: text };
  }
  return {
    message: `无法连接到玄盾本地服务。${howTo}`,
    detail: text || '（无更多信息）',
  };
}

/** 依据 action + severity 得出徽章样式类 */
export function actionBadgeClass(entry: { action: LogAction; severity: Severity }): string {
  if (entry.action === 'block') return 'danger';
  if (entry.action === 'alert' || entry.severity === 'medium') return 'suspect';
  if (entry.action === 'redact') return 'info';
  return 'safe';
}
