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
  /** 延迟突变次数（Phase 7）。评分扣分项之一，用于向用户解释分数来源。 */
  latency_anomalies?: number;
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
  model: string;
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
const TIMEOUT: Record<'FAST' | 'NORMAL', number> = {
  FAST: 5_000,      // 状态查询、配置读写
  NORMAL: 15_000,   // 列表查询、模式切换
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
  } = {}) => {
    const q = new URLSearchParams();
    if (params.limit) q.set('limit', String(params.limit));
    if (params.offset) q.set('offset', String(params.offset));
    if (params.log_type) q.set('log_type', params.log_type);
    if (params.action) q.set('action', params.action);
    if (params.search) q.set('search', params.search);
    if (params.days) q.set('days', String(params.days));
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

  // ── 中转站信誉 ──
  getRelays: () => call<RelaysResponse>('get_relays', 'GET', '/api/relays'),
  /**
   * 中转站静态风险预检（Phase 7）。
   *
   * ★ 必须独立于 getRelays：信誉记录只在真正转发过一次请求后建立。
   *   用户刚填完地址还没发过对话时列表里查无此人，
   *   若据此显示「无风险」等于蒙蔽用户。
   */
  precheckRelay: (baseUrl: string) =>
    call<RelayPrecheck>('precheck_relay', 'POST', '/api/relay/precheck', { base_url: baseUrl }),
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
