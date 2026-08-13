export interface StatusResponse {
  running: boolean;
  healthy: boolean;
  mode: string;
  learning_mode?: string;
  learning_progress?: number;
  sample_count?: number;
  uptime: number;
  total_requests: number;
  total_blocked: number;
  block_rate: number;
  startup_error?: string | null;
}

export interface LearningStatus {
  mode: string;
  sample_count: number;
  min_samples_for_switch: number;
  learning_progress: number;
  safe_prototypes: number;
  attack_prototypes: number;
  builtin_attacks_loaded: number;
  would_block_count: number;
  would_block_preview: Array<{
    timestamp: string;
    text_preview: string;
    would_be_blocked: boolean;
    trust_level: string;
    distance: number;
  }>;
  switched_at: number | null;
  call_count: number;
}

export interface ProtectResponse {
  allowed: boolean;
  trust_level: string;
  reject_stage: string | null;
  domain_distance: number | null;
  timing_distance: number | null;
  attack_category: string | null;
  latency_ms: number | null;
  fallback: boolean;
}

export interface LogEntry {
  id: number;
  timestamp: string;
  text_preview: string;
  allowed: boolean;
  trust_level: string;
  reject_stage: string | null;
  session_id: string | null;
  attack_category: string | null;
  latency_ms: number | null;
  domain_distance: number | null;
}

export interface TrendPoint {
  time: string;
  total_requests: number;
  total_blocked: number;
  avg_latency_ms: number;
  block_rate: number;
}

export interface TrendStatsResponse {
  granularity: string;
  points: TrendPoint[];
}

export interface AttackCategoryStat {
  category: string;
  total: number;
  blocked: number;
}

/**
 * RealtimeMetrics — 双源设计说明
 *
 * 数据来源：Rust 命令 `get_realtime_metrics` 直接从本地 EngineState 计算，
 * 不调用 Flask `/metrics/realtime` 端点。
 * - uptime_secs/mode/healthy：仅 Rust 维护（基于引擎心跳、模式状态、健康检查）
 * - qps：Rust 实时计算 = total_requests / uptime
 * - total_requests/total_blocked/block_rate：Rust 本地累计
 *
 * Flask `/metrics/realtime` 是独立指标端点（含 p50/p95/p99_latency_ms 分位数延迟），
 * 未被 Tauri 前端使用，仅供独立监控工具或调试访问。
 * 设计如此：避免前端实时指标依赖网络往返，保证 UI 响应速度。
 */
export interface RealtimeMetrics {
  total_requests: number;
  total_blocked: number;
  block_rate: number;
  uptime_secs: number;
  qps: number;
  mode: string;
  healthy: boolean;
}

export interface PeriodStats {
  total_requests: number;
  total_blocked: number;
}

export interface ComparisonStats {
  current: PeriodStats;
  baseline: PeriodStats;
}

export interface DualLayerStats {
  enabled: boolean;
  outer_gate: {
    total: number;
    rejects: number;
    passes: number;
    forwards: number;
    reject_rate: number;
    pass_rate: number;
    forward_rate: number;
    avg_latency_ms: number;
    learned_attack_count: number;
    learned_safe_count: number;
  };
  inner_gate: {
    total: number;
    rejects: number;
    passes: number;
    learning_events: number;
    reject_rate: number;
    avg_latency_ms: number;
  };
}

// ── 输出护栏（模型→用户）：stats / history / trend ──
// 数据由引擎按分钟桶内存采集（准实时、重启清空），脱敏返回。

export interface OutputStats {
  /** 输出护栏是否启用（引擎 config.enable_output_guardrail） */
  enabled?: boolean;
  total_checks: number;
  blocked: number;
  redacted: number;
  alerted: number;
}

export interface OutputHistoryEntry {
  time: string;
  action: 'block' | 'redact' | 'alert' | 'pass';
  risk_level: 'high' | 'medium' | 'low' | 'pass';
  reason: string;
  preview: string;
}

export interface OutputHistoryResponse {
  history: OutputHistoryEntry[];
}

export interface OutputTrendPoint {
  time: string;
  checked: number;
  blocked: number;
  redacted: number;
  alerted: number;
}

export interface OutputTrendResponse {
  points: OutputTrendPoint[];
}

// 输出护栏配置（引擎 /output/config 返回的生效快照）
export interface OutputConfigResponse {
  status?: string;
  config: {
    enable_output_guardrail?: boolean;
    output_guardrail_high_threshold?: number;
    output_guardrail_medium_threshold?: number;
    output_guardrail_low_threshold?: number;
    output_guardrail_safe_exempt?: number;
    output_guardrail_rule_block_signal?: number;
    output_guardrail_rule_medium_signal?: number;
    output_guardrail_redact_token?: string;
  };
}

// 输出护栏单次检测结果（对应引擎 /output/protect 的返回）
export interface OutputProtectResponse {
  allowed: boolean;
  risk_level: string;
  action: 'pass' | 'block' | 'redact' | 'alert';
  reason: string;
  /** 处置后的输出文本：redact 时为片段打码后的文本，block 时为安全提示，pass/alert 为原文 */
  output: string;
  violation_distance?: number | null;
  safe_distance?: number | null;
  degraded: boolean;
  latency_ms: number;
}

// ── 企业级运维：逃生通道 + 灰度部署 ──

export interface EmergencyBypassState {
  enabled: boolean;
}

export interface GrayDeployState {
  ratio: number;
}

/** 上游模型配置（设置页可视化表单）：OpenAI 兼容接口，引擎启动时注入环境变量 */
export interface UpstreamConfig {
  /** 上游模型 OpenAI 兼容地址（如 https://api.openai.com/v1） */
  url: string;
  /** 上游 API Key（可空，私有化模型无需鉴权） */
  apiKey: string;
  /** 默认模型名（可空，缺省用请求里的 model） */
  model: string;
  /** 请求上游超时秒数（默认 300） */
  timeout: number;
}

// ── 平面端 V2 新增接口（P1 中期优化）──

/** 模型服务器扫描结果 */
export interface ModelScanResult {
  success: boolean;
  models: Array<{ name: string; port: number; type: string }>;
  error?: string;
}

/** 周报预览数据 */
export interface WeeklyReportPreview {
  total_requests: number;
  total_blocked: number;
  block_rate: number;
  high_risk_count: number;
}

export interface BypassStats {
  emergency_bypass: boolean;
  gray_deploy_ratio: number;
  gray_bypass_count: number;
  bypass_log: Array<{
    timestamp: string;
    text_preview: string;
    reason: string;
  }>;
}

export interface LogResponse {
  entries: LogEntry[];
  total: number;
}

export interface HashChainReport {
  total_entries: number;
  verified_entries: number;
  broken_links: [number, string][];
  chain_intact: boolean;
  /** Rust 额外返回的旧版哈希条目数（v1 -> v2 迁移统计），前端可选展示 */
  legacy_entries?: number;
}

import { invoke } from '@tauri-apps/api/core';

declare global {
  interface Window {
    __TAURI_INTERNALS__?: {
      invoke?: (...args: unknown[]) => Promise<unknown>;
    };
  }
}

// ── P0-04 修复：invoke 超时包装器 ──
// 所有 invoke 调用必须经过超时包装，防止 Rust 后端挂起导致 UI 永久冻结。

/** 超时错误类型，调用方可通过 instanceof 或 name 识别 */
export class InvokeTimeoutError extends Error {
  readonly command: string;
  readonly timeoutMs: number;
  constructor(command: string, timeoutMs: number) {
    super(`操作超时: ${command} (${timeoutMs}ms 无响应)`);
    this.name = 'InvokeTimeoutError';
    this.command = command;
    this.timeoutMs = timeoutMs;
  }
}

/** 超时分档（毫秒）—— 按操作类型选择 */
export const TIMEOUT = {
  FAST: 5_000,          // 快速操作：状态查询、配置读写（5秒）
  NORMAL: 15_000,       // 普通操作：模式切换、报告生成（15秒）
  SLOW: 60_000,         // 长操作：模拟测试、预热（60秒）
  // P0-1 FM-L2-01 修复：restart_engine = stop(快) + sleep(1s) + ensure_engine_running(最坏60s) ≈ 61s
  // 前端超时预留34s冗余（保证Rust端先返回Err，而不是前端先抛InvokeTimeoutError导致永久waiting）
  RESTART_ENGINE: 95_000,
  // P0-5 FM-L4-03 修复：protect冷启动最坏28s（拒绝门四元组/KMeans初始化），
  // 前端15s NORMAL 会假超时截断调用，独立配置 35s 既不卡死也不截断
  PROTECT_COLD: 35_000,
  // IPC noop 心跳用短超时，快速识别桥接是否还活着
  NOOP_HEARTBEAT: 3_000,
} as const;

/** Toast/消息自动消失时间(ms)，全项目统一 */
export const MESSAGE_TIMEOUT_MS = 4000;

// ── 浏览器环境 HTTP API 回退 ──
// 当非 Tauri 环境（浏览器直接访问 Web Demo）时，
// 通过 fetch 调用 /xd/api/* 代理层，无需 Tauri bridge。

const API_BASE = (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_BASE) || '';

/** 命令名 → HTTP 端点 + 方法映射 + 响应转换 */
interface HttpMapping {
  method: string;
  path: string;
  bodyBuilder?: (args: any) => any;
  responseTransform?: (data: any) => any;
}
const COMMAND_HTTP_MAP: Record<string, HttpMapping> = {
  get_status: {
    method: 'GET',
    path: '/api/health',
    // HTTP /api/health 返回 {status, engine_running, ...} → 转换为 StatusResponse {running, healthy, ...}
    responseTransform: (data: any) => ({
      running: data.engine_running ?? (data.status === 'ok'),
      healthy: data.shield_ready ?? (data.status === 'ok'),
      mode: data.mode || 'balanced',
      learning_mode: data.learning_mode,
      learning_progress: data.learning_progress ?? 0,
      sample_count: data.sample_count ?? 0,
      uptime: data.uptime ?? 0,
      total_requests: data.total_requests ?? 0,
      total_blocked: data.total_blocked ?? 0,
      block_rate: data.block_rate ?? 0,
      startup_error: data.detail || null,
    }),
  },
  protect: {
    method: 'POST',
    path: '/api/protect',
    bodyBuilder: (args: any) => ({ text: args?.req?.text ?? '' }),
  },
  get_learning_status: {
    method: 'GET',
    path: '/api/mode',
    responseTransform: (data: any) => ({
      mode: data.learning_mode || 'protecting',
      sample_count: data.sample_count ?? 0,
      min_samples_for_switch: 1000,
      learning_progress: data.attack_learning_progress ?? 0,
      safe_prototypes: data.safe_prototypes ?? 30,
      attack_prototypes: data.attack_prototypes_total ?? 0,
      builtin_attacks_loaded: data.builtin_attacks_loaded ?? 0,
      would_block_count: 0,
      would_block_preview: [],
      switched_at: null,
      call_count: 0,
    }),
  },
  set_mode: {
    method: 'POST',
    path: '/api/mode',
    bodyBuilder: (args: any) => ({ mode: args?.mode }),
  },
  get_logs:    { method: 'GET',  path: '/api/logs/recent' },
  get_config: {
    method: 'GET',
    path: '/api/mode',
    responseTransform: (data: any) => data.current || 'balanced',
  },
};

/** HTTP API 回退：在非 Tauri 环境下用 fetch 调用后端 */
async function invokeHttp<T>(command: string, args?: Record<string, unknown>, timeoutMs: number = TIMEOUT.NORMAL): Promise<T> {
  const mapping = COMMAND_HTTP_MAP[command];
  if (!mapping) {
    return Promise.reject(new Error(`HTTP 回退不支持命令: ${command}（仅支持: ${Object.keys(COMMAND_HTTP_MAP).join(', ')}）`));
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const url = `${API_BASE}${mapping.path}`;
    const options: RequestInit = {
      method: mapping.method,
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      signal: controller.signal,
    };

    if (mapping.method === 'POST' && mapping.bodyBuilder && args) {
      options.body = JSON.stringify(mapping.bodyBuilder(args));
    } else if (mapping.method === 'POST' && args) {
      options.body = JSON.stringify(args);
    }

    const res = await fetch(url, options);
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`HTTP ${res.status}: ${body.slice(0, 200)}`);
    }
    const data = await res.json();
    // 如果有响应转换函数，转换字段名以匹配 Tauri IPC 返回的类型
    return (mapping.responseTransform ? mapping.responseTransform(data) : data) as T;
  } catch (e: any) {
    if (e.name === 'AbortError') {
      throw new InvokeTimeoutError(command, timeoutMs);
    }
    throw e;
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * 带超时的 invoke 包装器。
 * 超时后抛出 InvokeTimeoutError，调用方应通过 try-catch 捕获并在 UI 显示兜底提示。
 *
 * P0-01 修复：Tauri bridge 未注入兜底检测 → 已升级为 HTTP 回退。
 * 浏览器环境（Web Demo）下自动使用 fetch() 调用 /xd/api/* 端点，
 * 桌面应用（Tauri）下使用原生 IPC invoke。
 *
 * @param command Tauri 命令名
 * @param args 命令参数
 * @param timeoutMs 超时毫秒数（默认 NORMAL 15s）
 */
function invokeWithTimeout<T>(
  command: string,
  args?: Record<string, unknown>,
  timeoutMs: number = TIMEOUT.NORMAL,
): Promise<T> {
  // 非 Tauri 环境 → HTTP 回退
  if (typeof window === 'undefined' ||
      !window.__TAURI_INTERNALS__ ||
      typeof window.__TAURI_INTERNALS__?.invoke !== 'function') {
    return invokeHttp<T>(command, args, timeoutMs);
  }
  const timeoutPromise = new Promise<never>((_, reject) => {
    setTimeout(() => reject(new InvokeTimeoutError(command, timeoutMs)), timeoutMs);
  });
  return Promise.race([
    invoke<T>(command, args),
    timeoutPromise,
  ]) as Promise<T>;
}

/**
 * 判断当前是否运行在 Tauri 桌面环境中（P0-01 辅助）。
 * 用于 UI 层在桥接缺失时显示全局降级提示，而非各页面分别报错。
 */
export function isTauriBridgeAvailable(): boolean {
  return typeof window !== 'undefined' &&
    Boolean(window.__TAURI_INTERNALS__) &&
    typeof window.__TAURI_INTERNALS__?.invoke === 'function';
}

/**
 * 格式化 invoke 错误为用户可读的提示信息（P0-05 辅助 + NEW-P0-02 增强）。
 * 调用方在 catch 块中使用：showMessage('error', formatInvokeError(e, '测试告警'))
 *
 * NEW-P0-02 增强：识别常见 Tauri/Rust 错误模式，映射为用户可理解的修复指引
 */
export function formatInvokeError(e: unknown, action: string): string {
  if (e instanceof InvokeTimeoutError) {
    // R15 修复：超时后底层 Promise 仍可能正在执行，提示用户不要立即重试
    return `${action}超时。该操作可能仍在后台执行，请等待 30 秒后再重试。如果持续超时，请检查引擎是否正常运行。`;
  }
  if (e instanceof Error) {
    const msg = e.message || e.toString();
    // NEW-P0-02：识别常见错误模式，提供可操作的修复指引
    if (/missing required key/i.test(msg)) {
      return `${action}失败：配置参数缺失，请重启应用或联系技术支持。`;
    }
    if (/command not found/i.test(msg)) {
      return `${action}失败：应用版本不兼容，请检查更新或重新安装。`;
    }
    if (/os error 2|系统找不到指定的文件/i.test(msg)) {
      return `${action}失败：引擎可执行文件缺失，请重新安装或手动启动引擎。`;
    }
    if (/engine not running/i.test(msg)) {
      return `${action}失败：引擎未运行，请在设置页面重启引擎或手动启动。`;
    }
    // P1 韧性修复：识别 429 限流响应，提供明确的重试指引
    if (/429|too many requests|rate limit/i.test(msg)) {
      return `${action}请求过频，已被限流保护。请等待数秒后重试，或降低请求频率。`;
    }
    // P1 韧性修复：识别 HTML 响应（引擎返回错误页面而非 JSON），提供恢复指引
    if (/<!doctype html|<html/i.test(msg)) {
      return `${action}失败：引擎返回了错误页面，请尝试重启引擎。如果问题持续，请检查引擎日志。`;
    }
    return `${action}失败: ${msg}`;
  }
  return `${action}失败: ${String(e)}`;
}

/**
 * 信任等级中文映射（P1修复：将后端枚举值映射为用户友好的中文显示）。
 * 后端返回的 trust_level 是枚举值（UNKNOWN/HIGH/MEDIUM/LOW等），
 * 前端需统一映射为中文，避免直接显示英文枚举。
 */
const TRUST_LEVEL_MAP: Record<string, string> = {
  UNKNOWN: '未知',
  HIGH: '高信任',
  MEDIUM: '中信任',
  LOW: '低信任',
  FALLBACK: '降级',
  TEST: '测试',
};

export function formatTrustLevel(level: string | null | undefined): string {
  if (!level) return '—';
  return TRUST_LEVEL_MAP[level.toUpperCase()] || level;
}

export const api = {
  getStatus: () => invokeWithTimeout<StatusResponse>('get_status', undefined, TIMEOUT.FAST),
  // Sprint1-P0-5: protect冷启动假超时修复——首次调用需初始化拒绝门四元组/KMeans（最坏28s），
  // 使用独立的PROTECT_COLD=35s超时，避免NORMAL=15s假截断
  protect: (text: string, session: string = 'default', mode: string = 'balanced') => {
    // Cycle1-L5-2 修复：HCSE超时真实性测试注入点。
    // CDP测试通过设置window.__HCSE_HANG_PROTECT=true模拟后端protect永不返回的场景，
    // 返回一个永久pending的Promise，让前端35s setTimeout的InvokeTimeoutError真实触发，
    // 从而验证Detect.tsx第80行的超时分支（否则永远不触发，超时分支形同虚设）
    if (typeof window !== 'undefined' &&
        (window as any).__HCSE_HANG_PROTECT === true) {
      // 构造与 invokeWithTimeout 完全同构的超时结构：底层 invoke 永不 resolve（模拟后端卡死），
      // 外层 Promise.race 保留 PROTECT_COLD=35s 定时器，使 InvokeTimeoutError 真实触发，
      // 从而验证 Detect.tsx 的超时兜底分支（裸挂起 Promise 会绕过超时，分支形同虚设）。
      const hangPromise = new Promise<ProtectResponse>(() => {
        // 故意不调用 resolve/reject，模拟后端"永不返回"
      });
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new InvokeTimeoutError('protect', TIMEOUT.PROTECT_COLD)), TIMEOUT.PROTECT_COLD);
      });
      return Promise.race([hangPromise, timeoutPromise]) as Promise<ProtectResponse>;
    }
    return invokeWithTimeout<ProtectResponse>('protect', { req: { text, session, mode } }, TIMEOUT.PROTECT_COLD);
  },
  setMode: (mode: string) => invokeWithTimeout<void>('set_mode', { mode }, TIMEOUT.NORMAL),
  getLogs: (filterAllowed?: boolean, limit?: number, offset?: number) =>
    invokeWithTimeout<LogResponse>('get_logs', { filterAllowed, limit, offset }, TIMEOUT.FAST),
  getConfig: (key: string) => invokeWithTimeout<string | null>('get_config', { key }, TIMEOUT.FAST),
  setConfig: (key: string, value: string) => invokeWithTimeout<void>('set_config', { key, value }, TIMEOUT.FAST),
  // Sprint1-P0-1: restartEngine永不返回修复——stop(快)+sleep+ensure_running(最坏60s)≈61s，
  // 前端预留34s冗余，使用RESTART_ENGINE=95s，保证Rust端先返回Err而不是前端先抛超时
  restartEngine: () => invokeWithTimeout<void>('restart_engine', undefined, TIMEOUT.RESTART_ENGINE),
  stopEngine: () => invokeWithTimeout<void>('stop_engine', undefined, TIMEOUT.SLOW),
  // UI修复：打开引擎日志文件（Dashboard启动失败时供用户点击查看）
  openEngineLog: () => invokeWithTimeout<string>('open_engine_log', undefined, TIMEOUT.FAST),
  // Sprint1-P0-7: IPC析构散落报错修复——3s快速noop心跳，10s定时检测桥接是否还活着
  heartbeatNoop: () => invokeWithTimeout<{ ok: boolean; ts: number }>('noop_heartbeat', undefined, TIMEOUT.NOOP_HEARTBEAT),
  warmup: (safeTexts: string[], attackTexts: string[]) =>
    invokeWithTimeout<any>('warmup', { req: { safeTexts, attackTexts } }, TIMEOUT.SLOW),
  verifyAudit: () => invokeWithTimeout<HashChainReport>('verify_audit', undefined, TIMEOUT.NORMAL),
  storeSecretKey: (key: string) => invokeWithTimeout<void>('store_secret_key', { key }, TIMEOUT.FAST),
  getSecretKey: () => invokeWithTimeout<string>('get_secret_key', undefined, TIMEOUT.FAST),
  deleteSecretKey: () => invokeWithTimeout<void>('delete_secret_key', undefined, TIMEOUT.FAST),
  hasSecretKey: () => invokeWithTimeout<boolean>('has_secret_key', undefined, TIMEOUT.FAST),
  createSnapshot: (label: string) => invokeWithTimeout<number>('create_snapshot', { label }, TIMEOUT.NORMAL),
  listSnapshots: () => invokeWithTimeout<[number, string, string][]>('list_snapshots', undefined, TIMEOUT.FAST),
  restoreSnapshot: (snapshotId: number) => invokeWithTimeout<void>('restore_snapshot', { snapshotId }, TIMEOUT.NORMAL),
  deleteSnapshot: (snapshotId: number) => invokeWithTimeout<void>('delete_snapshot', { snapshotId }, TIMEOUT.NORMAL),
  getLearningStatus: () => invokeWithTimeout<LearningStatus>('get_learning_status', undefined, TIMEOUT.FAST),
  // Cycle1洁净度：已删除switchLearningMode（UI移除手动切换，防止运维误触，仅配置文件/API Key控制）
  // Cycle1洁净度：已删除getLearningDetails / runSimulation（独立页面删除，仅保留CLI脚本）
  sendNotification: (title: string, body: string) =>
    invokeWithTimeout<void>('send_notification', { title, body }, TIMEOUT.FAST),
  getTrendStats: (granularity: string, start: string, end: string) =>
    invokeWithTimeout<TrendStatsResponse>('get_trend_stats', { granularity, start, end }, TIMEOUT.NORMAL),
  getAttackDistribution: (start: string, end: string) =>
    invokeWithTimeout<AttackCategoryStat[]>('get_attack_distribution', { start, end }, TIMEOUT.NORMAL),
  getRealtimeMetrics: () => invokeWithTimeout<RealtimeMetrics>('get_realtime_metrics', undefined, TIMEOUT.FAST),
  getComparisonStats: (currentStart: string, currentEnd: string, baselineStart: string, baselineEnd: string) =>
    invokeWithTimeout<ComparisonStats>('get_comparison_stats', { currentStart, currentEnd, baselineStart, baselineEnd }, TIMEOUT.NORMAL),
  // Cycle1洁净度：已删除generateReport/listReports/getReport/deleteReport（Reports独立页面删除，完整报表走notifiers邮件推送）
  saveNotifierConfig: (channel: string, config: any) =>
    invokeWithTimeout<void>('save_notifier_config', { channel, config }, TIMEOUT.FAST),
  getNotifierConfig: (channel: string) =>
    invokeWithTimeout<any | null>('get_notifier_config', { channel }, TIMEOUT.FAST),
  testNotifier: (channel: string, config: any) =>
    invokeWithTimeout<any>('test_notifier', { channel, config }, TIMEOUT.SLOW),
  getDualLayerStats: () => invokeWithTimeout<DualLayerStats>('get_dual_layer_stats', undefined, TIMEOUT.FAST),
  // ── 输出护栏（模型→用户）数据接口 ──
  getOutputStats: () => invokeWithTimeout<OutputStats>('get_output_stats', undefined, TIMEOUT.FAST),
  getOutputHistory: (limit: number = 20) =>
    invokeWithTimeout<OutputHistoryResponse>('get_output_history', { limit }, TIMEOUT.FAST),
  getOutputTrend: (granularity: string = 'hour', start?: string, end?: string) =>
    invokeWithTimeout<OutputTrendResponse>('get_output_trend', { granularity, start, end }, TIMEOUT.NORMAL),
  // 输出护栏单次检测（Detect 页"输出侧护栏"标签）：返回打码后的实际文本
  checkOutput: (text: string, session: string = 'default') =>
    invokeWithTimeout<OutputProtectResponse>('check_output', { text, session }, TIMEOUT.PROTECT_COLD),
  // 输出护栏配置（Settings 专家模式）：读取生效快照 / 动态调校
  getOutputConfig: () =>
    invokeWithTimeout<OutputConfigResponse>('get_output_config', undefined, TIMEOUT.FAST),
  setOutputConfig: (config: Record<string, string | number | boolean>) =>
    invokeWithTimeout<OutputConfigResponse>('set_output_config', { config }, TIMEOUT.NORMAL),
  // ── 企业级运维：逃生通道 + 灰度部署 ──
  setEmergencyBypass: (enabled: boolean) =>
    invokeWithTimeout<EmergencyBypassState>('set_emergency_bypass', { enabled }, TIMEOUT.NORMAL),
  getEmergencyBypass: () =>
    invokeWithTimeout<EmergencyBypassState>('get_emergency_bypass', undefined, TIMEOUT.NORMAL),
  setGrayDeployRatio: (ratio: number) =>
    invokeWithTimeout<GrayDeployState>('set_gray_deploy_ratio', { ratio }, TIMEOUT.NORMAL),
  getGrayDeployRatio: () =>
    invokeWithTimeout<GrayDeployState>('get_gray_deploy_ratio', undefined, TIMEOUT.NORMAL),
  getBypassStats: () => invokeWithTimeout<BypassStats>('get_bypass_stats', undefined, TIMEOUT.NORMAL),
  // ── 上游模型配置（设置页可视化表单）──
  getUpstreamConfig: () => invokeWithTimeout<UpstreamConfig>('get_upstream_config', undefined, TIMEOUT.FAST),
  setUpstreamConfig: (config: UpstreamConfig) =>
    invokeWithTimeout<void>('set_upstream_config', { config }, TIMEOUT.NORMAL),
  // ── 平面端 V2 新接口（P1 中期优化，P2 实现）──
  scanModelServer: (ip: string) =>
    invokeWithTimeout<ModelScanResult>('scan_model_server', { ip }, TIMEOUT.NORMAL),
  connectModel: (modelName: string, port: number, ip?: string) =>
    invokeWithTimeout<{ success: boolean }>('connect_model', { modelName, port, ip }, TIMEOUT.NORMAL),
  markAsSafe: (text: string) =>
    invokeWithTimeout<{ success: boolean }>('mark_as_safe', { text }, TIMEOUT.FAST),
  getWeeklyReportPreview: () =>
    invokeWithTimeout<WeeklyReportPreview>('get_weekly_report_preview', undefined, TIMEOUT.NORMAL),
  generateWeeklyReport: (params: {
    start_date?: string;
    end_date?: string;
    format?: string;
    sections?: string[];
  }) =>
    invokeWithTimeout<{ file_path: string; file_size: number; format: string; summary: WeeklyReportPreview }>(
      'generate_weekly_report', params, TIMEOUT.SLOW
    ),
  exportReportFile: async (filePath: string, suggestedName?: string) => {
    // v1.3.4 修复: 改用 Tauri save dialog 让用户选择路径（非写死桌面）
    const { save } = await import('@tauri-apps/plugin-dialog');
    const ext = suggestedName?.endsWith('.pdf') ? ['pdf'] : ['html'];
    const dest = await save({
      defaultPath: suggestedName,
      filters: [{ name: '报告', extensions: ext }],
    });
    if (!dest) throw new Error('用户取消了保存');
    return invokeWithTimeout<string>('export_report_file', { filePath, destPath: dest }, TIMEOUT.NORMAL);
  },
  // v1.3.4 P1-2: 自动更新 — 网络 IO 用 SLOW 超时，避免 GitHub 访问慢导致前端假超时
  checkUpdate: () =>
    invokeWithTimeout<{ available: boolean; version?: string; body?: string; current_version?: string }>(
      'check_update', undefined, TIMEOUT.SLOW
    ),
  downloadAndInstallUpdate: () =>
    invokeWithTimeout<{ status: string }>('download_and_install_update', undefined, TIMEOUT.SLOW),
  dismissUpdate: (version?: string) =>
    invokeWithTimeout<void>('dismiss_update', { version }, TIMEOUT.FAST),
};
