/**
 * 网关 API 客户端 — 连接玄盾网关后端
 */
const BASE = '/'
const TIMEOUT_MS = 10000  // 10秒超时
const MAX_RETRIES = 2     // 最多重试2次
let _apiKey: string | null = null

function headers(): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json' }
  if (_apiKey) h['X-API-Key'] = _apiKey
  return h
}

function setApiKey(key: string | null) {
  _apiKey = key
}

// 带超时和指数退避重试的 fetch 封装
// P0-A-4 修复：每次重试新建 AbortController，避免第一次超时后重试全失效
async function fetchWithRetry(path: string, options: RequestInit = {}, retries = MAX_RETRIES): Promise<Response> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
    const fetchOptions = { ...options, signal: controller.signal }

    try {
      const res = await fetch(BASE + path.replace(/^\//, ''), fetchOptions)
      clearTimeout(timer)
      return res
    } catch (e: any) {
      clearTimeout(timer)
      // 最后一次重试或非超时/网络错误则直接抛出
      if (attempt >= retries || (e.name !== 'AbortError' && e.name !== 'TypeError')) {
        throw new Error(`${path}: ${e.name === 'AbortError' ? '请求超时' : '网络错误'} (重试${attempt}次)`)
      }
      // 指数退避: 1s, 2s
      await new Promise(r => setTimeout(r, 1000 * Math.pow(2, attempt)))
    }
  }
  throw new Error(`${path}: 请求失败`)
}

export interface Stats {
  requests_total: number
  blocks_total: number
  passes_total: number
  errors_total: number
  block_rate: number
  p50_latency_ms: number
  p95_latency_ms: number
  uptime_seconds: number
  engine_version: string
  engine_ready: boolean
  redis: { backend: string; connected: boolean }
  audit_log: { backend: string; connected: boolean; buffer_size: number }
}

export interface Health {
  status: string
  message: string
  version: string
  uptime_seconds: number
  engine_ready: boolean
  metrics_snapshot: Record<string, number>
}

export interface Status {
  engine: string
  engine_ready: boolean
  redis: { backend: string; connected: boolean }
  postgres: { backend: string; connected: boolean; buffer_size: number }
  router: { models: string[]; model_count: number; strategy: string }
  global_counters: Record<string, number>
}

export interface ModelInfo {
  name: string; endpoint: string; type: string; weight: number
}

// 交互式模型配置（保存到 gateway/config.yaml）
export interface ModelItemConfig {
  id: string
  name: string
  endpoint: string
  type: string      // public / private
  api_key: string
  weight: number
}

export interface RoutingConfig {
  strategy: string  // weighted / round_robin / first_match
  default: string
}

export interface ModelsSaveResult {
  success: boolean
  previous_models: number
  current_models: number
  model_ids: string[]
  routing: RoutingConfig
}

export interface ProtectRequest {
  text: string
  direction?: 'input' | 'output'   // 检测方向：input=输入护栏，output=模型输出护栏
  session_id?: string
  model_id?: string
}

export interface ProtectResponse {
  allowed: boolean
  reason: string | null
  reject_stage: string | null
  latency_ms: number
}

export interface DetectResult {
  text: string
  allowed: boolean
  reason: string | null
  reject_stage: string | null
  latency_ms: number
  timestamp: number
}

async function get<T>(path: string): Promise<T> {
  const res = await fetchWithRetry(path, { headers: headers() })
  if (!res.ok) throw new Error(`${path}: ${res.status}`)
  if (path.includes('metrics')) return (await res.text()) as unknown as T
  return res.json()
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetchWithRetry(path, {
    method: 'POST',
    headers: headers(),
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) throw new Error(`${path}: ${res.status}`)
  return res.json()
}

export const api = {
  setApiKey,
  getMetrics: () => get<string>('metrics'),
  getHealth: () => get<Health>('health'),
  getStats: () => get<Stats>('api/v1/stats'),
  exportReport: (params: { start_date: string; end_date: string; format: string; sections?: string[] }) =>
    post<any>('api/v1/report', params),
  getStatus: () => get<Status>('api/v1/status'),
  getModels: () => get<{ models: Record<string, ModelInfo> } & Record<string, unknown>>('api/v1/models'),
  reloadConfig: () => post<{ success: boolean; previous_models: number; current_models: number }>('api/config/reload'),
  saveModels: (data: { models: ModelItemConfig[]; routing: RoutingConfig }) =>
    post<ModelsSaveResult>('api/config/models', data),
  protect: (text: string, direction?: 'input' | 'output', sessionId?: string, modelId?: string, source?: string) =>
    post<ProtectResponse>('api/v1/protect', { text, direction: direction || 'input', session_id: sessionId, model_id: modelId, source: source || 'manual' }),
  getMode: () => get<{ mode: string; version: number; available: string[] }>('api/v1/mode'),
  switchMode: (mode: string, version?: number) =>
    post<{ mode: string; previous: string; version: number; message: string }>('api/v1/mode', { mode, version }),
  getAudit: (sessionId?: string, event?: string, limit?: number, offset?: number) => {
    const params = new URLSearchParams()
    if (sessionId) params.set('session_id', sessionId)
    if (event) params.set('event', event)
    if (limit) params.set('limit', String(limit))
    if (offset) params.set('offset', String(offset))
    const qs = params.toString()
    return get<{ connected: boolean; records: Record<string, unknown>[]; total: number; message?: string }>(
      `api/v1/audit${qs ? '?' + qs : ''}`)
  },
  verifyAuditChain: () => get<{ valid: boolean; records_checked: number; reason?: string }>('api/v1/audit/verify'),
  getEmergency: () => get<{ enabled: boolean; activated_at: number | null; reason: string }>('api/v1/emergency'),
  toggleEmergency: (enabled: boolean, reason?: string) =>
    post<{ enabled: boolean; message: string }>('api/v1/emergency', { enabled, reason: reason || '' }),
  // ── 灰度部署 ──
  getGrayRatio: () => get<{ ratio: number }>('api/v1/gray'),
  setGrayRatio: (ratio: number) => post<{ ratio: number; message: string }>('api/v1/gray', { ratio }),
  // ── 输出护栏 / 敏感检测开关 ──
  getGuardrails: () => get<{ output_guardrail: boolean; sensitive_leak: boolean }>('api/v1/guardrails'),
  setGuardrails: (data: { output_guardrail?: boolean; sensitive_leak?: boolean }) =>
    post<{ output_guardrail: boolean; sensitive_leak: boolean; message: string }>('api/v1/guardrails', data),
  // ── 配置快照 ──
  listSnapshots: () => get<{ snapshots: Array<{ id: string; timestamp: string; reason: string; mode: string; sample_count: number }> }>('api/v1/snapshots'),
  createSnapshot: (reason?: string) => post<{ ok: boolean; id: string; path: string; reason: string; timestamp: string }>('api/v1/snapshots', { reason: reason || 'manual' }),
  restoreSnapshot: (id: string) => post<{ ok: boolean; id: string; timestamp: string; reason: string; message: string }>('api/v1/snapshots/restore', { id }),
  // ── 告警通道 ──
  getNotifiersConfig: () => get<{ channels: Record<string, any> }>('api/v1/notifiers/config'),
  saveNotifiersConfig: (channels: Record<string, any>) => post<{ status: string; active_channels: number }>('api/v1/notifiers/config', { channels }),
  testNotifier: (channel: string, config: any) => post<{ status: string; channel: string }>('api/v1/notifiers/test', { channel, config }),
  // ── 企业 API Key 授权查询（只读，由供应商离线签发） ──
  listKeys: () => get<{ configured: boolean; provider: string; keys: Array<{
    jti: string; sub: string; tier: string; quota: number; exp: number;
    usage: number; revoked: boolean }> }>('api/v1/keys'),
  revokeKey: (jti: string) => post<{ ok: boolean; jti: string }>('api/v1/keys/revoke', { jti }),
}
