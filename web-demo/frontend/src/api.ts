// 道体·玄盾 Web Demo — API 调用层

const API_BASE = import.meta.env.DEV ? '' : (import.meta.env.VITE_API_BASE || '');

async function request<T>(path: string, options?: RequestInit & { timeoutMs?: number }): Promise<T> {
  const timeoutMs = options?.timeoutMs ?? 15000;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(`${API_BASE}${path}`, {
      ...options,
      signal: options?.signal ?? controller.signal,
      headers: { 'Content-Type': 'application/json', ...options?.headers },
    });
    if (!resp.ok) {
      const contentType = resp.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        const detail = Array.isArray(err.detail) ? (err.detail[0]?.msg || '参数校验失败') : (err.detail || `请求失败: ${resp.status}`);
        throw new Error(detail);
      }
      throw new Error(`服务暂不可用 (${resp.status})`);
    }
    return resp.json();
  } catch (e: any) {
    if (e.name === 'AbortError') throw new Error('请求超时，请检查网络或重试');
    if (!navigator.onLine) throw new Error('当前网络已断开，请检查网络连接');
    throw e;
  } finally {
    clearTimeout(timeoutId);
  }
}

// 类型定义
export interface ProtectResult {
  allowed: boolean;
  trust_level: string;
  reason: string;
  latency_ms: number | null;
  dual_layer: DualLayerStats;
}

export interface DualLayerStats {
  enabled: boolean;
  outer_gate: GateStats;
  inner_gate: GateStats;
}

export interface GateStats {
  total: number;
  rejects: number;
  passes: number;
  forwards: number;
  reject_rate: number;
  pass_rate: number;
  forward_rate: number;
  avg_latency_ms: number;
  learned_attack_count?: number;
  learned_safe_count?: number;
  learning_events?: number;
}

export interface LearningStatus {
  mode: string;
  sample_count: number;
  min_samples_for_switch: number;
  learning_progress: number;
  safe_prototypes: number;
  attack_prototypes: number;
  builtin_attacks_loaded: number;
}

export interface AttackSample {
  id: string;
  label: string;
  samples: string[];
  count: number;
}

export interface DemoAttacks {
  attack_types: AttackSample[];
  safe_samples: string[];
  total_attacks: number;
}

export interface BatchResult {
  attack_type: string;
  total: number;
  blocked: number;
  passed: number;
  results: Array<{ text: string; allowed: boolean; trust_level: string; reason: string }>;
  dual_layer: DualLayerStats;
}

export interface ShowcaseResult {
  attacks: { total: number; blocked: number; block_rate: number; results: Array<{ type: string; text: string; allowed: boolean; reason: string }> };
  safe: { total: number; passed: number; pass_rate: number; results: Array<{ text: string; allowed: boolean; reason: string }> };
  dual_layer: DualLayerStats;
  learning: LearningStatus;
}

// A/B 对比结果类型
export interface CompareResult {
  batch_total: number;
  single_layer: {
    blocked: number;
    passed: number;
    block_rate: number;
    description: string;
  };
  dual_layer: {
    blocked: number;
    passed: number;
    block_rate: number;
    extra_blocked: number;
    description: string;
  };
  improvement: {
    extra_blocked: number;
    rate_improvement: number;
  };
  results: Array<{ type: string; text: string; allowed: boolean; reason: string }>;
  dual_layer_stats: DualLayerStats;
}

// API 函数
export const api = {
  health: () => request<{ status: string; version: string; uptime: number; shield_ready: boolean }>('/api/health'),
  protect: (text: string, mode: string = 'balanced') =>
    request<ProtectResult>('/api/protect', { method: 'POST', body: JSON.stringify({ text, mode }) }),
  getStats: () => request<{ dual_layer: DualLayerStats; learning: LearningStatus }>('/api/stats'),
  getDemoAttacks: () => request<DemoAttacks>('/api/demo/attacks'),
  batchDemo: (attack_type: string) =>
    request<BatchResult>('/api/demo/batch', { method: 'POST', body: JSON.stringify({ attack_type }) }),
  safeDemo: () => request<{ total: number; passed: number; blocked: number; results: any[] }>('/api/demo/safe', { method: 'POST' }),
  showcase: (opts?: RequestInit & { timeoutMs?: number }) => request<ShowcaseResult>('/api/demo/showcase', opts),
  compare: (attack_type: string = 'all') =>
    request<CompareResult>('/api/demo/compare', { method: 'POST', body: JSON.stringify({ attack_type }) }),
};