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

export interface SimulationReport {
  mode: string;
  timestamp: string;
  elapsed_seconds: number;
  total_samples: number;
  attack_total: number;
  attack_blocked: number;
  benign_total: number;
  benign_blocked: number;
  block_rate: number;
  false_positive_rate: number;
  miss_rate: number;
  accuracy: number;
  avg_latency_ms: number;
  category_stats: Record<string, {
    name: string;
    total: number;
    blocked: number;
    passed: number;
    block_rate: number;
  }>;
  details: Array<{
    category_key: string;
    category_name: string;
    text_preview: string;
    expected: string;
    actual: string;
    allowed: boolean;
    correct: boolean | null;
    latency_ms: number;
    trust_level: string | null;
    domain_distance: number | null;
  }>;
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

export interface AgentInfo {
  name: string;
  process_name: string;
  pid: number | null;
  running: boolean;
  installed: boolean;
  policy_mode: string | null;
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

export interface ReportSummary {
  id: number;
  generated_at: string;
  report_type: string;
  period_start: string;
  period_end: string;
  format: string;
  summary: string | null;
  created_by: string | null;
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
}

import { invoke } from '@tauri-apps/api/core';

export const api = {
  getStatus: () => invoke<StatusResponse>('get_status'),
  protect: (text: string, session: string = 'default', mode: string = 'balanced') =>
    invoke<ProtectResponse>('protect', { req: { text, session, mode } }),
  setMode: (mode: string) => invoke<void>('set_mode', { mode }),
  discoverAgents: () => invoke<AgentInfo[]>('discover_agents'),
  getLogs: (filterAllowed?: boolean, limit?: number, offset?: number) =>
    invoke<LogResponse>('get_logs', { filterAllowed, limit, offset }),
  getConfig: (key: string) => invoke<string | null>('get_config', { key }),
  setConfig: (key: string, value: string) => invoke<void>('set_config', { key, value }),
  restartEngine: () => invoke<void>('restart_engine'),
  stopEngine: () => invoke<void>('stop_engine'),
  warmup: (safeTexts: string[], attackTexts: string[]) =>
    invoke<any>('warmup', { req: { safeTexts, attackTexts } }),
  verifyAudit: () => invoke<HashChainReport>('verify_audit'),
  storeSecretKey: (key: string) => invoke<void>('store_secret_key', { key }),
  getSecretKey: () => invoke<string>('get_secret_key'),
  deleteSecretKey: () => invoke<void>('delete_secret_key'),
  hasSecretKey: () => invoke<boolean>('has_secret_key'),
  createSnapshot: (label: string) => invoke<number>('create_snapshot', { label }),
  listSnapshots: () => invoke<[number, string, string][]>('list_snapshots'),
  restoreSnapshot: (snapshotId: number) => invoke<void>('restore_snapshot', { snapshotId }),
  startProxy: (port: number) => invoke<void>('start_proxy_cmd', { port }),
  stopProxy: () => invoke<void>('stop_proxy_cmd'),
  isProxyRunning: () => invoke<boolean>('is_proxy_running_cmd'),
  getLearningStatus: () => invoke<LearningStatus>('get_learning_status'),
  switchLearningMode: (mode: string) => invoke<any>('switch_learning_mode', { mode }),
  getLearningDetails: () => invoke<any>('get_learning_details'),
  runSimulation: (mode: string, categories?: string[], customTexts?: string[]) =>
    invoke<SimulationReport>('run_simulation', { mode, categories, customTexts }),
  sendNotification: (title: string, body: string) =>
    invoke<void>('send_notification', { title, body }),
  getTrendStats: (granularity: string, start: string, end: string) =>
    invoke<TrendStatsResponse>('get_trend_stats', { granularity, start, end }),
  getAttackDistribution: (start: string, end: string) =>
    invoke<AttackCategoryStat[]>('get_attack_distribution', { start, end }),
  getRealtimeMetrics: () => invoke<RealtimeMetrics>('get_realtime_metrics'),
  getComparisonStats: (currentStart: string, currentEnd: string, baselineStart: string, baselineEnd: string) =>
    invoke<ComparisonStats>('get_comparison_stats', { currentStart, currentEnd, baselineStart, baselineEnd }),
  generateReport: (reportType: string, start: string, end: string) =>
    invoke<number>('generate_report', { reportType, start, end }),
  listReports: (limit?: number) =>
    invoke<ReportSummary[]>('list_reports', { limit }),
  getReport: (reportId: number) =>
    invoke<any>('get_report', { reportId }),
  deleteReport: (reportId: number) =>
    invoke<void>('delete_report', { reportId }),
  saveNotifierConfig: (channel: string, config: any) =>
    invoke<void>('save_notifier_config', { channel, config }),
  getNotifierConfig: (channel: string) =>
    invoke<any | null>('get_notifier_config', { channel }),
  testNotifier: (channel: string, config: any) =>
    invoke<any>('test_notifier', { channel, config }),
};
