export interface StatusResponse {
  running: boolean;
  healthy: boolean;
  mode: string;
  uptime: number;
  total_requests: number;
  total_blocked: number;
  block_rate: number;
}

export interface ProtectResponse {
  allowed: boolean;
  trust_level: string;
  reject_stage: string | null;
  domain_distance: number | null;
  timing_distance: number | null;
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
    invoke<ProtectResponse>('protect', { text, session, mode }),
  setMode: (mode: string) => invoke<void>('set_mode', { mode }),
  discoverAgents: () => invoke<AgentInfo[]>('discover_agents'),
  getLogs: (filterAllowed?: boolean, limit?: number, offset?: number) =>
    invoke<LogResponse>('get_logs', { filterAllowed, limit, offset }),
  getConfig: (key: string) => invoke<string | null>('get_config', { key }),
  setConfig: (key: string, value: string) => invoke<void>('set_config', { key, value }),
  restartEngine: () => invoke<void>('restart_engine'),
  stopEngine: () => invoke<void>('stop_engine'),
  warmup: (safeTexts: string[], attackTexts: string[]) =>
    invoke<any>('warmup', { safeTexts, attackTexts }),
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
};
