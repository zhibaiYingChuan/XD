import { describe, it, expect, beforeEach, vi } from 'vitest';
import { api } from '../services/tauriApi';
import { invoke } from '@tauri-apps/api/core';

// 使用 vi.mocked 获取真正的 mock 引用（由 setup.ts 的 vi.mock 注入）
const mockInvoke = vi.mocked(invoke);

describe('tauriApi', () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  describe('getStatus', () => {
    it('calls get_status command', async () => {
      const mockStatus = {
        running: true,
        healthy: true,
        mode: 'balanced',
        uptime: 100,
        total_requests: 50,
        total_blocked: 5,
        block_rate: 0.1,
      };
      mockInvoke.mockResolvedValue(mockStatus);

      const result = await api.getStatus();
      // invokeWithTimeout 传递 (command, args=undefined, timeoutMs) 给 invoke
      expect(mockInvoke).toHaveBeenCalledWith('get_status', undefined);
      expect(result).toEqual(mockStatus);
    });
  });

  describe('protect', () => {
    it('calls protect command with correct params', async () => {
      const mockResponse = {
        allowed: true,
        trust_level: 'HIGH',
        reject_stage: null,
        domain_distance: 0.5,
        timing_distance: 0.3,
        fallback: false,
      };
      mockInvoke.mockResolvedValue(mockResponse);

      const result = await api.protect('hello', 'sess1', 'balanced');
      expect(mockInvoke).toHaveBeenCalledWith('protect', {
        req: {
          text: 'hello',
          session: 'sess1',
          mode: 'balanced',
        },
      });
      expect(result.allowed).toBe(true);
    });
  });

  describe('setMode', () => {
    it('calls set_mode command', async () => {
      mockInvoke.mockResolvedValue(undefined);
      await api.setMode('high_security');
      expect(mockInvoke).toHaveBeenCalledWith('set_mode', { mode: 'high_security' });
    });
  });

  describe('getLogs', () => {
    it('calls get_logs with filter params', async () => {
      mockInvoke.mockResolvedValue({ entries: [], total: 0 });
      await api.getLogs(false, 20, 0);
      expect(mockInvoke).toHaveBeenCalledWith('get_logs', {
        filterAllowed: false,
        limit: 20,
        offset: 0,
      });
    });

    it('calls get_logs without filter', async () => {
      mockInvoke.mockResolvedValue({ entries: [], total: 0 });
      await api.getLogs(undefined, 100, 0);
      expect(mockInvoke).toHaveBeenCalledWith('get_logs', {
        filterAllowed: undefined,
        limit: 100,
        offset: 0,
      });
    });
  });

  describe('warmup', () => {
    it('calls warmup command with text arrays', async () => {
      mockInvoke.mockResolvedValue({ status: 'ok', safe_count: 2, attack_count: 1 });
      const result = await api.warmup(['safe1', 'safe2'], ['attack1']);
      expect(mockInvoke).toHaveBeenCalledWith('warmup', {
        req: {
          safeTexts: ['safe1', 'safe2'],
          attackTexts: ['attack1'],
        },
      });
    });
  });

  describe('verifyAudit', () => {
    it('calls verify_audit command', async () => {
      mockInvoke.mockResolvedValue({
        total_entries: 10,
        verified_entries: 10,
        broken_links: [],
        chain_intact: true,
      });
      const result = await api.verifyAudit();
      expect(result.chain_intact).toBe(true);
    });
  });

  describe('keyring operations', () => {
    it('storeSecretKey calls store_secret_key', async () => {
      mockInvoke.mockResolvedValue(undefined);
      await api.storeSecretKey('test-key');
      expect(mockInvoke).toHaveBeenCalledWith('store_secret_key', { key: 'test-key' });
    });

    it('hasSecretKey returns boolean', async () => {
      mockInvoke.mockResolvedValue(true);
      const result = await api.hasSecretKey();
      expect(result).toBe(true);
    });
  });
});
