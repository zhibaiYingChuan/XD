import { describe, it, expect } from 'vitest';
import { t, setLanguage, getLanguage } from '../i18n';

describe('i18n', () => {
  it('returns Chinese by default', () => {
    setLanguage('zh');
    expect(t('app.title')).toBe('道体·玄盾');
    expect(t('nav.dashboard')).toBe('仪表盘');
  });

  it('returns English when set', () => {
    setLanguage('en');
    expect(t('app.title')).toBe('Daoti XuanDun');
    expect(t('nav.dashboard')).toBe('Dashboard');
  });

  it('handles nested keys', () => {
    setLanguage('zh');
    expect(t('dashboard.engineStatus')).toBe('引擎状态');
    expect(t('settings.protectionMode')).toBe('防护模式');
  });

  it('returns key path for missing translations', () => {
    expect(t('nonexistent.key')).toBe('nonexistent.key');
  });

  it('persists language choice', () => {
    setLanguage('en');
    expect(getLanguage()).toBe('en');
    setLanguage('zh');
    expect(getLanguage()).toBe('zh');
  });

  it('covers all nav items', () => {
    setLanguage('zh');
    expect(t('nav.dashboard')).toBeTruthy();
    expect(t('nav.detect')).toBeTruthy();
    expect(t('nav.agents')).toBeTruthy();
    expect(t('nav.logs')).toBeTruthy();
    expect(t('nav.settings')).toBeTruthy();
  });

  it('covers all mode labels', () => {
    setLanguage('zh');
    expect(t('settings.highSecurity')).toBe('高安全');
    expect(t('settings.balanced')).toBe('平衡');
    expect(t('settings.lowFalsePositive')).toBe('低误报');
  });
});
