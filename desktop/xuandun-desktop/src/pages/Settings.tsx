import { useState, useEffect } from 'react';
import { api } from '../services/tauriApi';

export default function Settings() {
  const [mode, setMode] = useState('balanced');
  const [autoStart, setAutoStart] = useState(false);
  const [interceptTraffic, setInterceptTraffic] = useState(true);
  const [warmupSafeText, setWarmupSafeText] = useState('');
  const [warmupAttackText, setWarmupAttackText] = useState('');
  const [warmupStatus, setWarmupStatus] = useState('');
  const [restarting, setRestarting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [auditReport, setAuditReport] = useState<string>('');
  const [hasKey, setHasKey] = useState(false);

  useEffect(() => {
    const loadConfig = async () => {
      try {
        const m = await api.getConfig('mode');
        if (m) setMode(m);
        const as = await api.getConfig('auto_start');
        if (as) setAutoStart(as === 'true');
        const it = await api.getConfig('intercept_traffic');
        if (it) setInterceptTraffic(it === 'true');
        const ws = await api.getConfig('warmup_safe_text');
        if (ws) setWarmupSafeText(ws);
        const wa = await api.getConfig('warmup_attack_text');
        if (wa) setWarmupAttackText(wa);
        const hk = await api.hasSecretKey();
        setHasKey(hk);
      } catch {
        // ignore
      }
    };
    loadConfig();
  }, []);

  const showMessage = (type: 'success' | 'error', text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 3000);
  };

  const handleModeChange = async (newMode: string) => {
    setMode(newMode);
    try {
      await api.setMode(newMode);
      await api.setConfig('mode', newMode);
      showMessage('success', '模式已更新');
    } catch {
      showMessage('error', '模式更新失败');
    }
  };

  const handleAutoStartChange = async (val: boolean) => {
    setAutoStart(val);
    try {
      await api.setConfig('auto_start', val ? 'true' : 'false');
      showMessage('success', '设置已保存');
    } catch {
      showMessage('error', '设置保存失败');
    }
  };

  const handleInterceptTrafficChange = async (val: boolean) => {
    setInterceptTraffic(val);
    try {
      await api.setConfig('intercept_traffic', val ? 'true' : 'false');
      showMessage('success', '设置已保存');
    } catch {
      showMessage('error', '设置保存失败');
    }
  };

  const handleWarmup = async () => {
    try {
      setWarmupStatus('预热中...');
      const safeTexts = warmupSafeText.split('\n').filter(t => t.trim());
      const attackTexts = warmupAttackText.split('\n').filter(t => t.trim());
      if (!safeTexts.length && !attackTexts.length) {
        setWarmupStatus('请输入至少一条预热文本');
        return;
      }
      const result = await api.warmup(safeTexts, attackTexts);
      await api.setConfig('warmup_safe_text', warmupSafeText);
      await api.setConfig('warmup_attack_text', warmupAttackText);
      setWarmupStatus(`预热成功: ${result.safe_count} 条良性, ${result.attack_count} 条攻击`);
    } catch (e: any) {
      setWarmupStatus(`预热失败: ${e}`);
    }
  };

  const handleRestart = async () => {
    setRestarting(true);
    try {
      await api.restartEngine();
      showMessage('success', '引擎已重启');
    } catch {
      showMessage('error', '重启失败');
    } finally {
      setRestarting(false);
    }
  };

  const handleStop = async () => {
    setStopping(true);
    try {
      await api.stopEngine();
      showMessage('success', '引擎已停止');
    } catch {
      showMessage('error', '停止失败');
    } finally {
      setStopping(false);
    }
  };

  const handleVerifyAudit = async () => {
    try {
      const report = await api.verifyAudit();
      if (report.chain_intact) {
        setAuditReport(`✅ 审计链完整: ${report.verified_entries}/${report.total_entries} 条记录验证通过`);
      } else {
        const broken = report.broken_links.map(([id, reason]: [number, string]) => `ID=${id}: ${reason}`).join('; ');
        setAuditReport(`⚠️ 审计链异常: ${report.verified_entries}/${report.total_entries} 通过, 断裂: ${broken}`);
      }
    } catch (e: any) {
      setAuditReport(`验证失败: ${e}`);
    }
  };

  const handleGenerateKey = async () => {
    try {
      const key = crypto.randomUUID();
      await api.storeSecretKey(key);
      setHasKey(true);
      showMessage('success', '密钥已生成并存储到系统密钥库');
    } catch (e: any) {
      showMessage('error', `密钥存储失败: ${e}`);
    }
  };

  const handleDeleteKey = async () => {
    try {
      await api.deleteSecretKey();
      setHasKey(false);
      showMessage('success', '密钥已从系统密钥库删除');
    } catch (e: any) {
      showMessage('error', `密钥删除失败: ${e}`);
    }
  };

  const modes = [
    { key: 'high_security', label: '高安全', desc: '最严格的防护策略，可能产生较多误报' },
    { key: 'balanced', label: '平衡', desc: '兼顾安全与可用性的推荐策略' },
    { key: 'low_false_positive', label: '低误报', desc: '减少误报，适合对可用性要求高的场景' },
  ];

  return (
    <div className="page settings-page">
      {message && (
        <div className={`alert-banner ${message.type === 'success' ? 'alert-success' : 'alert-danger'}`}>
          <span className="alert-icon">{message.type === 'success' ? '✅' : '⚠️'}</span>
          <span>{message.text}</span>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h3>防护模式</h3>
        </div>
        <div className="card-body">
          <div className="mode-cards">
            {modes.map((m) => (
              <div
                key={m.key}
                className={`mode-card ${mode === m.key ? 'mode-card-active' : ''}`}
                onClick={() => handleModeChange(m.key)}
              >
                <div className="mode-card-title">{m.label}</div>
                <div className="mode-card-desc">{m.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>通用设置</h3>
        </div>
        <div className="card-body">
          <div className="setting-item">
            <div className="setting-info">
              <div className="setting-label">开机自启动</div>
              <div className="setting-desc">系统启动时自动运行玄盾</div>
            </div>
            <label className="toggle">
              <input type="checkbox" checked={autoStart} onChange={(e) => handleAutoStartChange(e.target.checked)} />
              <span className="toggle-slider"></span>
            </label>
          </div>

          <div className="setting-item">
            <div className="setting-info">
              <div className="setting-label">流量拦截</div>
              <div className="setting-desc">启用实时流量拦截功能</div>
            </div>
            <label className="toggle">
              <input type="checkbox" checked={interceptTraffic} onChange={(e) => handleInterceptTrafficChange(e.target.checked)} />
              <span className="toggle-slider"></span>
            </label>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>领域自适应</h3>
        </div>
        <div className="card-body">
          <div className="form-group">
            <label className="form-label">良性预热文本</label>
            <textarea
              className="form-textarea"
              value={warmupSafeText}
              onChange={(e) => setWarmupSafeText(e.target.value)}
              placeholder="输入领域相关的良性文本，每行一条..."
              rows={3}
            />
          </div>
          <div className="form-group">
            <label className="form-label">攻击预热文本</label>
            <textarea
              className="form-textarea"
              value={warmupAttackText}
              onChange={(e) => setWarmupAttackText(e.target.value)}
              placeholder="输入已知的攻击样本，每行一条..."
              rows={3}
            />
          </div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <button className="btn btn-primary" onClick={handleWarmup}>提交预热</button>
            {warmupStatus && <span style={{ fontSize: '0.85em', color: warmupStatus.startsWith('预热成功') ? '#22c55e' : '#ef4444' }}>{warmupStatus}</span>}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>安全与审计</h3>
        </div>
        <div className="card-body">
          <div className="setting-item">
            <div className="setting-info">
              <div className="setting-label">审计日志完整性</div>
              <div className="setting-desc">验证日志哈希链是否完整未被篡改</div>
            </div>
            <button className="btn btn-primary" onClick={handleVerifyAudit}>验证</button>
          </div>
          {auditReport && <div style={{ marginTop: '8px', fontSize: '0.85em', padding: '8px', background: 'var(--bg-secondary)', borderRadius: '6px' }}>{auditReport}</div>}

          <div className="setting-item" style={{ marginTop: '12px' }}>
            <div className="setting-info">
              <div className="setting-label">密钥保护</div>
              <div className="setting-desc">将引擎密钥存储到操作系统密钥库{hasKey ? ' (已存储)' : ' (未设置)'}</div>
            </div>
            <div style={{ display: 'flex', gap: '6px' }}>
              {!hasKey && <button className="btn btn-primary" onClick={handleGenerateKey}>生成密钥</button>}
              {hasKey && <button className="btn btn-danger" onClick={handleDeleteKey}>删除密钥</button>}
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>引擎管理</h3>
        </div>
        <div className="card-body">
          <div className="engine-actions">
            <button className="btn btn-warning" onClick={handleRestart} disabled={restarting}>
              {restarting ? '重启中...' : '🔄 重启引擎'}
            </button>
            <button className="btn btn-danger" onClick={handleStop} disabled={stopping}>
              {stopping ? '停止中...' : '⏹ 停止引擎'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
