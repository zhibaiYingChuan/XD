import { useState, useEffect, useCallback } from 'react';
import { api, LearningStatus } from '../services/tauriApi';

interface NotifierField {
  key: string;
  label: string;
  type: string;
  placeholder?: string;
}

function NotifierChannel({
  channel,
  label,
  icon,
  config,
  fields,
  onFieldChange,
  onSave,
  onTest,
  testing,
}: {
  channel: string;
  label: string;
  icon: string;
  config: any;
  fields: NotifierField[];
  onFieldChange: (channel: string, field: string, value: any) => void;
  onSave: (channel: string, config: any) => void;
  onTest: (channel: string, config: any) => void;
  testing: boolean;
}) {
  const enabled = config.enabled || false;
  return (
    <div className={`notifier-channel ${enabled ? 'notifier-enabled' : ''}`}>
      <div className="notifier-header">
        <span className="notifier-icon">{icon}</span>
        <span className="notifier-label">{label}</span>
        <label className="toggle toggle-sm">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => onFieldChange(channel, 'enabled', e.target.checked)}
          />
          <span className="toggle-slider"></span>
        </label>
      </div>
      {enabled && (
        <div className="notifier-fields">
          {fields.map((f) => (
            <div key={f.key} className="form-group form-group-inline">
              <label className="form-label form-label-sm">{f.label}</label>
              <input
                type={f.type}
                className="form-input"
                value={config[f.key] || ''}
                placeholder={f.placeholder || ''}
                onChange={(e) => onFieldChange(channel, f.key, e.target.value)}
              />
            </div>
          ))}
          <div className="notifier-actions">
            <button className="btn btn-sm btn-primary" onClick={() => onSave(channel, config)}>保存</button>
            <button className="btn btn-sm btn-secondary" onClick={() => onTest(channel, config)} disabled={testing}>
              {testing ? '测试中...' : '测试告警'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

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
  const [learning, setLearning] = useState<LearningStatus | null>(null);
  const [switchingMode, setSwitchingMode] = useState(false);
  const [notifierConfigs, setNotifierConfigs] = useState<Record<string, any>>({});
  const [testingChannel, setTestingChannel] = useState<string | null>(null);

  const fetchLearning = useCallback(async () => {
    try {
      const l = await api.getLearningStatus();
      setLearning(l);
    } catch {
      // ignore
    }
  }, []);

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
        const channels = ['dingtalk', 'feishu', 'email', 'webhook', 'syslog'];
        const configs: Record<string, any> = {};
        for (const ch of channels) {
          try {
            const cfg = await api.getNotifierConfig(ch);
            if (cfg) configs[ch] = cfg;
          } catch { /* ignore */ }
        }
        setNotifierConfigs(configs);
      } catch {
        // ignore
      }
    };
    loadConfig();
    fetchLearning();
    const interval = setInterval(fetchLearning, 5000);
    return () => clearInterval(interval);
  }, [fetchLearning]);

  const handleSwitchLearningMode = async (target: string) => {
    setSwitchingMode(true);
    try {
      await api.switchLearningMode(target);
      showMessage('success', `已切换到${target === 'protecting' ? '保护' : '观察'}模式`);
      await fetchLearning();
    } catch {
      showMessage('error', '模式切换失败');
    } finally {
      setSwitchingMode(false);
    }
  };

  const showMessage = (type: 'success' | 'error', text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 3000);
  };

  const handleModeChange = async (newMode: string) => {
    const oldMode = mode;
    setMode(newMode);
    try {
      await api.setMode(newMode);
      await api.setConfig('mode', newMode);
      showMessage('success', '模式已更新');
    } catch {
      setMode(oldMode);
      showMessage('error', '模式更新失败');
    }
  };

  const handleAutoStartChange = async (val: boolean) => {
    const oldVal = autoStart;
    setAutoStart(val);
    try {
      await api.setConfig('auto_start', val ? 'true' : 'false');
      showMessage('success', '设置已保存');
    } catch {
      setAutoStart(oldVal);
      showMessage('error', '设置保存失败');
    }
  };

  const handleInterceptTrafficChange = async (val: boolean) => {
    const oldVal = interceptTraffic;
    setInterceptTraffic(val);
    try {
      await api.setConfig('intercept_traffic', val ? 'true' : 'false');
      showMessage('success', '设置已保存');
    } catch {
      setInterceptTraffic(oldVal);
      showMessage('error', '设置保存失败');
    }
  };

  const handleWarmup = async () => {
    const safeTexts = warmupSafeText.split('\n').filter(t => t.trim());
    const attackTexts = warmupAttackText.split('\n').filter(t => t.trim());
    if (!safeTexts.length && !attackTexts.length) {
      setWarmupStatus('请输入至少一条预热文本');
      return;
    }
    setWarmupStatus('预热中...');
    try {
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

  const handleSaveNotifier = async (channel: string, config: any) => {
    try {
      await api.saveNotifierConfig(channel, config);
      setNotifierConfigs(prev => ({ ...prev, [channel]: config }));
      showMessage('success', `${channel} 配置已保存`);
    } catch (e: any) {
      showMessage('error', `保存失败: ${e}`);
    }
  };

  const handleTestNotifier = async (channel: string, config: any) => {
    setTestingChannel(channel);
    try {
      const result = await api.testNotifier(channel, config);
      if (result?.status === 'ok') {
        showMessage('success', `${channel} 测试告警发送成功`);
      } else {
        showMessage('error', `${channel} 测试告警发送失败`);
      }
    } catch (e: any) {
      showMessage('error', `测试失败: ${e}`);
    } finally {
      setTestingChannel(null);
    }
  };

  const handleNotifierFieldChange = (channel: string, field: string, value: any) => {
    setNotifierConfigs(prev => ({
      ...prev,
      [channel]: { ...(prev[channel] || {}), [field]: value },
    }));
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
          <h3>活性防护模式</h3>
          <span className="card-subtitle">观察→学习→自动切换架构</span>
        </div>
        <div className="card-body">
          {learning ? (
            <>
              <div className="learning-mode-display">
                <span className={`mode-badge ${learning.mode === 'observing' ? 'mode-observing' : 'mode-protecting'}`}>
                  {learning.mode === 'observing' ? '🟡 观察模式（学习中）' : '🛡️ 保护模式'}
                </span>
              </div>

              {learning.mode === 'observing' && (
                <div className="learning-progress-section">
                  <div className="learning-progress-label">
                    已学习：{learning.sample_count} / {learning.min_samples_for_switch} 条正常对话
                  </div>
                  <div className="learning-progress-bar-large">
                    <div className="learning-progress-fill-large" style={{ width: `${Math.round(learning.learning_progress * 100)}%` }}>
                      <span className="learning-progress-text">{Math.round(learning.learning_progress * 100)}%</span>
                    </div>
                  </div>
                  <div className="learning-prototypes-mini">
                    <span>安全原型: {learning.safe_prototypes}</span>
                    <span>攻击原型: {learning.attack_prototypes}</span>
                    <span>模拟拦截: {learning.would_block_count}</span>
                  </div>
                </div>
              )}

              <div className="mode-switch-buttons" style={{ marginTop: '16px' }}>
                <button
                  className={`btn ${learning.mode === 'observing' ? 'btn-warning' : 'btn-secondary'}`}
                  onClick={() => handleSwitchLearningMode('observing')}
                  disabled={switchingMode || learning.mode === 'observing'}
                >
                  🟡 切换到观察模式
                </button>
                <button
                  className={`btn ${learning.mode === 'protecting' ? 'btn-primary' : 'btn-secondary'}`}
                  onClick={() => handleSwitchLearningMode('protecting')}
                  disabled={switchingMode || learning.mode === 'protecting'}
                >
                  🛡️ 切换到保护模式
                </button>
              </div>

              {learning.mode === 'observing' && learning.sample_count < learning.min_samples_for_switch && (
                <div className="mode-switch-warning">
                  ⚠️ 样本不足（{learning.sample_count}/{learning.min_samples_for_switch}），提前切换到保护模式可能导致误报率升高
                </div>
              )}
            </>
          ) : (
            <div className="empty-state">加载学习中...</div>
          )}
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
            {warmupStatus && <span style={{ fontSize: '0.85em', color: warmupStatus.startsWith('预热成功') ? 'var(--success)' : 'var(--danger)' }}>{warmupStatus}</span>}
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
          <h3>告警通道</h3>
          <span className="card-subtitle">拦截事件自动推送到企业 IM / 邮件 / SIEM</span>
        </div>
        <div className="card-body">
          <NotifierChannel
            channel="dingtalk"
            label="钉钉机器人"
            icon="📱"
            config={notifierConfigs['dingtalk'] || {}}
            onFieldChange={handleNotifierFieldChange}
            onSave={handleSaveNotifier}
            onTest={handleTestNotifier}
            testing={testingChannel === 'dingtalk'}
            fields={[
              { key: 'webhook_url', label: 'Webhook URL', type: 'text', placeholder: 'https://oapi.dingtalk.com/robot/send?access_token=...' },
              { key: 'secret', label: '加签密钥（可选）', type: 'text', placeholder: 'SEC...' },
              { key: 'at_phones', label: '@手机号（逗号分隔）', type: 'text', placeholder: '13800138000,13900139000' },
            ]}
          />
          <NotifierChannel
            channel="feishu"
            label="飞书机器人"
            icon="💬"
            config={notifierConfigs['feishu'] || {}}
            onFieldChange={handleNotifierFieldChange}
            onSave={handleSaveNotifier}
            onTest={handleTestNotifier}
            testing={testingChannel === 'feishu'}
            fields={[
              { key: 'webhook_url', label: 'Webhook URL', type: 'text', placeholder: 'https://open.feishu.cn/open-apis/bot/v2/hook/...' },
              { key: 'secret', label: '签名密钥（可选）', type: 'text', placeholder: '' },
            ]}
          />
          <NotifierChannel
            channel="email"
            label="邮件告警 (SMTP)"
            icon="📧"
            config={notifierConfigs['email'] || {}}
            onFieldChange={handleNotifierFieldChange}
            onSave={handleSaveNotifier}
            onTest={handleTestNotifier}
            testing={testingChannel === 'email'}
            fields={[
              { key: 'smtp_host', label: 'SMTP 服务器', type: 'text', placeholder: 'smtp.gmail.com' },
              { key: 'smtp_port', label: '端口', type: 'text', placeholder: '465' },
              { key: 'username', label: '用户名', type: 'text', placeholder: '' },
              { key: 'password', label: '密码', type: 'password', placeholder: '' },
              { key: 'from_addr', label: '发件人', type: 'text', placeholder: 'xuandun@company.com' },
              { key: 'to_addrs', label: '收件人（逗号分隔）', type: 'text', placeholder: 'admin@company.com' },
            ]}
          />
          <NotifierChannel
            channel="webhook"
            label="Webhook 通用告警"
            icon="🔗"
            config={notifierConfigs['webhook'] || {}}
            onFieldChange={handleNotifierFieldChange}
            onSave={handleSaveNotifier}
            onTest={handleTestNotifier}
            testing={testingChannel === 'webhook'}
            fields={[
              { key: 'webhook_url', label: 'Webhook URL', type: 'text', placeholder: 'https://your-siem.example.com/api/alert' },
            ]}
          />
          <NotifierChannel
            channel="syslog"
            label="Syslog (SIEM)"
            icon="🖥️"
            config={notifierConfigs['syslog'] || {}}
            onFieldChange={handleNotifierFieldChange}
            onSave={handleSaveNotifier}
            onTest={handleTestNotifier}
            testing={testingChannel === 'syslog'}
            fields={[
              { key: 'host', label: '服务器地址', type: 'text', placeholder: '192.168.1.100' },
              { key: 'port', label: '端口', type: 'text', placeholder: '514' },
              { key: 'protocol', label: '协议 (udp/tcp)', type: 'text', placeholder: 'udp' },
              { key: 'facility', label: 'Facility', type: 'text', placeholder: 'local0' },
            ]}
          />
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
