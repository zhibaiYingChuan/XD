/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   首次启动向导（3 步引导）— 消费级文案，不含技术术语。

   步骤 1：欢迎（说明玄盾做什么）
   步骤 2：配置 AI 工具（选择工具 + 填写中转站）
   步骤 3：完成
*/

import { useEffect, useState } from 'react';
import { Shield, ShieldCheck, CheckCircle2, ArrowRight, ArrowLeft, Sparkles } from 'lucide-react';
import { api, currentProxyPort, syncProxyPort, type PersonalConfig } from '../services/api';
import { useToast } from '../components/Toast';

type ToolChoice = 'cursor' | 'claude' | 'other';

const TOOL_INFO: Record<ToolChoice, { name: string; where: string }> = {
  cursor: { name: 'Cursor', where: '设置 → Models → API Base URL' },
  claude: { name: 'Claude Desktop', where: '配置文件中的 baseURL 字段' },
  other: { name: '其他工具', where: '工具的 API 设置页面' },
};

export default function Onboarding({ onFinish }: { onFinish: () => void }) {
  const toast = useToast();
  const [step, setStep] = useState(0);
  const [tool, setTool] = useState<ToolChoice>('cursor');
  const [relayName, setRelayName] = useState('我的中转站');
  const [relayUrl, setRelayUrl] = useState('');
  const [relayKey, setRelayKey] = useState('');
  const [model, setModel] = useState('');
  const [saving, setSaving] = useState(false);

  const canNext = step !== 1 || (relayUrl.trim() && relayKey.trim() && model.trim());

  // ★ P1-10：向导在 Layout 之外，需自行同步实际运行端口，
  //   否则步骤 3 会显示一个还没生效的地址。
  useEffect(() => {
    api
      .getActivePort()
      .then((p) => syncProxyPort(p))
      .catch(() => undefined);
  }, []);

  const handleSaveAndFinish = async () => {
    setSaving(true);
    try {
      // 先拉现有配置，保留其他字段
      let base: PersonalConfig | null = null;
      try {
        base = await api.getConfig();
      } catch {
        base = null;
      }
      if (!base) {
        toast.error('无法连接本地代理，请确认玄盾已启动');
        setSaving(false);
        return;
      }

      await api.updateConfig({
        relay: {
          name: relayName.trim() || '我的中转站',
          base_url: relayUrl.trim(),
          api_key: relayKey.trim(),
          model: model.trim(),
          enabled: true,
        },
        guard: {
          ...base.guard,
          security_level: 'balanced',
        },
      });
      toast.success('配置完成，玄盾已开始保护你的 AI 对话');
      onFinish();
    } catch (e) {
      toast.error(`保存失败：${e instanceof Error ? e.message : String(e)}`);
      setSaving(false);
    }
  };

  return (
    <div className="wizard-shell">
      <div className="wizard-card">
        {/* 步骤条 */}
        <div className="wizard-steps">
          {[0, 1, 2].map((i) => (
            <div
              key={i}
              className={`wizard-step-dot ${i === step ? 'active' : i < step ? 'done' : ''}`}
            />
          ))}
        </div>

        {/* 步骤 1：欢迎 */}
        {step === 0 && (
          <>
            <div className="wizard-icon">
              <Shield size={28} strokeWidth={1.5} />
            </div>
            <h1 className="wizard-title">欢迎使用道体·玄盾</h1>
            <div className="wizard-text">
              这是一款保护你在使用 AI 中转站时数据安全的工具。
              <br />
              它运行在你的电脑上，会检查：
              <ul>
                <li>中转站返回的内容是否被篡改（偷偷插入恶意命令）</li>
                <li>你发送的内容是否包含敏感信息（API 密钥、手机号等）</li>
                <li>中转站是否可信（是否保留你的对话记录）</li>
              </ul>
              <div className="muted" style={{ marginTop: 12, fontSize: 13 }}>
                整个过程都在本机完成，你的对话内容不会上传到任何服务器。
              </div>
            </div>
            <div className="wizard-actions">
              <span />
              <button className="btn" onClick={() => setStep(1)}>
                开始配置
                <ArrowRight size={15} strokeWidth={1.5} />
              </button>
            </div>
          </>
        )}

        {/* 步骤 2：配置 */}
        {step === 1 && (
          <>
            <div className="wizard-icon">
              <Sparkles size={28} strokeWidth={1.5} />
            </div>
            <h1 className="wizard-title">配置你的 AI 工具</h1>
            <div className="wizard-text">
              玄盾通过本地代理保护你的 AI 对话。你需要填写中转站信息，
              然后把 AI 工具的 API 地址改为玄盾的本地地址。
            </div>

            {/* 工具选择 */}
            <div className="field-label">你正在使用哪个工具？</div>
            <div className="tool-cards">
              {(Object.keys(TOOL_INFO) as ToolChoice[]).map((k) => (
                <div
                  key={k}
                  className={`tool-card ${tool === k ? 'active' : ''}`}
                  onClick={() => setTool(k)}
                >
                  <div className="tool-card-icon">
                    {k === 'cursor' ? (
                      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <path d="M4 4l16 8-16 8 3-8-3-8z" />
                      </svg>
                    ) : k === 'claude' ? (
                      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <path d="M12 3l9 5v8l-9 5-9-5V8l9-5z" />
                      </svg>
                    ) : (
                      <ShieldCheck size={26} strokeWidth={1.5} />
                    )}
                  </div>
                  <div className="tool-card-name">{TOOL_INFO[k].name}</div>
                </div>
              ))}
            </div>

            {/* 中转站信息 */}
            <div className="field">
              <label className="field-label" htmlFor="ob-name">
                中转站名称（便于识别）
              </label>
              <input
                id="ob-name"
                className="input"
                value={relayName}
                onChange={(e) => setRelayName(e.target.value)}
                placeholder="我的中转站"
              />
            </div>

            <div className="field">
              <label className="field-label" htmlFor="ob-url">
                中转站地址
              </label>
              <input
                id="ob-url"
                className="input mono"
                value={relayUrl}
                onChange={(e) => setRelayUrl(e.target.value)}
                placeholder="https://api.example.com"
              />
            </div>

            <div className="field">
              <label className="field-label" htmlFor="ob-key">
                中转站 API Key
              </label>
              <input
                id="ob-key"
                className="input mono"
                type="password"
                value={relayKey}
                onChange={(e) => setRelayKey(e.target.value)}
                placeholder="sk-..."
              />
              <div className="field-hint">
                这个 Key 只会保存在你的电脑上，玄盾不会上传
              </div>
            </div>

            <div className="field">
              <label className="field-label" htmlFor="ob-model">
                模型名称
              </label>
              <input
                id="ob-model"
                className="input mono"
                value={model}
                onChange={(e) => setModel(e.target.value)}
                placeholder="例如：gpt-4o"
              />
            </div>

            <div className="wizard-actions">
              <button className="btn secondary" onClick={() => setStep(0)}>
                <ArrowLeft size={15} strokeWidth={1.5} />
                上一步
              </button>
              <button
                className="btn"
                onClick={() => setStep(2)}
                disabled={!canNext}
              >
                下一步
                <ArrowRight size={15} strokeWidth={1.5} />
              </button>
            </div>
          </>
        )}

        {/* 步骤 3：完成 */}
        {step === 2 && (
          <>
            <div className="wizard-icon" style={{ background: 'linear-gradient(135deg, #00D4AA, #2B5FD7)' }}>
              <CheckCircle2 size={30} strokeWidth={1.5} />
            </div>
            <h1 className="wizard-title">配置完成</h1>
            <div className="wizard-text">
              玄盾正在运行，保护你的 AI 对话。
              <div className="mt-16">
                <div className="field-label">最后一步：修改 AI 工具的 API 地址</div>
                <div className="code-box mt-8">
                  http://127.0.0.1:{currentProxyPort()}/v1
                </div>
                <div className="field-hint">
                  在 {TOOL_INFO[tool].name} 的「{TOOL_INFO[tool].where}」中填入上面的地址，
                  并把 API Key 也改成你的中转站 Key。
                </div>
              </div>
            </div>
            <div className="wizard-actions">
              <button
                className="btn secondary"
                onClick={() => setStep(1)}
                disabled={saving}
              >
                <ArrowLeft size={15} strokeWidth={1.5} />
                返回修改
              </button>
              <button className="btn" onClick={handleSaveAndFinish} disabled={saving}>
                {saving ? '保存中...' : '完成并进入'}
                <ArrowRight size={15} strokeWidth={1.5} />
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
