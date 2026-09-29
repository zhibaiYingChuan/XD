/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   首次启动向导（4 步引导）— 消费级文案，不含技术术语。

   步骤 1：欢迎（说明玄盾做什么）
   步骤 2：激活（拿机器码 → 填激活码）
   步骤 3：配置 AI 工具（填写中转站信息）
   步骤 4：完成

   ★ 激活放在配置之前：用户第一时间就需要机器码去申请激活码，
     放在最后等于让他先配完一整套再发现用不了。
*/

import { useEffect, useState } from 'react';
import {
  Shield,
  CheckCircle2,
  ArrowRight,
  ArrowLeft,
  Sparkles,
  KeyRound,
  Copy,
  Laptop,
} from 'lucide-react';
import { api, currentProxyPort, syncProxyPort } from '../services/api';
import type { PersonalConfig, LicenseStatus } from '../services/api';
import { useToast } from '../components/Toast';
import { copyToClipboard } from '../lib/tauriShim';

export default function Onboarding({ onFinish }: { onFinish: () => void }) {
  const toast = useToast();
  // 0 欢迎 / 1 激活 / 2 配置 / 3 完成
  const [step, setStep] = useState(0);
  const [relayName, setRelayName] = useState('我的中转站');
  const [relayUrl, setRelayUrl] = useState('');
  const [relayKey, setRelayKey] = useState('');
  const [saving, setSaving] = useState(false);

  // ── 激活 ──
  const [license, setLicense] = useState<LicenseStatus | null>(null);
  const [code, setCode] = useState('');
  const [activating, setActivating] = useState(false);
  const [rebindOpen, setRebindOpen] = useState(false);
  const [rebindText, setRebindText] = useState('');

  // ★ 不强制激活：允许「先看看」，但会一直提醒。
  //   强制拦住不让进，等于在用户还没了解产品时就要掏钱，
  //   那是把试用变成了付费墙。
  //   中转站地址与 Key 是必填 —— 没有它们，玄盾无从转发，
  //   也就监控不了任何东西。
  const canNext = step !== 2 || (relayUrl.trim() && relayKey.trim());

  // ★ P1-10：向导在 Layout 之外，需自行同步实际运行端口，
  //   否则步骤 4 会显示一个还没生效的地址。
  useEffect(() => {
    api
      .getActivePort()
      .then((p) => syncProxyPort(p))
      .catch(() => undefined);
  }, []);

  // 进入激活步骤时才拉状态（此时引擎已由 Layout 拉起）
  useEffect(() => {
    if (step !== 1) return;
    api
      .getLicenseStatus()
      .then(setLicense)
      .catch(() => undefined);
  }, [step]);

  const handleActivate = async () => {
    const trimmed = code.trim();
    if (!trimmed) {
      toast.error('请输入激活码');
      return;
    }
    setActivating(true);
    try {
      const s = await api.activate(trimmed);
      setLicense(s);
      setCode('');
      toast.success('激活成功，玄盾已解锁完整防护');
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setActivating(false);
    }
  };

  const handleGenerateRebind = async () => {
    const trimmed = code.trim();
    if (!trimmed) {
      toast.error('请先在上方填写原激活码');
      return;
    }
    setActivating(true);
    try {
      const r = await api.buildRebindRequest(trimmed);
      setRebindText(r.request);
      const ok = await copyToClipboard(r.request);
      if (ok) toast.success('换机申请已复制，发给玄盾官方即可');
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setActivating(false);
    }
  };

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
          {[0, 1, 2, 3].map((i) => (
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
                开始
                <ArrowRight size={15} strokeWidth={1.5} />
              </button>
            </div>
          </>
        )}

        {/* 步骤 2：激活 */}
        {step === 1 && (
          <>
            <div className="wizard-icon">
              <KeyRound size={28} strokeWidth={1.5} />
            </div>
            <h1 className="wizard-title">激活玄盾</h1>

            {license?.activated ? (
              <>
                <div className="wizard-text">
                  <span className="badge safe">已激活</span>
                  {license.subject && <span className="muted"> 授权给 {license.subject}</span>}
                  {license.expiresAt && (
                    <div className="muted" style={{ marginTop: 8, fontSize: 13 }}>
                      有效期至 {new Date(license.expiresAt * 1000).toLocaleDateString('zh-CN')}
                    </div>
                  )}
                </div>
                <div className="wizard-actions">
                  <button className="btn secondary" onClick={() => setStep(0)}>
                    <ArrowLeft size={15} strokeWidth={1.5} />
                    上一步
                  </button>
                  <button className="btn" onClick={() => setStep(2)}>
                    下一步
                    <ArrowRight size={15} strokeWidth={1.5} />
                  </button>
                </div>
              </>
            ) : (
              <>
                <div className="wizard-text">
                  玄盾个人版需要激活码才能使用。
                  <br />
                  先把你的机器码发给玄盾官方，拿到激活码后填在下面。
                </div>

                <div className="field">
                  <label className="field-label">你的机器码</label>
                  <div className="code-box">{license?.machineCode ?? '（正在获取…）'}</div>
                  <div className="field-hint">复制这段发给玄盾官方，即可为你签发激活码</div>
                  {license && (
                    <div className="btn-row mt-8">
                      <button
                        className="btn secondary"
                        onClick={async () => {
                          const ok = await copyToClipboard(license.machineCode);
                          if (ok) toast.success('机器码已复制');
                          else toast.error('复制失败，请手动选中复制');
                        }}
                      >
                        <Copy size={14} strokeWidth={1.5} />
                        复制机器码
                      </button>
                    </div>
                  )}
                </div>

                <div className="field">
                  <label className="field-label" htmlFor="ob-code">
                    激活码
                  </label>
                  <textarea
                    id="ob-code"
                    className="input mono"
                    rows={2}
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    placeholder="XDACT-..."
                    spellCheck={false}
                  />
                </div>

                {license?.reason && (
                  <div
                    className="mt-8"
                    style={{ fontSize: 13, color: license.verifierAvailable ? 'var(--xd-suspect)' : 'var(--xd-danger)' }}
                  >
                    {license.reason}
                  </div>
                )}

                <div className="wizard-actions">
                  <button className="btn secondary" onClick={() => setStep(0)}>
                    <ArrowLeft size={15} strokeWidth={1.5} />
                    上一步
                  </button>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button
                      className="btn secondary"
                      onClick={() => setRebindOpen((v) => !v)}
                    >
                      <Laptop size={14} strokeWidth={1.5} />
                      换过电脑？
                    </button>
                    <button
                      className="btn"
                      onClick={() => void handleActivate()}
                      disabled={activating || !code.trim()}
                    >
                      {activating ? '激活中...' : '激活'}
                    </button>
                  </div>
                </div>

                {rebindOpen && (
                  <div className="field">
                    <div className="field-label">换机申请</div>
                    <div className="field-hint">
                      原激活码绑定了旧机器，换电脑后需要重新绑定。
                      在上方填入原激活码后生成，把整段发给玄盾官方。
                    </div>
                    <div className="code-box mt-8">{rebindText || '（尚未生成）'}</div>
                    <div className="btn-row mt-8">
                      <button
                        className="btn secondary"
                        onClick={() => void handleGenerateRebind()}
                        disabled={activating || !code.trim()}
                      >
                        生成换机申请
                      </button>
                    </div>
                  </div>
                )}

                <div className="btn-row" style={{ justifyContent: 'flex-end' }}>
                  <button className="btn ghost" onClick={() => setStep(2)}>
                    暂不激活，先看看
                  </button>
                </div>
              </>
            )}
          </>
        )}

        {/* 步骤 3：配置 */}
        {step === 2 && (
          <>
            <div className="wizard-icon">
              <Sparkles size={28} strokeWidth={1.5} />
            </div>
            <h1 className="wizard-title">配置你的 AI 工具</h1>
            <div className="wizard-text">
              玄盾通过本地代理保护你的 AI 对话。你需要填写中转站信息，
              然后把 AI 工具的 API 地址改为玄盾的本地地址。
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
              <div className="field-hint">
                粘贴中转站给你的地址即可（带不带 /v1 都行），玄盾会自动识别
              </div>
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

            <div className="wizard-actions">
              <button className="btn secondary" onClick={() => setStep(1)}>
                <ArrowLeft size={15} strokeWidth={1.5} />
                上一步
              </button>
              <button
                className="btn"
                onClick={() => setStep(3)}
                disabled={!canNext}
              >
                下一步
                <ArrowRight size={15} strokeWidth={1.5} />
              </button>
            </div>
          </>
        )}

        {/* 步骤 4：完成 */}
        {step === 3 && (
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
                  在你使用的 AI 工具的「API 地址 / Base URL」设置项中填入上面的地址，
                  并把 API Key 也改成你的中转站 Key。
                </div>
              </div>
            </div>
            <div className="wizard-actions">
              <button
                className="btn secondary"
                onClick={() => setStep(2)}
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
