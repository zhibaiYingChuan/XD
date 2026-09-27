/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   激活页 — 机器码展示 + 激活码输入 + 换机换绑。

   ★ 本页最重要的设计原则：**不许谎报状态**。
     「验不了」（引擎未启动 / 缺公钥）与「没激活」是两件完全不同的事，
     前者结论不可信。若统一显示成「激活码无效」，用户会反复换码
     却永远激活不了，且完全看不到真正的原因。
*/

import { useCallback, useEffect, useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  KeyRound,
  Copy,
  Check,
  RefreshCw,
  Laptop,
  AlertTriangle,
  Info,
} from 'lucide-react';
import { api, type LicenseStatus } from '../services/api';
import { useToast } from '../components/Toast';
import { copyToClipboard, isTauri } from '../lib/tauriShim';

type LoadState = 'loading' | 'ready' | 'unavailable';

/** 剩余天数的紧迫度（用于配色，越少越提醒） */
function urgencyClass(days: number): string {
  if (days <= 7) return 'danger';
  if (days <= 30) return 'suspect';
  return 'safe';
}
/** 一行「名称 — 值」。沿用项目既有的 field / field-label 约定。 */
function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="field">
      <div className="field-label">{label}</div>
      <div>{children}</div>
    </div>
  );
}

/** 提示条。kind 决定语气：info 中性 / warn 需要注意 / error 出问题。 */
function Notice({
  kind,
  children,
}: {
  kind: 'info' | 'warn' | 'error';
  children: React.ReactNode;
}) {
  const color =
    kind === 'error'
      ? 'var(--xd-danger)'
      : kind === 'warn'
        ? 'var(--xd-suspect)'
        : 'var(--xd-text-faint)';
  const Icon = kind === 'info' ? Info : kind === 'warn' ? AlertTriangle : ShieldAlert;
  return (
    <div
      className="mt-8"
      style={{ display: 'flex', gap: 8, alignItems: 'flex-start', color, fontSize: 13 }}
    >
      <Icon size={15} strokeWidth={1.5} style={{ flexShrink: 0, marginTop: 1 }} />
      <span>{children}</span>
    </div>
  );
}

export default function Activate() {
  const toast = useToast();
  const [loadState, setLoadState] = useState<LoadState>('loading');
  const [status, setStatus] = useState<LicenseStatus | null>(null);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  // 换机面板：collapsed=收起 / open=展开
  const [rebindOpen, setRebindOpen] = useState(false);
  const [rebindText, setRebindText] = useState('');

  const refresh = useCallback(async () => {
    try {
      const s = await api.getLicenseStatus();
      setStatus(s);
      setLoadState('ready');
    } catch {
      setStatus(null);
      setLoadState('unavailable');
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const handleActivate = async () => {
    const trimmed = code.trim();
    if (!trimmed) {
      toast.error('请输入激活码');
      return;
    }
    setBusy(true);
    try {
      const s = await api.activate(trimmed);
      setStatus(s);
      setCode('');
      toast.success('激活成功');
    } catch (e) {
      // 失败原因由后端给出，照原样呈现 —— 不做二次包装，
      // 免得把「验签组件不可用」说成「码无效」。
      toast.error(e instanceof Error ? e.message : String(e));
      // 失败后刷新：码可能已过期或被吊销，状态需要如实更新
      void refresh();
    } finally {
      setBusy(false);
    }
  };

  const handleGenerateRebind = async () => {
    const trimmed = code.trim();
    if (!trimmed) {
      toast.error('请先在上方填写原激活码');
      return;
    }
    setBusy(true);
    try {
      const r = await api.buildRebindRequest(trimmed);
      setRebindText(r.request);
      const ok = await copyToClipboard(r.request);
      setCopied(ok);
      if (ok) setTimeout(() => setCopied(false), 2000);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const copyMch = async () => {
    if (!status) return;
    const ok = await copyToClipboard(status.machineCode);
    if (ok) toast.success('机器码已复制');
    else toast.error('复制失败，请手动选中复制');
  };

  // ── 引擎不可达：如实说明，不假装「未激活」 ──
  if (loadState === 'unavailable') {
    return (
      <div style={{ maxWidth: 640 }}>
        <h1 className="page-title">激活</h1>
        <div className="card">
          <div className="card-title">
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
              <ShieldAlert size={18} strokeWidth={1.5} style={{ color: 'var(--xd-danger)' }} />
              暂时无法确认激活状态
            </span>
          </div>
          <p className="muted">
            本机代理没有运行，激活校验无法执行。
            <br />
            这<strong>不代表</strong>你的激活码有问题 —— 只是现在没法判断。
          </p>
          <div className="btn-row mt-16">
            <button className="btn secondary" onClick={() => void refresh()}>
              <RefreshCw size={15} strokeWidth={1.5} />
              重试
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (loadState === 'loading' || !status) {
    return (
      <div className="loading" style={{ height: 240 }}>
        <span className="spinner" />
        正在读取激活状态...
      </div>
    );
  }

  const s = status;

  return (
    <div style={{ maxWidth: 640 }}>
      <h1 className="page-title">激活</h1>

      {/* ── 已激活 ── */}
      {s.activated ? (
        <div className="card">
          <div className="card-title">
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
              <ShieldCheck size={18} strokeWidth={1.5} style={{ color: 'var(--xd-safe)' }} />
              已激活
            </span>
            <span className={`badge ${urgencyClass(s.remainingDays)}`}>
              剩余 {s.remainingDays} 天
            </span>
          </div>
          <Row label="授权给">{s.subject || '—'}</Row>
          <Row label="版本">{s.tier === 'personal-pro' ? '个人版 Pro' : '个人版'}</Row>
          <Row label="到期">
            {s.expiresAt ? new Date(s.expiresAt * 1000).toLocaleDateString('zh-CN') : '—'}
          </Row>
          <Row label="激活码 ID">
            <span className="mono faint">{s.jti || '—'}</span>
          </Row>
          {s.remainingDays <= 7 && (
            <Notice kind={s.remainingDays <= 0 ? 'error' : 'warn'}>
              {s.remainingDays <= 0
                ? '激活码已过期，玄盾已进入只读模式。'
                : `激活码将在 ${s.remainingDays} 天后过期。`}
              {' '}到期后防护会停止，记得提前续期。
            </Notice>
          )}
        </div>
      ) : (
        /* ── 未激活 ── */
        <div className="card">
          <div className="card-title">
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
              <KeyRound size={18} strokeWidth={1.5} style={{ color: 'var(--xd-suspect)' }} />
              尚未激活
            </span>
          </div>

          {/* ① 先让用户拿到机器码：不知道机器码就无从签发 */}
          <div className="field">
            <label className="field-label">本机机器码</label>
            <div className="code-box">{s.machineCode}</div>
            <div className="field-hint">申请激活码时，把这串机器码发给玄盾官方即可。</div>
            <div className="btn-row mt-8">
              <button className="btn secondary" onClick={() => void copyMch()}>
                <Copy size={14} strokeWidth={1.5} />
                复制机器码
              </button>
            </div>
          </div>

          <div className="field">
            <label className="field-label" htmlFor="act-code">
              激活码
            </label>
            <textarea
              id="act-code"
              className="input mono"
              rows={3}
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="XDACT-..."
              spellCheck={false}
            />
            <div className="field-hint">粘贴玄盾官方发给你的激活码（以 XDACT- 开头）</div>
          </div>

          {s.reason && (
            <Notice kind={s.verifierAvailable ? 'warn' : 'error'}>
              {s.reason}
              {!s.verifierAvailable && '（这是玄盾组件的问题，不是你的码有问题）'}
            </Notice>
          )}

          <div className="btn-row mt-16">
            <button className="btn" onClick={() => void handleActivate()} disabled={busy}>
              {busy ? '激活中...' : '激活'}
            </button>
          </div>

          {/* ② 换机：原码在新机上必然验不过，需要一条专门的出路 */}
          <div className="field">
            {rebindOpen ? (
              <>
                <div className="field-label">换机申请</div>
                <Notice kind="info">
                  在上方填入<strong>原激活码</strong>后生成，把整段发给玄盾官方。
                  官方会发回一张绑定本机的新码，粘贴到上面即可激活。
                </Notice>
                <div className="code-box mt-8">{rebindText || '（尚未生成）'}</div>
                <div className="btn-row mt-8">
                  <button
                    className="btn secondary"
                    onClick={() => void handleGenerateRebind()}
                    disabled={busy}
                  >
                    {rebindText ? '重新生成' : '生成换机申请'}
                  </button>
                  {rebindText && (
                    <button
                      className="btn secondary"
                      onClick={async () => {
                        const ok = await copyToClipboard(rebindText);
                        if (ok) {
                          setCopied(true);
                          setTimeout(() => setCopied(false), 2000);
                          toast.success('换机申请已复制');
                        } else {
                          toast.error('复制失败，请手动选中复制');
                        }
                      }}
                    >
                      {copied ? (
                        <Check size={14} strokeWidth={1.5} />
                      ) : (
                        <Copy size={14} strokeWidth={1.5} />
                      )}
                      {copied ? '已复制' : '复制'}
                    </button>
                  )}
                  <button className="btn ghost" onClick={() => setRebindOpen(false)}>
                    取消
                  </button>
                </div>
              </>
            ) : (
              <>
                <div className="field-hint">换了电脑或硬盘？原激活码在新机上用不了。</div>
                <div className="btn-row mt-8">
                  <button className="btn secondary" onClick={() => setRebindOpen(true)}>
                    <Laptop size={14} strokeWidth={1.5} />
                    生成换机申请
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {!isTauri() && (
        <div className="card mt-16">
          <Notice kind="warn">当前是浏览器预览模式，激活功能仅在桌面版可用。</Notice>
        </div>
      )}
    </div>
  );
}
