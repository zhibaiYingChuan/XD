/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   「始终允许」的高危判据列表（设置页）。

   ★ 为什么必须有撤销入口
   「始终允许」是为了不再重复打扰，但它是一次**放宽**：判据一旦
   写进允许表，同类高危就不再询问。如果没有可见的撤销入口，
   用户误点一次就只能改数据库 —— 等于把放宽变成了单向操作。
*/

import { useCallback, useEffect, useState } from 'react';

import { api } from '../services/api';
import type { DecisionAllowance } from '../services/api';
import { confirmDialog } from '../lib/confirm';
import { useI18n } from '../i18n';

export default function DecisionAllowances() {
  const { t } = useI18n();
  const [items, setItems] = useState<DecisionAllowance[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await api.listDecisionAllowances();
      setItems(res.items || []);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const revoke = async (item: DecisionAllowance) => {
    if (busy) return;
    const ok = await confirmDialog(
      t('撤销后，这组高危判据会重新弹窗询问。确定撤销吗？'),
    );
    if (!ok) return;
    setBusy(item.fingerprint);
    try {
      await api.removeDecisionAllowance(item.fingerprint);
      setItems((prev) => prev.filter((x) => x.fingerprint !== item.fingerprint));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="card" id="sec-decision-allowance">
      <div className="card-title">{t('高危拦截放行记录')}</div>
      <div className="field-hint">
        {t('你在拦截弹窗里选过「始终允许」的判据会列在这里。撤销后，同类拦截会重新询问你。')}
      </div>
      {loading ? (
        <div className="loading" style={{ marginTop: 10 }}>
          <span className="spinner" />
          {t('加载中...')}
        </div>
      ) : items.length === 0 ? (
        <div className="muted" style={{ marginTop: 8 }}>
          {t('还没有「始终允许」的记录。')}
        </div>
      ) : (
        <div style={{ marginTop: 8 }}>
          {items.map((item) => (
            <div
              key={item.fingerprint}
              style={{
                display: 'flex',
                gap: 12,
                alignItems: 'center',
                padding: '10px 0',
                borderTop: '1px solid var(--xd-border)',
              }}
            >
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 13, color: 'var(--xd-text)' }}>
                  {item.summary || t('未命名判据')}
                </div>
                <div className="field-hint" style={{ marginTop: 2 }}>
                  {new Date(item.last_seen * 1000).toLocaleString()} ·{' '}
                  {t('已放行')} {item.seen_count} {t('次')}
                </div>
              </div>
              <button
                className="btn secondary sm"
                disabled={busy === item.fingerprint}
                onClick={() => void revoke(item)}
                data-xd-allowance-revoke={item.fingerprint}
              >
                {t('撤销')}
              </button>
            </div>
          ))}
        </div>
      )}
      {error && (
        <div className="field-hint" style={{ color: 'var(--xd-danger)' }}>
          {error}
        </div>
      )}
    </div>
  );
}
