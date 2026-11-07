/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   本地代理不可用时的统一引导。

   ★ 为什么要有这个组件
   ────────────────────────────────────────────────────────────
   勘合的检测、转发、日志全部在**本机引擎**里完成。引擎没起来时，
   界面能做的只有一件事：把「为什么打不开」和「你现在能做什么」说清楚。

   此前首页只写「请确认勘合代理已启动（127.0.0.1:18765）」+「重试」——
   那是一句用户**无法执行**的指令：他不知道引擎是什么、在哪启动，
   也不知道「端口被别的程序占了」「改过端口没重启」这两种最常见的原因。
   结果就是反复点重试，然后卸装重来。

   同一段话在首页与设置页各写一版必然漂移，所以收敛到这里。
*/

import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, Loader2, RefreshCw, Settings2 } from 'lucide-react';
import { api, currentProxyPort, humanizeLoadError } from '../services/api';
import { isTauri } from '../lib/tauriShim';
import { useToast } from './Toast';
import { useI18n } from '../i18n';

/**
 * 「启动多久算超时」的兜底：到点之后不再假装还在启动。
 *
 * ★ 为什么必须按**时间**判，而不能只按「失败几次」判
 * ────────────────────────────────────────────────────────────
 * 端口被别的程序占着时，请求不一定快速失败，可能长时间挂着不回。
 * 此时既没有 success 也没有 catch，失败计数一直是 0 ——
 * 界面就会永远停在「正在启动本地代理… 首次启动需要几秒」。
 * 用户等了一分钟，看到的是「再等几秒」，于是只能重装或放弃。
 *
 * 20 秒是实测的保守值：冷启动正常在 2~5 秒内就绪。
 */
export const BOOT_DEADLINE_MS = 20_000;

export function useBootDeadline(ms: number = BOOT_DEADLINE_MS): boolean {
  const [expired, setExpired] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setExpired(true), ms);
    return () => clearTimeout(t);
  }, [ms]);
  return expired;
}

export function EngineOffline({
  error,
  onRetried,
}: {
  /** 原始错误串（用于「技术细节」折叠与技术判据） */
  error?: string | null;
  /** 重启成功后的回调（父页面应据此重新拉取数据） */
  onRetried?: () => void;
}) {
  const toast = useToast();
  const { t } = useI18n();
  const [busy, setBusy] = useState(false);
  const [restarted, setRestarted] = useState(false);
  const err = humanizeLoadError(error);

  /**
   * 重启引擎。
   *
   * ★ 这是一次**真的**恢复动作：Rust 侧会停掉旧进程、重新拉起并等到就绪
   *   （最长约 60 秒）。所以按钮在飞期间必须锁住并说明「正在重启」——
   *   否则用户会连点几次，每次都让刚起来的引擎再死一次。
   */
  const handleRestart = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await api.restartEngine();
      setRestarted(true);
      toast.success(t('引擎已重启，正在重新读取数据'));
      onRetried?.();
    } catch (e) {
      toast.error(
        `${t('重启失败：')}${e instanceof Error ? e.message : String(e)}。`
        + t('可到「设置 → 运行状态」查看具体原因。'),
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="alert danger">
      <AlertTriangle size={17} strokeWidth={1.5} className="alert-icon" />
      <div style={{ minWidth: 0, flex: 1 }}>
        <b>{t('本地代理没有在运行')}</b>
        <div className="mt-8">
          {t('勘合的检测与转发都在本机引擎里完成。引擎没起来时，')}
          {t('界面读不到数据，AI 工具也不能通过勘合访问中转站。')}
        </div>

        <div className="field-label mt-16">{t('按顺序排查这三件事')}</div>
        <ol style={{ margin: '4px 0 0 18px', padding: 0, lineHeight: 1.9 }}>
          <li>
            <b>{t('先试一次重启')}</b>{t('：点下方「重启引擎」。若仍然起不来，')}
            {t('具体原因（端口被占用、配置损坏等）会写在')}
            <Link to="/settings#sec-engine"> {t('「设置 → 运行状态」')}</Link>。
          </li>
          <li>
            <b>{t('只有某一家连不上？')}</b>{t('那是它分配到的')}<b>{t('专属端口')}</b>{t('没起来，')}
            {t('其它入口其实是正常的：到「设置 → 多中转站」看该端口是否被占用，')}
            {t('换一个再试。专属端口改完')}<b>{t('立即生效，不用重启应用')}</b>。
          </li>
          <li>
            <b>{t('改过主端口？需要重启应用')}</b>{t('：「设置 → 代理配置」里的主端口')}
            {t('是引擎启动时绑定的，改完必须右键托盘「退出勘合」再打开')}
            {t('（只点窗口上的 × 不算退出）。')}
          </li>
        </ol>

        <div className="mt-8 faint" style={{ fontSize: 12 }}>
          {t('主端口：')}<span className="mono">127.0.0.1:{currentProxyPort()}</span>
          {t('（各家中转站的专属端口在「设置 → 多中转站」里查看）')}
        </div>

        <div className="btn-row mt-16" style={{ marginBottom: 0 }}>
          {isTauri() && (
            <button
              className="btn"
              onClick={() => void handleRestart()}
              disabled={busy}
            >
              {busy ? (
                <Loader2 size={15} strokeWidth={1.5} className="spin-icon" />
              ) : (
                <RefreshCw size={15} strokeWidth={1.5} />
              )}
              {busy ? t('正在重启引擎…') : restarted ? t('再次重启引擎') : t('重启引擎')}
            </button>
          )}
          <Link className="btn secondary" to="/settings#sec-engine">
            <Settings2 size={15} strokeWidth={1.5} />
            {t('查看运行状态')}
          </Link>
        </div>

        <details className="mt-8">
          <summary
            className="faint"
            style={{ cursor: 'pointer', fontSize: 12, listStyle: 'none' }}
          >
            {t('技术细节')}
          </summary>
          <div className="mono faint" style={{ fontSize: 12, marginTop: 4 }}>
            {err.detail}
          </div>
        </details>
      </div>
    </div>
  );
}
