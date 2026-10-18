/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   设置页 — 设计原则：普通用户不需要理解技术细节。

   四大区块：
     A. 防护开关（3 个）
     B. 安全级别（宽松 / 均衡 / 严格）
     C. 代理配置（中转站地址 + API Key + 复制地址）
     D. 敏感信息脱敏（勾选哪些类型需要拦截）
*/

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Copy,
  Check,
  ExternalLink,
  AlertTriangle,
  ShieldX,
  Plus,
  X,
  RotateCcw,
  PlugZap,
  Loader2,
  CheckCircle2,
  Info,
  RefreshCw,
} from 'lucide-react';
import {
  api,
  CATEGORY_LABELS,
  currentProxyPort,
  syncProxyPort,
  displayDomain,
  humanizeLoadError,
  type PersonalConfig,
  type SecurityLevel,
  type RelayPrecheck,
  type RelayTestResult,
  type ConfiguredRelay,
  type EngineStatus,
} from '../services/api';
import { useToast } from '../components/Toast';
import { copyToClipboard, openExternal, isTauri } from '../lib/tauriShim';

// ══════════════════════════════════════════════════════════════
// 常量
// ══════════════════════════════════════════════════════════════

const SECURITY_LEVELS: Array<{
  value: SecurityLevel;
  title: string;
  desc: string;
}> = [
  {
    value: 'lenient',
    title: '宽松',
    desc: '仅拦截明确危险（如 rm -rf 删除命令），手机号/邮箱等仅记录不脱敏',
  },
  {
    value: 'balanced',
    title: '均衡（推荐）',
    desc: 'API 密钥/身份证/银行卡直接阻断，手机号/邮箱自动打码，危险响应告警',
  },
  {
    value: 'strict',
    title: '严格',
    desc: '所有敏感信息全部阻断，任何可疑响应都告警。误报率较高',
  },
];

const CATEGORY_ORDER = [
  'api_key',
  'aws_key',
  'private_key',
  'jwt',
  'idcard',
  'bankcard',
  'phone',
  'email',
  'custom',
];

/**
 * 把连通性测试返回的 HTTP 状态码翻译成用户看得懂的说法。
 *
 * ★ 光给一个「404」用户不知道意味着什么；补一句「接口不存在」
 *   他才知道该去核对地址，而不是怀疑自己的 Key 或网络。
 */
function describeRelayStatus(status: number): string {
  if (status === 401 || status === 403) return `${status}（Key 被拒绝）`;
  if (status === 404) return `${status}（接口不存在）`;
  if (status === 429) return `${status}（请求太频繁）`;
  if (status >= 500) return `${status}（对方服务器出错）`;
  return String(status);
}

/**
 * 取报错文本的首行作为「一句话原因」。
 *
 * ★ 引擎启动错误可能带着多行堆栈一起抛上来，直接铺开会把用户吓退，
 *   且他要的只是「为什么起不来」这一句。首行通常就是那句话，
 *   完整内容折叠起来给愿意核对/报障的人看即可。
 */
function firstLine(text: string): string {
  const line = text.split('\n')[0].trim();
  return line || text.trim();
}

/** 报错文本是否需要折叠（多行或过长时）——只显示首行、余下收进 details。 */
function isLongError(text: string): boolean {
  return text.includes('\n') || text.length > 100;
}

// ══════════════════════════════════════════════════════════════
// 页面
// ══════════════════════════════════════════════════════════════

export default function Settings() {
  const toast = useToast();
  const [config, setConfig] = useState<PersonalConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [newKeyword, setNewKeyword] = useState('');
  const [portInput, setPortInput] = useState('');
  const [portError, setPortError] = useState<string | null>(null);
  // ★ Phase 7：预检风险提示。非 null 时接管保存按钮，必须显式选择才能继续。
  const [relayRisk, setRelayRisk] = useState<RelayPrecheck | null>(null);
  // ★ 预检期间的忙碌标志。预检是**一次真实网络请求**，早先它发生在
  //   saving 置位之前，按钮既未禁用也无文案变化 —— 用户以为没点到，
  //   连点就会触发多次预检。这里把它独立出来，与 saving 一起锁住按钮。
  const [prechecking, setPrechecking] = useState(false);
  // ★ API Key 草稿：服务端返回的是掩码，绝不能让它进入可提交的状态。
  //   旧实现把掩码留在 config.relay.api_key 里，用户点一次「保存中转站配置」
  //   就会把 ``xxxx****yyyy`` 写回磁盘，真实 Key 被替换 —— 之后所有请求
  //   401，而配置页看不出任何异常，用户只会以为中转站封了他。
  const [keyDraft, setKeyDraft] = useState('');
  // ★ 真实连通性测试结果（发过真请求，非静态信誉判断）
  const [relayTest, setRelayTest] = useState<RelayTestResult | null>(null);
  const [testing, setTesting] = useState(false);
  // ★ 「测试连接」请求序号。见 handleTestRelay 处的说明：
  //   探针最长 45s，在飞请求的结论必须能被后续操作作废，
  //   否则会把基于旧地址的结论呈现给用户。
  const testSeqRef = useRef(0);
  const mountedRef = useRef(true);
  // ★ v0.1.0：已配置的中转站列表 + 切换中的操作锁。
  //   切换状态独立于 saving —— 保存配置与切换目标是两件事，
  //   混用会让用户在保存失败后连切换也点不动。
  const [configured, setConfigured] = useState<ConfiguredRelay[]>([]);
  const [switching, setSwitching] = useState(false);
  // ★ v0.1.0：新增中转站的草稿。
  //   必须独立于顶部的 keyDraft —— 那是「当前启用项」的 Key，
  //   两者共用一个 state 会让用户给第二家填的 Key
  //   被当成当前项的 Key 保存出去。
  // ★ adding(表单是否展开) 与 addingBusy(请求在飞) 必须是**两个** state：
  //   共用一个会让用户刚点开表单、什么都没干，
  //   按钮就已经显示「添加中…」—— 而实际并没有任何请求在发。
  //   那是在对用户说谎，CDP 实测抓到过这个形态。
  const [adding, setAdding] = useState(false);
  const [addingBusy, setAddingBusy] = useState(false);
  const [newRelay, setNewRelay] = useState({
    name: '', base_url: '', api_key: '',
  });

  // ★ 引擎运行状态 + 版本 + 重启中标志。
  //   engine 为 null 表示这一刻拿不到（浏览器预览模式没有本地引擎，
  //   或命令异常）—— 区块据此降级为不可用提示，而不是崩掉整个设置页。
  const [engine, setEngine] = useState<EngineStatus | null>(null);
  const [engineVersion, setEngineVersion] = useState<string | null>(null);
  const [restarting, setRestarting] = useState(false);

  // 已配置列表的加载刻意**不并入**上面的 load()：
  // 那是配置页的主数据，一旦它失败（引擎未起），
  // 切换列表也会跟着空掉，而两者本不该互相拖累。
  const loadConfigured = useCallback(async () => {
    try {
      const r = await api.getConfiguredRelays();
      if (mountedRef.current) setConfigured(r.relays ?? []);
    } catch {
      if (mountedRef.current) setConfigured([]);
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const load = useCallback(async () => {
    try {
      const c = await api.getConfig();
      if (mountedRef.current) {
        setConfig(c);
        setLoadError(null);
        // ★ P1-10：显示的必须是「实际运行中的端口」而非配置值。
        //   用户改过端口但还没重启时，两者不同 ——
        //   若用配置值引导用户去改 AI 工具，会让他填一个还没生效的地址。
        api
          .getActivePort()
          .then((p) => syncProxyPort(p))
          .catch(() => syncProxyPort(c?.server?.port));
      }
    } catch (e) {
      if (mountedRef.current) {
        setLoadError(e instanceof Error ? e.message : String(e));
      }
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    loadConfigured();
  }, [load, loadConfigured]);

  // ── E. 引擎运行状态 ──
  /**
   * 拉取引擎运行状态。
   *
   * ★ fetchVersion：引擎版本要连本机引擎的诊断接口才拿得到，
   *   只在「进入页面 / 重启完成」时取一次；轮询只刷状态，
   *   免得每 12 秒多发一次诊断请求。
   */
  const loadEngine = useCallback(async (fetchVersion: boolean) => {
    let s: EngineStatus | null = null;
    try {
      s = await api.getEngineStatus();
    } catch {
      // 命令异常（非浏览器降级）时同样按「不可用」展示 ——
      // 不能因为引擎状态取不到就让整个设置页报错。
      s = null;
    }
    if (!mountedRef.current) return;
    setEngine(s);
    if (!fetchVersion) return;
    if (s?.running) {
      try {
        const d = await api.getDiagnostics();
        if (mountedRef.current) setEngineVersion(d?.version ?? null);
      } catch {
        if (mountedRef.current) setEngineVersion(null);
      }
    } else if (mountedRef.current) {
      setEngineVersion(null);
    }
  }, []);

  // 进入设置页拉一次；之后每 12 秒轮询一次。
  // ★ 用递归 setTimeout 而非 setInterval：卸载时能确保清除掉「下一次」的
  //   定时器（参考 Layout.tsx StatusBar 的写法），页面切走后不再轮询。
  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = () => {
      if (cancelled) return;
      void loadEngine(false);
      timer = setTimeout(tick, 12000);
    };
    void loadEngine(true);
    timer = setTimeout(tick, 12000);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [loadEngine]);

  /**
   * 重启引擎。
   *
   * ★ 必须二次确认：重启要先停进程、再拉起并等就绪（最长 60 秒），
   *   期间正在进行的对话会中断。改成「点了就走」的话，用户在对话途中
   *   手滑点到就会莫名断线，还以为是玄盾坏了。
   */
  const handleRestartEngine = async () => {
    if (restarting) return;
    if (
      !window.confirm(
        '确定重启引擎吗？\n\n'
          + '重启期间正在进行的对话会短暂中断，请稍候片刻。',
      )
    ) {
      return;
    }
    setRestarting(true);
    try {
      await api.restartEngine();
      // 重启完成后立刻刷新：状态与版本都可能已变。
      await loadEngine(true);
      if (mountedRef.current) toast.success('引擎已重启');
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      // ★ 失败后同样刷新一次：Rust 侧会把失败原因写进 startup_error，
      //   刷新后区块里能长期看到它，而不是只剩一句转瞬即逝的 toast。
      await loadEngine(true);
      if (mountedRef.current) {
        toast.error(`重启失败：${msg}。可尝试重新打开玄盾。`);
      }
    } finally {
      if (mountedRef.current) setRestarting(false);
    }
  };

  // ★ v0.1.0：切换启用中的中转站。
  //   声明刻意放在 load 之后 —— 它要 await load()，
  //   放在前面会撞 TS2448（used before declaration）。
  const switchTo = useCallback(
    async (id: string, name: string) => {
      if (switching) return;
      setSwitching(true);
      try {
        await api.switchRelay(id);
        // 必须整体重载：切换后 config.relay 指向的是另一家，
        // 只刷新列表会让上面的地址输入框还显示旧那家的值。
        await load();
        await loadConfigured();
        if (mountedRef.current) toast.success(`已切换到「${name}」`);
      } catch (e) {
        if (mountedRef.current) {
          toast.error(
            `切换失败：${e instanceof Error ? e.message : String(e)}`,
          );
        }
      } finally {
        if (mountedRef.current) setSwitching(false);
      }
    },
    [switching, toast, load, loadConfigured],
  );

  // ★ v0.1.0：新增一家到列表（不设为启用）。
  const addRelay = useCallback(async () => {
    if (addingBusy) return;
    const name = newRelay.name.trim();
    const baseUrl = newRelay.base_url.trim();
    const key = newRelay.api_key.trim();
    // 前端也拦一道：不是「后端会拒绝」，而是**别让用户白等一趟**。
    // 但后端那道守卫不能省 —— 前端校验可以被绕过，
    // 而掩码 Key 落盘的后果是静默且不可逆的。
    if (!baseUrl) {
      toast.error('请填写中转站地址');
      return;
    }
    if (!key) {
      toast.error('请填写 API Key');
      return;
    }
    setAddingBusy(true);
    try {
      const r = await api.addRelay({
        name: name || '未命名', base_url: baseUrl, api_key: key,
      });
      // ★ 刻意**不**调 load()：新增不改变当前启用项，
      //   顶部那堆输入框不该被清掉 —— 用户填到一半的地址还在。
      await loadConfigured();
      setNewRelay({ name: '', base_url: '', api_key: '' });
      setAdding(false);
      if (mountedRef.current) toast.success(`已添加，现在共 ${r.total} 家`);
    } catch (e) {
      if (mountedRef.current) {
        toast.error(
          `添加失败：${e instanceof Error ? e.message : String(e)}`,
        );
      }
    } finally {
      if (mountedRef.current) setAddingBusy(false);
    }
  }, [addingBusy, newRelay, toast, loadConfigured]);

  /** 从列表移除一家。当前启用项不给按钮，后端也会拒。 */
  const dropRelay = useCallback(
    async (id: string, name: string) => {
      if (switching) return;
      // ★ 移除会当场删掉这一家的地址与 Key，且不可恢复 —— 必须先确认。
      //   此前一点即删：用户只是想换个默认目标，手滑点到「移除」就永久
      //   丢了一把 Key，而界面上再没有任何地方能找回它。
      if (
        !window.confirm(
          `确定移除「${name}」吗？\n\n`
            + '将删除该中转站的地址与 Key，此操作不可恢复。',
        )
      ) {
        return;
      }
      setSwitching(true);
      try {
        await api.removeRelay(id);
        await loadConfigured();
        if (mountedRef.current) toast.success(`已移除「${name}」`);
      } catch (e) {
        if (mountedRef.current) {
          toast.error(
            `移除失败：${e instanceof Error ? e.message : String(e)}`,
          );
        }
      } finally {
        if (mountedRef.current) setSwitching(false);
      }
    },
    [switching, toast, loadConfigured],
  );

  // ── 通用保存 ──
  const save = useCallback(
    async (patch: Partial<PersonalConfig>, successMsg: string) => {
      if (saving || !config) return false;
      setSaving(true);
      try {
        const r = await api.updateConfig(patch);
        if (mountedRef.current) setConfig(r.config);
        toast.success(successMsg);
        return true;
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        toast.error(`保存失败：${msg}`);
        // 失败时回滚到服务端真实状态
        await load();
        return false;
      } finally {
        if (mountedRef.current) setSaving(false);
      }
    },
    [config, saving, toast, load],
  );

  // ── A. 防护开关 ──
  const toggleGuard = async (key: keyof PersonalConfig['guard'], label: string) => {
    if (!config) return;
    const current = config.guard[key];
    if (typeof current !== 'boolean') return;
    // 乐观更新 + 失败回滚
    setConfig({ ...config, guard: { ...config.guard, [key]: !current } });
    const ok = await save(
      { guard: { ...config.guard, [key]: !current } as PersonalConfig['guard'] },
      `${label}已${!current ? '开启' : '关闭'}`,
    );
    if (!ok) await load();
  };

  // ── B. 安全级别 ──
  const changeLevel = async (level: SecurityLevel) => {
    if (!config || config.guard.security_level === level) return;
    await save(
      { guard: { ...config.guard, security_level: level } },
      `安全级别已切换为「${SECURITY_LEVELS.find((l) => l.value === level)?.title}」`,
    );
  };

  // ── C2. 代理端口（★ P1-10）──
  /**
   * 端口改动必须显式提示「需重启」。
   *
   * 原因：引擎的监听端口在进程启动时由 `--port` 参数确定，改配置不热生效。
   * 而桌面端（Rust 侧）在进程启动时锁定端口、本进程内不再重读
   * —— 这是刻意的：否则改配置后双方会各连各的端口，用户彻底失联
   * （连「改回旧端口」的自救操作都做不到）。
   * 所以正确路径是：保存配置 → 重启应用 → 新端口生效。
   */
  const savePort = async () => {
    if (!config) return;
    const raw = portInput.trim();
    if (!raw) {
      setPortError('请输入端口号');
      return;
    }
    const port = Number(raw);
    if (!Number.isInteger(port) || port < 1024 || port > 65535) {
      setPortError('端口需在 1024–65535 之间');
      return;
    }
    if (port === config.server.port) {
      // ★ 输入框一清空、又没有任何提示，用户会以为「没点到」而反复重试。
      //   这里明确回一句「无需修改」，把「静默无反应」变成一次可确认的反馈。
      setPortError(null);
      setPortInput('');
      toast.info('端口未变，无需修改');
      return;
    }
    const oldPort = config.server.port;
    const ok = await save(
      { server: { ...config.server, port } },
      `端口已改为 ${port}`,
    );
    if (ok) {
      setPortError(null);
      setPortInput('');
      // 必须告知「当前仍在用旧端口」——否则用户会直接去改 AI 工具配置，
      // 填了新地址却连不上，误以为玄盾坏了。
      toast.info(`当前玄盾仍运行在 ${oldPort}，重启玄盾后新端口才生效`);
    }
  };

  // ── C. 中转站配置 ──
  /**
   * 组装要提交的中转站配置。
   *
   * ★ api_key 一律取 keyDraft，绝不取 config.relay.api_key ——
   *   后者装的是服务端返回的掩码，提交它等于用 ``xxxx****yyyy``
   *   覆盖真实 Key。空串的语义是「保持原 Key 不变」（后端既有约定）。
   */
  const relayPayload = () => {
    if (!config) return null;
    return { ...config.relay, api_key: keyDraft };
  };

  /**
   * 保存中转站配置后就地做一次风险预检（Phase 7）。
   *
   * ★ 为什么必须在这里提示，而不是等首页：
   *   此刻是用户决定「要不要把真实数据交给这家」的前一秒。
   *   放到首页等于让用户先投钱再看风险，提示就失去了意义。
   *
   * ★ 为什么用预检而不是查信誉列表：
   *   信誉记录只在真正转发过一次请求后建立。全新配置的域名在列表里
   *   根本不存在，直接展示会变成「查无此站」，看起来像没问题。
   */
  const saveRelay = async () => {
    if (!config) return;
    // ★ 预检在飞时不能再点：否则同一份地址会被预检多次。
    //   与 save() 里 saving 的判据保持一致，只是范围扩到预检阶段。
    if (saving || prechecking) return;
    const baseUrl = config.relay.base_url.trim();
    // 先预检再保存：地址非法或高危时直接拦下，
    // 避免「已保存成功」的提示盖过风险，用户顺势点完就走。
    if (baseUrl) {
      // ★ 预检一开始就置 busy：按钮禁用 + 文案「检测中…」。
      //   结束（成功或失败）后在 finally 里复位，不能有遗留的假忙碌态。
      setPrechecking(true);
      try {
        const pc = await api.precheckRelay(baseUrl);
        if (pc.level === 'malicious' || pc.level === 'risky') {
          setRelayRisk(pc);
          return; // finally 仍会复位 prechecking
        }
        setRelayRisk(null);
      } catch {
        // 预检失败不阻断保存：这是附加提示，不能挡住正常配置流程
        setRelayRisk(null);
      } finally {
        if (mountedRef.current) setPrechecking(false);
      }
    }

    const payload = relayPayload();
    if (!payload) return;
    // 保存会作废在飞的测试：配置一旦落盘，
    // 先前那份「基于旧配置」的结论就不再对应用户看到的东西了。
    testSeqRef.current += 1;
    setRelayTest(null);
    const ok = await save({ relay: payload }, '中转站配置已保存并立即生效');
    if (ok) {
      // 保存成功后 api_key 会被掩码，需重新拉取
      setKeyDraft('');
      await load();
      // ★ 新配的一家也要出现在切换列表里。
      //   漏了这一步的话，用户保存完看不到自己刚加的中转站，
      //   会以为保存失败了 —— 而提示明明说的是「已保存」。
      await loadConfigured();
    }
  };

  /**
   * 用户在风险提示里明确选择「仍然使用」。
   *
   * ★ 必须是显式二次操作：提示的价值在于让用户真的做一次判断，
   *   预填好的「继续」按钮会让人下意识点掉，等于没有提示。
   */
  const forceSaveRelay = async () => {
    if (!config) return;
    const payload = relayPayload();
    if (!payload) return;
    testSeqRef.current += 1;
    setRelayTest(null);
    const ok = await save(
      { relay: payload },
      '中转站配置已保存并立即生效 — 请留意其数据留存行为',
    );
    setRelayRisk(null);
    if (ok) {
      setKeyDraft('');
      await load();
    }
  };

  /**
   * 真实连通性测试。
   *
   * ★ 为什么不能只靠「保存」来发现地址错：
   *   地址填错的症状是 404，而玄盾对上游错误是原样透传的 ——
   *   用户只会在真正发对话时看到一个 404，然后去怀疑中转站、
   *   怀疑 Key、怀疑网络。这里把「玄盾实际请求的地址」摆出来，
   *   让用户在配置这一步就能核对。
   */
  const handleTestRelay = async () => {
    if (!config) return;
    const baseUrl = config.relay.base_url.trim();
    if (!baseUrl) {
      toast.error('请先填写中转站地址');
      return;
    }
    // ★ 请求序号：探针最长可达 45s，期间用户可以改地址、改 Key。
    //   靠「onChange 里清空 relayTest」防陈旧是**不够**的 ——
    //   那是把「输入变了」与「结论作废」绑在一起，
    //   但在飞的请求返回时照样会 setRelayTest，把基于旧地址的结论重新画出来。
    //
    //   典型故障：测试 a.com（需 30s）→ 用户改成 b.com → 面板消失 →
    //   20s 后旧请求返回 → 面板显示「a.com 连接正常」。
    //   用户据此认为 b.com 可用，而 b.com 从未被探测过。
    const seq = ++testSeqRef.current;
    setTesting(true);
    setRelayTest(null);
    try {
      // 传 keyDraft 而非 config 里的掩码：用户没重填时是空串，
      // 引擎会回退到已保存的真实 Key。
      const r = await api.testRelay(baseUrl, keyDraft);
      // 序号不匹配说明用户已经改过输入或又点了一次：丢弃这次结论。
      if (!mountedRef.current || seq !== testSeqRef.current) return;
      setRelayTest(r);
      if (r.ok) toast.success(r.message);
      else toast.error(r.message);
    } catch (e) {
      if (mountedRef.current && seq === testSeqRef.current) {
        toast.error(`测试失败：${e instanceof Error ? e.message : String(e)}`);
      }
    } finally {
      if (mountedRef.current && seq === testSeqRef.current) setTesting(false);
    }
  };

  const handleCopyUrl = async () => {
    const ok = await copyToClipboard(proxyUrl);
    if (ok) {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
      toast.success('代理地址已复制');
    } else {
      toast.error('复制失败');
    }
  };

  // ── D. 敏感类型勾选 ──
  const toggleCategory = async (cat: string) => {
    if (!config) return;
    const next = { ...config.guard.enabled_categories, [cat]: !config.guard.enabled_categories[cat] };
    await save({ guard: { ...config.guard, enabled_categories: next } }, '脱敏设置已更新');
  };

  // ── 自定义关键词 ──
  const addKeyword = async () => {
    const kw = newKeyword.trim();
    if (!kw || !config) return;
    if (config.guard.custom_keywords.includes(kw)) {
      toast.error('该关键词已存在');
      return;
    }
    setNewKeyword('');
    await save(
      { guard: { ...config.guard, custom_keywords: [...config.guard.custom_keywords, kw] } },
      `已添加关键词「${kw}」`,
    );
  };

  const removeKeyword = async (kw: string) => {
    if (!config) return;
    await save(
      { guard: { ...config.guard, custom_keywords: config.guard.custom_keywords.filter((k) => k !== kw) } },
      `已移除关键词「${kw}」`,
    );
  };

  const resetKeywords = async () => {
    if (!config || config.guard.custom_keywords.length === 0) return;
    if (!window.confirm('确定清空全部自定义关键词吗？')) return;
    await save({ guard: { ...config.guard, custom_keywords: [] } }, '已清空自定义关键词');
  };

  // ★ P1-10：这里必须显示「当前实际运行」的端口，而不是 config.server.port。
  //   改端口后配置已落盘但引擎未重启，两者会不一致 ——
  //   若显示配置值，用户照着填进 AI 工具就会连不上（填了个还没生效的地址）。
  const proxyUrl = `http://127.0.0.1:${currentProxyPort()}/v1`;

  // ★ 引擎状态的展示映射：绿=运行中 / 灰=已停止 / 红=启动失败。
  //   判据优先级刻意是「先看 startup_error」—— 一次失败的重启会让
  //   running 与 startup_error 同时为真，此时用户真正要知道的是「它失败了」，
  //   而不是被显示成「运行中」。
  const engineView: { label: string; badge: string } = !engine
    ? { label: '读取中…', badge: 'neutral' }
    : engine.startup_error
      ? { label: '启动失败', badge: 'danger' }
      : engine.running
        ? { label: '运行中', badge: 'safe' }
        : { label: '已停止', badge: 'neutral' };

  // ══════════════════════════════════════════════════════════
  // 渲染
  // ══════════════════════════════════════════════════════════

  if (loading) {
    return (
      <div className="loading">
        <span className="spinner" />
        加载设置...
      </div>
    );
  }

  if (loadError || !config) {
    // 原始报错翻译成「怎么了 + 怎么办」，原始信息收进折叠的技术细节。
    const err = humanizeLoadError(loadError);
    return (
      <div>
        <div className="page-header">
          <h1 className="page-title">设置</h1>
        </div>
        <div className="alert danger">
          <AlertTriangle size={17} strokeWidth={1.5} className="alert-icon" />
          <div>
            <b>无法连接本地代理</b>
            <div className="mt-8">{err.message}</div>
            <details className="mt-8">
              <summary
                className="faint"
                style={{ cursor: 'pointer', fontSize: 12, listStyle: 'none' }}
              >
                技术细节
              </summary>
              <div className="mono faint" style={{ fontSize: 12, marginTop: 4 }}>
                {err.detail}
              </div>
            </details>
            <div className="mt-8 faint">
              请确认玄盾代理已启动（127.0.0.1:{currentProxyPort()}）。
            </div>
          </div>
        </div>
        <button className="btn" onClick={load}>
          重试
        </button>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 720 }}>
      <div className="page-header">
        <h1 className="page-title">设置</h1>
        <p className="page-subtitle">所有检测都在本机完成，不上传任何数据</p>
      </div>

      {/* ═══ A. 防护开关 ═══ */}
      <div className="card">
        <div className="card-title">防护开关</div>

        <div className="switch-row">
          <div>
            <div className="switch-label">响应验证</div>
            <div className="switch-desc">
              检查中转站返回的内容是否被篡改（恶意工具调用、隐藏指令等）
            </div>
          </div>
          <label className="switch">
            <input
              type="checkbox"
              checked={config.guard.enable_response_verify}
              disabled={saving}
              onChange={() => toggleGuard('enable_response_verify', '响应验证')}
            />
            <span className="switch-slider" />
          </label>
        </div>

        <div className="switch-row">
          <div>
            <div className="switch-label">请求脱敏</div>
            <div className="switch-desc">
              发送前自动遮住 API 密钥、手机号等，回答回来后自动还原成原文
            </div>
          </div>
          <label className="switch">
            <input
              type="checkbox"
              checked={config.guard.enable_request_sanitize}
              disabled={saving}
              onChange={() => toggleGuard('enable_request_sanitize', '请求脱敏')}
            />
            <span className="switch-slider" />
          </label>
        </div>

        <div className="switch-row">
          <div>
            <div className="switch-label">中转站评估</div>
            <div className="switch-desc">评估中转站可信度，看它是否保留你的对话、是否在已知的恶意名单里</div>
          </div>
          <label className="switch">
            <input
              type="checkbox"
              checked={config.guard.enable_reputation}
              disabled={saving}
              onChange={() => toggleGuard('enable_reputation', '中转站评估')}
            />
            <span className="switch-slider" />
          </label>
        </div>
      </div>

      {/* ═══ B. 安全级别 ═══ */}
      <div className="card">
        <div className="card-title">安全级别</div>
        <div className="radio-cards">
          {SECURITY_LEVELS.map((lv) => (
            <label
              key={lv.value}
              className={`radio-card ${config.guard.security_level === lv.value ? 'active' : ''}`}
            >
              <input
                type="radio"
                name="security_level"
                checked={config.guard.security_level === lv.value}
                disabled={saving}
                onChange={() => changeLevel(lv.value)}
              />
              <div>
                <div className="radio-title">{lv.title}</div>
                <div className="radio-desc">{lv.desc}</div>
              </div>
            </label>
          ))}
        </div>
      </div>

      {/* ═══ C. 代理配置 ═══ */}
      <div className="card">
        <div className="card-title">代理配置</div>

        <div className="field">
          <label className="field-label" htmlFor="relay-name">
            中转站名称
          </label>
          <input
            id="relay-name"
            className="input"
            placeholder="例如：我的 OpenAI 中转"
            value={config.relay.name}
            disabled={saving}
            onChange={(e) => setConfig({ ...config, relay: { ...config.relay, name: e.target.value } })}
          />
        </div>

        <div className="field">
          <label className="field-label" htmlFor="relay-url">
            中转站地址
          </label>
          <input
            id="relay-url"
            className="input mono"
            placeholder="https://api.example.com"
            value={config.relay.base_url}
            disabled={saving || testing}
            onChange={(e) => {
              setConfig({ ...config, relay: { ...config.relay, base_url: e.target.value } });
              // 地址一改，上一次的测试结论就作废了。
              // ★ 同时递增序号作废**在飞**的请求：只清面板不够，
              //   旧请求返回时会把基于旧地址的结论重新画出来。
              testSeqRef.current += 1;
              setRelayTest(null);
            }}
          />
          <div className="field-hint">
            粘贴中转站给你的地址即可 —— 带不带 /v1、是否连完整端点一起复制都行，
            玄盾会自动识别
          </div>
        </div>

        <div className="field">
          <label className="field-label" htmlFor="relay-key">
            中转站 API Key
          </label>
          <input
            id="relay-key"
            className="input mono"
            type="password"
            placeholder={
              config.relay.api_key ? '留空则保持当前 Key 不变' : '粘贴中转站给你的 API Key'
            }
            value={keyDraft}
            disabled={saving || testing}
            onChange={(e) => {
              setKeyDraft(e.target.value);
              testSeqRef.current += 1;
              setRelayTest(null);
            }}
          />
          <div className="field-hint">
            {config.relay.api_key
              ? `当前：${config.relay.api_key}（留空则保持不变）`
              : '尚未配置'}
          </div>
        </div>

        {/* ★ 真实连通性测试。
            地址填错的症状是 404，用户在真正发对话之前无从发现自己
            填的是完整端点、少了一层或路径不对。这里把「玄盾实际会请求的
            地址」摆出来，让配置这一步就能核对，而不是等用不了再猜。 */}
        <div className="field">
          <div className="btn-row" style={{ marginTop: 0, alignItems: 'center' }}>
            <button className="btn secondary" onClick={handleTestRelay} disabled={saving || testing}>
              {testing ? (
                <Loader2 size={14} strokeWidth={1.5} className="spin-icon" />
              ) : (
                <PlugZap size={14} strokeWidth={1.5} />
              )}
              {testing ? '测试中…' : '测试连接'}
            </button>
            <span className="faint" style={{ fontSize: 12 }}>
              会向该中转站发出一次真实请求，确认地址和 Key 是否可用
            </span>
          </div>

          {relayTest && (
            <div
              className={`alert ${
                relayTest.ok ? 'safe' : relayTest.kind === 'auth' ? 'suspect' : 'danger'
              }`}
              style={{ marginTop: 12, marginBottom: 0 }}
            >
              {relayTest.ok ? (
                <Check size={17} strokeWidth={1.5} className="alert-icon" />
              ) : relayTest.kind === 'auth' ? (
                <AlertTriangle size={17} strokeWidth={1.5} className="alert-icon" />
              ) : (
                <ShieldX size={17} strokeWidth={1.5} className="alert-icon" />
              )}
              <div style={{ minWidth: 0, flex: 1 }}>
                <b>{relayTest.message}</b>
                <div className="mt-8 faint" style={{ fontSize: 12 }}>
                  玄盾请求的地址：<span className="mono">{relayTest.request_url}</span>
                </div>
                {/* ★ 状态码与耗时都翻译成人话：光一个「404」用户不知道意味着什么，
                    「1.2 秒」也比「1234 ms」更贴近体感。 */}
                <div className="mt-8 faint" style={{ fontSize: 12 }}>
                  {relayTest.status !== null
                    && `对方返回 ${describeRelayStatus(relayTest.status)} · `}
                  {`用时 ${(relayTest.elapsed_ms / 1000).toFixed(1)} 秒`}
                </div>
                {/* ★ 上游原始响应体：只对排障有用，不该糊在脸上。
                    给个标题、默认折叠起来，愿意核对的人再展开。 */}
                {!relayTest.ok && relayTest.raw && (
                  <details className="mt-8">
                    <summary
                      className="faint"
                      style={{ fontSize: 12, cursor: 'pointer', listStyle: 'none' }}
                    >
                      对方返回的内容（仅用于排查）
                    </summary>
                    <div
                      className="mono faint"
                      style={{ fontSize: 12, marginTop: 4, wordBreak: 'break-all' }}
                    >
                      {relayTest.raw}
                    </div>
                  </details>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Phase 7：中转站风险提示（预检命中时才出现） */}
        {relayRisk && (
          <div
            className={`alert ${relayRisk.level === 'malicious' ? 'danger' : 'suspect'}`}
            style={{ marginBottom: 16 }}
          >
            {relayRisk.level === 'malicious' ? (
              <ShieldX size={17} strokeWidth={1.5} className="alert-icon" />
            ) : (
              <AlertTriangle size={17} strokeWidth={1.5} className="alert-icon" />
            )}
            <div style={{ minWidth: 0, flex: 1 }}>
              <b>
                {relayRisk.level === 'malicious'
                  ? '这家中转站已被列入高危名单'
                  : '这家中转站存在较高风险'}
              </b>
              <div className="mt-8">
                你的 AI 对话会经过 <span className="mono">{displayDomain(relayRisk.domain)}</span> 转发，
                对方能看到并保留全部内容。
              </div>
              {relayRisk.notes.length > 0 && (
                <div className="mt-8 faint" style={{ fontSize: 12 }}>
                  判定依据：
                  {relayRisk.notes.map((n) => (
                    <div key={n}>· {n}</div>
                  ))}
                </div>
              )}
              <div className="btn-row mt-16" style={{ marginBottom: 0 }}>
                <button className="btn danger" onClick={forceSaveRelay} disabled={saving}>
                  我了解风险，仍然使用
                </button>
                <button className="btn secondary" onClick={() => setRelayRisk(null)}>
                  换个中转站
                </button>
              </div>
            </div>
          </div>
        )}

        <button
          className="btn mb-24"
          onClick={relayRisk ? forceSaveRelay : saveRelay}
          // ★ 预检期间也要禁用：否则用户连点会触发多次预检。
          disabled={saving || prechecking}
        >
          {saving ? '保存中...' : prechecking ? '检测中…' : '保存中转站配置'}
        </button>

        {/* ═══ 多中转站 ═══ */}
        {/* ★ v0.1.0：多中转站切换
            ——
            为什么要显式切换而不是自动路由：
            带一个请求只发往一家，带宽不会被摊薄，
            多配几家不会变慢（只多一次哈希查找，微秒级）。
            反过来，自动故障转移必须靠探活，
            而探活是真实请求 —— 本机实测平均延迟 13 秒，
            拿它做后台探测等于持续制造慢请求。
            而且自动切换会让「这次扣了谁的钱」变得不可知，
            多中转站场景下最需要确定的恰恰就是这件事。 */}
        <div className="card relay-section">
          <div className="card-title">
            <span>已配置的中转站</span>
            <span className="relay-count">{configured.length} 家</span>
          </div>

          {configured.length === 0 ? (
            <div className="relay-empty">
              <Info size={16} strokeWidth={1.5} />
              <span>还没有配置中转站。在上方填入地址与 Key 后保存即可。</span>
            </div>
          ) : (
            <>
              <div className="relay-cards">
                {configured.map((r) => (
                  <div key={r.id} className={`relay-card ${r.active ? 'active' : ''}`}>
                    <span className={`relay-card-icon ${r.active ? 'active' : ''}`}>
                      {r.active ? (
                        <CheckCircle2 size={16} strokeWidth={1.8} />
                      ) : (
                        <Info size={16} strokeWidth={1.5} />
                      )}
                    </span>

                    <div className="relay-card-main">
                      <div className="relay-card-head">
                        <span className="relay-card-name">{r.name}</span>
                        {r.active && <span className="relay-badge">当前使用中</span>}
                      </div>
                      <div className="relay-card-url mono">
                        {r.normalized_base || r.base_url}
                      </div>
                    </div>

                    {!r.active && (
                      <div className="relay-card-actions">
                        <button
                          className="btn primary sm"
                          disabled={switching}
                          onClick={() => switchTo(r.id, r.name)}
                        >
                          切到这家
                        </button>
                        <button
                          className="btn ghost sm"
                          disabled={switching}
                          aria-label={`移除 ${r.name}`}
                          onClick={() => dropRelay(r.id, r.name)}
                        >
                          移除
                        </button>
                      </div>
                    )}
                  </div>
                ))}
              </div>
              <div className="field-hint">
                请求会按你填的 API Key 自动识别该发给哪家；
                Key 对不上时用「当前使用中」这家。
                切换只改默认目标，不会改动任何一家的配置。
              </div>
            </>
          )}

          {/* ── 新增一家 ── */}
          <div className="mt-12">
            {adding ? (
              <div className="relay-add-form">
                <div className="field-label">添加中转站</div>
                <input
                  className="input mb-8"
                  placeholder="显示名（可留空）"
                  aria-label="新增中转站的显示名"
                  value={newRelay.name}
                  onChange={(e) => setNewRelay(
                    { ...newRelay, name: e.target.value })}
                />
                <input
                  className="input mb-8"
                  placeholder="中转站地址，如 https://api.example.com"
                  aria-label="新增中转站的地址"
                  value={newRelay.base_url}
                  onChange={(e) => setNewRelay(
                    { ...newRelay, base_url: e.target.value })}
                />
                <input
                  className="input mb-8 mono"
                  type="password"
                  placeholder="API Key"
                  aria-label="新增中转站的 API Key"
                  value={newRelay.api_key}
                  onChange={(e) => setNewRelay(
                    { ...newRelay, api_key: e.target.value })}
                />
                <div className="flex items-center gap-8">
                  <button
                    className="btn primary sm"
                    disabled={addingBusy}
                    onClick={() => void addRelay()}
                  >
                    {addingBusy ? '添加中…' : '添加到列表'}
                  </button>
                  <button
                    className="btn ghost sm"
                    onClick={() => {
                      setAdding(false);
                      setNewRelay({ name: '', base_url: '', api_key: '' });
                    }}
                  >
                    取消
                  </button>
                </div>
                <div className="field-hint">
                  添加只是存起来备着，<b>不会</b>切换当前使用中的那家。
                </div>
              </div>
            ) : (
              /* ★ 此前是 .btn.ghost sm：透明背景 + --xd-text-dim 前景，
                 在深色卡片上与辅助文字几乎同色，用户报告「基本看不见」。
                 这里改成虚线边框的整行按钮，前景用主色，
                 既有明确边界又与旁边的说明文字明确区分。 */
              <button className="relay-add-btn" onClick={() => setAdding(true)}>
                <Plus size={15} strokeWidth={2} />
                添加另一家中转站
              </button>
            )}
          </div>
        </div>

        <div className="field">
          <label className="field-label" htmlFor="proxy-port">
            本地代理端口
          </label>
          <div className="flex items-center gap-8">
            <input
              id="proxy-port"
              className="input mono"
              style={{ maxWidth: 140 }}
              inputMode="numeric"
              placeholder={String(config.server.port)}
              value={portInput}
              disabled={saving}
              onChange={(e) => {
                setPortInput(e.target.value.replace(/[^\d]/g, ''));
                setPortError(null);
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter') savePort();
              }}
            />
            <button className="btn secondary" onClick={savePort} disabled={saving || !portInput}>
              更改端口
            </button>
          </div>
          <div className="field-hint" style={portError ? { color: 'var(--xd-danger)' } : undefined}>
            {portError ??
              `玄盾当前运行在 ${currentProxyPort()}。端口被占用时可改成 1024–65535 的其他端口，改完需重启玄盾。`}
          </div>
        </div>

        <div className="field-label">将你的 AI 工具 API 地址设置为</div>
        <div className="code-box">
          {proxyUrl}
          <button className="btn sm secondary" onClick={handleCopyUrl}>
            {copied ? <Check size={13} strokeWidth={1.5} /> : <Copy size={13} strokeWidth={1.5} />}
            {copied ? '已复制' : '复制地址'}
          </button>
        </div>
        <div className="field-hint">
          支持自定义 API 地址的工具：Cursor / VS Code 插件 / 自建脚本 / Cherry Studio 等。
          <button
            className="btn ghost sm"
            style={{ padding: '0 4px' }}
            onClick={() => openExternal('https://github.com/zhibaiYingChuan/XD/blob/main/personal/README.md')}
          >
            查看配置教程
            <ExternalLink size={12} strokeWidth={1.5} />
          </button>
        </div>
      </div>

      {/* ═══ D. 敏感信息脱敏 ═══ */}
      <div className="card">
        <div className="card-title">敏感信息脱敏</div>
        <div className="check-grid mb-16">
          {CATEGORY_ORDER.map((cat) => (
            <label key={cat} className="check-row">
              <input
                type="checkbox"
                checked={Boolean(config.guard.enabled_categories[cat])}
                disabled={saving}
                onChange={() => toggleCategory(cat)}
              />
              <span>{CATEGORY_LABELS[cat] ?? cat}</span>
            </label>
          ))}
        </div>

        <div className="field-label mt-24">自定义关键词</div>
        <div className="field-hint mb-8" style={{ marginTop: 0 }}>
          检测到这些词会在发送前自动打码（如公司内部代号、客户名）
        </div>

        <div style={{ display: 'flex', gap: 8 }}>
          <input
            className="input"
            placeholder="输入关键词后回车添加"
            value={newKeyword}
            disabled={saving}
            onChange={(e) => setNewKeyword(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') addKeyword();
            }}
          />
          <button className="btn" onClick={addKeyword} disabled={saving || !newKeyword.trim()}>
            <Plus size={15} strokeWidth={1.5} />
            添加
          </button>
        </div>

        {config.guard.custom_keywords.length > 0 ? (
          <div className="mt-16">
            <div className="flex items-center justify-between mb-8">
              <span className="faint" style={{ fontSize: 12 }}>
                已添加 {config.guard.custom_keywords.length} 个
              </span>
              <button className="btn ghost sm" onClick={resetKeywords} disabled={saving}>
                <RotateCcw size={13} strokeWidth={1.5} />
                清空
              </button>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {config.guard.custom_keywords.map((kw) => (
                <span key={kw} className="badge info" style={{ paddingRight: 4 }}>
                  {kw}
                  <button
                    className="btn ghost"
                    style={{ padding: '0 2px' }}
                    onClick={() => removeKeyword(kw)}
                    disabled={saving}
                    aria-label={`移除 ${kw}`}
                  >
                    <X size={12} strokeWidth={1.5} />
                  </button>
                </span>
              ))}
            </div>
          </div>
        ) : (
          <div className="faint mt-16" style={{ fontSize: 12 }}>
            尚未添加自定义关键词
          </div>
        )}
      </div>

      {/* ═══ E. 运行状态 ═══ */}
      {/* ★ 后端早已注册 get_engine_status / restart_engine，但此前界面
          没有任何入口能看到引擎状态、更无法重启 —— 引擎一崩，用户只能
          重开桌面端甚至重装。这块补上「看得见原因 + 能自助重启」两步。 */}
      <div className="card">
        <div className="card-title">
          <span>运行状态</span>
          {isTauri() && (
            <span className={`badge ${engineView.badge}`}>{engineView.label}</span>
          )}
        </div>

        {!isTauri() ? (
          // 浏览器预览模式没有本地引擎进程，命令无从执行：
          // 只给一句说明，不渲染状态与重启按钮，避免出现按不动的死控件。
          <div className="field-hint" style={{ marginTop: 0 }}>
            运行状态仅在桌面版可查看 —— 浏览器预览模式没有本地引擎进程。
          </div>
        ) : (
          <>
            <div className="detail-row">
              <div className="detail-key">引擎状态</div>
              <div className="detail-val">
                {engineView.label}
                {engineVersion && (
                  <span className="faint" style={{ fontSize: 12 }}>
                    {' '}· 版本 {engineVersion}
                  </span>
                )}
              </div>
            </div>

            {/* 启动失败原因：只给一句可读的话，长文本/堆栈折叠备查。 */}
            {engine?.startup_error && (
              <div className="alert danger" style={{ marginTop: 12, marginBottom: 0 }}>
                <AlertTriangle size={17} strokeWidth={1.5} className="alert-icon" />
                <div style={{ minWidth: 0, flex: 1 }}>
                  <b>引擎启动失败</b>
                  <div className="mt-8">{firstLine(engine.startup_error)}</div>
                  {isLongError(engine.startup_error) && (
                    <details className="mt-8">
                      <summary
                        className="faint"
                        style={{ cursor: 'pointer', fontSize: 12, listStyle: 'none' }}
                      >
                        查看完整错误
                      </summary>
                      <div
                        className="mono faint"
                        style={{ fontSize: 12, marginTop: 4, wordBreak: 'break-all' }}
                      >
                        {engine.startup_error}
                      </div>
                    </details>
                  )}
                </div>
              </div>
            )}

            <div className="btn-row mt-16" style={{ marginBottom: 0 }}>
              <button
                className="btn secondary"
                onClick={() => void handleRestartEngine()}
                disabled={restarting}
              >
                {restarting ? (
                  <Loader2 size={14} strokeWidth={1.5} className="spin-icon" />
                ) : (
                  <RefreshCw size={14} strokeWidth={1.5} />
                )}
                {restarting ? '重启中…' : '重启引擎'}
              </button>
              <span className="faint" style={{ fontSize: 12 }}>
                引擎无响应或启动失败时，可在这里重启
              </span>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
