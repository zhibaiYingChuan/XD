/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   轻量 i18n —— 中文为源语言，英文为译文。

   设计取舍
   ────────
   · 不做 key 体系：直接以中文原文为 key。这样新增文案时不必先想 key，
     漏翻时自动回退中文，不会出现「界面上写着 nav.dashboard」。
   · 语言来源：localStorage 优先，其次跟随系统（zh* → 中文，其余 → 英文）。
   · 组件用 useI18n() 订阅语言变化；非组件模块用 t() 读取当前语言。
   · 词条用 [中文, 英文] 数组声明，避免中文标点作为对象键时的语法问题。
*/

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';

export type Lang = 'zh' | 'en';

const STORAGE_KEY = 'xuandun-lang';

/** [中文原文, 英文译文]。未收录的条目回退中文。 */
const EN_PAIRS: Array<[string, string]> = [
  // ── 导航 / 通用 ──
  ['首页', 'Home'],
  ['日志', 'Logs'],
  ['设置', 'Settings'],
  ['帮助', 'Help'],
  ['激活', 'Activate'],
  ['未激活', 'Not activated'],
  ['本地运行', 'Runs locally'],
  ['正在启动', 'Starting'],
  ['正在启动...', 'Starting...'],
  ['读取中', 'Loading'],
  ['刷新', 'Refresh'],
  ['刷新中', 'Refreshing'],
  ['重试', 'Retry'],
  ['取消', 'Cancel'],
  ['确定', 'OK'],
  ['复制', 'Copy'],
  ['已复制', 'Copied'],
  ['保存中...', 'Saving...'],
  ['上一步', 'Back'],
  ['下一步', 'Next'],
  ['完成', 'Done'],
  ['开始', 'Start'],
  ['查看全部', 'View all'],
  ['查看原因', 'See why'],
  ['重启引擎', 'Restart engine'],
  ['正在重启…', 'Restarting…'],

  // ── 状态栏 ──
  ['防护中', 'Protecting'],
  ['学习中', 'Learning'],
  ['已暂停', 'Paused'],
  ['端口', 'Port'],
  ['没有响应', 'is not responding'],
  ['可重启引擎，或看「设置 → 运行状态」里的原因',
    'Restart the engine, or see Settings → Runtime status for the cause'],
  ['防护已暂停', 'Protection paused'],
  ['本地代理未运行', 'Local proxy is not running'],
  ['正在建立基线', 'Building baseline'],
  ['正在启动本地代理…', 'Starting local proxy…'],
  ['首次启动需要几秒', 'First start takes a few seconds'],
  ['未激活，当前为只读模式（不执行拦截）',
    'Not activated — read-only mode (no blocking)'],
  ['降级运行：', 'Degraded: '],
  ['今日已转发', 'Forwarded today'],
  ['今日检查', 'Checked today'],
  ['危险', 'Danger'],
  ['提示', 'Notice'],
  ['今日已打码', 'Redacted today'],
  ['次', 'times'],
  ['处', 'places'],
  ['次（未经检测）', 'times (unchecked)'],

  // ── 首页 ──
  ['安全', 'Safe'],
  ['近期安全记录', 'Recent security events'],
  ['当前中转站', 'Current relay'],
  ['快速操作', 'Quick actions'],
  ['恢复防护', 'Resume protection'],
  ['暂停 5 分钟', 'Pause 5 min'],
  ['暂停 30 分钟', 'Pause 30 min'],
  ['永久暂停', 'Pause indefinitely'],
  ['打开日志', 'Open logs'],
  ['分享诊断报告', 'Share diagnostics'],
  ['去激活', 'Activate now'],
  ['未激活：当前只转发，不做防护', 'Not activated: forwarding only, no protection'],
  ['勘合现在只会把你的请求原样转给中转站 ——',
    'Kanghe currently forwards your requests to the relay as-is —'],
  ['不会脱敏、也不会拦截', 'no masking, no blocking'],
  ['。激活后才会开始检查。', '. Checks begin after activation.'],
  ['正在读取状态…', 'Reading status…'],
  ['尚未更新', 'Not updated yet'],
  ['更新于', 'Updated at'],
  ['刷新数据', 'Refresh data'],
  ['今天检查了', 'Checked'],
  ['打码', 'redacted'],
  ['拦下', 'blocked'],
  ['，打码', ', redacted'],
  ['，拦下', ', blocked'],
  ['条', 'items'],
  ['最近的对话没有新问题。今天累计：危险',
    'No new issues in recent conversations. Today: danger'],
  ['条、提示', ', notices'],
  ['条，点「查看全部」可逐条核对。', '. Click “View all” to review each one.'],
  ['正在加载记录…', 'Loading records…'],
  ['今天没有发现危险响应，你的 AI 对话很安全',
    'No dangerous responses today. Your AI conversations are safe.'],
  ['还没有检测记录 — 使用 AI 工具发起一次对话试试',
    'No records yet — start a conversation in your AI tool to try it.'],
  ['信誉良好', 'Good reputation'],
  ['正常', 'Normal'],
  ['存在风险', 'At risk'],
  ['高危中转站', 'High-risk relay'],
  ['已使用', 'In use for'],
  ['天', 'days'],
  ['今天开始使用', 'Started today'],
  ['累计', 'Total'],
  ['次调用', 'calls'],
  ['次危险响应', 'dangerous responses'],
  ['次提示', 'notices'],
  ['检测到数据保留迹象', 'Data-retention signal detected'],
  ['为什么是这个分数？', 'Why this score?'],
  ['收起评分明细', 'Hide score details'],
  ['扣分项', 'Deduction'],
  ['依据', 'Reason'],
  ['扣分', 'Points'],
  ['当前信誉分', 'Current score'],
  ['满分', 'Max'],
  ['证据：', 'Evidence: '],
  ['平均响应延迟', 'Average latency'],
  ['暂无样本', 'No samples'],
  ['次采样', 'samples'],
  ['正在读取中转站配置…', 'Reading relay configuration…'],
  ['已配置 · 尚未产生调用记录', 'Configured · no calls recorded yet'],
  ['还差一步：把 AI 工具的 API 地址改成',
    'One step left: set your AI tool’s API base URL to'],
  ['复制地址', 'Copy address'],
  ['改完发起一次对话，这里就会显示它的信誉评分与调用统计。',
    'Start a conversation after the change; its reputation and call stats will appear here.'],
  ['尚未配置中转站', 'No relay configured'],
  ['前往设置', 'Go to settings'],
  ['防护已暂停，你的 AI 对话当前', 'Protection is paused. Your AI conversations are currently'],
  ['不受任何检测保护', 'not protected by any checks'],
  ['。中转站可以自由篡改返回内容、截留你的数据。',
    '. The relay can freely alter responses and retain your data.'],
  ['确定暂停防护吗？\n\n暂停期间新的对话不会被脱敏，也不会被拦截。',
    'Pause protection?\n\nWhile paused, new conversations will not be masked or blocked.'],
  ['防护已永久暂停，直到手动恢复', 'Protection paused indefinitely until you resume it'],
  ['防护已恢复', 'Protection resumed'],
  ['诊断报告已复制到剪贴板', 'Diagnostics copied to clipboard'],
  ['复制失败，请手动截图', 'Copy failed — please take a screenshot'],
  ['代理地址已复制，粘贴到 AI 工具的 API 地址',
    'Proxy address copied — paste it into your AI tool’s API base URL'],
  ['复制失败，请手动选中地址', 'Copy failed — please select the address manually'],

  // ── 激活页 ──
  ['暂时无法确认激活状态', 'Cannot confirm activation status'],
  ['本机代理没有运行，激活校验无法执行。',
    'The local proxy is not running, so activation cannot be verified.'],
  ['这', 'This'],
  ['不代表', 'does not mean'],
  ['你的激活码有问题 —— 只是现在没法判断。',
    'your license is invalid — it simply cannot be checked right now.'],
  ['正在读取激活状态...', 'Reading activation status...'],
  ['已激活', 'Activated'],
  ['剩余', 'Remaining'],
  ['授权给', 'Licensed to'],
  ['版本', 'Edition'],
  ['到期', 'Expires'],
  ['激活码ID', 'License ID'],
  ['本机机器码', 'Machine code'],
  ['激活码已过期，勘合已进入只读模式。',
    'License expired. Kanghe is now in read-only mode.'],
  ['激活码将在', 'Your license expires in'],
  ['天后过期。', 'days.'],
  ['到期后防护会停止，记得提前续期。',
    'Protection stops at expiry — remember to renew in advance.'],
  ['续期 / 换机 / 报障，都发邮件给官方（',
    'For renewal, device transfer, or support, email us ('],
  ['）。', ').'],
  ['换机申请', 'Device transfer request'],
  ['填入', 'Enter'],
  ['原激活码', 'the original license'],
  ['后生成，把整段发给勘合官方（', 'to generate it, then send the whole block to us ('],
  ['）。官方会发回一张绑定本机的新码。',
    '). We will reply with a new license bound to this machine.'],
  ['（尚未生成）', '(not generated yet)'],
  ['重新生成', 'Regenerate'],
  ['生成换机申请', 'Generate transfer request'],
  ['换机申请已复制', 'Transfer request copied'],
  ['复制失败，请手动选中复制', 'Copy failed — please select and copy manually'],
  ['换了电脑或硬盘？原激活码在新机上用不了，需要换绑。',
    'Changed computer or disk? The original license will not work on the new machine; it must be rebound.'],
  ['换机', 'Transfer'],
  ['尚未激活', 'Not activated'],
  ['申请激活码：把这串机器码发邮件给官方',
    'To request a license, email this machine code to'],
  ['，勘合会回邮件发激活码给你。', '. We will reply with your license.'],
  ['复制机器码', 'Copy machine code'],
  ['粘贴勘合官方发给你的激活码（以 XDACT- 开头）',
    'Paste the license we sent you (starts with XDACT-)'],
  ['（这是勘合组件的问题，不是你的码有问题）',
    ' (this is a Kanghe component issue, not a problem with your license)'],
  ['激活中...', 'Activating...'],
  ['当前是浏览器预览模式，激活功能仅在桌面版可用。',
    'Browser preview mode — activation is only available in the desktop app.'],
  ['请输入激活码', 'Please enter a license'],
  ['激活成功', 'Activated'],
  ['请先填写原激活码', 'Please enter the original license first'],
  ['机器码已复制', 'Machine code copied'],

  // ── 首次引导 ──
  ['欢迎使用道体·勘合', 'Welcome to Daoti · Kanghe'],
  ['这是一款保护你在使用 AI 中转站时数据安全的工具。',
    'This tool protects your data when you use third-party AI relays.'],
  ['它运行在你的电脑上，会检查：', 'It runs on your computer and checks:'],
  ['中转站返回的内容是否被篡改（偷偷插入恶意命令）',
    'whether relay responses were tampered with (malicious commands injected)'],
  ['你发送的内容是否包含敏感信息（API 密钥、手机号等）',
    'whether your messages contain sensitive data (API keys, phone numbers, etc.)'],
  ['中转站是否可信（是否保留你的对话记录）',
    'whether the relay is trustworthy (does it retain your conversations)'],
  ['检测过程都在本机完成，勘合不会把内容上传到它自己的服务器。',
    'All checks run locally. Kanghe never uploads content to its own servers.'],
  ['你的对话仍会发给你配置的中转站 —— 那正是要被检查的那一跳。',
    'Your conversations still go to the relay you configured — that is the hop being checked.'],
  ['激活勘合', 'Activate Kanghe'],
  ['有效期至', 'Valid until'],
  ['激活码用于开启完整防护。未激活时勘合只做转发，',
    'A license unlocks full protection. Without one, Kanghe only forwards,'],
  ['不脱敏、也不拦截', 'without masking or blocking'],
  ['先把你的机器码发给勘合官方，拿到激活码后填在下面。',
    'Send your machine code to us first, then paste the license below.'],
  ['你的机器码', 'Your machine code'],
  ['（获取失败）', '(failed to load)'],
  ['（正在获取…）', '(loading…)'],
  ['机器码获取失败：', 'Failed to load machine code: '],
  ['请确认勘合本地引擎已启动，然后重试。',
    'Make sure the local engine is running, then retry.'],
  ['复制这段发给勘合官方，即可为你签发激活码',
    'Send this to us to receive a license'],
  ['换过电脑？', 'Changed computer?'],
  ['原激活码绑定了旧机器，换电脑后需要重新绑定。',
    'The original license is bound to the old machine and must be rebound.'],
  ['在上方填入原激活码后生成，把整段发给勘合官方。',
    'Enter the original license above, generate the request, and send the whole block to us.'],
  ['暂不激活，先看看', 'Skip activation for now'],
  ['配置你的 AI 工具', 'Configure your AI tool'],
  ['勘合通过本地代理保护你的 AI 对话。你需要填写中转站信息，',
    'Kanghe protects your AI conversations through a local proxy. Enter your relay details,'],
  ['然后把 AI 工具的 API 地址改为勘合的本地地址。',
    'then point your AI tool’s API base URL to Kanghe’s local address.'],
  ['中转站名称（便于识别）', 'Relay name (for identification)'],
  ['我的中转站', 'My relay'],
  ['中转站地址', 'Relay URL'],
  ['粘贴中转站给你的地址即可（带不带 /v1 都行），勘合会自动识别',
    'Paste the URL your relay gave you (/v1 optional); Kanghe detects it automatically'],
  ['中转站API Key', 'Relay API key'],
  ['这个Key只会保存在你的电脑上，勘合不会上传',
    'This key is stored only on your computer; Kanghe never uploads it'],
  ['先跳过，进主界面看看', 'Skip for now and open the app'],
  ['配置完成', 'Setup complete'],
  ['勘合正在运行，保护你的 AI 对话。',
    'Kanghe is running and protecting your AI conversations.'],
  ['勘合正在运行，但尚未激活 —— 当前只会转发请求，不脱敏也不拦截。',
    'Kanghe is running but not activated — it only forwards requests, without masking or blocking.'],
  ['最后一步：修改 AI 工具的 API 地址',
    'Last step: set your AI tool’s API base URL'],
  ['在你使用的 AI 工具的「API 地址 / Base URL」设置项中填入上面的地址，',
    'Enter the address above in your AI tool’s “API base URL” setting.'],
  ['API Key 一栏填中转站给你的那把 Key（不是勘合的）。',
    'Use the relay’s API key (not a Kanghe key).'],
  ['返回修改', 'Back to edit'],
  ['完成并进入', 'Finish and enter'],
  ['配置完成，勘合已开始保护你的 AI 对话。',
    'Setup complete. Kanghe is now protecting your AI conversations.'],
  ['配置完成。未激活时勘合只转发、不防护，记得去「激活」页完成激活',
    'Setup complete. Without activation Kanghe only forwards; activate it on the Activate page.'],
  ['无法连接本地代理，请确认勘合已启动',
    'Cannot reach the local proxy. Make sure Kanghe is running.'],
  ['激活成功，勘合已解锁完整防护',
    'Activated. Kanghe has unlocked full protection.'],
  ['换机申请已复制，发给勘合官方即可',
    'Transfer request copied — send it to us'],
  ['请先在上方填写原激活码', 'Please enter the original license above'],

  // ── 设置 ──
  ['语言', 'Language'],
  ['界面语言会立即切换，并记住你的选择。',
    'The interface language changes immediately and your choice is remembered.'],
  ['所有检测都在本机完成；勘合自身不上传任何数据（对话仍会发给你配置的中转站）',
    'All checks run locally. Kanghe uploads nothing (conversations still go to your configured relay).'],
  ['加载设置...', 'Loading settings...'],

  // ── 通用组件 ──
  ['加载中', 'Loading'],
  ['出错了', 'Something went wrong'],
  ['重新加载', 'Reload'],
  ['关闭', 'Close'],
  ['有新版本可用', 'Update available'],
  ['下载并安装', 'Download and install'],
  ['以后再说', 'Later'],
  ['跳过这个版本', 'Skip this version'],
  ['引擎未运行', 'Engine is not running'],
  ['正在启动本地引擎…', 'Starting the local engine…'],
  ['本地引擎没有响应', 'The local engine is not responding'],
  ['常见原因', 'Common causes'],
  ['端口被占用', 'Port already in use'],
  ['配置损坏', 'Corrupted configuration'],
  ['引擎进程已退出', 'Engine process exited'],
  ['重启引擎后仍无效', 'Still failing after restart'],
  ['查看运行状态', 'View runtime status'],
];

const EN: Record<string, string> = Object.fromEntries(EN_PAIRS);

let currentLang: Lang = 'zh';

/** 读取系统语言偏好。 */
function systemLang(): Lang {
  if (typeof navigator === 'undefined') return 'zh';
  return navigator.language?.toLowerCase().startsWith('zh') ? 'zh' : 'en';
}

/** 首次启动：localStorage 优先，其次跟随系统。 */
export function detectLang(): Lang {
  if (typeof localStorage !== 'undefined') {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === 'zh' || saved === 'en') return saved;
  }
  return systemLang();
}

export function getLang(): Lang {
  return currentLang;
}

/** 非组件模块用：按当前语言翻译。 */
export function t(zh: string): string {
  return currentLang === 'en' ? (EN[zh] ?? zh) : zh;
}

interface I18nValue {
  lang: Lang;
  setLang: (lang: Lang) => void;
  t: (zh: string) => string;
}

const LangContext = createContext<I18nValue>({
  lang: 'zh',
  setLang: () => undefined,
  t: (zh) => zh,
});

export function LangProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(() => detectLang());

  // 初始化时把模块级语言同步好，保证非组件代码（如 api.ts）也拿到正确语言。
  useEffect(() => {
    currentLang = lang;
    document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
  }, [lang]);

  const setLang = useCallback((next: Lang) => {
    currentLang = next;
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // 隐私模式下 localStorage 可能不可写；语言仍在本会话生效。
    }
    setLangState(next);
  }, []);

  const value = useMemo<I18nValue>(
    () => ({
      lang,
      setLang,
      t: (zh: string) => (lang === 'en' ? (EN[zh] ?? zh) : zh),
    }),
    [lang, setLang],
  );

  return <LangContext.Provider value={value}>{children}</LangContext.Provider>;
}

export function useI18n(): I18nValue {
  return useContext(LangContext);
}
