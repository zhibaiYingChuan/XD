import { useState } from 'react';
import {
  BookOpen, ShieldCheck, Wrench, Bell, Camera, KeyRound,
  ChevronDown, ChevronRight, ExternalLink, Plug, Zap,
  AlertTriangle, List, HelpCircle, ArrowRight,
} from 'lucide-react';
import { open as openUrl } from '@tauri-apps/plugin-shell';

// ── 帮助中心内容模型（2026-08-05 重构：从"产品介绍"改为"操作指南"） ──
// 每个功能都按"药品说明书"的信息结构组织，解决用户三个核心诉求：
//   1. 这个功能是什么？（说明）
//   2. 我应该怎么用？（操作步骤）
//   3. 我哪些操作会产生什么后果？（后果/风险警示，最常见踩坑点）
// 4. 常见问题（FAQ）
interface FaqItem { q: string; a: string; }
interface GuideItem { h?: string; p: string; }
interface Section {
  id: string;
  icon: typeof BookOpen;
  title: string;
  desc: string;
  steps: GuideItem[];
  consequences: GuideItem[];
  faq?: FaqItem[];
}

const SECTIONS: Section[] = [
  {
    id: 'quickstart',
    icon: BookOpen,
    title: '快速上手',
    desc: '玄盾保护你的大模型调用，双向检测：既拦「进」的恶意输入，也拦「出」的敏感/违规内容。三分钟完成最基础的配置。',
    steps: [
      { p: '打开「安全检测」页，输入一段文本，点「开始检测」。这是最快验证引擎是否正常运行的方式。' },
      { p: '到「系统设置 → 防护模式」，选择「平衡」（默认推荐，兼顾拦截与放行）。' },
      { p: '到「告警通道」配置钉钉/飞书，这样拦截事件才会推送到你手上。' },
      { p: '切到「安全检测」的「输出护栏」标签，粘贴一段模型返回内容点「检查输出」，体验输出打码效果。' },
    ],
    consequences: [
      { h: '先别碰专家模式', p: '专家模式里的领域预热、快照恢复、密钥等属于敏感操作，配置不当会影响识别效果，建议先按默认使用。' },
      { h: '模式别一上来就调最高', p: '「高安全」拦截最严但误报可能上升，先用「平衡」观察再看是否需要收紧。' },
    ],
  },
  {
    id: 'mode',
    icon: ShieldCheck,
    title: '防护模式',
    desc: '决定拦截的严格程度，共三档。选择后，设置页下方的「当前模式」说明面板会实时联动显示该模式的详细说明。',
    steps: [
      { p: '进入「系统设置」，找到「防护模式」卡片。' },
      { p: '点击「高安全 / 平衡 / 低误报」中的一项。' },
      { p: '确认下方「当前模式」说明面板显示的是你选中的那档，并阅读其具体拦截策略。' },
    ],
    consequences: [
      { h: '高安全', p: '拦截最严格，适合高风险或合规敏感环境；但正常提问可能被误拦（误报率约 1.6%）。' },
      { h: '平衡', p: '默认推荐，在拦截效果与正常放行之间取平衡。' },
      { h: '低误报', p: '尽量少拦，适合对误报零容忍的业务；代价是漏防风险相对上升。' },
    ],
    faq: [
      { q: '「活性防护模式」和「防护模式」是不是一回事？', a: '不是。防护模式（三档）由你手动选择，决定拦截的严格度；活性防护（观察/保护）由引擎根据学习进度自动切换，决定「是否已真正启用拦截」。两者相互独立，切换三档模式时活性模式会联动显示当前生效状态。' },
    ],
  },
  {
    id: 'detect',
    icon: Zap,
    title: '安全检测（含输出护栏）',
    desc: '双向检测控制台。输入侧（用户 → 模型）判断用户输入是否恶意；输出护栏（模型 → 用户）判断模型输出是否夹带敏感信息或违规内容。',
    steps: [
      { p: '页面上方有两个标签：「输入侧检测」和「输出护栏」。' },
      { p: '输入侧检测：输入要检测的文本，点「开始检测」，得到信任等级与拦截结论。' },
      { p: '输出护栏：切到「输出护栏」标签，粘贴大模型返回的内容，点「检查输出」。' },
      { p: '看处置结果：放行 / 拦截 / 打码 / 告警。若命中打码，下方会直接显示「打码后的输出」——敏感片段已替换为 [REDACTED]，上下文保留。' },
      { p: '批量检测：可上传 .txt / .csv / .jsonl（单文件 ≤10MB、单批 ≤5000 条），逐条检测并导出 CSV 报告。' },
    ],
    consequences: [
      { h: '输出护栏命中敏感片段', p: '仅这几处（手机号/邮箱/密钥/身份证号等）被替换为 [REDACTED]，其余内容照常保留。' },
      { h: '输出护栏命中高危违规内容', p: '整段拦截，不对外输出，并返回通用安全提示。' },
      { h: '输出护栏命中低风险内容', p: '仅记录告警，原样放行，不打断正常使用。' },
      { h: '引擎不可达时', p: '输入侧会进入「保护性阻断」模式（宁可错拦不可漏放），并提示引擎异常，请检查引擎是否在运行。' },
    ],
    faq: [
      { q: '「打码输出」是什么意思？', a: '当模型输出里夹带敏感信息时，不整条拦截，而是只把命中的敏感片段替换成 [REDACTED]，保留上下文。这样既遮住了不该泄露的信息，也不破坏整段内容的可读性。' },
      { q: '输出护栏的数据会保存多久？', a: '输出护栏统计是引擎在内存里按分钟采集的「准实时」数据，引擎重启后会清零，不会像输入侧那样持久化保存历史。' },
    ],
  },
  {
    id: 'expert',
    icon: Wrench,
    title: '专家模式',
    desc: '暴露领域自适应预热、阴阳门状态、密钥保护、数据快照、引擎管理等敏感配置，供运维/架构师使用。日常普通操作无需开启。',
    steps: [
      { p: '进入「系统设置」，在页面顶部开启「专家模式」。' },
      { p: '领域自适应：在「领域自适应」卡片上传或手工输入领域相关的良性/攻击文本，点「预热」，让引擎识别你所在领域的特有表达。' },
      { p: '数据快照：在页面下方「数据快照」处创建带标签的快照，作为配置备份。' },
    ],
    consequences: [
      { h: '领域预热教错样本有风险', p: '上传的「攻击样本」会被当作攻击典型来学习。若误把正常文本标成攻击，会让引擎更敏感、误报上升。务必只上传你确认的良性/攻击文本。' },
      { h: '恢复快照会覆盖当前配置', p: '恢复是不可中途撤销的：会覆盖现有的模式、预热、告警等全部配置。恢复前务必确认当前配置已不需要。' },
      { h: '删除密钥', p: '删除后引擎会自动生成新密钥，无需手动备份；旧配置的签名校验会失效，属正常现象。' },
      { h: '阴阳门状态', p: '只读展示双层架构实时指标，仅供调试观察，不提供手动修改。' },
    ],
  },
  {
    id: 'alert',
    icon: Bell,
    title: '告警通道',
    desc: '把「拦截事件」自动推送到你的企业工具（钉钉/飞书/邮件/Webhook/Syslog），让安全人员实时收到告警。',
    steps: [
      { p: '进入「系统设置 → 告警通道」。' },
      { p: '选择要配置的通道（钉钉、飞书、邮件 SMTP、通用 Webhook、Syslog）。' },
      { p: '填写该通道的推送地址/密钥等参数。' },
      { p: '点「测试告警」发送一条测试消息，确认对方能收到。' },
      { p: '测试通过后保存，拦截事件即开始自动推送。' },
    ],
    consequences: [
      { h: '测试会真实发一条消息', p: '点「测试告警」会立即向目标推送一条测试通知，请确认接收方地址无误再点。' },
      { h: '未配置或配置失败', p: '拦截事件不会推送，但不会影响引擎本身的拦截功能——拦截照常进行，只是你看不到通知。' },
    ],
  },
  {
    id: 'snapshot',
    icon: Camera,
    title: '数据快照',
    desc: '在重大变更或升级前，把当前全部配置（防护模式、领域预热、告警通道等）保存为快照，需要时可一键恢复。',
    steps: [
      { p: '在「系统设置」开启专家模式，找到「数据快照」卡片。' },
      { p: '点「创建快照」，填写一个能说明用途的标签（如 《升级 1.3.2 前备份》）。' },
      { p: '重大变更完成后若出问题，回到此处选择对应快照点「恢复」。' },
    ],
    consequences: [
      { h: '恢复会覆盖当前配置', p: '恢复操作会把当前模式/预热/告警等全部覆盖为快照里的状态，且不可中途撤销。恢复前建议再创建一份当前状态的快照。' },
      { h: '标签建议写清楚', p: '快照只靠标签区分，标签写清楚（时间+用途）才能避免过几天找不到要找的那份。' },
    ],
  },
  {
    id: 'key',
    icon: KeyRound,
    title: '密钥保护',
    desc: '玄盾运行时生成的引擎签名密钥，用于防止配置与日志被恶意篡改。密钥存入系统密钥库（Windows 凭据管理器 / macOS Keychain），不落明文盘。',
    steps: [
      { p: '日常无需任何操作。' },
      { p: '仅在需要重置签名时，在「专家模式 → 密钥保护」中删除密钥。' },
    ],
    consequences: [
      { h: '删除后自动重新生成', p: '删除密钥后引擎会立即生成新密钥，无需手动备份，过程无感。' },
    ],
  },
  {
    id: 'integrate',
    icon: Plug,
    title: '接入方式',
    desc: '玄盾应作为网关/SDK 接入企业 AI 服务调用链路，让发往大模型的请求全部经过检测。',
    steps: [
      { p: '在企业 AI 服务调用链路上接入玄盾网关或 SDK（推荐方式）。' },
    ],
    consequences: [
      { h: 'v1.3.2 起已移除本地 HTTP 代理', p: '因 HTTPS 加密流量无法在本地代理层检测内容，且该方式与网关定位脱节，已移除。请改用网关/SDK 接入。' },
    ],
  },
];

// 可折叠章节行组件：按"是什么 / 怎么用 / 会产生什么后果 / 常见问题"渲染
function SectionRow({ section, defaultOpen }: { section: Section; defaultOpen: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const Icon = section.icon;
  return (
    // P1 修复：为卡片根元素添加锚点 id + scroll-margin，供顶部"目录"锚点索引跳转
    <div className="card" id={section.id} style={{ marginBottom: '12px', scrollMarginTop: '80px' }}>
      <div
        className="card-header"
        onClick={() => setOpen((v) => !v)}
        style={{ cursor: 'pointer', userSelect: 'none' }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {open ? (
            <ChevronDown size={18} strokeWidth={1.5} />
          ) : (
            <ChevronRight size={18} strokeWidth={1.5} />
          )}
          <Icon size={18} strokeWidth={1.5} style={{ color: 'var(--dt-primary)' }} />
          <h3>{section.title}</h3>
        </div>
      </div>
      {open && (
        <div className="card-body" style={{ display: 'grid', gap: '16px' }}>
          {/* 这是什么 */}
          <div className="help-block">
            <div className="help-block-title">
              <BookOpen size={14} strokeWidth={1.5} style={{ marginRight: 6, verticalAlign: '-2px' }} />
              这是什么
            </div>
            <div className="help-block-desc">{section.desc}</div>
          </div>

          {/* 怎么用 */}
          <div className="help-block">
            <div className="help-block-title">
              <List size={14} strokeWidth={1.5} style={{ marginRight: 6, verticalAlign: '-2px' }} />
              怎么用
            </div>
            <ol className="help-steps">
              {section.steps.map((s, i) => (
                <li key={i}>
                  {s.h && <div className="help-step-h">{s.h}</div>}
                  <div className="help-step-p">{s.p}</div>
                </li>
              ))}
            </ol>
          </div>

          {/* 会产生什么后果 */}
          <div className="help-block">
            <div className="help-block-title warning">
              <AlertTriangle size={14} strokeWidth={1.5} style={{ marginRight: 6, verticalAlign: '-2px' }} />
              会产生什么后果
            </div>
            <div className="help-consequences">
              {section.consequences.map((c, i) => (
                <div key={i} className="help-consequence">
                  <div className="help-consequence-h">{c.h}</div>
                  <div className="help-consequence-p">{c.p}</div>
                </div>
              ))}
            </div>
          </div>

          {/* 常见问题 */}
          {section.faq && section.faq.length > 0 && (
            <div className="help-block">
              <div className="help-block-title">
                <HelpCircle size={14} strokeWidth={1.5} style={{ marginRight: 6, verticalAlign: '-2px' }} />
                常见问题
              </div>
              <div className="help-faq">
                {section.faq.map((f, i) => (
                  <div key={i} className="help-faq-item">
                    <div className="help-faq-q">
                      <ArrowRight size={13} strokeWidth={1.5} style={{ marginRight: 6, verticalAlign: '-2px' }} />
                      {f.q}
                    </div>
                    <div className="help-faq-a">{f.a}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function Help() {
  return (
    <div className="page">
      <div className="page-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <h1 className="page-title">帮助中心</h1>
        <button
          className="btn btn-sm btn-secondary"
          onClick={() => openUrl('https://github.com/zhibaiYingChuan/XD/blob/main/docs/%E7%94%A8%E6%88%B7%E6%8C%87%E5%8D%97.md').catch(() => {})}
        >
          <ExternalLink size={14} strokeWidth={1.5} style={{ marginRight: '6px' }} />
          在浏览器查看完整文档
        </button>
      </div>
      <p style={{ color: 'var(--text-secondary)', fontSize: '0.9em', marginTop: '-8px', marginBottom: '20px' }}>
        不只是"能做什么"，更告诉你"怎么用、会有什么后果"。每个功能都按「是什么 → 怎么用 → 会产生什么后果 → 常见问题」组织。
      </p>
      {/* P1 修复：顶部锚点目录索引，解决 8 节平铺无可发现性问题 */}
      <div className="help-index" style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginBottom: '20px', padding: '10px 12px', border: '1px solid var(--dt-border)', borderRadius: '8px', background: 'var(--dt-bg-secondary)' }}>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '0.85em', color: 'var(--text-secondary)' }}>
          <List size={14} strokeWidth={1.5} /> 目录：
        </span>
        {SECTIONS.map((s) => (
          <a
            key={s.id}
            href={`#${s.id}`}
            onClick={(e) => {
              // 使用 scrollIntoView 平滑滚动到目标章节，避免锚点默认跳转丢失滚动位置
              e.preventDefault();
              document.getElementById(s.id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }}
            style={{ fontSize: '0.85em', color: 'var(--dt-primary)', textDecoration: 'none', padding: '2px 8px', borderRadius: '4px', background: 'var(--dt-bg)', border: '1px solid var(--dt-border)' }}
          >
            {s.title}
          </a>
        ))}
      </div>
      {SECTIONS.map((s, i) => (
        <SectionRow key={s.id} section={s} defaultOpen={i === 0} />
      ))}
    </div>
  );
}