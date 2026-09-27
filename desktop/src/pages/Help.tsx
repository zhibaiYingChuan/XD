/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   帮助页 — 消费级 FAQ + 配置教程。
*/

import { useState } from 'react';
import {
  ChevronDown,
  ChevronRight,
  Shield,
  Monitor,
  Settings as SettingsIcon,
  FileText,
  CircleHelp,
} from 'lucide-react';
import { currentProxyPort } from '../services/api';

/** 代理地址占位符。
 *  ★ P1-10：端口可配置，若把地址写死，用户改端口后照着教程填就会失效。
 *  渲染时统一替换为当前实际端口。 */
const P = '{proxy}';

const FAQ = [
  {
    q: '玄盾到底在做什么？',
    a: '你使用第三方 AI 中转站时，中转站理论上能看到你说的一切、模型的回答的一切，还可能偷偷修改模型的回答。玄盾在你的电脑和中转站之间建了一道安检站：\n\n• 发送前：自动遮盖你的 API 密钥、手机号等敏感信息\n• 接收时：检查中转站返回的内容有没有被偷偷塞入恶意命令\n• 全过程都在你的电脑上完成，不会上传任何数据',
  },
  {
    q: '为什么需要修改 API 地址？',
    a: `因为玄盾要"站在中间"检查数据，就像安检机需要你把行李放上传送带。\n\n你需要把 AI 工具的 API 地址从 https://api.xxx.com 改成 ${P}，这样流量就会先经过玄盾再发往中转站。\n\n只有支持自定义 API 地址的工具才能这样配置（Cursor、Cherry Studio、VS Code 插件、自建脚本等都支持）。`,
  },
  {
    q: '支持 HTTPS 吗？',
    a: '首版不支持。玄盾目前只拦截 HTTP 流量，这是为了降低安装门槛（不需要安装根证书）。\n\n这意味着如果某个 AI 工具只支持 HTTPS 且无法自定义地址，它就得不到保护。后续版本会提供"完整模式"（安装本地证书做系统级代理），但 macOS 需要手动信任证书。',
  },
  {
    q: '会拖慢 AI 响应吗？',
    a: '几乎不会。玄盾的检测通常在 10 毫秒以内，相比 AI 生成回答动辄几秒到几十秒的时间，可以忽略不计。\n\n唯一的例外是首次请求——引擎需要"学习"你的正常对话模式（通常在 50 条样本后建立基线），首次会稍慢一点。',
  },
  {
    q: '我的对话内容会被保存吗？',
    a: '会，但只保存在你自己的电脑上。\n\n玄盾在本地 SQLite 数据库中记录：时间、检测结果、触发的规则、脱敏的片段。原始的敏感信息（API 密钥、手机号）也只存本地，且在响应返回后立即从内存清除。\n\n你可以在「日志」页面随时查看和清空这些记录。玄盾不会把任何内容上传到服务器。',
  },
  {
    q: '安全级别怎么选？',
    a: '默认「均衡」适合大多数人：\n\n• 宽松：只有明确的危险才拦（比如删除所有文件的命令），手机号邮箱只记录不遮盖。误报最少。\n• 均衡（推荐）：API 密钥/身份证/银行卡直接阻断，手机号/邮箱自动打码。\n• 严格：任何敏感信息都阻断，任何可疑响应都告警。最安全但误报较多。\n\n建议先用「均衡」，如果你经常误报（比如正常的技术讨论被判为危险）就降到「宽松」。',
  },
  {
    q: '中转站信誉分是怎么算的？',
    a: '基于你在本机观察到的行为，四个维度：\n\n• 历史行为：它返回过多少次危险内容\n• 响应延迟模式：条件触发型攻击会先表现正常，之后突变\n• 数据保留迹象：响应中是否包含"本平台保留对话记录"这类声明\n• 恶意指纹库：是否匹配已知的恶意中转站\n\n分数只反映你在本机的观察，不代表该中转站的客观信誉。',
  },
  {
    q: '发现危险响应后会发生什么？',
    a: '取决于安全级别：\n\n• 均衡/严格：直接阻断，你不会看到被篡改的内容，同时在首页和日志中记录原因\n• 宽松：放行但标记为"可疑"，首页状态栏变黄\n\n无论哪种情况，你都可以在「日志」页面查看具体触发了哪条规则、原始响应片段是什么。\n\n另外，右下角系统托盘图标会变色提示状态：绿色正常、黄色有可疑、红色刚拦截了一次危险。',
  },
  {
    q: '关掉窗口后防护还生效吗？',
    a: '生效。关闭窗口只是隐藏到系统托盘，代理会继续运行。\n\n要真正退出，请右键点击托盘图标选择「退出玄盾」。托盘图标颜色就是当前防护状态：绿色正常、黄色今日有可疑、红色今日已拦截过、灰色表示防护未启用。',
  },
];

const TOOL_GUIDES = [
  {
    icon: Monitor,
    name: 'Cursor',
    steps: [
      '打开 Cursor → 设置（Settings）',
      '搜索 "Override OpenAI Base URL"',
      `填入 ${P}`,
      '把 OpenAI API Key 改成你的中转站 Key',
    ],
  },
  {
    icon: FileText,
    name: 'Cherry Studio / Chatbox 等第三方客户端',
    steps: [
      '打开设置 → 模型服务 / OpenAI 配置',
      `API 地址填 ${P}`,
      'API Key 填你的中转站 Key',
      '模型名称与玄盾设置页保持一致',
    ],
  },
  {
    icon: SettingsIcon,
    name: '自建脚本 / 任意程序',
    steps: [
      `把代码中的 base_url 改为 ${P}`,
      'api_key 仍用你的中转站 Key',
      `如果用 OpenAI SDK：client = OpenAI(base_url="${P}", api_key=...)`,
    ],
  },
];

/** 把占位符替换为当前实际代理地址 */
function fill(text: string): string {
  return text.split(P).join(`http://127.0.0.1:${currentProxyPort()}/v1`);
}

export default function Help() {
  const [openIndex, setOpenIndex] = useState<number | null>(0);

  return (
    <div style={{ maxWidth: 780 }}>
      <div className="page-header">
        <h1 className="page-title">帮助</h1>
        <p className="page-subtitle">常见问题与配置教程</p>
      </div>

      {/* 核心概念 */}
      <div className="card">
        <div className="card-title">
          <span className="flex items-center gap-8">
            <Shield size={16} strokeWidth={1.5} />
            玄盾如何保护你
          </span>
        </div>
        <div className="flex items-center gap-12" style={{ flexWrap: 'wrap' }}>
          {[
            { label: '你的 AI 工具', color: 'var(--xd-text-dim)' },
            { label: '玄盾本地代理', color: 'var(--xd-safe)' },
            { label: '中转站', color: 'var(--xd-suspect)' },
            { label: '模型', color: 'var(--xd-text-dim)' },
          ].map((n, i, arr) => (
            <div key={n.label} className="flex items-center gap-12">
              <span
                className="badge"
                style={{
                  background: 'var(--xd-card-hover)',
                  color: n.color,
                  padding: '6px 12px',
                  fontSize: 13,
                }}
              >
                {n.label}
              </span>
              {i < arr.length - 1 && <span className="faint">→</span>}
            </div>
          ))}
        </div>
        <div className="field-hint mt-16">
          玄盾只处理经过它的流量，不会主动读取你的其他文件或联网。
        </div>
      </div>

      {/* 配置教程 */}
      <div className="card">
        <div className="card-title">配置你的 AI 工具</div>
        <div className="field-hint mb-16" style={{ marginTop: 0 }}>
          统一把 API 地址改成{' '}
          <code className="mono" style={{ color: 'var(--xd-safe)' }}>
            http://127.0.0.1:{currentProxyPort()}/v1
          </code>
        </div>

        {TOOL_GUIDES.map((g) => {
          const Icon = g.icon;
          return (
            <div key={g.name} style={{ marginBottom: 18 }}>
              <div className="flex items-center gap-8 mb-8" style={{ fontWeight: 500 }}>
                <Icon size={15} strokeWidth={1.5} />
                {g.name}
              </div>
              <ol style={{ paddingLeft: 22, fontSize: 13, color: 'var(--xd-text-dim)', lineHeight: 1.9 }}>
                {g.steps.map((s, i) => (
                  <li key={i}>{fill(s)}</li>
                ))}
              </ol>
            </div>
          );
        })}
      </div>

      {/* FAQ */}
      <div className="card">
        <div className="card-title">
          <span className="flex items-center gap-8">
            <CircleHelp size={16} strokeWidth={1.5} />
            常见问题
          </span>
        </div>

        {FAQ.map((item, i) => {
          const open = openIndex === i;
          return (
            <div key={i} style={{ borderBottom: '1px solid var(--xd-border)' }}>
              <button
                onClick={() => setOpenIndex(open ? null : i)}
                style={{
                  width: '100%',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  padding: '13px 0',
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  textAlign: 'left',
                  fontSize: 14,
                  fontWeight: open ? 500 : 400,
                  color: 'var(--xd-text)',
                }}
              >
                {open ? (
                  <ChevronDown size={15} strokeWidth={1.5} style={{ flexShrink: 0, color: 'var(--xd-text-faint)' }} />
                ) : (
                  <ChevronRight size={15} strokeWidth={1.5} style={{ flexShrink: 0, color: 'var(--xd-text-faint)' }} />
                )}
                {item.q}
              </button>
              {open && (
                <div
                  style={{
                    padding: '0 0 16px 23px',
                    fontSize: 13,
                    color: 'var(--xd-text-dim)',
                    lineHeight: 1.85,
                    whiteSpace: 'pre-wrap',
                    animation: 'page-in 200ms ease-out',
                  }}
                >
                  {fill(item.a)}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
