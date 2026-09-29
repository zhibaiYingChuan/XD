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
    q: '我还没激活，防护是不是就没用了？',
    a: '是的，这一点必须说清楚：「未激活时玄盾处于只读模式」—— 界面、日志、设置都能正常用，但「不执行脱敏与拦截」，请求会原样转发给中转站。\n\n状态栏会显示「未激活，当前为只读模式」，不会让你误以为防护还开着。\n\n激活：在「激活」页把本机机器码发邮件给官方（spring60@foxmail.com），收到激活码粘贴回去即可。一码一机，换机器需要走换机流程。',
  },
  {
    q: '为什么需要修改 API 地址？',
    a: `因为玄盾要"站在中间"检查数据，就像安检机需要你把行李放上传送带。\n\n你需要把 AI 工具的 API 地址从 https://api.xxx.com 改成 ${P}，这样流量就会先经过玄盾再发往中转站。\n\n只有支持自定义 API 地址的工具才能这样配置（Cursor、Cherry Studio、VS Code 插件、自建脚本等都支持）。`,
  },
  {
    q: '支持 HTTPS 吗？',
    a: '要分两段看，别混在一起：\n\n【你的 AI 工具 → 玄盾】\n只能是 http://127.0.0.1:端口/v1。玄盾是明文本地代理，不装根证书，所以这一段不支持 https —— 好在它只走本机回环，没有暴露风险。\n\n【玄盾 → 你的中转站】\nhttps 完全支持。在「设置」页填中转站地址时照常填 https:// 开头即可，玄盾不会把它降级成 http。\n\n这也意味着：只有支持「自定义 API 地址」的 AI 工具才能接上玄盾（Cursor、Cherry Studio 等都支持）。若某个工具只能连固定 https 地址且不许改，它就接不到玄盾。\n\n后续版本计划提供「完整模式」（安装本地证书做系统级代理），那时连只支持固定 https 的工具也能覆盖。',
  },
  {
    q: '会拖慢 AI 响应吗？',
    a: '几乎不会。玄盾只做文本匹配与规则检查，开销相对于 AI 生成回答（动辄几秒到几十秒）可以忽略。\n\n唯一需要留意的是刚开始使用时 —— 玄盾要先观察几次你的正常请求（延迟基线取前 5 次），才谈得上识别「响应模式突变」，这段期间会稍慢一点。',
  },
  {
    q: '我的对话内容会被保存吗？',
    a: '会，但只保存在你自己的电脑上。\n\n玄盾在本地 SQLite 数据库中记录：时间、检测结果、触发的规则、脱敏的片段。原始的敏感信息（API 密钥、手机号）也只存本地，且在响应返回后立即从内存清除。\n\n你可以在「日志」页面随时查看和清空这些记录。玄盾不会把任何内容上传到服务器。',
  },
  {
    q: '安全级别怎么选？',
    a: '默认「均衡」适合大多数人。玄盾在两个方向上按级别处置，规则不完全一样：\n\n【发送前·你的敏感信息】\n• 宽松：手机号邮箱只记录不遮盖，API 密钥/身份证/银行卡仍直接阻断（这些外泄后果不可逆）\n• 均衡（推荐）：API 密钥/身份证/银行卡阻断，手机号/邮箱自动打码\n• 严格：手机号/邮箱也一并阻断\n\n【接收时·中转站返回的内容】\n• 宽松：高危内容放行但标记为「可疑」，中等风险不处理\n• 均衡：高危内容直接阻断，中等风险标记为「可疑」\n• 严格：任何可疑响应都告警或阻断\n\n建议先用「均衡」，如果你经常误报（比如正常的技术讨论被判为危险）就降到「宽松」。',
  },
  {
    q: '中转站信誉分是怎么算的？',
    a: '基于你在本机观察到的行为，四个维度：\n\n• 历史行为：它返回过多少次危险内容\n• 响应延迟模式：条件触发型攻击会先表现正常，之后突变\n• 数据保留迹象：响应中是否包含"本平台保留对话记录"这类声明\n• 恶意指纹库：是否匹配已知的恶意中转站\n\n分数只反映你在本机的观察，不代表该中转站的客观信誉。',
  },
  {
    q: '发现危险响应后会发生什么？',
    a: '取决于安全级别：\n\n• 均衡/严格：直接阻断，你不会看到被篡改的内容，同时在首页和日志中记录原因\n• 宽松：放行并标记为「可疑」，首页与日志里能看到这次记录\n\n无论哪种情况，你都可以在「日志」页面查看具体触发了哪条规则、响应内容片段是什么。\n\n另外，系统托盘图标会在「刚拦截了一次危险」时红色脉冲一下（几秒后恢复）—— 那是「刚刚发生」的提醒，不是常驻状态。托盘的常驻颜色只有三种：绿色=防护运行中、灰色=防护已暂停或引擎未运行。',
  },
  {
    q: '关掉窗口后防护还生效吗？',
    a: '生效。关闭窗口只是隐藏到系统托盘，代理会继续运行。\n\n要真正退出，请右键点击托盘图标选择「退出玄盾」。\n\n托盘常驻颜色的含义：绿色=防护运行中；灰色=防护已暂停，或引擎未运行（此时防护确实没在跑，别以为它还在工作）。危险拦截只会让托盘红色「脉冲」几秒，不改变常驻颜色。',
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
      '模型名按中转站支持的填，玄盾原样转发、不改写',
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

        {/* ★ 第 0 步必须先讲：很多用户照着下面的教程改完地址，
             却发现玄盾首页写着「尚未配置中转站」——
             因为中转站地址和 Key 是在玄盾自己的「设置」页里填的，
             不填就没有「中转站」可谈。这不是玄盾坏了，是第 0 步没做。 */}
        <div className="field-hint mb-16" style={{ marginTop: 0 }}>
          <b>第 0 步（先做这个）：</b>打开玄盾「设置」页 →
          「中转站」区域填入<b>你自己中转站的 API 地址和 Key</b> → 保存。
          首页「当前中转站」显示出来才算配好。
        </div>

        <div className="field-hint mb-16">
          第 1 步：把 AI 工具的 API 地址统一改成{' '}
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
