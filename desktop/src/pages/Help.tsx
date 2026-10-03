/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   帮助页 — 消费级 FAQ + 上手步骤。

   ★ 关于「AI 工具」这一段的写法（2026-09-29 改）：
     原先按 Cursor / Cherry Studio / 自建脚本逐个列教程，
     但那些具体菜单路径从未被验证过 —— 写没核实过的步骤，
     等于让用户照着可能失效的操作去折腾。
     现在的写法只讲两件事：
       ① 在玄盾设置页填平台给的中转站地址与 Key；
       ② 在 AI 工具里填玄盾给的本地地址。
     不点名具体工具、不描述各家菜单在哪 ——
     用户用的是哪个工具、界面长什么样，只有他自己知道。
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
    a: `因为玄盾要"站在中间"检查数据，就像安检机需要你把行李放上传送带。\n\n你需要把 AI 工具的 API 地址从 https://api.xxx.com 改成 ${P}，这样流量就会先经过玄盾再发往中转站。\n\n前提是这个工具支持自定义 API 地址 —— 玄盾是本地代理，不是全局代理，它只处理「被指向它」的流量。`,
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
    q: '可以配多家中转站吗？该怎么切换？',
    a: `可以。在「设置」页的「已配置的中转站」区域点「添加另一家中转站」，填入显示名、地址与 API Key 就多存一家；不需要的随时可以「移除」。\n\n每一家是一张独立卡片，带绿色边框和「当前使用中」徽标的那家就是当前生效的。点其它家的「切到这家」即可切换。\n\n★ 三条容易踩的坑：\n• 添加只是「存起来备着」，不会自动切换 —— 当前用哪家仍由你手动指定\n• 切换只改默认目标，不会改动任何一家的地址与 Key\n• 不做自动轮询或自动故障转移：一个请求只发往一家，带宽不会摊薄；而且自动切换会让「这次扣了谁的钱」变得不可知\n\n转发时的实际规则：玄盾按请求里带的 API Key 自动识别发给哪家；Key 对不上时用「当前使用中」这家。所以 AI 工具里填的 Key 必须是其中一家的 —— 否则会落到默认那家，看起来「明明配了却没生效」。`,
  },
  {
    q: '为什么有时候回答突然变长/变短，会被记一条？',
    a: '会记，但不会拦你。\n\n玄盾会看每次回答的长度和结构跟你之前的对话比一比。如果这次明显不一样（比如你问「你好」回3 个字，下一个技术问题回了 11000 字），它会记一条「这次回答和平时不太一样」。\n\n★ 这类检查只是记录，永远不会因此中断你的对话，也不会算中转站信誉分。因为长度不一样只是「样子不同」，并不能证明中转站动了手脚—— 你换个话题，答案长度自然就变了。\n\n真正会拦你的只有明确的证据：中转站调用了你没授权的功能、偷偷换掉了你付费买的模型、在回答里藏了不给你看的指令、或者泄漏了本该属于你的敏感信息。遇到这些时，玄盾会拦下并告诉你原因，同时建议你换个官方 API 地址把没干完的活继续做完。',
  },
  {
    q: '被拦下来了怎么办？我还有活没干完。',
    a: '被拦说明当前中转站确实有问题（比如它调了你没授权的功能，或换了你的模型）。玄盾拦下时会明确告诉你原因。\n\n★ 三个可行的做法：\n\n① 把 AI 工具的 API 地址改回模型厂商官方地址，接着把没干完的活做完 —— 这是最彻底的办法，中转站碰不到你的数据\n② 在「设置 → 已配置的中转站」换一家，再重试\n③ 如果你确认是误报，在日志详情里点「标记为安全」，这一条就不会再计入统计\n\n注意：这段对话在换地址前无法继续 —— 玄盾不会把被拦下的内容放行。',
  },
  {
    q: '日志里那些看不懂的检测项是什么意思？',
    a: '日志会用人话告诉你「发现了什么」，比如「中转站调用了你没有授权的功能」。\n\n★ 如果你想看技术细节（比如具体命中了哪个模型、片段长什么样），在每条发现下面点「查看技术细节」就能展开 —— 不展开也能看懂，不需要看 σ 值或字符偏移。',
  },
  {
    q: '端口可以改吗？',
    a: `可以。在「设置」页的「本地代理端口」填一个 1024–65535 之间的端口，点「更改端口」后重启玄盾即可生效。\n\n常见需要改端口的情况：\n• 18765 已被别的程序占用\n• 你同时开着多个玄盾实例（比如稳定版和开发版）\n\n★ 改完端口后，AI 工具里的 API 地址也要跟着改成新端口，否则连不上。玄盾界面底部显示的本地地址始终是当前实际端口，照着填就不会错。`,
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
    name: '第一步 · 在玄盾里填中转站',
    steps: [
      '打开玄盾「设置」页',
      '「代理配置」区域填入平台给你的 API 地址与 API Key',
      '点「测试连接」确认地址与 Key 可用（会发出一真实请求）',
      '保存。首页「当前中转站」显示出域名即成功',
      '要同时用多家中转站，就在下方「已配置的中转站」点「添加另一家中转站」存着备用',
    ],
  },
  {
    icon: FileText,
    name: '第二步 · 在 AI 工具里填玄盾给的地址',
    steps: [
      '玄盾会给你一个本地地址，形如 http://127.0.0.1:18765/v1（端口以界面显示为准）',
      '在 AI 工具的 API 地址一栏填这个本地地址，API Key 仍填中转站那把',
      '之后所有请求都先经过玄盾再转发给中转站',
    ],
  },
  {
    icon: SettingsIcon,
    name: '如果连不上，按这个顺序排查',
    steps: [
      '首页「当前中转站」是否显示了域名 —— 没显示说明玄盾侧还没配上',
      'AI 工具里填的是玄盾的本地地址，而不是中转站的地址（两者不能混）',
      'Key 是否与玄盾设置页里填的是同一把',
      '填的是多家中转站时，Key 必须属于其中一家 —— 否则会落到「当前使用中」那家',
      '以上都正常仍无记录 → 你的工具可能不支持自定义 API 地址',
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
        <p className="page-subtitle">常见问题与上手步骤</p>
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
        <div className="card-title">让玄盾生效（两步，缺一不可）</div>

        {/* ★ 两步都在「设置」类页面里完成，但分属两个软件：
             ① 玄盾里填中转站 —— 平台给你的 API 地址与 Key 填在这里；
             ② AI 工具里填玄盾的本地地址 —— 之后流量才先经过玄盾。
             少任何一步，防护都不生效，而界面看不出异常。 */}
        <div className="field-hint mb-16" style={{ marginTop: 0 }}>
          <b>第 2 步要填的地址长这样：</b>
          <div className="mt-8">
            <code className="mono" style={{ color: 'var(--xd-safe)' }}>
              http://127.0.0.1:{currentProxyPort()}/v1
            </code>
          </div>
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
