/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   更新说明的「人话化」解析。

   ★ 为什么需要这一层
   ────────────────────────────────────────────────────────────
   latest.json 里的 notes 来自发布流程，天然可能带 Markdown
   （`## 标题`、`- 列表`、`**加粗**`、行内代码）。直接 pre-wrap
   丢进弹窗，用户看到的是：

       ## 本次更新
       - **修复**了 `xxx` 场景下……

   这不叫「用人话描述」。这里把每一行归一成一条短句，
   弹窗按条目渲染，用户扫一眼就知道这版改了什么。
   单一来源仍是发布侧（.github/release_notes/<version>.md），
   前端不再维护第二份版本说明 —— 两份必然不同步。
*/

/** 单条说明的最大长度：超过则截断，避免某条失控长文撑爆弹窗。 */
const MAX_ITEM_LEN = 180;

/** 最多展示的条目数：再多用户也不会看，只会觉得「又在堆更新日志」。 */
const MAX_ITEMS = 12;

/** 释放 URL 编码，便于对外展示与比对 */
function tidy(s: string): string {
  return s
    // 行内代码 → 纯文本
    .replace(/`([^`]+)`/g, '$1')
    // 加粗 / 斜体 → 纯文本
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/__([^_]+)__/g, '$1')
    // 链接 [文案](地址) → 文案
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    // 列表/引用前缀
    .replace(/^[-*+]\s+/, '')
    .replace(/^\d+[.)]\s+/, '')
    .replace(/^>\s?/, '')
    .trim();
}

/**
 * 把更新说明原文拆成人类可读的条目。
 *
 * @param raw latest.json 的 notes（Markdown 或纯文本均可）
 * @param limit 最多返回条数
 */
export function parseUpdateNotes(raw?: string | null, limit = MAX_ITEMS): string[] {
  if (!raw) return [];
  const out: string[] = [];
  for (const line of raw.split(/\r?\n/)) {
    let s = line.trim();
    if (!s) continue;
    // 分隔线（--- / === / ***）不带信息，跳过
    if (/^([-_*=])\1{2,}$/.test(s)) continue;
    // 标题行保留文字，去掉井号
    s = s.replace(/^#{1,6}\s*/, '');
    s = tidy(s);
    if (!s) continue;
    if (s.length > MAX_ITEM_LEN) s = `${s.slice(0, MAX_ITEM_LEN)}…`;
    out.push(s);
    if (out.length >= limit) break;
  }
  return out;
}

/** 没有任何可用说明时的兜底文案（对照组：默认值不能是「见 GitHub Release 说明」）。 */
export const FALLBACK_NOTE =
  '这一版主要是稳定性与使用体验上的修复，没有需要你重新学习的变化，建议更新。';
