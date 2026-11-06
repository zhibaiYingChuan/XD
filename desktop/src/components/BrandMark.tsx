/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   品牌标志 ⟦玄⟧。
   双括号来自产品的占位符格式 ⟦XD_n⟧，代表「你看到的」和「它收到的」之间的边界。
   路径由思源宋体转出，不依赖字体安装。
*/

type Props = {
  size?: number;
  /** 括号颜色，默认品牌朱砂 */
  bracket?: string;
  /** 「玄」字颜色，默认主文字 */
  glyph?: string;
};

export function BrandMark({
  size = 24,
  bracket = 'var(--xd-primary)',
  glyph = 'var(--xd-text)',
}: Props) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 120 120"
      aria-hidden="true"
      style={{ display: 'block', flexShrink: 0 }}
    >
      <path d="M26 18 H10 V102 H26" stroke={bracket} strokeWidth={5} fill="none" />
      <path d="M40 27 H26 V93 H40" stroke={bracket} strokeWidth={5} fill="none" />
      <path d="M80 27 H94 V93 H80" stroke={bracket} strokeWidth={5} fill="none" />
      <path d="M94 18 H110 V102 H94" stroke={bracket} strokeWidth={5} fill="none" />
      <path
        d="M842 759 771 670H518C585 689 602 820 386 852L378 846C411 806 444 743 450 687C461 678 472 673 483 670H31L40 641H410C368 562 252 430 170 388C158 381 132 377 132 377L196 239C205 243 214 251 221 263C324 284 417 306 494 326C388 225 262 127 171 82C152 71 118 66 118 66L183 -75C191 -71 199 -65 205 -56C441 -12 636 30 773 64C793 21 808 -22 816 -63C952 -169 1051 126 653 266L643 259C684 213 725 155 757 94C555 81 364 71 240 65C433 160 668 315 774 422C798 416 814 423 820 433L674 533C647 489 601 434 547 378C423 374 309 371 233 370C338 419 461 497 527 558C547 554 560 561 565 571L429 641H942C957 641 968 646 970 657C922 699 842 759 842 759Z"
        fill={glyph}
        transform="translate(32.97,80.70) scale(0.054,-0.054)"
      />
    </svg>
  );
}
