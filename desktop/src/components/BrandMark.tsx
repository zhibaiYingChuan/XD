/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   品牌标志 ⟦勘⟧。
   双括号来自产品的占位符格式 ⟦KH_n⟧，代表「你看到的」和「它收到的」之间的边界。
   路径由思源宋体转出，不依赖字体安装。
*/

type Props = {
  size?: number;
  /** 括号颜色，默认品牌朱砂 */
  bracket?: string;
  /** 「勘」字颜色，默认主文字 */
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
        d="M385 248 266 300C249 220 225 127 205 69L219 61C266 107 310 171 345 231C366 229 379 236 385 248ZM389 293 378 287C408 241 437 170 441 113C519 42 607 204 389 293ZM533 408 487 339V675H588C602 675 612 680 615 691C582 725 527 775 527 775L487 717V811C511 815 519 824 521 838L385 851V704H239V809C263 813 270 822 272 836L136 849V704H42L50 675H136V339H25L33 311H93V45C79 37 64 25 55 16L165 -43L199 5H499C513 5 523 10 526 21C490 56 429 106 429 106L375 33H191V311H593C607 311 617 316 619 327C588 360 533 408 533 408ZM782 834 634 848V589H536L545 560H634C631 303 605 94 463 -73L475 -87C697 67 735 286 743 560H823C817 224 808 75 778 45C769 36 761 33 745 33C726 33 683 36 655 38L654 24C688 16 712 3 725 -13C737 -28 739 -54 739 -90C788 -90 831 -77 862 -43C913 9 925 140 931 543C953 545 966 552 973 561L872 650L812 589H744L746 806C770 810 779 819 782 834ZM385 675V582H239V675ZM385 339H239V436H385ZM385 465H239V553H385Z"
        fill={glyph}
        transform="translate(33.05,80.55) scale(0.054,-0.054)"
      />
    </svg>
  );
}
