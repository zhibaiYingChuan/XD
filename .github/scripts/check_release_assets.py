#!/usr/bin/env python3
# SPDX-License-Identifier: DaoTi-Research-1.0
"""发布前校验**必备资产清单**，缺件必须显式豁免才允许发布（P0-9）。

为什么需要
────────────────────────────────────────────────────────────
v0.1.27-alpha 的实际形态：整体 run 是 success，Release 也建出来了，
但只有 3/4 个平台产物 —— Linux AppImage 那一个 job 在
`Build Tauri app` 被 runner 取消（同一形态已第 4 次），
而该 job 带 `continue-on-error`，于是它失败也不影响整体结论，
`Create Release` 的 `if: success()` 照常执行。

结果是「少了一个包」这件事**没有任何人被告知**：
Release 页面看起来正常，日志里只有一条早已被埋掉的 warning。
对用户而言，Linux 用户点进 Release 找不到 AppImage 才发现；
对维护者而言，下次同样的事再发生一次也不会被叫醒。

所以判据从「构建 job 成功与否」换成「**最终资产清单是否齐**」：
以 dist/ 里实际要上传的文件为准，缺了就是缺了。

判定位置
────────────────────────────────────────────────────────────
放在**创建 Release 之前**（由 release 工作流在 Compose notes 之前调用）。
理由：缺件时 Release 根本不存在，不需要「建了再删」——
删 Release 本身就有失败风险（删除 API 失败就留下一个残缺的公开
Release，而它已经通知了 watcher），而且会留下一次「发布了又撤」
的审计痕迹。发布前拦下，代价最小、状态最干净。

为什么 AppImage 可以缺
────────────────────────────────────────────────────────────
它走 linuxdeploy，会把 numpy 自带的 OpenBLAS 依赖链扫一遍，
历史上多次失败；Linux 用户还有 .deb 可装。
但「可以缺」必须由**人**显式声明（仓库变量 ALLOW_MISSING_APPIMAGE=1），
不能由流水线自己默认 -- 默认放行等于这道门禁不存在。

豁免必须让用户看见
────────────────────────────────────────────────────────────
豁免成立时脚本会写一段提示文本（--notice-out），
由发布说明步骤原样贴进 Release 正文。
缺件在正文里说清楚，用户才知道该下哪个包、Linux 自动更新为什么没了。

用法
────────────────────────────────────────────────────────────
    python .github/scripts/check_release_assets.py dist
    ALLOW_MISSING_APPIMAGE=1 python .github/scripts/check_release_assets.py dist \
        --notice-out /tmp/asset-notice.md
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# ★ 每个平台至少一个资产，缺一即失败。glob 针对的是
#   「Stage release assets with ASCII names」重命名之后的文件名。
REQUIRED: dict[str, str] = {
    "Windows 安装包（.exe）": "*.exe",
    "macOS 镜像（.dmg）": "*.dmg",
    "macOS 更新包（.app.tar.gz）": "*.app.tar.gz",
    "Linux 安装包（.deb）": "*.deb",
}

# ★ 可缺，但必须显式豁免（仓库变量 / 环境变量）。
EXEMPTABLE: dict[str, str] = {
    "Linux AppImage（.AppImage）": "*.AppImage",
}

EXEMPT_ENV = "ALLOW_MISSING_APPIMAGE"

# ★ 这段话会被原样贴进 Release 正文。不要写「构建失败」这类内部措辞 ——
#   用户只关心「我该下哪个包」和「自动更新还行不行」。
NOTICE = """## ⚠ 本次发布缺少 Linux AppImage

本次 Linux AppImage 缺件（linuxdeploy 打包未能完成），已按仓库变量
`ALLOW_MISSING_APPIMAGE=1` **显式豁免**后发布。

- Linux 用户请下载 **`.deb`** 安装，功能与 AppImage 版本一致。
- **Linux 上的自动更新本次不可用**：更新清单（`latest.json`）里没有
  Linux 条目，旧版本不会自动升级到这一版，请手动下载 `.deb` 覆盖安装。
"""


def _missing(dist: Path, patterns: dict[str, str]) -> dict[str, str]:
    return {
        label: pat
        for label, pat in patterns.items()
        if not any(dist.glob(pat))
    }


def main(argv: list[str]) -> int:
    dist_arg = ""
    notice_out = ""
    i = 0
    while i < len(argv):
        if argv[i] == "--notice-out":
            notice_out = argv[i + 1] if i + 1 < len(argv) else ""
            i += 2
            continue
        if not dist_arg:
            dist_arg = argv[i]
        i += 1

    dist = Path(dist_arg or "dist")
    if not dist.is_dir():
        print(f"::error::资产目录不存在：{dist}")
        return 1

    exempt = os.getenv(EXEMPT_ENV, "").strip() == "1"

    print(f"核对发布资产：{dist}")
    for label, pat in list(REQUIRED.items()) + list(EXEMPTABLE.items()):
        hits = sorted(p.name for p in dist.glob(pat))
        mark = "OK  " if hits else "缺失"
        print(f"  [{mark}] {label:<28} {', '.join(hits) if hits else '（无）'}")

    # ① 硬性缺件：任何豁免都不覆盖
    missing_required = _missing(dist, REQUIRED)
    if missing_required:
        for label, pat in missing_required.items():
            print(f"::error::缺少必备资产：{label}（{pat}）")
        print(
            "阻断发布：必备产物缺件时发布等于让那个平台的用户找不到安装包。\n"
            "处理：先查对应 build job 是否被取消/失败，重跑该 job 后再发。"
        )
        return 1

    # ② 可缺件：没豁免就阻断
    missing_optional = _missing(dist, EXEMPTABLE)
    if missing_optional and not exempt:
        for label, pat in missing_optional.items():
            print(f"::error::缺少资产且未豁免：{label}（{pat}）")
        print(
            f"阻断发布：如确认本次可以缺件，请设置仓库变量 {EXEMPT_ENV}=1 后重跑；\n"
            "豁免会自动在 Release 正文里写明缺件与影响（Linux 自动更新不可用）。"
        )
        return 1

    # ③ 豁免成立：留下正文提示，不能静默
    if missing_optional:
        print(
            f"::warning title=本次发布缺 Linux AppImage::已按 {EXEMPT_ENV}=1 豁免，"
            "缺件说明会写入 Release 正文（Linux 用户改用 .deb，自动更新不可用）。"
        )
        if notice_out:
            out = Path(notice_out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(NOTICE, encoding="utf-8")
            print(f"已写出正文提示：{out}")

    print("PASS：必备发布资产齐全")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
