#!/usr/bin/env python3
# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""误报申诉材料包生成器。

为什么要单独做一个脚本
──────────────────────
杀软误报申诉不是「点一下提交」就完事：每家都要文件哈希、版本号、
签名主体、行为说明，而且**每次发版哈希都会变**，必须重新提交。
手工收集这些信息，第一次还能耐着性子做，第二次开始就会漏 ——
漏了哈希，厂商回复「请提供文件 SHA256」，又要等一轮。

所以把它做成一条命令：跑完得到一个目录，里面是
  · REPORT.md        —— 一页纸事实表（版本/哈希/大小/PE 信息/扫描结论）
  · sha256.txt       —— 纯哈希清单，方便复制粘贴
  · appeal-火绒.md / appeal-360.md / appeal-腾讯.md / appeal-microsoft.md
                     —— 各家的申诉正文，事实已填好，只需补提交入口

用法
──────
    python .github/scripts/fp_appeal_pack.py <产物目录> [--out 输出目录]

产物目录里放本次要申诉的文件（安装包、引擎 exe、主程序 exe 均可）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PRODUCT = "道体·玄盾 个人版（XuanDun Personal）"
VENDOR = "DaoTi Research（独立研究者 知白）"
POSITIONING = (
    "本地 AI 防护网关：在本机 127.0.0.1 上监听，对用户与 AI 服务之间"
    "的请求做敏感信息脱敏（出站）与响应验真（入站），并把判定结果"
    "记录在本地数据库，供用户自查。不采集、不上传任何用户数据。"
)

# 各家申诉入口。★ 入口可能改版，脚本只负责把材料准备好，
#   不代替人工提交 —— 提交需要企业/个人实名，无法自动化。
VENDORS = {
    "火绒": {
        "entry": "火绒安全官网 → 误报反馈（需附样本与哈希）",
        "note": "火绒对 Python 打包产物（Nuitka/PyInstaller）的启发式较敏感，"
                "务必说明这是自研软件而非加载器。",
    },
    "360": {
        "entry": "360 样本上报平台 https://sample.360.cn/",
        "note": "选择「误报」类型，附上文件与哈希；可同时提交 VirusTotal 链接。",
    },
    "腾讯": {
        "entry": "腾讯哈勃分析 https://habo.qq.com/ → 误报申诉",
        "note": "腾讯电脑管家与哈勃共用样本库，提交一次即可。",
    },
    "microsoft": {
        "entry": "Microsoft WDSI 文件提交 https://www.microsoft.com/en-us/wdsi/filesubmission",
        "note": "选择 “Incorrectly detected as malware”，并勾选企业软件身份。",
    },
}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _pe_info(path: Path) -> dict:
    """只读 Windows 有效：返回 PE 版本资源里的厂商标识。"""
    if platform.system().lower() != "windows":
        return {}
    try:
        script = (
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
            "$i = (Get-Item -LiteralPath '%s').VersionInfo; "
            "@{company=$i.CompanyName; product=$i.ProductName; "
            "desc=$i.FileDescription; ver=$i.FileVersion; "
            "copyright=$i.LegalCopyright} | ConvertTo-Json -Compress"
        ) % str(path)
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=20,
            # ★ 中文 Windows 上 PowerShell 默认按 GBK 输出，直接按 UTF-8 解会
            #   在读取线程里抛 UnicodeDecodeError（主流程已经跑完，只在末尾
            #   吐一段吓人的 traceback）。errors="replace" 保证永远能读完。
            encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if out.returncode == 0 and (out.stdout or "").strip():
            return json.loads((out.stdout or "").strip())
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        pass
    return {}


def _signature(path: Path) -> str:
    if platform.system().lower() != "windows":
        return "（非 Windows 平台，未检查）"
    try:
        script = (
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
            "$s = Get-AuthenticodeSignature -LiteralPath '%s'; "
            "\"$($s.Status)|$($s.SignerCertificate.Subject)\""
        ) % str(path)
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=20,
            encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if out.returncode == 0 and (out.stdout or "").strip():
            return (out.stdout or "").strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return "（检查失败）"


def _version() -> str:
    """版本号从 Cargo.toml 读，保持与构建脚本同一真源。"""
    cargo = Path(__file__).resolve().parents[2] / "desktop" / "src-tauri" / "Cargo.toml"
    try:
        for line in cargo.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("version"):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "unknown"


def _collect(root: Path) -> list[dict]:
    items = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        if path.suffix.lower() not in (".exe", ".msi", ".dmg", ".deb", ".appimage"):
            continue
        items.append({
            "name": path.name,
            "path": str(path),
            "size": path.stat().st_size,
            "sha256": _sha256(path),
            "pe": _pe_info(path),
            "signature": _signature(path),
        })
    return items


def _facts_table(items: list[dict]) -> str:
    lines = [
        f"| 文件 | 大小 | SHA256 |",
        "|---|---|---|",
    ]
    for it in items:
        lines.append(
            f"| `{it['name']}` | {it['size'] / 1024 / 1024:.1f} MB | `{it['sha256']}` |"
        )
    return "\n".join(lines)


def _appeal_body(vendor: str, items: list[dict], version: str) -> str:
    sig = items[0]["signature"] if items else ""
    file_list = "\n".join(
        f"- {it['name']}（{it['size'] / 1024 / 1024:.1f} MB）\n  SHA256: {it['sha256']}"
        for it in items
    )
    return f"""# {vendor} 误报申诉：{PRODUCT}

您好，

我方产品 **{PRODUCT}** 被贵方引擎判定为恶意/可疑，申请复核并解除误报。

## 一、产品身份

- 产品名称：{PRODUCT}
- 开发者：{VENDOR}
- 版本：{version}
- 技术栈：Rust（Tauri 桌面端）+ Python（Nuitka 打包的本地引擎）
- 签名状态：{sig or "（未签名）"}

## 二、产品用途（无恶意行为）

{POSITIONING}

关键事实：

1. 只监听 `127.0.0.1`，不对外开放任何端口；
2. 所有数据留在本机 SQLite，不向开发者服务器上传；
3. 不修改系统设置、不注册开机自启动以外的持久化项；
4. 桌面端与引擎均为我方自研，不含第三方注入模块。

## 三、为什么会被启发式命中

本产品**必然**包含以下内容，它们是被误判的直接原因：

1. 引擎内含**攻击特征词表**（如提示词注入、越狱话术、恶意命令样例）——
   这是检测能力本身，不是载荷；
2. 引擎会把 Base64/Hex 编码的文本**解码后再匹配关键词**（用于识别
   混淆过的攻击载荷），这在外观上与「加载器解码后执行」相似，
   但解码结果只用于**匹配规则**，从不执行、不写盘、不联网；
3. 产物由 Nuitka 打包，Python 运行时会以压缩形式内嵌 ——
   这是打包工具的通用特征，不是加壳行为。

## 四、待复核文件

{file_list}

## 五、请求

1. 对上述文件做人工复核；
2. 若确认误报，将其加入白名单，并按发布者/证书主体做**持续信任**
   （本产品每次发版哈希都会变化）；
3. 如需补充材料（源码片段、行为录屏、沙箱日志），请告知，我们会配合提供。

谢谢。

—— {VENDOR}
生成时间：{datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")}
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="生成杀软误报申诉材料包")
    parser.add_argument("root", help="本次要申诉的产物目录")
    parser.add_argument("--out", default="appeal", help="输出目录（默认 ./appeal）")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"::error::目录不存在：{root}", file=sys.stderr)
        return 1

    items = _collect(root)
    if not items:
        print(f"::error::在 {root} 下未找到可执行产物", file=sys.stderr)
        return 1

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = Path(args.out).resolve() / stamp
    out_dir.mkdir(parents=True, exist_ok=True)
    version = _version()

    # 1) 纯哈希清单
    (out_dir / "sha256.txt").write_text(
        "\n".join(f"{it['sha256']}  {it['name']}" for it in items) + "\n",
        encoding="utf-8",
    )

    # 2) 一页纸事实表
    pe_lines = []
    for it in items:
        if it["pe"]:
            pe_lines.append(
                f"- `{it['name']}`：{it['pe'].get('company')} / "
                f"{it['pe'].get('product')} / {it['pe'].get('ver')}"
            )
    report = [
        f"# 误报申诉材料包 · {version}",
        "",
        f"生成时间：{datetime.now().astimezone().isoformat(timespec='seconds')}",
        "",
        "## 文件事实",
        "",
        _facts_table(items),
        "",
        "## 签名状态",
        "",
        *[f"- `{it['name']}`：{it['signature']}" for it in items],
        "",
        "## PE 元数据",
        "",
        *(pe_lines or ["（无）"]),
        "",
        "## 提交入口",
        "",
        *[f"- **{k}**：{v['entry']}\n  提示：{v['note']}" for k, v in VENDORS.items()],
        "",
        "## 提交后要做的事",
        "",
        "1. 把每家的回执编号记录到发布记录里；",
        "2. 回执到手后用 VirusTotal 重扫，确认对应引擎已放过；",
        "3. 若某家坚持判毒，先发版说明，不要硬发 —— 用户装不上等于没发。",
    ]
    (out_dir / "REPORT.md").write_text("\n".join(report) + "\n", encoding="utf-8")

    # 3) 各家申诉正文
    for vendor in VENDORS:
        (out_dir / f"appeal-{vendor}.md").write_text(
            _appeal_body(vendor, items, version), encoding="utf-8"
        )

    print(f"已生成：{out_dir}")
    for p in sorted(out_dir.iterdir()):
        print(f"  · {p.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
