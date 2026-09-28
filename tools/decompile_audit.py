# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""反编译风险评估：检查发布产物里还剩下什么。

为什么需要这个脚本
────────────────────────────────────────────────────────────────
「加了混淆/加固就安全了」是个危险念头。真正该问的是：
**发布产物里还剩下哪些可被直接读取的东西？**

本脚本对编译后的引擎二进制做静态检查，列出：
  · 明文密钥（激活私钥、护栏 fallback 密钥）
  · 私钥 PEM 特征串
  · 内部提示词/系统提示词
  · 源码路径与函数名残留（辅助逆向的定位信息）
  · 检测规则全文（判据一旦公开，攻击者可针对性绕过）

用法：
    python tools/decompile_audit.py [引擎二进制路径]

判定原则：**只报事实，不下结论**。
「二进制里有 X」是事实；「所以是否安全」需要结合攻击模型判断。
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# ══════════════════════════════════════════════════════════════
# 检查项定义
# ══════════════════════════════════════════════════════════════
#
# ★ 每一项都要写清「为什么这条要紧」，否则没人会认真看结果。
#   写「检测私钥」不如写「私钥出现 = 任何人都能签发激活码 = 授权体系失效」。

CHECKS = [
    {
        "name": "激活码签名私钥",
        "why": "私钥出现 = 任何人都能签发激活码 = 授权体系瞬间失效。"
               "这是整个发布链路里唯一不可逆的底线。",
        "severity": "critical",
        "patterns": [
            # ★ 必须匹配**完整 PEM 块**，不能只搜头部字符串。
            #   只搜 "BEGIN PRIVATE KEY" 会稳定误报，因为二进制里必然含有：
            #     · cryptography 库的 PEM 头部解析正则
            #     · PyJWT 内置的官方测试样例私钥（AKIAIOSFODNN7EXAMPLE）
            #     · 护栏库的中文文档字符串（列举 PEM 头部做示例）
            #   那三处都不是我们的密钥。误报的审计等于没有审计。
            rb"-----BEGIN (?:RSA |ENCRYPTED )?PRIVATE KEY-----[ \t]*\r?\n"
            rb"(?:[A-Za-z0-9+/]{60,}[ \t]*\r?\n){4,}"
            rb"-----END (?:RSA |ENCRYPTED )?PRIVATE KEY-----",
        ],
    },
    {
        "name": "护栏 fallback 明文密钥",
        "why": "shell_key / mapping_key 是动态壳与符号映射的初始化种子。"
               "固定值公开 = 反编译者拿到种子，可复现内部状态。",
        "severity": "high",
        "patterns": [
            rb"daoti_xuandun_16",
            rb"ancient_map_16b!",
        ],
    },
    {
        "name": "构建期密钥",
        "why": "build_secrets.json 的**真实密钥值**若以明文落在二进制里，"
               "等同于没做构建期注入。注意不能搜 'build_secrets' 这个词 ——"
               "函数名 _inject_build_secrets 与文件名常量必然命中，那是误报。",
        "severity": "high",
        # ★ 不放静态 pattern：搜 "build_secrets" 只会命中函数名与文件名常量，
        #   那不是密钥。真实值由 audit() 读 build_secrets.json 后动态比对。
        "patterns": [],
        "from_secrets_file": "build_secrets.json",
    },
    {
        "name": "内部路径",
        "why": "绝对路径会直接指出源码位置与构建机用户名，"
               "为后续逆向提供定位信息。不致命，但清理成本极低。",
        "severity": "low",
        "patterns": [
            rb"[A-Z]:\\\\?XuanDun",
            rb"/home/[a-z]+/",
            rb"C:\\\\Users\\\\[A-Za-z0-9_.-]+",
        ],
    },
    {
        "name": "Python 内部标识",
        "why": "__nuitka__ / co_filename 等是 Nuitka 的固有产物，"
               "删不掉也不必删（说明用了编译而非打包源码）。"
               "列出来是为了避免误以为是自己的疏漏。",
        "severity": "info",
        "patterns": [
            rb"__nuitka__",
        ],
    },
    {
        "name": "检测判据文本",
        "why": "判据以明文存在时，攻击者能反推哪些模式会被拦，"
               "从而构造绕过样本。这是检测类产品的固有暴露面，"
               "列出以便评估是否需要外置或加密。",
        "severity": "medium",
        "patterns": [
            rb"undeclared_tool",
            rb"toolchain_injection",
            rb"model_downgrade",
            rb"system_prompt_inject",
        ],
    },
]

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_LABEL = {
    "critical": "阻断",
    "high": "高",
    "medium": "中",
    "low": "低",
    "info": "信息",
}


def find_engine() -> Path | None:
    """定位引擎二进制。"""
    here = Path(__file__).resolve().parent.parent
    cands = [
        here / "desktop" / "src-tauri" / "resources" / "engine",
        here / "desktop" / "src-tauri" / "resources",
    ]
    for d in cands:
        if not d.is_dir():
            continue
        for p in d.iterdir():
            if p.is_file() and p.name.startswith("xuandun-engine-"):
                return p
    return None


def audit(binary: Path) -> int:
    data = binary.read_bytes()
    size_mb = len(data) / 1024 / 1024

    print("=" * 70)
    print("  玄盾个人版 — 发布产物反编译风险评估")
    print("=" * 70)
    print(f"  产物: {binary}")
    print(f"  体积: {size_mb:.1f} MB")
    print()

    findings = []
    secrets_path = binary.parent / "build_secrets.json"
    secret_values: list[str] = []
    if secrets_path.is_file():
        try:
            raw = json.loads(secrets_path.read_text(encoding="utf-8"))
            secret_values = [str(v) for v in raw.values() if v]
        except (OSError, ValueError) as e:
            print(f"  [警告] 读取 {secrets_path.name} 失败：{e}\n")

    for chk in CHECKS:
        hits = {}
        for pat in chk["patterns"]:
            n = len(re.findall(pat, data))
            if n:
                key = pat.decode("ascii", "replace")
                hits[key] = n
        # ★ 动态比对：真实密钥值是否被编进了二进制
        #   只对「构建期密钥」这一项做，避免同一个值在每一项里重复报警
        if chk.get("from_secrets_file"):
            for val in secret_values:
                if val.encode("ascii", "ignore") in data:
                    hits[f"实际密钥值 {val[:6]}…"] = 1
        findings.append((chk, hits))

    findings.sort(key=lambda x: (SEV_ORDER[x[0]["severity"]], sum(x[1].values())))

    worst = "info"
    for chk, hits in findings:
        sev = chk["severity"]
        label = SEV_LABEL[sev]
        mark = "✗" if hits else "·"
        if hits and SEV_ORDER[sev] < SEV_ORDER[worst]:
            worst = sev
        print(f"[{label:>2}] {mark} {chk['name']}")
        if hits:
            for k, n in sorted(hits.items(), key=lambda x: -x[1]):
                print(f"        命中 {n:>4} 次: {k}")
        print(f"        为什么要紧: {chk['why']}")
        print()

    print("=" * 70)
    if worst in ("critical",):
        print("  ✗ 存在阻断级风险 —— 不得发布")
    elif worst == "high":
        print("  ⚠ 存在高风险项 —— 建议处理后再发布")
    else:
        print("  ✓ 未发现阻断级或高风险项")
    print("=" * 70)
    print()
    print("诚实说明：本脚本只能看到**静态可读**的部分。")
    print("以下情况它看不到，也不该被当成「安全」：")
    print("  · 运行时动态解密得到的值（本项目的密钥本就是构建期随机生成）")
    print("  · 调试器附加后的运行时修改")
    print("  · 打补丁跳过校验（校验点分散只能抬高门槛，不能根除）")
    return 0


def main() -> int:
    if len(sys.argv) > 1:
        binary = Path(sys.argv[1])
        if not binary.is_file():
            print(f"找不到文件: {binary}", file=sys.stderr)
            return 2
    else:
        binary = find_engine()
        if binary is None:
            print("未找到引擎二进制，请先运行 build_engine.py", file=sys.stderr)
            return 2

    return audit(binary)


if __name__ == "__main__":
    sys.exit(main())
