# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""护栏缺失时的降级行为自检（CI 门禁 0）。

为什么需要这个文件
────────────────────────────────────────────────────────────────
README 承诺「未安装企业版 SDK 时个人版仍可运行（仅少了护栏层）」。

这条承诺有一个危险的失效模式：某次依赖调整后，
`import daoti_xuandun` 开始失败，而 `_try_load_guardrail()`
用 `except Exception` 把它吞掉、只打一条 warning ——
代理照常启动，`get_stats()` 里 `guardrail_available` 变成 False，
但**没有任何地方告诉用户少了两层检测**。

结果不是报错，而是「防护能力静默减半」。
这类问题不会被任何常规测试发现：代码能跑、测试全绿。

本文件把「降级必须是可见的」这条要求固化成可执行断言。

两种模式（CI 里两个 job 各跑一种）：
    python personal/tests/check_degradation.py                    # 护栏应缺失
    python personal/tests/check_degradation.py --with-guardrail   # 护栏应可用

只跑一种的话，另一种的退化不会被发现。
"""

import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from daoti_xuandun_personal.proxy.baseline import build_baseline  # noqa: E402
from daoti_xuandun_personal.proxy.verifier import ResponseVerifier  # noqa: E402


def main() -> int:
    v = ResponseVerifier()
    stats = v.get_stats()

    # 带 --with-guardrail 时校验「护栏已加载」，否则校验「护栏缺失」。
    # 两种环境都要在 CI 里跑 —— 只测一种，另一种的退化不会被发现。
    expect_guardrail = "--with-guardrail" in sys.argv

    print("=" * 66)
    print("  护栏状态自检" + ("（含护栏模式）" if expect_guardrail else ""))
    print("=" * 66)
    print(f"  护栏可用        : {stats['guardrail_available']}")
    print(f"  规则来源        : {stats['rules_source']}")
    print(f"  规则数          : {stats['rules_count']}")
    print(f"  失效的检测层    : {stats['guardrail_missing_layers']}")
    print(f"  degraded 标志   : {stats['degraded']}")
    print()

    problems = []

    # ① 护栏状态必须符合当前模式
    #
    # ★ 语义已变更（2026-09）：护栏从「依赖企业版 SDK」改为
    #   **仓库内置子集**（src/daoti_xuandun/，见 GUARDRAIL.md）。
    #   所以「护栏缺失」不再是 CI 的预期环境 ——
    #   恰恰相反，护栏不可用现在是一个**真实缺陷**，
    #   因为它意味着少两层检测而用户界面照常显示「防护中」。
    #
    #   两种模式下都要求护栏可用：
    #     · --with-guardrail：显式验证
    #     · 默认模式：也必须可用（内置了就不该再靠外部 SDK）
    if not stats["guardrail_available"]:
        if expect_guardrail:
            print(f"[FAIL] 护栏不可用（--with-guardrail 模式）：{stats}")
            problems.append("护栏未加载")
        else:
            print("[FAIL] 护栏不可用 —— 内置护栏子集未能加载")
            print("       提示词注入 + 敏感泄露两类检测已失效，")
            print("       而界面会照常显示「防护中」，用户无从察觉")
            print("       排查：python -m pytest tests/test_guardrail_parity.py -v")
            problems.append("内置护栏未加载（检测能力静默下降）")
    elif stats["degraded"]:
        print(f"[FAIL] 护栏可用却处于降级状态：{stats}")
        problems.append("degraded 标志与实际状态矛盾")
    else:
        src = sys.modules.get("daoti_xuandun")
        origin = getattr(src, "__file__", "?")
        in_repo = str(Path(origin).resolve()).startswith(
            str((Path(__file__).resolve().parent.parent / "src").resolve())
        )
        print(f"[PASS] 护栏已加载且未降级（来源：{'仓库内置' if in_repo else origin}）")
        if not in_repo:
            # 本机装了企业版 SDK 时，加载的可能不是仓库内置那份 ——
            # 那种情况下 CI 的「通过」验的不是要发布的那份代码。
            print("[WARN] 护栏来自仓库外部，可能是本机安装的企业版 SDK")
            print("       而非仓库内置子集 —— 测试通过但验的不是要发布的代码")

    # ② 降级必须对外可见，不能静默
    expected_missing = (
        [] if stats["guardrail_available"]
        else ["system_prompt_inject", "sensitive_leak"]
    )
    if stats["guardrail_missing_layers"] != expected_missing:
        print(f"[FAIL] 失效层未正确暴露："
              f"{stats['guardrail_missing_layers']}（应为 {expected_missing}）")
        problems.append("guardrail_missing_layers 未如实报告失效的检测层")
    else:
        print("[PASS] 失效的检测层已如实暴露")

    if stats["degraded"] is not (not stats["guardrail_available"]):
        print(f"[FAIL] degraded 标志与实际状态矛盾：{stats['degraded']}")
        problems.append("degraded 标志与实际状态矛盾")
    else:
        print("[PASS] degraded 标志与实际状态一致")

    # ③ 规则必须从文件加载（外置判据未生效同样是静默降级）
    if stats["rules_source"] != "file":
        print(f"[FAIL] 规则来自 {stats['rules_source']}，"
              f"外置判据未生效（拦截能力大幅下降）")
        problems.append(f"规则来源为 {stats['rules_source']} 而非 file")
    else:
        print(f"[PASS] 规则从文件加载（{stats['rules_count']} 条）")

    # ④ 护栏缺失时，其余检测类别必须仍然工作
    bl = build_baseline({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "x"}],
        "tools": [{"type": "function", "function": {"name": "read_file"}}],
    })
    clean = v.verify('{"choices":[{"message":{"content":"ok"}}]}',
                     session_id="deg", baseline=bl)
    if clean.findings:
        print(f"[FAIL] 无攻击样本产生了告警："
              f"{sorted({f.category for f in clean.findings})}")
        problems.append("正常内容被误判")
    else:
        print("[PASS] 无攻击样本不产生告警")

    # ⑤ 护栏缺失时，自研检测（工具名/模型/约束）仍应有效
    #    必须传 payload=：否则 extract_response_facts 拿不到 tool_calls
    #    中的工具名，undeclared_tool 判据不会触发。
    evil_payload = {
        "choices": [{"message": {"tool_calls": [
            {"function": {"name": "exfiltrate_env", "arguments": "{}"}}
        ]}}]
    }
    evil = v.verify(
        json.dumps(evil_payload, ensure_ascii=False),
        session_id="deg2", baseline=bl, payload=evil_payload,
    )
    cats = {f.category for f in evil.findings}
    if "undeclared_tool" not in cats:
        print(f"[FAIL] 护栏缺失后自研检测也失效了：{sorted(cats)}")
        problems.append("护栏缺失导致全部检测层失效")
    else:
        print("[PASS] 自研检测层正常（undeclared_tool，不依赖企业版护栏）")

    # ⑥ 激活校验能力必须可见
    #
    # ★ 为什么要单独查：激活码校验依赖「公钥 + pyjwt」。
    #   两者任一缺失，用户看到的都是「激活码无效」，
    #   而真因是「验签组件没打进去」—— 反复换码永远激活不了，
    #   且客服从错误文案里看不出真因。
    #
    #   这里断言的是「状态可被查询」，而不是「公钥必须存在」：
    #   开发环境下没有公钥是合法的（此时应如实报告不可用）。
    from daoti_xuandun_personal import license as _lic

    pub = _lic.load_public_key()
    try:
        import jwt as _jwt  # noqa: F401
        has_jwt = True
    except ImportError:
        has_jwt = False

    if not has_jwt:
        print("[FAIL] pyjwt 未安装 —— 激活码验签无法执行")
        print("       用户会看到「激活码无效」，而真因是组件缺失")
        problems.append("pyjwt 缺失，激活码验签不可用")
    elif not pub:
        # 缺公钥是合法的开发态，但必须可见
        print("[WARN] 未配置激活码公钥 —— 激活功能当前不可用")
        print("       （开发态可接受；发布前必须注入公钥）")
    else:
        print("[PASS] 激活校验组件就绪（公钥已加载 + pyjwt 可用）")

    # ⑦ 「验不了」绝不能被当成「验过了」
    #
    # 这是整个激活系统最危险的失效方向：公钥缺失时若返回 ok=true，
    # 全部防护白嫖且无任何报错。所以必须有一致性断言。
    r = _lic.verify("XDACT-dummy.payload.sig", "x")
    if r.ok:
        print("[FAIL] 无效激活码竟然通过了验签")
        problems.append("激活码验签形同虚设")
    elif r.reason == "verifier_unavailable" and pub:
        print("[FAIL] 公钥已加载却报验签组件不可用")
        problems.append("验签组件状态报告矛盾")
    else:
        print(f"[PASS] 无效激活码被正确拒绝（reason={r.reason}）")

    print()
    print("=" * 66)
    if problems:
        print(f"  自检失败：{len(problems)} 项问题")
        for p in problems:
            print(f"    · {p}")
        print("=" * 66)
        return 1
    print("  自检通过：能力状态与对外报告一致")
    print("=" * 66)
    return 0


if __name__ == "__main__":
    sys.exit(main())
