# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
"""引擎 HTTP 响应与 Rust 侧的契约一致性。

为什么需要这个测试
────────────────────────────────────────────────────────────────
2026-09-28 用户激活失败，界面报错「验签结果解析失败:
missing field `verifier_available`」。

根因：Python 侧 ``VerifyResult::to_dict`` 输出的键是驼峰
（``verifierAvailable``），而 Rust 的 ``VerifyOutcome`` 字段是
蛇形且**没有**标注 ``#[serde(rename_all = "camelCase")]``，
serde 因缺字段而整体反序列化失败。

★ 这类故障最恶劣的地方：
  - 无论激活码对不对都会失败（错误信息指向码，用户反复换码）
  - 编译不报错、测试全绿（要等真实响应才暴露）
  - 报错信息（missing field）完全指不出真正原因是键名大小写

所以判据必须直接比对**两侧的键名**，而不是靠集成测试碰运气。
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from daoti_xuandun_personal import license as lic  # noqa: E402

LICENSE_RS = ROOT / "desktop" / "src-tauri" / "src" / "license.rs"


def _strip_rust_comments(src: str) -> str:
    """剥掉 Rust 注释，只留代码（字符串字面量原样保留）。"""
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        two = src[i : i + 2]
        if two == "//":
            end = src.find("\n", i)
            i = n if end == -1 else end
        elif two == "/*":
            depth, i = 1, i + 2
            while i < n and depth:
                if src[i : i + 2] == "/*":
                    depth += 1
                    i += 2
                elif src[i : i + 2] == "*/":
                    depth -= 1
                    i += 2
                else:
                    i += 1
        elif src[i] == '"':
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            out.append(src[i:j])
            i = j
        else:
            out.append(src[i])
            i += 1
    return "".join(out)


def _verify_outcome_fields() -> list[str]:
    """从 Rust 源码里取出 VerifyOutcome 的字段名（蛇形原样）。"""
    code = _strip_rust_comments(LICENSE_RS.read_text(encoding="utf-8"))
    m = re.search(r"pub struct VerifyOutcome\s*\{(.*?)\n\}", code, re.S)
    assert m, "Rust 侧找不到 struct VerifyOutcome"
    return re.findall(r"pub (\w+):", m.group(1))


def _has_camel_case_rename() -> bool:
    code = _strip_rust_comments(LICENSE_RS.read_text(encoding="utf-8"))
    m = re.search(
        r"#\[serde\(rename_all\s*=\s*\"camelCase\"\)\]\s*pub struct VerifyOutcome",
        code,
    )
    return bool(m)


def _to_camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(w.capitalize() for w in rest)


class TestVerifyOutcomeMatchesEngineJson:
    def test_every_field_is_camel_case_on_the_wire(self) -> None:
        """Python 实际吐出的每一个键，Rust 都必须能接住。

        判据是**直接跑一次 to_dict** 拿到真实键集，
        而不是抄一份「应该是什么」—— 后者会与实现一起漂移。
        """
        payload = lic.VerifyResult(True, subject="契约测试").to_dict()

        # 所有键都要对上，一个都不能漏 —— 包括 ok。
        # （`ok` 没有下划线，camelCase 转换后仍是它自己。）
        for field in _verify_outcome_fields():
            expected = _to_camel(field)
            assert expected in payload, (
                f"Rust 字段 `{field}` 经 camelCase 转换后应为 `{expected}`，"
                f"但引擎返回的键里没有它。引擎实际返回：{sorted(payload)}"
            )

    def test_struct_declares_camel_case_rename(self) -> None:
        """VerifyOutcome 必须标注 rename_all = "camelCase"。

        ★ 这是 2026-09-28 线上激活失败的直接原因。
           缺这个标注时 serde 逐字段按原名匹配，
           遇到 verifierAvailable vs verifier_available 不一致
           就报 missing field，而真实原因从报错里完全看不出来。
        """
        assert _has_camel_case_rename(), (
            "VerifyOutcome 缺少 #[serde(rename_all = \"camelCase\")] —— "
            "引擎返回驼峰键，Rust 按蛇形解析，必然反序列化失败"
        )

    def test_engine_verify_endpoint_returns_camel_keys(self) -> None:
        """verify 端点的响应键名也必须是驼峰。

        直接检查端点源码里的 to_dict 调用，确保没被改回蛇形。
        """
        app_py = (ROOT / "src" / "daoti_xuandun_personal" / "proxy" / "app.py").read_text(
            encoding="utf-8"
        )
        assert "result.to_dict()" in app_py, (
            "verify 端点必须原样返回 to_dict() 的结果 —— "
            "手工重组字典会引入键名漂移"
        )
