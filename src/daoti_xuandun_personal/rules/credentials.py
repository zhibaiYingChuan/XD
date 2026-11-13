# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发

"""凭据判据 —— 个人版入口（re-export）。

★★ 真源不在这里，在 ``daoti_xuandun/credentials.py``。

为什么真源放在护栏包而不是这里：
  凭据判据同时被两个发行单元使用 ——
    · 个人版：sanitizer（请求侧）、verifier（响应侧）、detection_rules.yaml
    · 护栏包：sensitive_leak（企业版检测器）、_check_output（输出护栏）
  个人版依赖护栏包（build_engine 已把护栏子集打进引擎），
  但护栏包不能反向依赖个人版。所以真源只能放在被依赖的那一侧。

★ 这里只做 re-export，**不允许**再写第二份判据。
  真出现第二份时，`tests/test_credential_registry.py` 会通过
  「同一判据在多个模块里字面不一致」直接判失败。
"""

from __future__ import annotations

from daoti_xuandun.credentials import (  # noqa: F401
    BY_KEY,
    SPECS,
    CredentialSpec,
    cn_id_checksum_valid,
    combined_pattern,
    find_all,
    luhn_valid,
    specs_for,
)

#: 个人版沿用的私钥正则别名（历史代码引用这个常量名）
PEM_PRIVATE_KEY_PATTERN = BY_KEY["private_key_pem"].pattern

__all__ = [
    "BY_KEY",
    "SPECS",
    "CredentialSpec",
    "cn_id_checksum_valid",
    "combined_pattern",
    "find_all",
    "luhn_valid",
    "specs_for",
    "PEM_PRIVATE_KEY_PATTERN",
]
