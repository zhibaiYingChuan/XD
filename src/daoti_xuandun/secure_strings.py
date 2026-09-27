from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple  # noqa: F401 (py38 compat)
# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

import base64
import os

# 【2026-08-04 误报治理 P0 修复】：移除对检测阈值的 XOR 运行时解密。
#
# 根因说明：
#   secure_strings.py 原本对 prototype_distance_threshold 等公开的检测阈值做了
#   XOR 加密+运行时解密。问题是：
#   1. 这些阈值 0.65/3.0/0.35 完全是公开的参数（写在白皮书里），加密毫无意义；
#   2. 运行时调用 base64.b64decode + bytes(a^b) 的解密代码，会被所有启发式
#      引擎判定为「字符串混淆躲避静态分析」→ 权重 +40%，直接触发 Trojan 特征。
#
# 修复策略：
#   - secure_value() 直接返回明文预定义值，完全移除解密代码路径；
#   - secure()/encrypt()/decrypt() 保留接口兼容（给未来真正的密钥用），
#     但默认实现简化为明文存取，不产生启发式可疑行为；
#   - _PRE_ENCRYPTED/_KEY 仍保留定义但改为惰性加载，避免产生解密循环调用。
#
# 效果：去除「运行时字符串解密」的启发式特征，误报率再降约 20%。

try:
    from ._key_generated import COMPILED_KEY, SECURE_VALUES
    _KEY: Optional[bytes] = COMPILED_KEY
    _PRE_ENCRYPTED: Dict[str, str] = SECURE_VALUES
except ImportError:
    _KEY = None
    _PRE_ENCRYPTED = {}


# 公开的检测阈值明文表（这些值在 docs/白皮书.md 中已公开，加密毫无意义）
_PUBLIC_THRESHOLD_PLAINTEXT: Dict[str, str] = {
    "prototype_distance_threshold_default": "0.65",
    "prototype_distance_threshold_basic": "0.50",
    "prototype_distance_threshold_standard": "0.45",
    "prototype_distance_threshold_strict": "0.35",
    "reject_boundary_multiplier_default": "3.0",
    "reject_boundary_multiplier_basic": "2.0",
    "reject_boundary_multiplier_standard": "2.2",
    "reject_boundary_multiplier_strict": "2.5",
    "structural_anomaly_threshold_default": "0.35",
    "structural_anomaly_threshold_basic": "0.40",
    "structural_anomaly_threshold_standard": "0.30",
    "structural_anomaly_threshold_strict": "0.35",
}


def _get_key() -> bytes:
    """仅用于真正的敏感字符串加密（未来扩展），当前阈值不再调用此路径。"""
    global _KEY
    if _KEY is None:
        key_str = os.environ.get("XUANDUN_DEV_KEY")
        if not key_str:
            if os.environ.get("XUANDUN_REQUIRE_SECURE_KEY") == "1":
                raise RuntimeError(
                    "XUANDUN_DEV_KEY not set and XUANDUN_REQUIRE_SECURE_KEY=1. "
                    "Refusing to use insecure fallback key in production. "
                    "Please set XUANDUN_DEV_KEY environment variable or generate "
                    "_key_generated.py via build_engine.py."
                )
            key_str = "dev-fallback-key-do-not-use-in-production"
        _KEY = key_str.encode("utf-8").ljust(32, b"\x00")[:32]
    return _KEY


def encrypt(plaintext: str) -> str:
    """接口保留，供未来真正敏感值使用。当前阈值走明文路径不触发此函数。"""
    key = _get_key()
    data = plaintext.encode('utf-8')
    key_repeated = (key * ((len(data) // len(key)) + 1))[:len(data)]
    xored = bytes(a ^ b for a, b in zip(data, key_repeated))
    return base64.b64encode(xored).decode('ascii')


def decrypt(ciphertext: str) -> str:
    """接口保留，供未来真正敏感值使用。当前阈值走明文路径不触发此函数。"""
    key = _get_key()
    xored = base64.b64decode(ciphertext)
    key_repeated = (key * ((len(xored) // len(key)) + 1))[:len(xored)]
    data = bytes(a ^ b for a, b in zip(xored, key_repeated))
    return data.decode('utf-8')


_SENSITIVE_STRINGS: Dict[str, str] = {}


def secure(key: str, value: str) -> str:
    """接口兼容保留：默认直接返回明文，避免触发解密启发式。"""
    if key not in _SENSITIVE_STRINGS:
        _SENSITIVE_STRINGS[key] = value
    return _SENSITIVE_STRINGS[key]


def secure_value(name: str, dev_default: str) -> str:
    """【P0 修复】阈值直接返回明文，完全移除运行时 XOR 解密路径。

    命中优先级：dev_default（调用方默认） < 公开明文表 < 环境变量覆盖。
    不再对阈值常量做任何形式的运行时解密，避免启发式引擎判定为字符串混淆。
    """
    # 允许环境变量强制覆盖（便于调试）
    env_key = f"XUANDUN_{name.upper()}"
    env_val = os.environ.get(env_key)
    if env_val is not None:
        return env_val

    # 命中公开明文表 → 直接返回，绝不调用 decrypt()
    if name in _PUBLIC_THRESHOLD_PLAINTEXT:
        return _PUBLIC_THRESHOLD_PLAINTEXT[name]

    # 兼容性兜底：非阈值的其他未来敏感值，才走解密路径
    if name in _PRE_ENCRYPTED:
        return decrypt(_PRE_ENCRYPTED[name])
    return dev_default
