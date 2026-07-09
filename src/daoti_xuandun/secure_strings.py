# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

import base64
import os

try:
    from ._key_generated import COMPILED_KEY, SECURE_VALUES
    _KEY: bytes | None = COMPILED_KEY
    _PRE_ENCRYPTED: dict[str, str] = SECURE_VALUES
except ImportError:
    _KEY = None
    _PRE_ENCRYPTED = {}


def _get_key() -> bytes:
    global _KEY
    if _KEY is None:
        key_str = os.environ.get("XUANDUN_DEV_KEY")
        if not key_str:
            import sys
            sys.stderr.write("[XuanDun] WARNING: XUANDUN_DEV_KEY not set, using insecure fallback key\n")
            key_str = "dev-fallback-key-do-not-use-in-production"
        _KEY = key_str.encode("utf-8").ljust(32, b"\x00")[:32]
    return _KEY


def encrypt(plaintext: str) -> str:
    key = _get_key()
    data = plaintext.encode('utf-8')
    key_repeated = (key * ((len(data) // len(key)) + 1))[:len(data)]
    xored = bytes(a ^ b for a, b in zip(data, key_repeated))
    return base64.b64encode(xored).decode('ascii')


def decrypt(ciphertext: str) -> str:
    key = _get_key()
    xored = base64.b64decode(ciphertext)
    key_repeated = (key * ((len(xored) // len(key)) + 1))[:len(xored)]
    data = bytes(a ^ b for a, b in zip(xored, key_repeated))
    return data.decode('utf-8')


_SENSITIVE_STRINGS: dict[str, str] = {}


def secure(key: str, value: str) -> str:
    if key not in _SENSITIVE_STRINGS:
        _SENSITIVE_STRINGS[key] = encrypt(value)
    return decrypt(_SENSITIVE_STRINGS[key])


def secure_value(name: str, dev_default: str) -> str:
    """返回解密后的敏感值。生产环境从 _key_generated.py 预加密值解密；开发环境用 dev_default。"""
    if name in _PRE_ENCRYPTED:
        return decrypt(_PRE_ENCRYPTED[name])
    return dev_default
