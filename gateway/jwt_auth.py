"""玄盾网关 — 企业 API Key 离线校验（RS256 JWT）。

企业 API Key 由供应商（玄盾）离线签发，形如 `XDKEY-<base64url(jwt)>`，
携带 iss/exp/tier/sub/jti 等声明。网关内置公钥做离线验签，无需外部服务。

公钥来源（二选一，均通过环境变量）：
  - XUANDUN_PUBLIC_KEY     直接给 PEM 公钥内容
  - XUANDUN_PUBLIC_KEY_PATH 给 PEM 公钥文件路径

安全默认：未配置公钥时，任何企业 API Key 都无法通过校验（fail-closed）。
"""
from __future__ import annotations

import logging
import os
from typing import Optional

import jwt

_PREFIX = "XDKEY-"
_ISSUER = "xuanDun"

logger = logging.getLogger("xuandun-jwt")


def _load_public_key() -> Optional[str]:
    content = os.getenv("XUANDUN_PUBLIC_KEY")
    path = os.getenv("XUANDUN_PUBLIC_KEY_PATH")
    if content and content.strip():
        return content.strip()
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except OSError as e:
            logger.warning("读取公钥文件失败: %s", e)
    return None


class ApiKeyVerifier:
    """企业 API Key 校验器。"""

    def __init__(self, public_key: Optional[str] = None) -> None:
        self.public_key = public_key or _load_public_key()

    def is_configured(self) -> bool:
        return bool(self.public_key)

    def verify(self, api_key: str, revoked_jtis: frozenset = frozenset()) -> Optional[dict]:
        """校验 API Key。合法且未吊销返回 claims，否则返回 None。"""
        if not self.public_key or not api_key or not api_key.startswith(_PREFIX):
            return None
        token = api_key[len(_PREFIX):]
        try:
            claims = jwt.decode(
                token, self.public_key, algorithms=["RS256"],
                options={"require": ["iss", "exp", "jti"]},
            )
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        if claims.get("iss") != _ISSUER:
            return None
        if claims.get("jti") in revoked_jtis:
            return None
        return claims
