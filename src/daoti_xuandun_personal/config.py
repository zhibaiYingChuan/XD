# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""个人版配置。

配置来源优先级：命令行参数 > 环境变量 > SQLite > 默认值
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Dict, List, Optional

from .types import SecurityLevel

logger = logging.getLogger("xuandun-personal.config")

DEFAULT_PORT = 18765

# 地址末段是否已是「版本段」：/v1、/v1beta、/api/v4 …
#
# ★ 判据不能用 `endswith("/v1")`：那只认字面量 /v1，
#   而 /v1beta、/api/v4 会被再拼一层 /v1，请求直接 404。
_VERSION_SEG = re.compile(r"/v\d+[a-z]*$")

# 用户可能连端点一起粘进来的尾巴。
#
# ★ 这不是「用户填错了」，而是产品必须接住的一种输入：
#   中转站后台把「接入地址」与「完整端点」并排展示，用户按
#   配置 API 的直觉复制的是完整端点。实测（2026-09-29）本机
#   配置填的就是 https://api.commandcode.ai/provider/v1/chat/completions。
#   Anthropic 形态（/messages）也一并收下。
_ENDPOINT_TAIL = re.compile(
    r"/(?:chat/completions|completions|messages|responses|embeddings|models)$"
)

# 掩码串的标记（mask_key() 的产物里必然含它）。
_MASK_MARK = "****"


def is_masked_key(value: Any) -> bool:
    """该值是否是掩码串，而不是真实的 API Key。

    ★ 这是一条**不可省略**的边界校验：
      服务端读取配置时返回的是掩码（``mask_key()`` 的产物），
      前端若原样回传，掩码就会被当成新 Key 写进 config.json ——
      之后所有请求都 401，而配置页上完全看不出异常，
      用户只会以为中转站封了他。失效是静默的，所以判据必须独立存在、
      可被单独测试，而不是埋在某个视图函数里。
    """
    text = str(value or "").strip()
    if not text:
        return False
    # mask_key() 有两种产物：长 Key 的 ``xxxx****yyyy``、短 Key 的 ``***``
    return _MASK_MARK in text or set(text) <= {"*"}


# 配置文件路径
_CONFIG_DIR = (
    Path(os.getenv("LOCALAPPDATA") or Path.home() / ".config")
    / "com.daoti.xuandun-personal"
)
CONFIG_FILE = _CONFIG_DIR / "config.json"


def _known_fields(cls: type, raw: Any) -> Dict[str, Any]:
    """按 dataclass 声明过滤字段，丢弃配置里的未知键。

    ★ 为什么不直接 `cls(**raw)`：dataclass 对未知关键字抛 TypeError，
      而 load() 把 TypeError 一律当作「配置损坏」整体降级为默认值 ——
      用户的中转站地址、API Key、安全级别、端口会被**全部静默丢弃**。

      典型场景：某版本删掉了某个字段（如 relay.model），
      用户 config.json 里仍留着旧键，升级后所有设置瞬间归零，
      且只留一行 warning。一个过期的键不该有这种杀伤力。
    """
    if not isinstance(raw, dict):
        return {}
    known = {f.name for f in fields(cls)}
    unknown = sorted(set(raw) - known)
    if unknown:
        logger.info("%s 忽略未知配置项: %s", cls.__name__, ", ".join(unknown))
    return {k: v for k, v in raw.items() if k in known}


@dataclass
class RelayConfig:
    """中转站配置（个人版核心配置）。

    ★ 这里**不**包含 model 字段：玄盾监控的是 API，不是某个模型。
      请求里的 model 原样透传给中转站，玄盾不改写它。
    """

    name: str = "默认中转站"           # 显示名
    base_url: str = ""                 # 如 https://api.example.com
    api_key: str = ""                  # 中转站 API Key
    enabled: bool = True

    def validate(self) -> List[str]:
        """校验配置，返回错误列表（空表示通过）。"""
        errors: List[str] = []
        if not self.base_url:
            errors.append("中转站地址不能为空")
        elif not self.base_url.startswith(("http://", "https://")):
            errors.append("中转站地址必须以 http:// 或 https:// 开头")
        if not self.api_key:
            errors.append("中转站 API Key 不能为空")
        return errors

    @property
    def normalized_base(self) -> str:
        """规范化地址：去空白 → 去查询串 → 剥端点 → 补 /v1。

        ★ 设计前提：**用户不该需要知道地址该填到哪一段**。
          中转站给什么形式就粘什么 —— 带 /v1、不带 /v1、
          连完整端点一起、带查询串、Anthropic 形态，
          都要能直接用。要求用户先理解 base_url 与 endpoint 的区别，
          等于把配置门槛推给了最不懂的人。

        ★ 实测（2026-09-29）本机配置填的是
          ``https://api.commandcode.ai/provider/v1/chat/completions``。
          旧判据 ``endswith("/v1")`` 不成立 → 拼成
          ``.../chat/completions/v1/chat/completions``，该地址实测返回
          404「is not a registered route」；本属性拼出的
          ``.../provider/v1/chat/completions`` 实测路由命中
          （返回的是模型不支持，属另一层问题）。
        """
        base = (self.base_url or "").strip()
        # 从文档复制时常带查询串/锚点，留着会污染请求路径
        for sep in ("?", "#"):
            base = base.split(sep, 1)[0]
        base = base.rstrip("/")
        # 剥掉误粘的端点尾巴（在补 /v1 之前做，才能得到干净的接入地址）
        base = _ENDPOINT_TAIL.sub("", base).rstrip("/")
        if not _VERSION_SEG.search(base):
            base = f"{base}/v1"
        return base

    def mask_key(self) -> str:
        """掩码显示 API Key。"""
        if len(self.api_key) <= 8:
            return "***"
        return f"{self.api_key[:4]}****{self.api_key[-4:]}"


@dataclass
class GuardConfig:
    """防护配置。"""

    security_level: str = SecurityLevel.BALANCED.value
    enable_response_verify: bool = True    # 响应验证
    enable_request_sanitize: bool = True   # 请求脱敏
    enable_reputation: bool = True          # 中转站评估
    enable_pattern_check: bool = True      # 响应模式异常检测
    # 敏感类型开关
    # ★ P1-5 修复：文档 4.4 图示中「银行卡」「自定义关键词」默认未勾选，
    #   原实现全部默认 True；由于 bankcard 三级均为 BLOCK，默认勾选时
    #   误命中 16-19 位数字会直接阻断整个请求，比文档预期严格得多。
    enabled_categories: Dict[str, bool] = field(default_factory=lambda: {
        "api_key": True,
        "aws_key": True,
        "private_key": True,
        "jwt": True,
        "idcard": True,
        "phone": True,
        "email": True,
        "bankcard": False,   # 文档默认未勾选（误报率高，命中即阻断）
        "custom": False,     # 文档默认未勾选
    })
    custom_keywords: List[str] = field(default_factory=list)

    def validate(self) -> List[str]:
        errors: List[str] = []
        if self.security_level not in (s.value for s in SecurityLevel):
            errors.append(f"无效的安全级别: {self.security_level}")
        return errors


@dataclass
class ServerConfig:
    """代理服务配置。"""

    host: str = "127.0.0.1"        # 只监听本地（安全底线）
    port: int = DEFAULT_PORT
    log_level: str = "INFO"
    request_timeout_s: int = 300     # 上游超时（与流式长响应兼容）

    def validate(self) -> List[str]:
        errors: List[str] = []
        if not (1024 <= self.port <= 65535):
            errors.append(f"端口超出合法范围: {self.port}")
        if self.host not in ("127.0.0.1", "localhost", "::1"):
            errors.append(
                f"个人版代理只允许监听本地（当前 {self.host}），"
                "如需远程访问请使用企业版网关"
            )
        return errors


@dataclass
class PersonalConfig:
    """个人版完整配置。"""

    relay: RelayConfig = field(default_factory=RelayConfig)
    guard: GuardConfig = field(default_factory=GuardConfig)
    server: ServerConfig = field(default_factory=ServerConfig)

    def validate(self) -> List[str]:
        """全量校验，返回所有错误。"""
        errors: List[str] = []
        errors.extend(self.server.validate())
        errors.extend(self.guard.validate())
        if self.relay.enabled:
            errors.extend(self.relay.validate())
        return errors

    def is_valid(self) -> bool:
        return len(self.validate()) == 0

    # ── 持久化 ──

    @staticmethod
    def load() -> "PersonalConfig":
        """从配置文件加载（不存在则返回默认配置）。"""
        if not CONFIG_FILE.exists():
            logger.info("配置文件不存在，使用默认配置: %s", CONFIG_FILE)
            return PersonalConfig()

        try:
            # ★★ 必须用 utf-8-sig 而不是 utf-8。
            #   Windows 记事本、PowerShell 的 Out-File、某些同步工具
            #   写出的文本文件会带 UTF-8 BOM。utf-8 会把它当成
            #   JSON 的第一个字符而抛「Unexpected UTF-8 BOM」——
            #   用户的全部设置（中转站地址、安全级别、API Key）
            #   随之被丢弃，且只留一行 warning，多数人不会注意到。
            #   utf-8-sig 对有无 BOM 都正确，是这里唯一该用的编码。
            raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8-sig"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("配置文件读取失败（%s），使用默认配置", e)
            return PersonalConfig()

        try:
            return PersonalConfig(
                relay=RelayConfig(**_known_fields(RelayConfig, raw.get("relay", {}))),
                guard=GuardConfig(**_known_fields(GuardConfig, raw.get("guard", {}))),
                server=ServerConfig(**_known_fields(ServerConfig, raw.get("server", {}))),
            )
        except TypeError as e:
            logger.warning("配置字段不匹配（%s），使用默认配置", e)
            return PersonalConfig()

    def save(self) -> Path:
        """保存到配置文件。"""
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "relay": asdict(self.relay),
            "guard": asdict(self.guard),
            "server": asdict(self.server),
        }
        CONFIG_FILE.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        # Windows 下配置文件不应对其他用户可读（含 API Key）
        try:
            os.chmod(CONFIG_FILE, 0o600)
        except OSError:
            pass
        logger.info("配置已保存: %s", CONFIG_FILE)
        return CONFIG_FILE

    # ── 环境变量覆盖 ──

    def apply_env_overrides(self) -> None:
        """应用环境变量覆盖（便于 CI / 脚本化配置）。"""
        if v := os.getenv("XUANDUN_PERSONAL_RELAY_URL"):
            self.relay.base_url = v
        if v := os.getenv("XUANDUN_PERSONAL_RELAY_KEY"):
            self.relay.api_key = v
        if v := os.getenv("XUANDUN_PERSONAL_PORT"):
            try:
                self.server.port = int(v)
            except ValueError:
                logger.warning("无效的端口环境变量: %s", v)
        if v := os.getenv("XUANDUN_PERSONAL_LEVEL"):
            self.guard.security_level = v
        logger.info("已应用环境变量覆盖")

    # ── 脱敏视图（供 API 返回，不含密钥明文）──

    def to_safe_dict(self) -> Dict[str, Any]:
        """返回不含 API Key 明文的配置视图。"""
        relay = asdict(self.relay)
        relay["api_key"] = self.relay.mask_key()
        return {
            "relay": relay,
            "guard": asdict(self.guard),
            "server": asdict(self.server),
        }
