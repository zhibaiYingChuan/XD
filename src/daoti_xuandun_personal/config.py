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
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .types import SecurityLevel

logger = logging.getLogger("xuandun-personal.config")

DEFAULT_PORT = 18765

# 配置文件路径
_CONFIG_DIR = (
    Path(os.getenv("LOCALAPPDATA") or Path.home() / ".config")
    / "com.daoti.xuandun-personal"
)
CONFIG_FILE = _CONFIG_DIR / "config.json"


@dataclass
class RelayConfig:
    """中转站配置（个人版核心配置）。"""

    name: str = "默认中转站"           # 显示名
    base_url: str = ""                 # 如 https://api.example.com
    api_key: str = ""                  # 中转站 API Key
    model: str = ""                    # 默认模型
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
        if not self.model:
            errors.append("模型名称不能为空")
        return errors

    @property
    def normalized_base(self) -> str:
        """规范化地址（去掉尾部斜杠 + 补 /v1）。"""
        base = self.base_url.rstrip("/")
        if not base.endswith("/v1"):
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
            raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("配置文件读取失败（%s），使用默认配置", e)
            return PersonalConfig()

        try:
            return PersonalConfig(
                relay=RelayConfig(**raw.get("relay", {})),
                guard=GuardConfig(**raw.get("guard", {})),
                server=ServerConfig(**raw.get("server", {})),
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
        if v := os.getenv("XUANDUN_PERSONAL_MODEL"):
            self.relay.model = v
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
