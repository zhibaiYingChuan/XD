# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""玄盾 AI 安全网关 — 安全检测集成（T04）。

复用核心检测能力（洛书映射器 + 阴阳门），
通过共享 XuanDun 实例 + 按模型策略开关（A-12）。

检测策略应用时机（A-11 修正）：
1. 接收请求 → 提取 model 字段
2. 路由引擎匹配 → 确定目标模型
3. 读取目标模型的 security 配置
4. 按配置决定是否调用检测
5. 检测通过 → 转发到后端模型
6. 检测命中 → 阴阳门拦截（403）
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

from .schema import ModelConfig, SecurityPolicy

logger = logging.getLogger("xuandun-gateway-security")

# 防御层级映射
_POLICY_TO_DEFENSE_LEVEL = {
    "strict": "STRICT",
    "balanced": "STANDARD",
    "permissive": "BASIC",
}


def _extract_text_from_messages(messages: list[Any]) -> str:
    """从 OpenAI 协议 messages 中提取待检测文本。

    OpenAI 协议 messages 格式：
    [
        {"role": "system", "content": "..."},
        {"role": "user", "content": "..."},
        {"role": "assistant", "content": "..."},
        {"role": "user", "content": [{"type": "text", "text": "..."}, ...]}
    ]
    """
    parts: list[str] = []
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content", "")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            # 多模态消息：提取文本部分
            for item in content:
                if isinstance(item, dict):
                    if item.get("type") == "text":
                        parts.append(str(item.get("text", "")))
                    elif "text" in item:
                        parts.append(str(item["text"]))
    return "\n".join(parts)


class SecurityChecker:
    """安全检测器：共享 XuanDun 实例 + 按模型策略开关。

    设计决策（A-12）：共享 shield 实例，避免每模型加载一份 numpy 内存。
    洛书映射器语言无关，共享避免资源浪费。

    线程安全：XuanDun 内部已用锁保护，此处不再加锁。
    """

    def __init__(self):
        self._shields: dict[str, Any] = {}
        self._lock = threading.Lock()
        self._available = False
        try:
            from daoti_xuandun import XuanDun, XuanDunConfig, DefenseLevel
            self._XuanDun = XuanDun
            self._XuanDunConfig = XuanDunConfig
            self._DefenseLevel = DefenseLevel
            self._available = True
            logger.info("玄盾核心检测能力加载成功")
        except ImportError as e:
            logger.warning(
                "玄盾核心检测能力不可用（daoti_xuandun 未安装）: %s", e
            )

    @property
    def available(self) -> bool:
        return self._available

    def _get_shield_for_policy(self, policy: SecurityPolicy):
        """按策略获取共享 shield 实例（每策略一个实例，非每模型）。"""
        if not self._available:
            return None

        level_name = _POLICY_TO_DEFENSE_LEVEL.get(policy, "STANDARD")
        with self._lock:
            if level_name not in self._shields:
                level = getattr(self._DefenseLevel, level_name)
                config = self._XuanDunConfig.for_level(level)
                shield = self._XuanDun(config)
                # 桌面端/网关强制启用保护模式
                shield.switch_mode("protecting")
                self._shields[level_name] = shield
                logger.info(
                    "创建 shield 实例: policy=%s, level=%s",
                    policy, level_name,
                )
            return self._shields[level_name]

    async def check_request(
        self, model_config: ModelConfig, request_body: dict
    ) -> None:
        """检测请求是否安全。

        Args:
            model_config: 目标模型配置（含 security 策略）
            request_body: OpenAI 协议请求体

        Raises:
            BlockedByShieldError: 检测命中威胁时抛出（403）
        """
        # 按模型策略决定是否检测（A-11 修正）
        if not model_config.security.input_check:
            logger.debug(
                "模型 %s input_check=False，跳过输入检测",
                model_config.id,
            )
            return

        if not self._available:
            logger.warning(
                "模型 %s 需要输入检测但核心能力不可用，fail-open 放行",
                model_config.id,
            )
            return

        # 提取待检测文本
        messages = request_body.get("messages", [])
        text = _extract_text_from_messages(messages)
        if not text.strip():
            logger.debug("模型 %s 请求无文本内容，跳过检测", model_config.id)
            return

        shield = self._get_shield_for_policy(model_config.security.policy)

        # 在线程池中执行同步检测，避免阻塞事件循环
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                None, self._sync_check, shield, text
            )
        except Exception as e:
            logger.error(
                "模型 %s 检测异常，fail-open 放行: %s",
                model_config.id, e, exc_info=True,
            )
            return

        if result is None:
            # 检测异常已记录，放行
            return

        is_safe, reason = result
        if not is_safe:
            logger.info(
                "模型 %s 请求被拦截: policy=%s, reason=%s",
                model_config.id, model_config.security.policy, reason,
            )
            from .errors import BlockedByShieldError
            raise BlockedByShieldError(
                reason=reason, policy=model_config.security.policy
            )

        logger.debug(
            "模型 %s 请求检测通过: policy=%s",
            model_config.id, model_config.security.policy,
        )

    def _sync_check(self, shield, text: str):
        """同步执行检测（在线程池中调用）。

        Returns:
            (is_safe, reason) 元组，异常时返回 None
        """
        try:
            result = shield.check(text)
            # XuanDun.check 返回检测结果，is_safe=True 表示安全
            # 兼容不同返回格式
            if isinstance(result, dict):
                is_safe = result.get("is_safe", True)
                reason = result.get("reason", "")
                if not is_safe:
                    return False, reason or "检测到潜在威胁"
                return True, ""
            elif isinstance(result, bool):
                return result, "" if result else "检测到潜在威胁"
            elif hasattr(result, "is_safe"):
                return (
                    result.is_safe,
                    getattr(result, "reason", "") or "检测到潜在威胁",
                )
            else:
                # 未知返回格式，fail-open
                logger.warning(
                    "检测返回未知格式 %s，fail-open 放行",
                    type(result).__name__,
                )
                return True, ""
        except Exception as e:
            logger.error(
                "检测执行异常，fail-open 放行: %s", e, exc_info=True
            )
            return None


# 全局单例（共享 shield 实例）
_checker: SecurityChecker | None = None


def get_security_checker() -> SecurityChecker:
    """获取全局安全检测器单例。"""
    global _checker
    if _checker is None:
        _checker = SecurityChecker()
    return _checker
