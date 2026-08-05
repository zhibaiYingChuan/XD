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
from typing import Any, Dict, List, Optional, Set, Tuple


from .schema import ModelConfig, SecurityPolicy

logger = logging.getLogger("xuandun-gateway-security")

# 防御层级映射
_POLICY_TO_DEFENSE_LEVEL = {
    "strict": "STRICT",
    "balanced": "STANDARD",
    "permissive": "BASIC",
}


def _extract_text_from_messages(messages: List[Any]) -> str:
    """从 OpenAI 协议 messages 中提取待检测文本。

    OpenAI 协议 messages 格式：
    [
        {"role": "system", "content": "..."},
        {"role": "user", "content": "..."},
        {"role": "assistant", "content": "..."},
        {"role": "user", "content": [{"type": "text", "text": "..."}, ...]}
    ]
    """
    parts: List[str] = []
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
        self._shields: Dict[str, Any] = {}
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

    # ---------- P2 无限消耗防护：限流/配额 管理接口 ----------
    def rate_limit_status(
        self,
        policy: str | None = None,
        session_id: str | None = None,
        top_n: int = 20,
    ) -> Dict[str, Any]:
        """聚合所有安全策略（或指定策略）的 XuanDun shield 限流状态。

        返回：{ policy_name: rate_limit_status() 结果 }
        """
        out: Dict[str, Any] = {}
        # 确保 shields 已初始化：构造 STANDARD 策略触发实例化（最少一个）
        with self._lock:
            level_names = list(self._shields.keys())
        if not level_names:
            # 无已创建 shield：先尝试用默认策略实例化
            # SecurityPolicy = Literal["strict", "balanced", "permissive"]（不是枚举，用字符串）
            self._get_shield_for_policy("balanced")
            with self._lock:
                level_names = list(self._shields.keys())

        for level_name in level_names:
            if policy is not None and level_name != policy:
                continue
            shield = self._shields.get(level_name)
            if shield is None:
                continue
            try:
                if hasattr(shield, "rate_limit_status"):
                    out[level_name] = shield.rate_limit_status(
                        session_id=session_id, top_n=top_n
                    )
                else:
                    out[level_name] = {"error": "rate_limit_status 未实现"}
            except Exception as e:  # noqa: BLE001
                out[level_name] = {"error": str(e)}
        if policy is not None and policy not in out:
            # 指定策略但未找到：明确返回空占位
            out[policy] = {"sessions": {}, "error": "policy_not_created"}
        return out

    def update_rate_limit_config(
        self,
        policy: str | None,
        **updates: Any,
    ) -> Dict[str, Any]:
        """批量更新一个或多个安全策略下 shield 的限流配置（字段白名单）。

        白名单字段：global_qps_limit / max_request_length /
                    session_quota_per_minute / session_quota_per_hour
        每字段更新后写回 shield.config（XuanDunConfig 为普通 dataclass，可直接赋值）。
        """
        ALLOWED = {
            "global_qps_limit",
            "max_request_length",
            "session_quota_per_minute",
            "session_quota_per_hour",
        }
        # 过滤非白名单字段
        clean = {k: v for k, v in updates.items() if k in ALLOWED}
        if not clean:
            return {"applied": 0, "rejected_fields": sorted(set(updates) - ALLOWED)}

        rejected = sorted(set(updates) - ALLOWED)
        applied_count = 0
        touched_policies: List[str] = []

        with self._lock:
            level_names = list(self._shields.keys())
        if not level_names:
            # SecurityPolicy = Literal["strict", "balanced", "permissive"]，不是枚举
            self._get_shield_for_policy("balanced")
            with self._lock:
                level_names = list(self._shields.keys())

        for level_name in level_names:
            if policy is not None and level_name != policy:
                continue
            shield = self._shields.get(level_name)
            if shield is None or shield.config is None:
                continue
            cfg = shield.config
            applied_here = False
            for k, v in clean.items():
                if not hasattr(cfg, k):
                    continue
                prev = getattr(cfg, k)
                # 类型校验：4 个字段全部为 int
                try:
                    cast_v = int(v)
                except (TypeError, ValueError):
                    logger.warning(
                        "rate_limit 配置字段 %s 需要 int，实际 %s，跳过",
                        k, type(v).__name__,
                    )
                    continue
                if cast_v < 0:
                    cast_v = 0
                if cast_v != prev:
                    setattr(cfg, k, cast_v)
                    applied_here = True
            if applied_here:
                applied_count += 1
                touched_policies.append(level_name)
        return {
            "applied_policies": applied_count,
            "touched_policies": touched_policies,
            "updated_fields": list(clean.keys()),
            "rejected_fields": rejected,
        }

    def reset_session_quota(
        self,
        session_id: str,
        policy: str | None = None,
    ) -> Dict[str, Any]:
        """重置指定 session_id 的配额计数（分钟 + 小时窗口都清零）。

        可指定 policy，缺省=遍历所有已创建策略。
        """
        reset_count = 0
        reset_in_policies: List[str] = []
        with self._lock:
            level_names = list(self._shields.keys())
        for level_name in level_names:
            if policy is not None and level_name != policy:
                continue
            shield = self._shields.get(level_name)
            if shield is None:
                continue
            quotas = getattr(shield, "_session_quotas", None)
            if isinstance(quotas, dict) and session_id in quotas:
                now = __import__("time").monotonic()
                quotas[session_id] = {
                    "min_cnt": 0, "min_start": now,
                    "hr_cnt": 0, "hr_start": now,
                }
                reset_count += 1
                reset_in_policies.append(level_name)
        return {
            "session_id": session_id,
            "reset_count": reset_count,
            "policies": reset_in_policies,
        }


# 全局单例（共享 shield 实例）
_checker: Optional[SecurityChecker] = None


def get_security_checker() -> SecurityChecker:
    """获取全局安全检测器单例。"""
    global _checker
    if _checker is None:
        _checker = SecurityChecker()
    return _checker
