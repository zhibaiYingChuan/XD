# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""玄盾 AI 安全网关 — 错误传播规范（A-24）。

对应 v2.0 文档 4.6 节错误传播规范。

核心原则：
- 流式已开始：用 SSE error event 后关闭流（HTTP 状态码已是 200）
- 流式未开始：用 HTTP 状态码 + JSON 错误体
- 玄盾检测拦截：403 + 拦截原因
- 后端不可达：503 + 兜底错误体
- 密钥失效：502 + Retry-After: 0 + 禁止自动重试标记
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple


logger = logging.getLogger("xuandun-gateway-errors")


# 玄盾错误类型常量
ERROR_TYPE_BLOCKED = "xuandun_blocked"
ERROR_TYPE_UPSTREAM_TIMEOUT = "upstream_timeout"
ERROR_TYPE_UPSTREAM_UNREACHABLE = "upstream_unreachable"
ERROR_TYPE_UPSTREAM_KEY_INVALID = "upstream_key_invalid"
ERROR_TYPE_NO_ROUTE = "no_route_matched"
ERROR_TYPE_MODEL_DISABLED = "model_disabled"
ERROR_TYPE_BAD_REQUEST = "bad_request"
ERROR_TYPE_INTERNAL = "xuandun_internal"


def build_error_body(
    message: str,
    error_type: str = ERROR_TYPE_INTERNAL,
    code: Optional[str] = None,
    hint: Optional[str] = None,
) -> Dict[str, Any]:
    """构造 OpenAI 兼容的错误响应体。

    OpenAI 协议错误格式：
    {
        "error": {
            "message": "...",
            "type": "...",
            "code": "...",
            "param": null
        }
    }
    """
    err: Dict[str, Any] = {
        "message": message,
        "type": error_type,
        "param": None,
    }
    if code is not None:
        err["code"] = code
    if hint is not None:
        err["hint"] = hint
    return {"error": err}


def build_blocked_body(reason: str, policy: str = "balanced") -> Dict[str, Any]:
    """构造安全检测拦截错误体（403）。"""
    return build_error_body(
        message=f"请求被玄盾安全策略拦截：{reason}",
        error_type=ERROR_TYPE_BLOCKED,
        code="prompt_injection_detected",
        hint=f"policy={policy}",
    )


def build_sse_error_event(error_body: Dict[str, Any]) -> bytes:
    """构造 SSE error event（流式中断时使用）。

    流式响应已开始（HTTP 200 已发送），无法再用 HTTP 状态码，
    通过 SSE error event 通知客户端，然后关闭流。
    """
    data = json.dumps(error_body, ensure_ascii=False)
    return f"event: error\ndata: {data}\n\n".encode("utf-8")


def build_upstream_error_body(
    status_code: int, upstream_body: Optional[bytes] = None
) -> Dict[str, Any]:
    """根据上游状态码构造错误体。

    密钥失效（上游 401）特殊处理（评审修订重要-3）：
    - 返回 502 + 玄盾错误体（含"上游密钥失效"hint）
    - Retry-After: 0 头
    - 禁止自动重试标记
    """
    if status_code == 401:
        # 密钥失效：不透传 401，转为 502 + 玄盾错误体
        return build_error_body(
            message="上游密钥失效或已过期",
            error_type=ERROR_TYPE_UPSTREAM_KEY_INVALID,
            code="upstream_auth_failed",
            hint="上游密钥失效，禁止自动重试",
        )
    if status_code == 429:
        return build_error_body(
            message="上游限流",
            error_type="rate_limit_error",
            code="upstream_rate_limited",
        )
    if 400 <= status_code < 500:
        return build_error_body(
            message=f"上游返回 {status_code}",
            error_type="upstream_client_error",
            code=f"upstream_{status_code}",
        )
    if 500 <= status_code < 600:
        return build_error_body(
            message=f"上游服务器错误 {status_code}",
            error_type="upstream_server_error",
            code=f"upstream_{status_code}",
        )
    return build_error_body(
        message=f"上游返回非预期状态码 {status_code}",
        error_type="upstream_unexpected",
    )


def map_status_for_upstream_error(status_code: int) -> int:
    """根据上游状态码映射玄盾返回的 HTTP 状态码。

    - 401 → 502（密钥失效特殊处理，评审修订重要-3）
    - 4xx → 透传上游码
    - 5xx → 透传上游码
    """
    if status_code == 401:
        return 502
    return status_code


def should_disable_retry(status_code: int) -> bool:
    """判断是否应禁止自动重试。

    G-21 修复：429 限流时也应禁止立即重试，避免 SDK 触发更严限流。
    401 密钥失效时禁止重试（评审修订重要-3）。
    """
    return status_code in (401, 429)


class GatewayError(Exception):
    """网关错误基类。"""

    def __init__(
        self,
        status_code: int,
        error_body: Dict[str, Any],
        headers: Dict[str, str] | None = None,
    ):
        self.status_code = status_code
        self.error_body = error_body
        self.headers = headers or {}
        super().__init__(error_body.get("error", {}).get("message", ""))


class BlockedByShieldError(GatewayError):
    """请求被玄盾安全策略拦截（403）。"""

    def __init__(self, reason: str, policy: str = "balanced"):
        super().__init__(
            status_code=403,
            error_body=build_blocked_body(reason, policy),
        )


class NoRouteError(GatewayError):
    """无路由匹配且无兜底（404）。"""

    def __init__(self, request_model: Optional[str] = None):
        msg = f"无路由匹配: model={request_model!r}"
        if request_model is None:
            msg = "请求未指定 model 且无兜底路由"
        super().__init__(
            status_code=404,
            error_body=build_error_body(
                message=msg,
                error_type=ERROR_TYPE_NO_ROUTE,
                code="no_route_matched",
            ),
        )


class ModelDisabledError(GatewayError):
    """目标模型已禁用（503）。"""

    def __init__(self, model_id: str, reason: str = "disabled"):
        super().__init__(
            status_code=503,
            error_body=build_error_body(
                message=f"模型 {model_id!r} 不可用：{reason}",
                error_type=ERROR_TYPE_MODEL_DISABLED,
                code="model_disabled",
                hint=f"model_id={model_id}",
            ),
        )


class UpstreamTimeoutError(GatewayError):
    """上游超时（502/504）。"""

    def __init__(self, timeout_type: str = "read"):
        code = 504 if timeout_type == "read" else 502
        super().__init__(
            status_code=code,
            error_body=build_error_body(
                message=f"上游{timeout_type}超时",
                error_type=ERROR_TYPE_UPSTREAM_TIMEOUT,
                code=f"upstream_{timeout_type}_timeout",
            ),
        )


class UpstreamUnreachableError(GatewayError):
    """上游不可达（503）。"""

    def __init__(self, detail: str = "上游不可达"):
        super().__init__(
            status_code=503,
            error_body=build_error_body(
                message=detail,
                error_type=ERROR_TYPE_UPSTREAM_UNREACHABLE,
                code="upstream_unreachable",
            ),
        )


class UpstreamHttpError(GatewayError):
    """上游返回非 2xx 状态码。"""

    def __init__(self, status_code: int, upstream_body: Optional[bytes] = None):
        mapped = map_status_for_upstream_error(status_code)
        error_body = build_upstream_error_body(status_code, upstream_body)
        headers: Dict[str, str] = {}
        # G-21 修复 + 评审修订重要-3：401/429 禁止自动重试
        if should_disable_retry(status_code):
            headers["X-XuanDun-NoRetry"] = "1"
            if status_code == 401:
                # 密钥失效：立即停止重试
                headers["Retry-After"] = "0"
            elif status_code == 429:
                # 限流：默认 60s 后重试（生产环境应从上游 Retry-After 头透传）
                headers["Retry-After"] = "60"
        super().__init__(
            status_code=mapped,
            error_body=error_body,
            headers=headers,
        )
